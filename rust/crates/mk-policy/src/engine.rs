//! The policy engine.

use chrono::{DateTime, Datelike, Timelike, Utc};
use mk_contracts::{ActionRequest, ApprovalRecord};
use mk_crypto::Digest;
use mk_domain::{ActionId, ActionKind, Channel, Risk, TenantId, UserId};

use crate::approval::check_binding;
use crate::consent::{
    ConsentQuery, ContactPermissionFact, SuppressionFact, check_outreach_consent,
};
use crate::decision::{Decision, DenyCode, Obligation};
use crate::tools::ToolAllowlist;

/// Per-tenant policy configuration, loaded by the caller.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TenantPolicy {
    pub tenant_id: TenantId,
    /// Kill switch. `false` fails every consequential action closed.
    pub dispatch_enabled: bool,
    /// Entitlement gate (billing). `false` denies outreach.
    pub agent_operations_entitled: bool,
    pub allow_self_approval: bool,
    /// Local contact hours, inclusive start, exclusive end (0-24).
    pub contact_hours: (u8, u8),
    /// IANA zone name used for the send window obligation; hour checks here
    /// use the caller-supplied `local_hour`.
    pub contact_tz: String,
    /// Max outreach actions per contact per channel in a rolling 24h.
    pub max_per_contact_per_day: u32,
    pub approval_ttl_secs: u32,
    pub required_opt_out_phrase: String,
    pub roles_allowed_to_propose: Vec<String>,
}

impl TenantPolicy {
    /// Conservative defaults. Production loads these from `kernel.policy_versions`.
    #[must_use]
    pub fn defaults(tenant_id: TenantId) -> Self {
        Self {
            tenant_id,
            dispatch_enabled: true,
            agent_operations_entitled: true,
            allow_self_approval: false,
            contact_hours: (8, 21),
            contact_tz: "America/Chicago".into(),
            max_per_contact_per_day: 2,
            approval_ttl_secs: 900,
            required_opt_out_phrase: "reply stop".into(),
            roles_allowed_to_propose: vec![
                "agent".into(),
                "consultant".into(),
                "manager".into(),
                "tenant_admin".into(),
            ],
        }
    }
}

#[derive(Debug, Clone)]
pub struct PolicyInput<'a> {
    pub request: &'a ActionRequest,
    /// From the verified assertion, never from the body.
    pub actor_tenant: TenantId,
    pub actor_user: UserId,
    pub actor_roles: &'a [String],
    pub tenant_policy: &'a TenantPolicy,
    pub tools: &'a ToolAllowlist,
    pub global_dispatch_enabled: bool,
    /// Channel resolved for this action (from kind or work-order target).
    pub channel: Option<Channel>,
    /// HMAC fingerprint of the normalized destination (never the raw value).
    pub destination_hash: &'a str,
    pub permissions: &'a [ContactPermissionFact],
    pub suppressions: &'a [SuppressionFact],
    /// Outreach already sent to this contact+channel in the last 24h.
    pub sends_last_24h: u32,
    /// Hour of day (0-23) in the tenant's contact timezone.
    pub local_hour: u8,
    pub now: DateTime<Utc>,
}

/// Proposal-time evaluation. Deny-by-default: every branch that does not
/// positively establish a requirement denies.
#[must_use]
pub fn evaluate(input: &PolicyInput<'_>) -> Decision {
    let r = input.request;
    let deny = |code: DenyCode, reason: &str| Decision::Deny {
        code,
        reason: reason.to_owned(),
    };

    // 1. Identity binding. Body tenant/user must equal the assertion.
    if r.tenant_id != input.actor_tenant || input.tenant_policy.tenant_id != input.actor_tenant {
        return deny(
            DenyCode::TenantMismatch,
            "request tenant does not match assertion",
        );
    }
    if r.requested_by != input.actor_user {
        return deny(
            DenyCode::ActorNotAuthorized,
            "requested_by does not match assertion subject",
        );
    }
    if !input
        .actor_roles
        .iter()
        .any(|role| input.tenant_policy.roles_allowed_to_propose.contains(role))
    {
        return deny(DenyCode::ActorNotAuthorized, "role may not propose actions");
    }

    // 2. Kill switches.
    if !input.global_dispatch_enabled || !input.tenant_policy.dispatch_enabled {
        return deny(DenyCode::DispatchDisabled, "dispatch is disabled");
    }

    // 3. Time bounds.
    if r.expires_at <= input.now {
        return deny(DenyCode::ActionExpired, "action expired before evaluation");
    }

    // 4. Tool allowlist and kind/channel binding.
    let Some(tool) = input.tools.get(&r.tool_id) else {
        return deny(DenyCode::ToolNotAllowlisted, "tool_id is not allowlisted");
    };
    if !input
        .tools
        .permits(&r.tool_id, r.action_kind, input.channel)
    {
        return deny(
            DenyCode::ToolKindMismatch,
            "tool does not permit this action kind/channel",
        );
    }
    // Effective risk: the proposer may raise risk, never lower it.
    let risk = r.risk.max(tool.floor_risk);

    let mut obligations = vec![
        Obligation::RedactFields {
            keys: vec!["rendered_text".into(), "destination".into()],
        },
        Obligation::AdapterKind {
            kind: tool.adapter_kind.to_owned(),
        },
    ];

    // 5. Outreach-specific gates.
    if r.action_kind.is_outreach() {
        if !input.tenant_policy.agent_operations_entitled {
            return deny(
                DenyCode::EntitlementMissing,
                "tenant is not entitled to agent operations",
            );
        }
        let Some(channel) = input.channel else {
            return deny(DenyCode::ToolKindMismatch, "outreach requires a channel");
        };
        let Ok(contact_id) = r.resource.id.parse() else {
            return deny(
                DenyCode::ContactPermissionMissing,
                "resource id is not a contact id",
            );
        };
        if let Err(e) = check_outreach_consent(&ConsentQuery {
            tenant_id: r.tenant_id,
            contact_id,
            channel,
            purpose: &r.purpose,
            destination_hash: input.destination_hash,
            permissions: input.permissions,
            suppressions: input.suppressions,
            now: input.now,
        }) {
            return deny(e.code, "contact consent check failed");
        }
        let (start, end) = input.tenant_policy.contact_hours;
        if input.local_hour < start || input.local_hour >= end {
            return deny(
                DenyCode::OutsideContactHours,
                "outside tenant contact hours",
            );
        }
        if input.sends_last_24h >= input.tenant_policy.max_per_contact_per_day {
            return deny(
                DenyCode::FrequencyLimitExceeded,
                "per-contact daily frequency reached",
            );
        }
        if requires_opt_out(r.action_kind) {
            let phrase = input.tenant_policy.required_opt_out_phrase.to_lowercase();
            let text = r
                .arguments
                .get("rendered_text")
                .and_then(serde_json::Value::as_str)
                .unwrap_or_default()
                .to_lowercase();
            if !text.contains(&phrase) {
                return deny(DenyCode::OptOutTextMissing, "required opt-out text missing");
            }
            obligations.push(Obligation::RequireOptOutText {
                phrase: input.tenant_policy.required_opt_out_phrase.clone(),
            });
        }
        obligations.push(Obligation::MaxRecipients { max: 1 });
        obligations.push(Obligation::SendWindow {
            start_hour: start,
            end_hour: end,
            tz: input.tenant_policy.contact_tz.clone(),
        });
    }

    // 6. Approval requirement: all outreach and anything High.
    if r.action_kind.is_outreach()
        || risk == Risk::High
        || r.origin.origin_type.is_autonomous() && risk >= Risk::Medium
    {
        obligations.push(Obligation::ApprovalTtlSecs {
            secs: input.tenant_policy.approval_ttl_secs,
        });
        if !input.tenant_policy.allow_self_approval || r.workflow.forbids_self_approval() {
            obligations.push(Obligation::SeparateApprover);
        }
        let policy = match (r.action_kind.is_outreach(), risk) {
            (true, _) => "outreach_high",
            (false, Risk::High) => "high_risk",
            (false, _) => "autonomous_medium",
        };
        return Decision::RequireApproval {
            approval_policy: policy.to_owned(),
            obligations,
        };
    }

    Decision::Allow { obligations }
}

const fn requires_opt_out(kind: ActionKind) -> bool {
    matches!(
        kind,
        ActionKind::SendSms | ActionKind::SendEmail | ActionKind::SendDm
    )
}

/// Facts needed immediately before a side effect.
#[derive(Debug, Clone)]
pub struct RecheckInput<'a> {
    pub action_id: ActionId,
    pub tenant_id: TenantId,
    pub request: &'a ActionRequest,
    pub stored_digest: &'a Digest,
    /// The approval row loaded under lock; `None` only for actions that were
    /// `Allow`ed at proposal time (never outreach).
    pub approval: Option<&'a ApprovalRecord>,
    pub tenant_policy: &'a TenantPolicy,
    pub global_dispatch_enabled: bool,
    pub channel: Option<Channel>,
    pub destination_hash: &'a str,
    pub permissions: &'a [ContactPermissionFact],
    pub suppressions: &'a [SuppressionFact],
    pub local_hour: u8,
    /// Outreach already committed to this contact+channel in the last 24h,
    /// counted under a per-contact lock so concurrent workers serialize.
    pub sends_last_24h: u32,
    /// Attempt number about to start (0 = first). On a retry the approval
    /// was already consumed by this same action's first attempt; that is
    /// the one case where a consumed approval still authorizes.
    pub attempt: u32,
    pub now: DateTime<Utc>,
}

/// Dispatch-time recheck. Returns `Ok(())` only if the action may execute
/// *right now*. Any failure is a typed denial so the worker can choose
/// between `Suppressed`, `Expired`, and `Denied`.
pub fn recheck_at_dispatch(input: &RecheckInput<'_>) -> Result<(), DenyCode> {
    let r = input.request;
    if r.tenant_id != input.tenant_id || input.tenant_policy.tenant_id != input.tenant_id {
        return Err(DenyCode::TenantMismatch);
    }
    if !input.global_dispatch_enabled || !input.tenant_policy.dispatch_enabled {
        return Err(DenyCode::DispatchDisabled);
    }
    if r.expires_at <= input.now {
        return Err(DenyCode::ActionExpired);
    }
    // Re-derive the digest from the stored canonical request and compare to
    // what was stored: detects any post-approval mutation of the row.
    let fresh = r.digest().map_err(|_| DenyCode::ApprovalDigestMismatch)?;
    if !fresh.ct_eq(input.stored_digest) {
        return Err(DenyCode::ApprovalDigestMismatch);
    }
    let needs_approval = r.action_kind.is_outreach() || r.risk == Risk::High;
    match (needs_approval, input.approval) {
        (true, None) => return Err(DenyCode::ApprovalMissing),
        (_, Some(a)) => {
            let r = check_binding(
                a,
                input.tenant_id,
                input.action_id,
                input.stored_digest,
                input.now,
            );
            match r {
                Err(e) if e.code == DenyCode::ApprovalConsumed && input.attempt > 0 => {
                    // Consumed by this action's own earlier attempt. Re-run
                    // every other binding check with the consumption cleared.
                    let mut again = a.clone();
                    again.consumed_at = None;
                    check_binding(
                        &again,
                        input.tenant_id,
                        input.action_id,
                        input.stored_digest,
                        input.now,
                    )
                    .map_err(|e| e.code)?;
                }
                other => other.map_err(|e| e.code)?,
            }
        }
        (false, None) => {}
    }
    if r.action_kind.is_outreach() {
        let channel = input.channel.ok_or(DenyCode::ToolKindMismatch)?;
        let contact_id = r
            .resource
            .id
            .parse()
            .map_err(|_| DenyCode::ContactPermissionMissing)?;
        check_outreach_consent(&ConsentQuery {
            tenant_id: r.tenant_id,
            contact_id,
            channel,
            purpose: &r.purpose,
            destination_hash: input.destination_hash,
            permissions: input.permissions,
            suppressions: input.suppressions,
            now: input.now,
        })
        .map_err(|e| e.code)?;
        let (start, end) = input.tenant_policy.contact_hours;
        if input.local_hour < start || input.local_hour >= end {
            return Err(DenyCode::OutsideContactHours);
        }
        // A retry is the same send, not a new one; only first attempts count
        // against the cap (the first attempt is already in the count once
        // it reached Dispatching).
        if input.attempt == 0 && input.sends_last_24h >= input.tenant_policy.max_per_contact_per_day
        {
            return Err(DenyCode::FrequencyLimitExceeded);
        }
    }
    Ok(())
}

/// Hour of day in the tenant's IANA zone at `now`, honouring DST. Falls
/// back to a fixed offset only when the zone name is unknown.
#[must_use]
pub fn local_hour_in_zone(now: DateTime<Utc>, tz: &str, fallback_offset_minutes: i32) -> u8 {
    match tz.parse::<chrono_tz::Tz>() {
        Ok(zone) => u8::try_from(now.with_timezone(&zone).hour()).unwrap_or(0),
        Err(_) => local_hour_with_offset(now, fallback_offset_minutes),
    }
}

/// Helper for callers that hold a UTC instant and a fixed offset: compute the
/// local hour without pulling a timezone database into this pure crate.
#[must_use]
pub fn local_hour_with_offset(now: DateTime<Utc>, offset_minutes: i32) -> u8 {
    let shifted = now + chrono::Duration::minutes(i64::from(offset_minutes));
    // Datelike import keeps the signature honest about date math.
    let _ = shifted.ordinal();
    u8::try_from(shifted.hour()).unwrap_or(0)
}

#[cfg(test)]
#[allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::unreadable_literal,
    clippy::cast_possible_truncation,
    clippy::float_cmp
)]
mod tests {
    use super::*;
    use chrono::TimeZone;
    use mk_contracts::{Evidence, Origin, Resource};
    use mk_domain::{
        ApprovalDecision, ApprovalId, ContactId, OriginType, PermissionStatus, ResourceType,
        Workflow,
    };
    use serde_json::json;

    fn t(h: u32) -> DateTime<Utc> {
        Utc.with_ymd_and_hms(2026, 10, 19, h, 0, 0)
            .single()
            .unwrap_or_default()
    }

    struct Fx {
        tenant: TenantId,
        user: UserId,
        contact: ContactId,
        req: ActionRequest,
        policy: TenantPolicy,
        perms: Vec<ContactPermissionFact>,
        roles: Vec<String>,
    }

    fn fx() -> Fx {
        let tenant = TenantId::new();
        let user = UserId::new();
        let contact = ContactId::new();
        let req = ActionRequest {
            schema_version: "mk.action.v1".into(),
            action_id: Some(ActionId::new()),
            tenant_id: tenant,
            requested_by: user,
            origin: Origin {
                origin_type: OriginType::Agent,
                session_id: Some("s".into()),
                model_call_id: None,
                mcp_server_id: None,
            },
            workflow: Workflow::CustomerFollowUp,
            action_kind: ActionKind::SendSms,
            tool_id: "mobile.sms.send.v1".into(),
            resource: Resource {
                resource_type: ResourceType::Contact,
                id: contact.to_string(),
            },
            arguments: json!({"contact_id": contact.to_string(), "template_id": "t.v1", "rendered_text": "Hi! Reply STOP to opt out."})
                .as_object()
                .cloned()
                .unwrap_or_default(),
            purpose: "customer_requested_follow_up".into(),
            risk: Risk::High,
            requested_at: t(9),
            expires_at: t(12),
            idempotency_key: "k-12345678".into(),
            evidence: vec![Evidence {
                evidence_type: "conversation".into(),
                id: "c".into(),
                digest: Digest::of(b"c"),
            }],
        };
        let perms = vec![ContactPermissionFact {
            tenant_id: tenant,
            contact_id: contact,
            channel: Channel::Sms,
            status: PermissionStatus::Granted,
            scope: vec!["customer_requested_follow_up".into()],
            granted_at: t(1),
            expires_at: t(23),
            revoked_at: None,
        }];
        Fx {
            tenant,
            user,
            contact,
            req,
            policy: TenantPolicy::defaults(tenant),
            perms,
            roles: vec!["agent".into()],
        }
    }

    fn input<'a>(
        f: &'a Fx,
        tools: &'a ToolAllowlist,
        sups: &'a [SuppressionFact],
    ) -> PolicyInput<'a> {
        PolicyInput {
            request: &f.req,
            actor_tenant: f.tenant,
            actor_user: f.user,
            actor_roles: &f.roles,
            tenant_policy: &f.policy,
            tools,
            global_dispatch_enabled: true,
            channel: Some(Channel::Sms),
            destination_hash: "dest",
            permissions: &f.perms,
            suppressions: sups,
            sends_last_24h: 0,
            local_hour: 10,
            now: t(10),
        }
    }

    #[test]
    fn outreach_requires_approval_with_obligations() {
        let f = fx();
        let tools = ToolAllowlist::v1();
        let d = evaluate(&input(&f, &tools, &[]));
        let Decision::RequireApproval {
            approval_policy,
            obligations,
        } = d
        else {
            unreachable!("expected RequireApproval, got {d:?}");
        };
        assert_eq!(approval_policy, "outreach_high");
        assert!(obligations.contains(&Obligation::SeparateApprover));
        assert!(
            obligations
                .iter()
                .any(|o| matches!(o, Obligation::RequireOptOutText { .. }))
        );
        assert!(
            obligations
                .iter()
                .any(|o| matches!(o, Obligation::MaxRecipients { max: 1 }))
        );
    }

    #[test]
    fn denial_matrix() {
        let tools = ToolAllowlist::v1();
        let code = |f: &Fx, sups: &[SuppressionFact]| evaluate(&input(f, &tools, sups)).deny_code();

        let mut f = fx();
        f.req.tenant_id = TenantId::new();
        assert_eq!(code(&f, &[]), Some(DenyCode::TenantMismatch));

        let mut f = fx();
        f.req.requested_by = UserId::new();
        assert_eq!(code(&f, &[]), Some(DenyCode::ActorNotAuthorized));

        let mut f = fx();
        f.roles = vec!["viewer".into()];
        assert_eq!(code(&f, &[]), Some(DenyCode::ActorNotAuthorized));

        let mut f = fx();
        f.policy.dispatch_enabled = false;
        assert_eq!(code(&f, &[]), Some(DenyCode::DispatchDisabled));

        let mut f = fx();
        f.req.expires_at = t(9);
        assert_eq!(code(&f, &[]), Some(DenyCode::ActionExpired));

        let mut f = fx();
        f.req.tool_id = "shell.exec.v1".into();
        assert_eq!(code(&f, &[]), Some(DenyCode::ToolNotAllowlisted));

        let mut f = fx();
        f.req.action_kind = ActionKind::SendEmail;
        assert_eq!(code(&f, &[]), Some(DenyCode::ToolKindMismatch));

        let mut f = fx();
        f.policy.agent_operations_entitled = false;
        assert_eq!(code(&f, &[]), Some(DenyCode::EntitlementMissing));

        let mut f = fx();
        f.perms.clear();
        assert_eq!(code(&f, &[]), Some(DenyCode::ContactPermissionMissing));

        let mut f = fx();
        f.perms[0].revoked_at = Some(t(9));
        assert_eq!(code(&f, &[]), Some(DenyCode::ContactPermissionRevoked));

        let f = fx();
        let sup = SuppressionFact {
            tenant_id: f.tenant,
            channel: None,
            destination_hash: Some("dest".into()),
            permanent: true,
            created_at: t(1),
            lifted_at: None,
        };
        assert_eq!(code(&f, &[sup]), Some(DenyCode::Suppressed));

        let mut f = fx();
        f.policy.contact_hours = (12, 18);
        assert_eq!(code(&f, &[]), Some(DenyCode::OutsideContactHours));

        let mut f = fx();
        f.policy.max_per_contact_per_day = 0;
        assert_eq!(code(&f, &[]), Some(DenyCode::FrequencyLimitExceeded));

        let mut f = fx();
        f.req
            .arguments
            .insert("rendered_text".into(), json!("Hi there"));
        assert_eq!(code(&f, &[]), Some(DenyCode::OptOutTextMissing));
    }

    #[test]
    fn global_kill_switch_wins() {
        let f = fx();
        let tools = ToolAllowlist::v1();
        let mut i = input(&f, &tools, &[]);
        i.global_dispatch_enabled = false;
        assert_eq!(evaluate(&i).deny_code(), Some(DenyCode::DispatchDisabled));
    }

    #[test]
    fn proposer_cannot_lower_risk() {
        let mut f = fx();
        f.req.risk = Risk::Low;
        let tools = ToolAllowlist::v1();
        assert!(matches!(
            evaluate(&input(&f, &tools, &[])),
            Decision::RequireApproval { .. }
        ));
    }

    #[test]
    fn low_risk_internal_update_by_human_is_allowed_with_obligations() {
        let mut f = fx();
        f.req.action_kind = ActionKind::UpdateContact;
        f.req.tool_id = "crm.contact.update.v1".into();
        f.req.risk = Risk::Low;
        f.req.origin.origin_type = OriginType::Human;
        f.roles = vec!["consultant".into()];
        let tools = ToolAllowlist::v1();
        let mut i = input(&f, &tools, &[]);
        i.channel = None;
        let d = evaluate(&i);
        assert!(matches!(d, Decision::Allow { .. }), "{d:?}");
        assert!(!d.obligations().is_empty());
    }

    #[test]
    fn autonomous_medium_risk_requires_approval() {
        let mut f = fx();
        f.req.action_kind = ActionKind::CreateAppointment;
        f.req.tool_id = "calendar.appointment.create.v1".into();
        f.req.resource.resource_type = ResourceType::Appointment;
        f.req.risk = Risk::Low; // floor is Medium; origin is Agent
        let tools = ToolAllowlist::v1();
        let mut i = input(&f, &tools, &[]);
        i.channel = None;
        assert!(
            matches!(evaluate(&i), Decision::RequireApproval { ref approval_policy, .. } if approval_policy == "autonomous_medium")
        );
    }

    fn approval_for(f: &Fx, digest: &Digest) -> ApprovalRecord {
        ApprovalRecord {
            schema_version: "mk.approval.v1".into(),
            approval_id: ApprovalId::new(),
            tenant_id: f.tenant,
            action_id: f.req.action_id.unwrap_or_default(),
            action_digest: digest.clone(),
            approver_id: UserId::new(),
            approver_roles: vec!["manager".into()],
            decision: ApprovalDecision::Approved,
            reason: None,
            created_at: t(10),
            expires_at: t(11),
            consumed_at: None,
            revoked_at: None,
            session_id: None,
            human_binding: "webauthn".into(),
            approval_credential_row_id: None,
        }
    }

    fn recheck<'a>(
        f: &'a Fx,
        digest: &'a Digest,
        approval: Option<&'a ApprovalRecord>,
        sups: &'a [SuppressionFact],
        now: DateTime<Utc>,
    ) -> RecheckInput<'a> {
        RecheckInput {
            action_id: f.req.action_id.unwrap_or_default(),
            tenant_id: f.tenant,
            request: &f.req,
            stored_digest: digest,
            approval,
            tenant_policy: &f.policy,
            global_dispatch_enabled: true,
            channel: Some(Channel::Sms),
            destination_hash: "dest",
            permissions: &f.perms,
            suppressions: sups,
            local_hour: 10,
            sends_last_24h: 0,
            attempt: 0,
            now,
        }
    }

    #[test]
    fn dispatch_recheck_enforces_frequency_cap_on_first_attempt_only() {
        let f = fx();
        let digest = f.req.digest().unwrap_or_else(|_| Digest::of(b""));
        let a = approval_for(&f, &digest);
        let mut i = recheck(&f, &digest, Some(&a), &[], t(10));
        i.sends_last_24h = 2; // default cap is 2
        assert_eq!(
            recheck_at_dispatch(&i),
            Err(DenyCode::FrequencyLimitExceeded)
        );
        let mut consumed = a.clone();
        consumed.consumed_at = Some(t(10));
        let mut retry = recheck(&f, &digest, Some(&consumed), &[], t(10));
        retry.sends_last_24h = 2;
        retry.attempt = 1;
        assert_eq!(
            recheck_at_dispatch(&retry),
            Ok(()),
            "retry of the same send is not a new send"
        );
    }

    #[test]
    fn local_hour_honours_dst() {
        // 2026-07-01 15:00Z is 10:00 CDT (UTC-5); 2026-01-15 15:00Z is 09:00 CST (UTC-6).
        let summer = Utc
            .with_ymd_and_hms(2026, 7, 1, 15, 0, 0)
            .single()
            .unwrap_or_default();
        let winter = Utc
            .with_ymd_and_hms(2026, 1, 15, 15, 0, 0)
            .single()
            .unwrap_or_default();
        assert_eq!(local_hour_in_zone(summer, "America/Chicago", -300), 10);
        assert_eq!(local_hour_in_zone(winter, "America/Chicago", -300), 9);
        assert_eq!(
            local_hour_in_zone(winter, "Not/AZone", -300),
            10,
            "fallback offset only when zone unknown"
        );
    }

    #[test]
    fn send_dm_resolves_channel_from_platform() {
        let mut f = fx();
        f.req.action_kind = ActionKind::SendDm;
        f.req.tool_id = "mobile.dm.send.v1".into();
        f.perms[0].channel = Channel::Instagram;
        let tools = ToolAllowlist::v1();
        let mut i = input(&f, &tools, &[]);
        i.channel = Some(Channel::Instagram);
        assert!(matches!(evaluate(&i), Decision::RequireApproval { .. }));
        i.channel = Some(Channel::Dm);
        assert_eq!(evaluate(&i).deny_code(), Some(DenyCode::ToolKindMismatch));
        i.channel = None;
        assert_eq!(
            evaluate(&i).deny_code(),
            Some(DenyCode::ToolKindMismatch),
            "outreach without a channel is refused"
        );
    }

    #[test]
    fn retry_may_reuse_its_own_consumed_approval_but_not_an_expired_one() {
        let f = fx();
        let digest = f.req.digest().unwrap_or_else(|_| Digest::of(b""));
        let mut a = approval_for(&f, &digest);
        a.consumed_at = Some(t(10));
        let mut i = recheck(&f, &digest, Some(&a), &[], t(10));
        assert_eq!(
            recheck_at_dispatch(&i),
            Err(DenyCode::ApprovalConsumed),
            "first attempt cannot use a consumed approval"
        );
        i.attempt = 1;
        assert_eq!(recheck_at_dispatch(&i), Ok(()));
        let mut late = recheck(&f, &digest, Some(&a), &[], t(11));
        late.attempt = 1;
        assert_eq!(
            recheck_at_dispatch(&late),
            Err(DenyCode::ApprovalExpired),
            "retry still honours expiry"
        );
        let mut revoked = a.clone();
        revoked.revoked_at = Some(t(10));
        let mut r = recheck(&f, &digest, Some(&revoked), &[], t(10));
        r.attempt = 1;
        assert_eq!(
            recheck_at_dispatch(&r),
            Err(DenyCode::ApprovalRevoked),
            "retry still honours revocation"
        );
    }

    #[test]
    fn dispatch_recheck_happy_and_every_late_change() {
        let f = fx();
        let digest = f.req.digest().unwrap_or_else(|_| Digest::of(b""));
        let a = approval_for(&f, &digest);
        assert_eq!(
            recheck_at_dispatch(&recheck(&f, &digest, Some(&a), &[], t(10))),
            Ok(())
        );

        // No approval for outreach.
        assert_eq!(
            recheck_at_dispatch(&recheck(&f, &digest, None, &[], t(10))),
            Err(DenyCode::ApprovalMissing)
        );

        // Approval expired by dispatch time.
        assert_eq!(
            recheck_at_dispatch(&recheck(&f, &digest, Some(&a), &[], t(11))),
            Err(DenyCode::ApprovalExpired)
        );

        // Permission revoked after approval.
        let mut g = fx();
        g.req = f.req.clone();
        g.tenant = f.tenant;
        g.perms[0].tenant_id = f.tenant;
        g.perms[0].contact_id = f.contact;
        g.perms[0].revoked_at = Some(t(10));
        g.policy = TenantPolicy::defaults(f.tenant);
        let a2 = approval_for(&g, &digest);
        assert_eq!(
            recheck_at_dispatch(&recheck(&g, &digest, Some(&a2), &[], t(10))),
            Err(DenyCode::ContactPermissionRevoked)
        );

        // Suppression added after approval.
        let sup = SuppressionFact {
            tenant_id: f.tenant,
            channel: Some(Channel::Sms),
            destination_hash: None,
            permanent: false,
            created_at: t(10),
            lifted_at: None,
        };
        assert_eq!(
            recheck_at_dispatch(&recheck(&f, &digest, Some(&a), &[sup], t(10))),
            Err(DenyCode::Suppressed)
        );

        // Row mutated after approval: stored digest no longer matches.
        let mut mutated = fx();
        mutated.req = f.req.clone();
        mutated.tenant = f.tenant;
        mutated.perms = f.perms.clone();
        mutated.policy = TenantPolicy::defaults(f.tenant);
        mutated
            .req
            .arguments
            .insert("rendered_text".into(), json!("Hi! Reply STOP. [edited]"));
        assert_eq!(
            recheck_at_dispatch(&recheck(&mutated, &digest, Some(&a), &[], t(10))),
            Err(DenyCode::ApprovalDigestMismatch)
        );

        // Approval consumed already (duplicate delivery).
        let mut used = a.clone();
        used.consumed_at = Some(t(10));
        assert_eq!(
            recheck_at_dispatch(&recheck(&f, &digest, Some(&used), &[], t(10))),
            Err(DenyCode::ApprovalConsumed)
        );

        // Kill switch flipped between approval and dispatch.
        let mut i = recheck(&f, &digest, Some(&a), &[], t(10));
        i.global_dispatch_enabled = false;
        assert_eq!(recheck_at_dispatch(&i), Err(DenyCode::DispatchDisabled));
    }

    #[test]
    fn consent_change_codes_map_to_suppressed() {
        assert!(DenyCode::ContactPermissionRevoked.is_consent_change());
        assert!(DenyCode::Suppressed.is_consent_change());
        assert!(!DenyCode::ApprovalExpired.is_consent_change());
    }

    #[test]
    fn local_hour_helper() {
        assert_eq!(local_hour_with_offset(t(10), -300), 5);
        assert_eq!(local_hour_with_offset(t(23), 120), 1);
    }
}
