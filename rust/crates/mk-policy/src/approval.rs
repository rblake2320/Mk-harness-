//! Approval authority and exact-digest binding.
//!
//! An approval is valid for dispatch only if **all** of the following hold,
//! checked here deterministically:
//! * same tenant as the action,
//! * same `action_id`,
//! * `action_digest` byte-equal (constant time) to the canonical digest of
//!   the action as stored,
//! * decision is `approved`,
//! * not revoked, not consumed, not expired at `now`.
//!
//! The *atomic consume* happens in `mk-store` under a row lock; this module
//! decides, it does not mutate.

use chrono::{DateTime, Utc};
use mk_contracts::ApprovalRecord;
use mk_crypto::Digest;
use mk_domain::{ActionId, ApprovalDecision, TenantId, UserId, Workflow};

use crate::decision::DenyCode;

#[derive(Debug, thiserror::Error, Clone, Copy, PartialEq, Eq)]
#[error("approval not valid for dispatch: {code:?}")]
pub struct ApprovalBindingError {
    pub code: DenyCode,
}

/// Verify an approval record against the action it claims to authorize.
pub fn check_binding(
    approval: &ApprovalRecord,
    tenant_id: TenantId,
    action_id: ActionId,
    stored_digest: &Digest,
    now: DateTime<Utc>,
) -> Result<(), ApprovalBindingError> {
    let fail = |code| Err(ApprovalBindingError { code });
    if approval.tenant_id != tenant_id {
        return fail(DenyCode::ApprovalWrongTenant);
    }
    if approval.action_id != action_id {
        return fail(DenyCode::ApprovalWrongAction);
    }
    if !approval.action_digest.ct_eq(stored_digest) {
        return fail(DenyCode::ApprovalDigestMismatch);
    }
    if approval.decision != ApprovalDecision::Approved {
        return fail(DenyCode::ApprovalRejected);
    }
    if approval.revoked_at.is_some_and(|r| r <= now) {
        return fail(DenyCode::ApprovalRevoked);
    }
    if approval.consumed_at.is_some() {
        return fail(DenyCode::ApprovalConsumed);
    }
    if approval.expires_at <= now || approval.created_at > now {
        return fail(DenyCode::ApprovalExpired);
    }
    Ok(())
}

/// Who is trying to approve what.
#[derive(Debug, Clone)]
pub struct ApproverContext<'a> {
    pub tenant_id: TenantId,
    pub approver_id: UserId,
    pub approver_roles: &'a [String],
    pub action_tenant_id: TenantId,
    pub requested_by: UserId,
    pub workflow: Workflow,
    /// Tenant setting: may a user approve their own proposal?
    pub tenant_allows_self_approval: bool,
}

/// Roles that may approve outreach. Agents never hold these roles because
/// assertions for agent-origin proposals carry only `agent`.
const APPROVER_ROLES: [&str; 3] = ["consultant", "manager", "tenant_admin"];

pub fn check_approver(ctx: &ApproverContext<'_>) -> Result<(), ApprovalBindingError> {
    if ctx.tenant_id != ctx.action_tenant_id {
        return Err(ApprovalBindingError {
            code: DenyCode::ApprovalWrongTenant,
        });
    }
    if !ctx
        .approver_roles
        .iter()
        .any(|r| APPROVER_ROLES.contains(&r.as_str()))
    {
        return Err(ApprovalBindingError {
            code: DenyCode::ApproverNotAuthorized,
        });
    }
    if ctx.approver_id == ctx.requested_by
        && (!ctx.tenant_allows_self_approval || ctx.workflow.forbids_self_approval())
    {
        return Err(ApprovalBindingError {
            code: DenyCode::SelfApprovalForbidden,
        });
    }
    Ok(())
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
    use mk_domain::ApprovalId;

    fn t(h: u32) -> DateTime<Utc> {
        Utc.with_ymd_and_hms(2026, 10, 19, h, 0, 0)
            .single()
            .unwrap_or_default()
    }

    fn record(tenant: TenantId, action: ActionId, digest: &Digest) -> ApprovalRecord {
        ApprovalRecord {
            schema_version: mk_contracts::APPROVAL_SCHEMA_VERSION.into(),
            approval_id: ApprovalId::new(),
            tenant_id: tenant,
            action_id: action,
            action_digest: digest.clone(),
            approver_id: UserId::new(),
            approver_roles: vec!["consultant".into()],
            decision: ApprovalDecision::Approved,
            reason: None,
            created_at: t(10),
            expires_at: t(11),
            consumed_at: None,
            revoked_at: None,
            session_id: None,
        }
    }

    #[test]
    fn valid_binding_passes() {
        let (tn, a, d) = (TenantId::new(), ActionId::new(), Digest::of(b"action"));
        assert_eq!(check_binding(&record(tn, a, &d), tn, a, &d, t(10)), Ok(()));
    }

    #[test]
    fn every_mismatch_is_a_distinct_denial() {
        let (tn, a, d) = (TenantId::new(), ActionId::new(), Digest::of(b"action"));
        let base = record(tn, a, &d);
        let code = |r: Result<(), ApprovalBindingError>| r.map_err(|e| e.code);

        assert_eq!(
            code(check_binding(&base, TenantId::new(), a, &d, t(10))),
            Err(DenyCode::ApprovalWrongTenant)
        );
        assert_eq!(
            code(check_binding(&base, tn, ActionId::new(), &d, t(10))),
            Err(DenyCode::ApprovalWrongAction)
        );
        assert_eq!(
            code(check_binding(&base, tn, a, &Digest::of(b"edited"), t(10))),
            Err(DenyCode::ApprovalDigestMismatch)
        );
        let mut r = base.clone();
        r.decision = ApprovalDecision::Rejected;
        assert_eq!(
            code(check_binding(&r, tn, a, &d, t(10))),
            Err(DenyCode::ApprovalRejected)
        );
        let mut r = base.clone();
        r.revoked_at = Some(t(10));
        assert_eq!(
            code(check_binding(&r, tn, a, &d, t(10))),
            Err(DenyCode::ApprovalRevoked)
        );
        let mut r = base.clone();
        r.consumed_at = Some(t(10));
        assert_eq!(
            code(check_binding(&r, tn, a, &d, t(10))),
            Err(DenyCode::ApprovalConsumed)
        );
        assert_eq!(
            code(check_binding(&base, tn, a, &d, t(11))),
            Err(DenyCode::ApprovalExpired),
            "expiry exclusive"
        );
        assert_eq!(
            code(check_binding(&base, tn, a, &d, t(9))),
            Err(DenyCode::ApprovalExpired),
            "not yet created"
        );
    }

    #[test]
    fn copied_approved_flag_has_no_authority() {
        // An approval for action A, replayed against action B with the same
        // digest (identical content) still fails: binding is per action_id.
        let (tn, d) = (TenantId::new(), Digest::of(b"same-content"));
        let a = ActionId::new();
        let b = ActionId::new();
        let r = record(tn, a, &d);
        assert!(check_binding(&r, tn, b, &d, t(10)).is_err());
    }

    #[test]
    fn approver_rules() {
        let tn = TenantId::new();
        let requester = UserId::new();
        let roles = vec!["consultant".to_string()];
        let mut ctx = ApproverContext {
            tenant_id: tn,
            approver_id: UserId::new(),
            approver_roles: &roles,
            action_tenant_id: tn,
            requested_by: requester,
            workflow: Workflow::CustomerFollowUp,
            tenant_allows_self_approval: false,
        };
        assert_eq!(check_approver(&ctx), Ok(()));
        ctx.approver_id = requester;
        assert_eq!(
            check_approver(&ctx).map_err(|e| e.code),
            Err(DenyCode::SelfApprovalForbidden)
        );
        ctx.tenant_allows_self_approval = true;
        assert_eq!(check_approver(&ctx), Ok(()));
        ctx.workflow = Workflow::RecruitOutreach;
        assert_eq!(
            check_approver(&ctx).map_err(|e| e.code),
            Err(DenyCode::SelfApprovalForbidden),
            "high-risk workflow overrides tenant setting"
        );
        let agent_roles = vec!["agent".to_string()];
        ctx.approver_roles = &agent_roles;
        ctx.approver_id = UserId::new();
        assert_eq!(
            check_approver(&ctx).map_err(|e| e.code),
            Err(DenyCode::ApproverNotAuthorized)
        );
        ctx.approver_roles = &roles;
        ctx.action_tenant_id = TenantId::new();
        assert_eq!(
            check_approver(&ctx).map_err(|e| e.code),
            Err(DenyCode::ApprovalWrongTenant)
        );
    }
}
