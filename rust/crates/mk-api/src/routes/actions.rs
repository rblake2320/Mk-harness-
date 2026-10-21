//! Proposal intake, status, cancel, replay.

use axum::Json;
use axum::extract::{Path, State};
use axum::http::{HeaderMap, StatusCode};
use chrono::Utc;
use mk_contracts::{ActionRequest, ActionResult};
use mk_domain::{ActionId, ActionState, Channel, ContactId, OriginType, Transition};
use mk_policy::{Decision, PolicyInput, evaluate, local_hour_in_zone};
use mk_store::idempotency::IdempotencyOutcome;
use mk_store::{actions, consent, idempotency, outbox, policy};
use serde::Serialize;
use serde_json::{Value, json};

use crate::auth::Principal;
use crate::error::ApiError;
use crate::metrics::{DecisionKind, DecisionLabels};
use crate::routes::{actor_of, destination_hash};
use crate::state::AppState;

#[derive(Debug, Serialize)]
pub struct ProposalResponse {
    pub result: ActionResult,
    pub decision: Decision,
    /// True when this request matched an earlier idempotent submission.
    pub replayed: bool,
}

/// `POST /internal/v1/actions`
pub async fn propose(
    State(st): State<AppState>,
    p: Principal,
    headers: HeaderMap,
    Json(body): Json<Value>,
) -> Result<(StatusCode, Json<ProposalResponse>), ApiError> {
    let rid = |e: ApiError| e.with_request_id(&headers);
    // 1. Schema validation before anything else.
    let req = ActionRequest::from_value(&body).map_err(|e| rid(e.into()))?;
    // 2. Bind identity from the assertion; body values are discarded.
    let action_id = ActionId::new();
    let mut req = req.bound_to(p.tenant, p.user, action_id);
    // The origin is derived from the authenticated principal, never from the
    // body: an agent cannot claim to be a human to skip the approval rule
    // for autonomous medium-risk actions, and a human cannot claim `system`.
    req.origin.origin_type = bound_origin(&p, req.origin.origin_type);
    // Platform-specific kinds (DMs) take their channel from `platform`;
    // every other kind has a fixed channel or none.
    let channel = match req.action_kind.channel() {
        Some(c) => Some(c),
        None => req
            .arguments
            .get("platform")
            .and_then(Value::as_str)
            .and_then(|s| serde_json::from_value(Value::String(s.to_owned())).ok())
            .filter(|c: &Channel| {
                matches!(
                    c,
                    Channel::Instagram | Channel::Facebook | Channel::Tiktok | Channel::X
                )
            }),
    };
    // Normalize the destination *before* the canonical digest is taken, so
    // the approver, the policy, and the adapter all see one value.
    if let (Some(ch), Some(raw)) = (
        channel,
        req.arguments
            .get("to")
            .and_then(Value::as_str)
            .map(str::to_owned),
    ) {
        req.arguments.insert(
            "to".into(),
            Value::String(crate::routes::normalize_destination(ch, &raw)),
        );
    }
    let dest = req.arguments.get("to").and_then(Value::as_str).map(|d| {
        channel.map_or(d.to_owned(), |c| {
            destination_hash(&st.master, p.tenant, c, d)
        })
    });
    let now = Utc::now();
    let actor_id = p.user.to_string();
    let actor = actor_of(&p, &actor_id);

    let mut tx = st.store.begin(p.tenant).await.map_err(|e| rid(e.into()))?;
    // 3. Idempotency: identical resubmission returns the original.
    match idempotency::check_or_insert(
        &mut tx,
        req.action_kind,
        &req.idempotency_key,
        &digest_without_id(&req),
        action_id,
    )
    .await
    .map_err(|e| rid(e.into()))?
    {
        IdempotencyOutcome::Replay(orig) => {
            let a = actions::get(&mut tx, orig)
                .await
                .map_err(|e| rid(e.into()))?;
            tx.commit().await.map_err(|e| rid(e.into()))?;
            return Ok((
                StatusCode::OK,
                Json(ProposalResponse {
                    result: a.to_result(None),
                    decision: Decision::RequireMoreInformation { fields: vec![] },
                    replayed: true,
                }),
            ));
        }
        IdempotencyOutcome::Fresh => {}
    }
    // 4. Persist the draft and the canonical bytes the approval will bind to.
    actions::insert_draft(&mut tx, &req, channel, dest.as_deref(), actor, now)
        .await
        .map_err(|e| rid(e.into()))?;
    actions::transition(
        &mut tx,
        action_id,
        Transition::SubmitForPolicy,
        None,
        actor,
        now,
    )
    .await
    .map_err(|e| rid(e.into()))?;

    // 5. Facts for policy.
    let (tenant_policy, tz) = policy::load(&mut tx).await.map_err(|e| rid(e.into()))?;
    let global = policy::global_dispatch_enabled(st.store.pool())
        .await
        .map_err(|e| rid(e.into()))?;
    let (permissions, suppressions, sends) = match (
        channel,
        dest.as_deref(),
        req.resource.id.parse::<ContactId>(),
    ) {
        (Some(ch), Some(d), Ok(c)) if req.action_kind.is_outreach() => (
            consent::permissions_for(&mut tx, c, ch)
                .await
                .map_err(|e| rid(e.into()))?,
            consent::suppressions_for(&mut tx, ch, d)
                .await
                .map_err(|e| rid(e.into()))?,
            actions::sends_last_24h(&mut tx, &req.resource.id, ch, now)
                .await
                .map_err(|e| rid(e.into()))?,
        ),
        _ => (Vec::new(), Vec::new(), 0),
    };
    // Contact hours run in the customer's zone when the application supplied
    // one; an unparseable zone is refused rather than silently falling back.
    let contact_tz = match mk_policy::contact_zone(&req.arguments, &tenant_policy.contact_tz) {
        Ok(z) => z,
        Err(code) => {
            return Err(rid(ApiError::new(
                StatusCode::UNPROCESSABLE_ENTITY,
                "CONTACT_TZ_INVALID",
                code,
            )));
        }
    };
    let decision = evaluate(&PolicyInput {
        request: &req,
        actor_tenant: p.tenant,
        actor_user: p.user,
        actor_roles: &p.roles,
        tenant_policy: &tenant_policy,
        tools: &st.tools,
        global_dispatch_enabled: global,
        channel,
        destination_hash: dest.as_deref().unwrap_or_default(),
        permissions: &permissions,
        suppressions: &suppressions,
        sends_last_24h: sends,
        local_hour: local_hour_in_zone(now, contact_tz, tz),
        now,
    });
    let (kind, code) = match &decision {
        Decision::Allow { .. } => (DecisionKind::Allow, "ok".to_owned()),
        Decision::Deny { code, .. } => (DecisionKind::Deny, code.as_str().to_owned()),
        Decision::RequireApproval {
            approval_policy, ..
        } => (DecisionKind::RequireApproval, approval_policy.clone()),
        Decision::RequireMoreInformation { .. } => (DecisionKind::MoreInfo, "fields".to_owned()),
    };
    st.metrics
        .decisions
        .get_or_create(&DecisionLabels {
            decision: kind,
            code: code.clone(),
        })
        .inc();
    mk_store::audit::append_event(&mut tx, mk_audit::NewEvent {
        tenant_id: p.tenant, occurred_at: now, actor_type: mk_audit::ActorType::System, actor_id: "policy", action_id: Some(action_id),
        event_type: mk_audit::EventType::PolicyDecision,
        payload_redacted: json!({"decision": decision_name(&decision), "code": code, "obligations": decision.obligations().len()}),
        trace_id: Some(&p.request_id), policy_version: mk_policy::POLICY_VERSION.0,
    }).await.map_err(|e| rid(e.into()))?;

    // 6. Apply the decision through the state machine.
    let stored = match &decision {
        Decision::Deny { code, .. } => {
            actions::transition(
                &mut tx,
                action_id,
                Transition::PolicyDeny,
                Some(code.as_str()),
                actor,
                now,
            )
            .await
        }
        Decision::RequireMoreInformation { .. } => {
            actions::transition(
                &mut tx,
                action_id,
                Transition::PolicyDeny,
                Some("more_information_required"),
                actor,
                now,
            )
            .await
        }
        Decision::RequireApproval { .. } => {
            actions::transition(
                &mut tx,
                action_id,
                Transition::PolicyRequireApproval,
                None,
                actor,
                now,
            )
            .await
        }
        Decision::Allow { .. } => {
            actions::transition(
                &mut tx,
                action_id,
                Transition::PolicyAllow,
                None,
                actor,
                now,
            )
            .await?;
            if st.rust_kernel_enabled {
                actions::transition(&mut tx, action_id, Transition::Enqueue, None, actor, now)
                    .await?;
                outbox::enqueue(&mut tx, action_id, "dispatch", now, json!({})).await?;
            }
            actions::get(&mut tx, action_id).await
        }
    }
    .map_err(|e| rid(e.into()))?;
    tx.commit().await.map_err(|e| rid(e.into()))?;
    let status = match stored.state {
        ActionState::Denied => StatusCode::FORBIDDEN,
        _ => StatusCode::ACCEPTED,
    };
    Ok((
        status,
        Json(ProposalResponse {
            result: stored.to_result(None),
            decision,
            replayed: false,
        }),
    ))
}

/// Origin as the kernel will record it. Autonomous principals (role set is
/// exactly `agent`) may be `agent` or `mcp`; everyone else is `human`.
/// `system` is reserved for kernel-internal origins and is never accepted
/// from a request.
fn bound_origin(p: &Principal, claimed: OriginType) -> OriginType {
    let autonomous = p.has_role("agent") && p.roles.len() == 1;
    match (autonomous, claimed) {
        (true, OriginType::Mcp) => OriginType::Mcp,
        (true, _) => OriginType::Agent,
        (false, _) => OriginType::Human,
    }
}

/// Idempotency must be keyed on content, not on the server-assigned id.
fn digest_without_id(req: &ActionRequest) -> mk_crypto::Digest {
    let mut r = req.clone();
    r.action_id = None;
    r.digest()
        .unwrap_or_else(|_| mk_crypto::Digest::of(b"unhashable"))
}

fn decision_name(d: &Decision) -> &'static str {
    match d {
        Decision::Allow { .. } => "allow",
        Decision::Deny { .. } => "deny",
        Decision::RequireApproval { .. } => "require_approval",
        Decision::RequireMoreInformation { .. } => "require_more_information",
    }
}

/// `GET /internal/v1/actions/{action_id}`
pub async fn get(
    State(st): State<AppState>,
    p: Principal,
    headers: HeaderMap,
    Path(action_id): Path<ActionId>,
) -> Result<Json<ActionResult>, ApiError> {
    let mut tx = st
        .store
        .begin(p.tenant)
        .await
        .map_err(|e| ApiError::from(e).with_request_id(&headers))?;
    let a = actions::get(&mut tx, action_id)
        .await
        .map_err(|e| ApiError::from(e).with_request_id(&headers))?;
    let mut result = a.to_result(None);
    super::messaging::enrich_result(&mut tx, &mut result)
        .await
        .map_err(|e| e.with_request_id(&headers))?;
    Ok(Json(result))
}

/// `POST /internal/v1/actions/{action_id}/cancel`
pub async fn cancel(
    State(st): State<AppState>,
    p: Principal,
    headers: HeaderMap,
    Path(action_id): Path<ActionId>,
) -> Result<Json<ActionResult>, ApiError> {
    let now = Utc::now();
    let actor_id = p.user.to_string();
    let actor = actor_of(&p, &actor_id);
    let mut tx = st
        .store
        .begin(p.tenant)
        .await
        .map_err(|e| ApiError::from(e).with_request_id(&headers))?;
    let a = actions::get_for_update(&mut tx, action_id)
        .await
        .map_err(|e| ApiError::from(e).with_request_id(&headers))?;
    // Agents may cancel only their own proposals; humans any in-tenant.
    if p.has_role("agent") && p.roles.len() == 1 && a.request.requested_by != p.user {
        return Err(ApiError::new(
            StatusCode::FORBIDDEN,
            "NOT_OWNER",
            "Agents may cancel only their own proposals",
        )
        .with_request_id(&headers));
    }
    let a = actions::transition(
        &mut tx,
        action_id,
        Transition::Cancel,
        Some("cancelled_by_request"),
        actor,
        now,
    )
    .await
    .map_err(|e| ApiError::from(e).with_request_id(&headers))?;
    tx.commit()
        .await
        .map_err(|e| ApiError::from(e).with_request_id(&headers))?;
    Ok(Json(a.to_result(None)))
}

/// `POST /internal/v1/actions/{action_id}/replay` — operator only; creates
/// a new linked action in `Draft`, which must go through policy again.
pub async fn replay(
    State(st): State<AppState>,
    p: Principal,
    headers: HeaderMap,
    Path(action_id): Path<ActionId>,
) -> Result<(StatusCode, Json<ActionResult>), ApiError> {
    p.require_role("tenant_admin")
        .map_err(|e| e.with_request_id(&headers))?;
    let now = Utc::now();
    let actor_id = p.user.to_string();
    let actor = actor_of(&p, &actor_id);
    let mut tx = st
        .store
        .begin(p.tenant)
        .await
        .map_err(|e| ApiError::from(e).with_request_id(&headers))?;
    let orig = actions::get(&mut tx, action_id)
        .await
        .map_err(|e| ApiError::from(e).with_request_id(&headers))?;
    let new = actions::insert_replay(&mut tx, &orig, ActionId::new(), actor, now)
        .await
        .map_err(|e| ApiError::from(e).with_request_id(&headers))?;
    tx.commit()
        .await
        .map_err(|e| ApiError::from(e).with_request_id(&headers))?;
    Ok((StatusCode::CREATED, Json(new.to_result(None))))
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
mod tests {
    use super::*;
    use mk_crypto::ActorAssertion;
    use mk_domain::{TenantId, UserId};

    fn principal(roles: &[&str]) -> Principal {
        let (t, u) = (TenantId::new(), UserId::new());
        Principal {
            tenant: t,
            user: u,
            roles: roles.iter().map(|r| (*r).to_owned()).collect(),
            session_id: "s".into(),
            request_id: "r".into(),
            assertion: ActorAssertion {
                iss: "mk-fastapi".into(),
                aud: "mk-action-kernel".into(),
                sub: u.0,
                tenant_id: t.0,
                roles: roles.iter().map(|r| (*r).to_owned()).collect(),
                session_id: "s".into(),
                request_id: "r".into(),
                iat: 0,
                exp: 60,
                jti: uuid::Uuid::now_v7(),
            },
        }
    }

    #[test]
    fn agent_cannot_claim_human_or_system_origin() {
        let agent = principal(&["agent"]);
        assert_eq!(bound_origin(&agent, OriginType::Human), OriginType::Agent);
        assert_eq!(bound_origin(&agent, OriginType::System), OriginType::Agent);
        assert_eq!(bound_origin(&agent, OriginType::Mcp), OriginType::Mcp);
        let human = principal(&["consultant"]);
        assert_eq!(bound_origin(&human, OriginType::Agent), OriginType::Human);
        assert_eq!(bound_origin(&human, OriginType::System), OriginType::Human);
        let mixed = principal(&["agent", "consultant"]);
        assert_eq!(
            bound_origin(&mixed, OriginType::Agent),
            OriginType::Human,
            "a human session that also carries agent is a human"
        );
    }
}
