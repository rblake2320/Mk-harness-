//! Human decisions. Never reachable by an agent-only principal.

use axum::Json;
use axum::extract::{Path, State};
use axum::http::{HeaderMap, StatusCode};
use chrono::Utc;
use mk_contracts::{ActionResult, ApprovalRecord};
use mk_domain::{ActionId, ApprovalDecision, ApprovalId, Transition};
use mk_policy::{ApproverContext, Decision, check_approver};
use mk_store::approvals::HumanBinding;
use mk_store::{actions, approvals, outbox, policy};
use serde::{Deserialize, Serialize};
use serde_json::json;

use crate::auth::Principal;
use crate::error::ApiError;
use crate::routes::actor_of;
use crate::state::AppState;

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DecisionBody {
    #[serde(default)]
    pub reason: Option<String>,
    /// The digest the approver saw in the UI. Must equal the stored digest;
    /// this defends against approving a row that changed under the UI.
    pub action_digest: mk_crypto::Digest,
    /// Transaction-bound WebAuthn assertion over the kernel-issued challenge
    /// for this exact action digest. Required for `approve` whenever the
    /// kernel is configured with `MK_APPROVAL_RP_ID`; optional for `reject`.
    #[serde(default)]
    pub webauthn: Option<super::human_approval::WebAuthnAssertionBody>,
}

#[derive(Debug, Serialize)]
pub struct DecisionResponse {
    pub approval: ApprovalRecord,
    pub result: ActionResult,
}

async fn decide(
    st: &AppState,
    p: &Principal,
    headers: &HeaderMap,
    action_id: ActionId,
    decision: ApprovalDecision,
    body: DecisionBody,
) -> Result<DecisionResponse, ApiError> {
    let rid = |e: ApiError| e.with_request_id(headers);
    if p.has_role("agent") && p.roles.len() == 1 {
        return Err(rid(ApiError::new(
            StatusCode::FORBIDDEN,
            "AGENT_CANNOT_APPROVE",
            "Approval requires a human principal",
        )));
    }
    let now = Utc::now();
    let actor_id = p.user.to_string();
    let actor = actor_of(p, &actor_id);
    // Burn any WebAuthn challenge BEFORE opening the decision transaction: the
    // burn commits on its own connection, and a request must never hold two
    // pooled connections at once (pool deadlock under load). The burn binds to
    // the action's stored digest, read on a short connection of its own.
    let burned = match (st.approval_rp.is_some(), body.webauthn.as_ref()) {
        (true, Some(w)) => {
            let stored = {
                let mut r = st.store.begin(p.tenant).await.map_err(|e| rid(e.into()))?;
                let a = actions::get(&mut r, action_id)
                    .await
                    .map_err(|e| rid(e.into()))?;
                r.commit().await.map_err(|e| rid(e.into()))?;
                a.digest
            };
            if !stored.ct_eq(&body.action_digest) {
                return Err(rid(ApiError::new(
                    StatusCode::CONFLICT,
                    "APPROVAL_DIGEST_MISMATCH",
                    "The action changed since it was displayed",
                )));
            }
            Some(
                super::human_approval::burn_step_up_challenge(
                    st,
                    p,
                    mk_store::human_approval::ChallengeKind::Approve,
                    action_id,
                    &stored,
                    w,
                    now,
                )
                .await
                .map_err(rid)?,
            )
        }
        _ => None,
    };
    let mut tx = st.store.begin(p.tenant).await.map_err(|e| rid(e.into()))?;
    let a = actions::get_for_update(&mut tx, action_id)
        .await
        .map_err(|e| rid(e.into()))?;
    if !a.digest.ct_eq(&body.action_digest) {
        return Err(rid(ApiError::new(
            StatusCode::CONFLICT,
            "APPROVAL_DIGEST_MISMATCH",
            "The action changed since it was displayed",
        )));
    }
    // Row H6: approval authority is the human's authenticator, not the
    // proposal service's assertion key. A missing or invalid WebAuthn
    // assertion fails closed unless the kernel explicitly runs unbound.
    let binding = match (decision, st.approval_rp.is_some(), body.webauthn.as_ref()) {
        (ApprovalDecision::Approved, true, None) => {
            return Err(rid(ApiError::new(
                StatusCode::FORBIDDEN,
                "WEBAUTHN_REQUIRED",
                "Approval requires a transaction-bound WebAuthn assertion",
            )));
        }
        (_, true, Some(w)) => HumanBinding::WebAuthn(
            super::human_approval::verify_step_up(
                st,
                &mut tx,
                p,
                burned.as_deref().unwrap_or_default(),
                w,
                now,
            )
            .await
            .map_err(rid)?,
        ),
        (_, false, Some(_)) => {
            return Err(rid(ApiError::new(
                StatusCode::NOT_IMPLEMENTED,
                "HUMAN_APPROVAL_NOT_CONFIGURED",
                "Kernel runs without MK_APPROVAL_RP_ID",
            )));
        }
        _ => HumanBinding::Unbound,
    };
    let (tenant_policy, _) = policy::load(&mut tx).await.map_err(|e| rid(e.into()))?;
    check_approver(&ApproverContext {
        tenant_id: p.tenant,
        approver_id: p.user,
        approver_roles: &p.roles,
        action_tenant_id: a.tenant_id,
        requested_by: a.request.requested_by,
        workflow: a.request.workflow,
        tenant_allows_self_approval: tenant_policy.allow_self_approval,
    })
    .map_err(|e| rid(ApiError::deny(e.code)))?;
    let ttl = tenant_policy.approval_ttl_secs;
    let approval = approvals::record_decision(
        &mut tx,
        action_id,
        p.user,
        &p.roles,
        decision,
        body.reason.as_deref(),
        ttl,
        Some(&p.session_id),
        None,
        now,
        binding,
    )
    .await
    .map_err(|e| rid(e.into()))?;
    let result = match decision {
        ApprovalDecision::Approved => {
            actions::transition(&mut tx, action_id, Transition::Approve, None, actor, now)
                .await
                .map_err(|e| rid(e.into()))?;
            if st.rust_kernel_enabled {
                actions::transition(&mut tx, action_id, Transition::Enqueue, None, actor, now)
                    .await
                    .map_err(|e| rid(e.into()))?;
                outbox::enqueue(&mut tx, action_id, "dispatch", now, json!({}))
                    .await
                    .map_err(|e| rid(e.into()))?;
            }
            actions::get(&mut tx, action_id)
                .await
                .map_err(|e| rid(e.into()))?
        }
        ApprovalDecision::Rejected => actions::transition(
            &mut tx,
            action_id,
            Transition::Reject,
            Some("rejected_by_approver"),
            actor,
            now,
        )
        .await
        .map_err(|e| rid(e.into()))?,
    };
    tx.commit().await.map_err(|e| rid(e.into()))?;
    Ok(DecisionResponse {
        approval,
        result: result.to_result(None),
    })
}

pub async fn approve(
    State(st): State<AppState>,
    p: Principal,
    headers: HeaderMap,
    Path(action_id): Path<ActionId>,
    Json(body): Json<DecisionBody>,
) -> Result<Json<DecisionResponse>, ApiError> {
    decide(
        &st,
        &p,
        &headers,
        action_id,
        ApprovalDecision::Approved,
        body,
    )
    .await
    .map(Json)
}

pub async fn reject(
    State(st): State<AppState>,
    p: Principal,
    headers: HeaderMap,
    Path(action_id): Path<ActionId>,
    Json(body): Json<DecisionBody>,
) -> Result<Json<DecisionResponse>, ApiError> {
    decide(
        &st,
        &p,
        &headers,
        action_id,
        ApprovalDecision::Rejected,
        body,
    )
    .await
    .map(Json)
}

#[derive(Debug, Serialize)]
pub struct PendingItem {
    pub result: ActionResult,
    /// What the approver must see: the exact rendered text, redacted
    /// destination, channel, purpose, evidence count, and expiry.
    pub display: serde_json::Value,
}

/// `GET /internal/v1/approvals/pending`
pub async fn pending(
    State(st): State<AppState>,
    p: Principal,
    headers: HeaderMap,
) -> Result<Json<Vec<PendingItem>>, ApiError> {
    let rid = |e: ApiError| e.with_request_id(&headers);
    if !p.has_role("consultant") && !p.has_role("manager") && !p.has_role("tenant_admin") {
        return Err(rid(ApiError::new(
            StatusCode::FORBIDDEN,
            "HUMAN_ROLE_REQUIRED",
            "Approval previews require a human role",
        )));
    }
    let mut tx = st.store.begin(p.tenant).await.map_err(|e| rid(e.into()))?;
    let (tenant_policy, _) = policy::load(&mut tx).await.map_err(|e| rid(e.into()))?;
    let ids = approvals::pending(&mut tx, 200)
        .await
        .map_err(|e| rid(e.into()))?;
    let mut out = Vec::with_capacity(ids.len());
    for id in ids {
        let a = actions::get(&mut tx, id).await.map_err(|e| rid(e.into()))?;
        let args = &a.request.arguments;
        let authority = check_approver(&ApproverContext {
            tenant_id: p.tenant,
            approver_id: p.user,
            approver_roles: &p.roles,
            action_tenant_id: a.tenant_id,
            requested_by: a.request.requested_by,
            workflow: a.request.workflow,
            tenant_allows_self_approval: tenant_policy.allow_self_approval,
        });
        let display = json!({
            "rendered_text": args.get("rendered_text"),
            "destination_redacted": args.get("to").and_then(serde_json::Value::as_str).map(redact_destination),
            "channel": a.channel,
            "workflow": a.request.workflow,
            "purpose": a.request.purpose,
            "risk": a.request.risk,
            "evidence_count": a.request.evidence.len(),
            "expires_at": a.expires_at,
            "action_digest": a.digest.to_string(),
            "sender_identity_id": args.get("sender_identity_id"),
            "scheduled_for": args.get("scheduled_for"),
            "can_approve": authority.is_ok(),
            "approval_denial": authority.err().map(|e| e.code.as_str()),
            "self_approval": p.user == a.request.requested_by,
            "approval_ttl_seconds": tenant_policy.approval_ttl_secs,
        });
        out.push(PendingItem {
            result: a.to_result(None),
            display,
        });
    }
    st.metrics
        .approvals_pending
        .set(i64::try_from(out.len()).unwrap_or(i64::MAX));
    Ok(Json(out))
}

fn redact_destination(d: &str) -> String {
    let n = d.chars().count();
    if n <= 4 {
        "****".into()
    } else {
        let tail: String = d.chars().skip(n - 4).collect();
        format!("{}{tail}", "*".repeat(n - 4))
    }
}

/// `POST /internal/v1/approvals/{approval_id}/revoke`
pub async fn revoke(
    State(st): State<AppState>,
    p: Principal,
    headers: HeaderMap,
    Path(approval_id): Path<ApprovalId>,
) -> Result<Json<ApprovalRecord>, ApiError> {
    let rid = |e: ApiError| e.with_request_id(&headers);
    if p.has_role("agent") && p.roles.len() == 1 {
        return Err(rid(ApiError::new(
            StatusCode::FORBIDDEN,
            "AGENT_CANNOT_REVOKE",
            "Revocation requires a human principal",
        )));
    }
    let now = Utc::now();
    let actor_id = p.user.to_string();
    let actor = actor_of(&p, &actor_id);
    let mut tx = st.store.begin(p.tenant).await.map_err(|e| rid(e.into()))?;
    let rec = approvals::revoke(&mut tx, approval_id, p.user, actor, now)
        .await
        .map_err(|e| rid(e.into()))?;
    // A queued action whose approval was revoked must not dispatch.
    let a = actions::get_for_update(&mut tx, rec.action_id)
        .await
        .map_err(|e| rid(e.into()))?;
    if a.state.is_cancellable() {
        actions::transition(
            &mut tx,
            rec.action_id,
            Transition::Cancel,
            Some("approval_revoked"),
            actor,
            now,
        )
        .await
        .map_err(|e| rid(e.into()))?;
    }
    tx.commit().await.map_err(|e| rid(e.into()))?;
    Ok(Json(rec))
}

#[allow(dead_code)]
fn _decision_type_check(_: Decision) {}
