//! Passkey-protected C4 operator decisions. Never sends or changes delivery facts.
use axum::{
    Json,
    extract::{Path, State},
    http::{HeaderMap, StatusCode},
};
use chrono::Utc;
use mk_crypto::{Digest, webauthn::b64url};
use mk_domain::ActionId;
use mk_store::{
    human_approval as ha,
    resolutions::{self, Decision},
};
use serde::Deserialize;
use serde_json::{Value, json};
use uuid::Uuid;

use super::human_approval::{WebAuthnAssertionBody, burn_step_up_challenge, verify_step_up};
use crate::{auth::Principal, error::ApiError, state::AppState};

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ChallengeBody {
    pub decision: Decision,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ResolveBody {
    pub decision: Decision,
    pub operation_digest: Digest,
    pub webauthn: WebAuthnAssertionBody,
}

fn authorize(st: &AppState, p: &Principal) -> Result<(), ApiError> {
    p.require_role("tenant_admin")?;
    if !st.approval_rp.as_ref().is_some_and(|rp| rp.require_uv) {
        return Err(ApiError::new(
            StatusCode::SERVICE_UNAVAILABLE,
            "RESOLUTION_PASSKEY_REQUIRED",
            "Resolution requires configured user-verified passkeys",
        ));
    }
    Ok(())
}

pub async fn challenge(
    State(st): State<AppState>,
    p: Principal,
    headers: HeaderMap,
    Path(id): Path<Uuid>,
    Json(body): Json<ChallengeBody>,
) -> Result<Json<Value>, ApiError> {
    let rid = |e: ApiError| e.with_request_id(&headers);
    authorize(&st, &p).map_err(rid)?;
    let now = Utc::now();
    let mut tx = st.store.begin(p.tenant).await.map_err(|e| rid(e.into()))?;
    let s = resolutions::snapshot(&mut tx, ActionId::from_uuid(id), body.decision)
        .await
        .map_err(|e| rid(e.into()))?;
    let credentials = ha::list_credentials(&mut tx, p.user)
        .await
        .map_err(|e| rid(e.into()))?;
    let allowed: Vec<_> = credentials
        .into_iter()
        .filter(|c| c.revoked_at.is_none())
        .map(|c| c.credential_id_b64)
        .collect();
    if allowed.is_empty() {
        return Err(rid(ApiError::new(
            StatusCode::PRECONDITION_FAILED,
            "NO_APPROVAL_CREDENTIAL",
            "Register a passkey first",
        )));
    }
    let ch = ha::issue_operator_challenge(&mut tx, p.user, &s.operation_digest, now)
        .await
        .map_err(|e| rid(e.into()))?;
    tx.commit().await.map_err(|e| rid(e.into()))?;
    Ok(Json(json!({"challenge": b64url(&ch.challenge),
        "rp_id": st.approval_rp.as_ref().map(|rp| &rp.rp_id), "user_verification":"required",
        "allow_credentials":allowed, "expires_at":ch.expires_at,
        "action_id":id, "action_digest":s.action_digest, "decision":body.decision,
        "operation_digest":s.operation_digest, "provider_message_id":s.delivery.provider_message_id,
        "delivery_state":s.delivery.state})))
}

pub async fn resolve(
    State(st): State<AppState>,
    p: Principal,
    headers: HeaderMap,
    Path(id): Path<Uuid>,
    Json(body): Json<ResolveBody>,
) -> Result<Json<Value>, ApiError> {
    let rid = |e: ApiError| e.with_request_id(&headers);
    authorize(&st, &p).map_err(rid)?;
    let now = Utc::now();
    // A tampered, stale or replayed resolution burns its single-use challenge
    // even when the decision transaction below rolls back. No pool nesting.
    let challenge = burn_step_up_challenge(
        &st,
        &p,
        ha::ChallengeKind::Operator,
        ActionId::from_uuid(Uuid::nil()),
        &body.operation_digest,
        &body.webauthn,
        now,
    )
    .await
    .map_err(rid)?;
    let mut tx = st.store.begin(p.tenant).await.map_err(|e| rid(e.into()))?;
    let s = resolutions::snapshot(&mut tx, ActionId::from_uuid(id), body.decision)
        .await
        .map_err(|e| rid(e.into()))?;
    if !s.operation_digest.ct_eq(&body.operation_digest) {
        return Err(rid(ApiError::new(
            StatusCode::CONFLICT,
            "RESOLUTION_CHANGED",
            "Provider observation changed; review again",
        )));
    }
    let credential = verify_step_up(&st, &mut tx, &p, &challenge, &body.webauthn, now)
        .await
        .map_err(rid)?;
    let resolved_at = Utc::now();
    resolutions::record(&mut tx, &s, body.decision, p.user, credential, resolved_at)
        .await
        .map_err(|e| rid(e.into()))?;
    tx.commit().await.map_err(|e| rid(e.into()))?;
    Ok(Json(
        json!({"action_id":id,"decision":body.decision,"resolved_at":resolved_at,
        "operation_digest":s.operation_digest,"replacement_requires_new_approval":true}),
    ))
}
