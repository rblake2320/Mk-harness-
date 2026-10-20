//! Separated human-approval authority (WP06): credential registration, approval
//! challenges, and revocations. FastAPI relays these calls; it cannot forge the
//! WebAuthn bytes because it holds no user's authenticator key.

use axum::Json;
use axum::extract::{Path, State};
use axum::http::{HeaderMap, StatusCode};
use chrono::Utc;
use mk_crypto::webauthn::{self, b64url, b64url_decode};
use mk_domain::{ActionId, UserId};
use mk_store::human_approval::{self as ha, ChallengeKind, RevocationTarget};
use mk_store::{actions, approvals};
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use uuid::Uuid;

use crate::auth::Principal;
use crate::error::ApiError;
use crate::state::{AppState, ApprovalRp};

fn human_only(p: &Principal, what: &str) -> Result<(), ApiError> {
    if p.has_role("agent") && p.roles.len() == 1 {
        return Err(ApiError::new(
            StatusCode::FORBIDDEN,
            "AGENT_CANNOT_APPROVE",
            "Requires a human principal",
        )
        .detail(format!("{what} requires a human principal")));
    }
    Ok(())
}

fn rp_or_unbound(st: &AppState) -> Result<&ApprovalRp, ApiError> {
    st.approval_rp.as_ref().ok_or_else(|| {
        ApiError::new(
            StatusCode::NOT_IMPLEMENTED,
            "HUMAN_APPROVAL_NOT_CONFIGURED",
            "Kernel runs without MK_APPROVAL_RP_ID (unbound approvals, development only)",
        )
    })
}

fn webauthn_err(e: webauthn::WebAuthnError) -> ApiError {
    ApiError::new(
        StatusCode::FORBIDDEN,
        &e.code().to_ascii_uppercase(),
        "WebAuthn verification failed",
    )
    .detail(e.to_string())
}

// ----------------------------------------------------------------- registration

#[derive(Debug, Serialize)]
pub struct RegisterBeginResponse {
    pub challenge: String,
    pub rp_id: String,
    pub user_id: UserId,
    pub expires_at: chrono::DateTime<Utc>,
    /// Credential ids already registered, so the browser can exclude them.
    pub exclude_credentials: Vec<String>,
    pub pub_key_cred_params: Vec<Value>,
    pub authenticator_selection: Value,
    pub attestation: &'static str,
}

/// `POST /internal/v1/approval-credentials/register/begin`
pub async fn register_begin(
    State(st): State<AppState>,
    p: Principal,
    headers: HeaderMap,
) -> Result<Json<RegisterBeginResponse>, ApiError> {
    let rid = |e: ApiError| e.with_request_id(&headers);
    human_only(&p, "credential registration").map_err(rid)?;
    let rp = rp_or_unbound(&st).map_err(rid)?;
    let now = Utc::now();
    let mut tx = st.store.begin(p.tenant).await.map_err(|e| rid(e.into()))?;
    let ch = ha::issue_register_challenge(&mut tx, p.user, now)
        .await
        .map_err(|e| rid(e.into()))?;
    let existing = ha::list_credentials(&mut tx, p.user)
        .await
        .map_err(|e| rid(e.into()))?;
    tx.commit().await.map_err(|e| rid(e.into()))?;
    Ok(Json(RegisterBeginResponse {
        challenge: b64url(&ch.challenge),
        rp_id: rp.rp_id.clone(),
        user_id: p.user,
        expires_at: ch.expires_at,
        exclude_credentials: existing
            .into_iter()
            .filter(|c| c.revoked_at.is_none())
            .map(|c| c.credential_id_b64)
            .collect(),
        pub_key_cred_params: vec![
            json!({"type": "public-key", "alg": -7}),
            json!({"type": "public-key", "alg": -8}),
            json!({"type": "public-key", "alg": -257}),
        ],
        authenticator_selection: json!({
            "residentKey": "preferred",
            "userVerification": if rp.require_uv { "required" } else { "preferred" },
        }),
        attestation: "none",
    }))
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RegisterFinishBody {
    /// base64url `clientDataJSON`
    pub client_data_json: String,
    /// base64url `attestationObject`
    pub attestation_object: String,
    #[serde(default)]
    pub label: String,
}

/// `POST /internal/v1/approval-credentials/register/finish`
pub async fn register_finish(
    State(st): State<AppState>,
    p: Principal,
    headers: HeaderMap,
    Json(body): Json<RegisterFinishBody>,
) -> Result<(StatusCode, Json<Value>), ApiError> {
    let rid = |e: ApiError| e.with_request_id(&headers);
    human_only(&p, "credential registration").map_err(rid)?;
    let rp = rp_or_unbound(&st).map_err(rid)?.clone();
    if body.label.chars().count() > 80 {
        return Err(rid(ApiError::new(StatusCode::UNPROCESSABLE_ENTITY, "LABEL_TOO_LONG", "label > 80 chars")));
    }
    let cdj = b64url_decode(&body.client_data_json).map_err(|e| rid(webauthn_err(e)))?;
    let att = b64url_decode(&body.attestation_object).map_err(|e| rid(webauthn_err(e)))?;
    // Challenge is inside clientDataJSON; read it first so we can consume the row.
    let challenge = extract_challenge(&cdj).map_err(rid)?;
    let now = Utc::now();
    let mut tx = st.store.begin(p.tenant).await.map_err(|e| rid(e.into()))?;
    ha::consume_challenge(&mut tx, p.user, ChallengeKind::Register, &challenge, None, now)
        .await
        .map_err(|e| rid(e.into()))?;
    let cred = webauthn::verify_registration(&cdj, &att, &challenge, &rp.rp_id, &rp.origins, rp.require_uv)
        .map_err(|e| rid(webauthn_err(e)))?;
    let row = ha::insert_credential(&mut tx, p.user, &cred, &body.label, now)
        .await
        .map_err(|e| rid(e.into()))?;
    tx.commit().await.map_err(|e| rid(e.into()))?;
    Ok((
        StatusCode::CREATED,
        Json(json!({
            "credential_row_id": row,
            "alg": cred.public_key.alg.as_str(),
            "attestation_format": cred.attestation_format,
            "user_verified": cred.user_verified,
        })),
    ))
}

fn extract_challenge(client_data_json: &[u8]) -> Result<Vec<u8>, ApiError> {
    #[derive(Deserialize)]
    struct Cd {
        challenge: String,
    }
    let cd: Cd = serde_json::from_slice(client_data_json)
        .map_err(|_| webauthn_err(webauthn::WebAuthnError::Malformed("clientDataJSON")))?;
    b64url_decode(&cd.challenge).map_err(webauthn_err)
}

/// `GET /internal/v1/approval-credentials`
pub async fn list(
    State(st): State<AppState>,
    p: Principal,
    headers: HeaderMap,
) -> Result<Json<Vec<ha::CredentialView>>, ApiError> {
    let rid = |e: ApiError| e.with_request_id(&headers);
    let mut tx = st.store.begin(p.tenant).await.map_err(|e| rid(e.into()))?;
    let v = ha::list_credentials(&mut tx, p.user).await.map_err(|e| rid(e.into()))?;
    Ok(Json(v))
}

/// `POST /internal/v1/approval-credentials/{row}/revoke` — own credential, or
/// any credential in the tenant for a tenant admin.
pub async fn revoke_credential(
    State(st): State<AppState>,
    p: Principal,
    headers: HeaderMap,
    Path(row): Path<Uuid>,
) -> Result<Json<Value>, ApiError> {
    let rid = |e: ApiError| e.with_request_id(&headers);
    human_only(&p, "credential revocation").map_err(rid)?;
    let now = Utc::now();
    let mut tx = st.store.begin(p.tenant).await.map_err(|e| rid(e.into()))?;
    if !p.has_role("tenant_admin") {
        let mine = ha::list_credentials(&mut tx, p.user).await.map_err(|e| rid(e.into()))?;
        if !mine.iter().any(|c| c.credential_row_id == row) {
            return Err(rid(ApiError::new(StatusCode::NOT_FOUND, "NOT_FOUND", "Not found")));
        }
    }
    ha::revoke_credential(&mut tx, row, p.user, now).await.map_err(|e| rid(e.into()))?;
    tx.commit().await.map_err(|e| rid(e.into()))?;
    Ok(Json(json!({"credential_row_id": row, "revoked_at": now})))
}

// ------------------------------------------------------------- approval challenge

#[derive(Debug, Serialize)]
pub struct ApprovalChallengeResponse {
    pub challenge: String,
    pub rp_id: String,
    pub action_id: ActionId,
    pub action_digest: String,
    pub expires_at: chrono::DateTime<Utc>,
    pub allow_credentials: Vec<String>,
    pub user_verification: &'static str,
}

/// `POST /internal/v1/actions/{id}/approval-challenge`
///
/// Returns the challenge the approver's authenticator must sign. It is derived
/// from the action's *current stored digest*; if the action changes before the
/// approve call, the challenge no longer matches and approval fails closed.
pub async fn approval_challenge(
    State(st): State<AppState>,
    p: Principal,
    headers: HeaderMap,
    Path(action_id): Path<ActionId>,
) -> Result<Json<ApprovalChallengeResponse>, ApiError> {
    let rid = |e: ApiError| e.with_request_id(&headers);
    human_only(&p, "approval").map_err(rid)?;
    let rp = rp_or_unbound(&st).map_err(rid)?.clone();
    let now = Utc::now();
    let mut tx = st.store.begin(p.tenant).await.map_err(|e| rid(e.into()))?;
    let a = actions::get(&mut tx, action_id).await.map_err(|e| rid(e.into()))?;
    let creds = ha::list_credentials(&mut tx, p.user).await.map_err(|e| rid(e.into()))?;
    let live: Vec<String> = creds.into_iter().filter(|c| c.revoked_at.is_none()).map(|c| c.credential_id_b64).collect();
    if live.is_empty() {
        return Err(rid(ApiError::new(
            StatusCode::PRECONDITION_FAILED,
            "NO_APPROVAL_CREDENTIAL",
            "Register a passkey before approving",
        )));
    }
    let ch = ha::issue_approve_challenge(&mut tx, p.user, action_id, &a.digest, now)
        .await
        .map_err(|e| rid(e.into()))?;
    tx.commit().await.map_err(|e| rid(e.into()))?;
    Ok(Json(ApprovalChallengeResponse {
        challenge: b64url(&ch.challenge),
        rp_id: rp.rp_id,
        action_id,
        action_digest: a.digest.to_string(),
        expires_at: ch.expires_at,
        allow_credentials: live,
        user_verification: if rp.require_uv { "required" } else { "preferred" },
    }))
}

/// The WebAuthn assertion carried on an approve call.
#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct WebAuthnAssertionBody {
    pub credential_id: String,
    pub client_data_json: String,
    pub authenticator_data: String,
    pub signature: String,
}

/// Verify a transaction-bound WebAuthn assertion for `(action, digest)` inside
/// the approver's transaction. Returns the credential row that proved it.
pub async fn verify_for_approval(
    st: &AppState,
    tx: &mut mk_store::TenantTx<'_>,
    p: &Principal,
    action_id: ActionId,
    digest: &mk_crypto::Digest,
    body: &WebAuthnAssertionBody,
    now: chrono::DateTime<Utc>,
) -> Result<Uuid, ApiError> {
    verify_step_up(st, tx, p, ChallengeKind::Approve, action_id, digest, body, now).await
}

/// Platform-operator step-up: same verification, challenge bound to an
/// operation digest instead of an action.
pub async fn verify_operator_step_up(
    st: &AppState,
    tx: &mut mk_store::TenantTx<'_>,
    p: &Principal,
    op_digest: &mk_crypto::Digest,
    body: &WebAuthnAssertionBody,
    now: chrono::DateTime<Utc>,
) -> Result<Uuid, ApiError> {
    verify_step_up(st, tx, p, ChallengeKind::Operator, ActionId::from_uuid(Uuid::nil()), op_digest, body, now).await
}

#[allow(clippy::too_many_arguments)]
async fn verify_step_up(
    st: &AppState,
    tx: &mut mk_store::TenantTx<'_>,
    p: &Principal,
    kind: ChallengeKind,
    action_id: ActionId,
    digest: &mk_crypto::Digest,
    body: &WebAuthnAssertionBody,
    now: chrono::DateTime<Utc>,
) -> Result<Uuid, ApiError> {
    let rp = rp_or_unbound(st)?;
    let cred_id = b64url_decode(&body.credential_id).map_err(webauthn_err)?;
    let cdj = b64url_decode(&body.client_data_json).map_err(webauthn_err)?;
    let ad = b64url_decode(&body.authenticator_data).map_err(webauthn_err)?;
    let sig = b64url_decode(&body.signature).map_err(webauthn_err)?;
    let challenge = extract_challenge(&cdj)?;
    // Consume first, in its own committed transaction: a failed verification
    // must still burn the challenge (the caller's transaction will roll back).
    {
        let mut burn = st.store.begin(p.tenant).await?;
        let outcome =
            ha::consume_challenge(&mut burn, p.user, kind, &challenge, Some((action_id, digest)), now).await;
        // Commit the burn even when the binding check failed.
        burn.commit().await?;
        outcome?;
    }
    let cred = ha::credential_for_update(tx, p.user, &cred_id).await.map_err(|e| match e {
        mk_store::StoreError::NotFound => ApiError::new(
            StatusCode::FORBIDDEN,
            "WEBAUTHN_CREDENTIAL_MISMATCH",
            "Credential is not registered to this user",
        ),
        other => other.into(),
    })?;
    let new_count = webauthn::verify_assertion(
        &cdj,
        &ad,
        &sig,
        &challenge,
        &rp.rp_id,
        &rp.origins,
        &cred.public_key,
        cred.sign_count,
        rp.require_uv,
    )
    .map_err(webauthn_err)?;
    ha::record_use(tx, cred.credential_row_id, new_count, now).await?;
    Ok(cred.credential_row_id)
}

// ------------------------------------------------------------------ revocations

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RevokeBody {
    #[serde(default)]
    pub session_id: Option<String>,
    #[serde(default)]
    pub user_id: Option<UserId>,
    #[serde(default)]
    pub reason: String,
}

/// `POST /internal/v1/revocations` — a user may revoke their own sessions; a
/// tenant admin may revoke any session or user in the tenant. Takes effect on
/// the next request (auth) and at the next dispatch (worker).
pub async fn revoke_principal(
    State(st): State<AppState>,
    p: Principal,
    headers: HeaderMap,
    Json(body): Json<RevokeBody>,
) -> Result<(StatusCode, Json<Value>), ApiError> {
    let rid = |e: ApiError| e.with_request_id(&headers);
    human_only(&p, "revocation").map_err(rid)?;
    if body.reason.chars().count() > 500 {
        return Err(rid(ApiError::new(StatusCode::UNPROCESSABLE_ENTITY, "REASON_TOO_LONG", "reason > 500 chars")));
    }
    // Target user defaults to the caller; naming another user needs tenant_admin.
    let target_user = body.user_id.unwrap_or(p.user);
    if target_user != p.user && !p.has_role("tenant_admin") {
        return Err(rid(ApiError::new(StatusCode::FORBIDDEN, "ROLE_REQUIRED", "tenant_admin required to revoke another user")));
    }
    let target = match &body.session_id {
        Some(s) if !s.is_empty() && s.len() <= 128 => RevocationTarget::Session(target_user, s),
        Some(_) => {
            return Err(rid(ApiError::new(StatusCode::UNPROCESSABLE_ENTITY, "REVOCATION_TARGET", "session_id must be 1..128 chars")));
        }
        None if body.user_id.is_some() => RevocationTarget::User(target_user),
        None => {
            return Err(rid(ApiError::new(
                StatusCode::UNPROCESSABLE_ENTITY,
                "REVOCATION_TARGET",
                "session_id (own session) or user_id is required",
            )));
        }
    };
    let now = Utc::now();
    let mut tx = st.store.begin(p.tenant).await.map_err(|e| rid(e.into()))?;
    let id = ha::revoke(&mut tx, target, p.user, &body.reason, now).await.map_err(|e| rid(e.into()))?;
    // Any live approval by a revoked user/session is revoked too (H9: blocks
    // dispatch even if the worker has not yet re-checked).
    let revoked_approvals = match target {
        RevocationTarget::User(u) => approvals::revoke_live_by_approver(&mut tx, u, None, p.user, now).await,
        RevocationTarget::Session(u, s) => approvals::revoke_live_by_approver(&mut tx, u, Some(s), p.user, now).await,
    }
    .map_err(|e| rid(e.into()))?;
    tx.commit().await.map_err(|e| rid(e.into()))?;
    Ok((
        StatusCode::CREATED,
        Json(json!({"revocation_id": id, "revoked_at": now, "approvals_revoked": revoked_approvals})),
    ))
}

// ------------------------------------------------------------ operator step-up

/// Operation digest for re-enabling the global kill switch.
#[must_use]
pub fn global_enable_op_digest() -> mk_crypto::Digest {
    mk_crypto::Digest::of(b"mk-operator-op:global-kill-switch:enable:v1")
}

/// `POST /internal/v1/kill-switch/global/challenge` — step-up challenge for
/// re-enabling dispatch globally. Disabling never needs step-up (fail-safe).
pub async fn global_enable_challenge(
    State(st): State<AppState>,
    p: Principal,
    headers: HeaderMap,
) -> Result<Json<Value>, ApiError> {
    let rid = |e: ApiError| e.with_request_id(&headers);
    p.require_role("platform_operator").map_err(rid)?;
    human_only(&p, "operator step-up").map_err(rid)?;
    let rp = rp_or_unbound(&st).map_err(rid)?.clone();
    let now = Utc::now();
    let mut tx = st.store.begin(p.tenant).await.map_err(|e| rid(e.into()))?;
    if !ha::has_live_credential(&mut tx, p.user).await.map_err(|e| rid(e.into()))? {
        return Err(rid(ApiError::new(StatusCode::PRECONDITION_FAILED, "NO_APPROVAL_CREDENTIAL", "Register a passkey first")));
    }
    let ch = ha::issue_operator_challenge(&mut tx, p.user, &global_enable_op_digest(), now).await.map_err(|e| rid(e.into()))?;
    tx.commit().await.map_err(|e| rid(e.into()))?;
    Ok(Json(json!({"challenge": b64url(&ch.challenge), "rp_id": rp.rp_id, "expires_at": ch.expires_at,
                   "operation": "global-kill-switch:enable", "user_verification": if rp.require_uv { "required" } else { "preferred" }})))
}
