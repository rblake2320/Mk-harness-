//! Health, readiness, metrics, kill switches.

use axum::Json;
use axum::extract::State;
use axum::http::{HeaderMap, StatusCode};
use chrono::Utc;
use mk_store::policy;
use serde::{Deserialize, Serialize};

use crate::auth::Principal;
use crate::error::ApiError;
use crate::routes::actor_of;
use crate::state::AppState;

pub async fn live() -> StatusCode {
    StatusCode::OK
}

#[derive(Debug, Serialize)]
pub struct Ready {
    pub database: bool,
    pub dispatch_enabled: bool,
    pub rust_kernel_enabled: bool,
    /// Effective security configuration of THIS process (no secrets), so the
    /// enable pre-flight checks what the running kernel enforces rather than
    /// what an operator's shell claims.
    pub effective: Effective,
}

#[derive(Debug, Serialize)]
pub struct Effective {
    /// `webauthn` (approvals need a kernel-verified passkey) or `unbound`.
    pub approval_binding: &'static str,
    pub approval_require_uv: bool,
    /// Keyring versions loaded; `0` present = legacy master-key seal still accepted.
    pub key_versions: Vec<u32>,
    pub current_key_version: u32,
    pub legacy_seal_accepted: bool,
    /// Destination-fingerprint kids, current first.
    pub fingerprint_kids: Vec<String>,
    pub public_webhook_base_https: bool,
}

/// Readiness fails when PostgreSQL is unreachable: no DB, no authority.
pub async fn ready(State(st): State<AppState>) -> (StatusCode, Json<Ready>) {
    let database = st.store.ping().await.is_ok();
    let dispatch_enabled = policy::global_dispatch_enabled(st.store.pool())
        .await
        .unwrap_or(false);
    let status = if database {
        StatusCode::OK
    } else {
        StatusCode::SERVICE_UNAVAILABLE
    };
    (
        status,
        Json(Ready {
            database,
            dispatch_enabled,
            rust_kernel_enabled: st.rust_kernel_enabled,
            effective: Effective {
                approval_binding: if st.approval_rp.is_some() {
                    "webauthn"
                } else {
                    "unbound"
                },
                approval_require_uv: st.approval_rp.as_ref().is_some_and(|r| r.require_uv),
                key_versions: st.keyring.versions(),
                current_key_version: st.keyring.current_version(),
                legacy_seal_accepted: st.keyring.versions().contains(&mk_crypto::LEGACY_VERSION),
                fingerprint_kids: st
                    .fingerprints
                    .kids()
                    .iter()
                    .map(|k| (*k).to_owned())
                    .collect(),
                public_webhook_base_https: st
                    .public_webhook_base
                    .as_deref()
                    .is_some_and(|b| b.starts_with("https://")),
            },
        }),
    )
}

pub async fn metrics(
    State(st): State<AppState>,
) -> ([(axum::http::HeaderName, &'static str); 1], String) {
    (
        [(
            axum::http::header::CONTENT_TYPE,
            "application/openmetrics-text; version=1.0.0; charset=utf-8",
        )],
        st.metrics.encode(),
    )
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct KillSwitchBody {
    pub dispatch_enabled: bool,
    /// Required to re-enable the *global* switch when the kernel has an
    /// approval RP configured: a platform operator's registered passkey must
    /// sign the kernel-issued operator challenge. Disabling never needs it.
    #[serde(default)]
    pub webauthn: Option<super::human_approval::WebAuthnAssertionBody>,
}

pub async fn tenant_kill_switch(
    State(st): State<AppState>,
    p: Principal,
    headers: HeaderMap,
    Json(b): Json<KillSwitchBody>,
) -> Result<StatusCode, ApiError> {
    p.require_role("tenant_admin")
        .map_err(|e| e.with_request_id(&headers))?;
    let actor_id = p.user.to_string();
    let actor = actor_of(&p, &actor_id);
    let mut tx = st
        .store
        .begin(p.tenant)
        .await
        .map_err(|e| ApiError::from(e).with_request_id(&headers))?;
    policy::set_tenant_dispatch(&mut tx, b.dispatch_enabled, actor, Utc::now())
        .await
        .map_err(|e| ApiError::from(e).with_request_id(&headers))?;
    tx.commit()
        .await
        .map_err(|e| ApiError::from(e).with_request_id(&headers))?;
    Ok(StatusCode::NO_CONTENT)
}

/// Global switch: requires the `platform_operator` role, which FastAPI only
/// mints for operators (never tenants, never agents).
pub async fn global_kill_switch(
    State(st): State<AppState>,
    p: Principal,
    headers: HeaderMap,
    Json(b): Json<KillSwitchBody>,
) -> Result<StatusCode, ApiError> {
    p.require_role("platform_operator")
        .map_err(|e| e.with_request_id(&headers))?;
    if b.dispatch_enabled && st.approval_rp.is_some() {
        // Threat model T4: a compromised proxy can mint `platform_operator`; it
        // must not be able to turn dispatch back on without the operator's key.
        let Some(w) = b.webauthn.as_ref() else {
            return Err(ApiError::new(
                StatusCode::FORBIDDEN,
                "WEBAUTHN_REQUIRED",
                "Re-enabling the global kill switch requires an operator passkey step-up",
            )
            .with_request_id(&headers));
        };
        let now = Utc::now();
        // Burn first on its own connection, then verify in the decision transaction.
        let challenge = super::human_approval::burn_step_up_challenge(
            &st,
            &p,
            mk_store::human_approval::ChallengeKind::Operator,
            mk_domain::ActionId::from_uuid(uuid::Uuid::nil()),
            &super::human_approval::global_enable_op_digest(),
            w,
            now,
        )
        .await
        .map_err(|e| e.with_request_id(&headers))?;
        let mut tx = st
            .store
            .begin(p.tenant)
            .await
            .map_err(|e| ApiError::from(e).with_request_id(&headers))?;
        super::human_approval::verify_step_up(&st, &mut tx, &p, &challenge, w, now)
            .await
            .map_err(|e| e.with_request_id(&headers))?;
        tx.commit()
            .await
            .map_err(|e| ApiError::from(e).with_request_id(&headers))?;
    }
    policy::set_global_dispatch(st.store.pool(), b.dispatch_enabled, &p.user.to_string())
        .await
        .map_err(|e| ApiError::from(e).with_request_id(&headers))?;
    tracing::warn!(by = %p.user, enabled = b.dispatch_enabled, "GLOBAL KILL SWITCH CHANGED");
    Ok(StatusCode::NO_CONTENT)
}
