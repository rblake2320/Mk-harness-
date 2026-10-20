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
    policy::set_global_dispatch(st.store.pool(), b.dispatch_enabled, &p.user.to_string())
        .await
        .map_err(|e| ApiError::from(e).with_request_id(&headers))?;
    tracing::warn!(by = %p.user, enabled = b.dispatch_enabled, "GLOBAL KILL SWITCH CHANGED");
    Ok(StatusCode::NO_CONTENT)
}
