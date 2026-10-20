//! Adapter registration and credential lifecycle (tenant_admin only).

use axum::Json;
use axum::extract::{Path, State};
use axum::http::{HeaderMap, StatusCode};
use chrono::{Duration, Utc};
use mk_domain::AdapterId;
use mk_store::adapters::{self, AdapterRegistration};
use secrecy::ExposeSecret;
use serde::{Deserialize, Serialize};

use crate::auth::Principal;
use crate::error::ApiError;
use crate::routes::actor_of;
use crate::state::AppState;

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RegisterBody {
    pub agent_id: String,
    pub name: String,
    pub platform: String,
    pub version: String,
    pub capabilities: Vec<String>,
    pub allowed_actions: Vec<String>,
    /// Must be one of the deployment's allowlisted callback authorities.
    pub callback_authority: String,
}

#[derive(Debug, Serialize)]
pub struct RegisterResponse {
    pub adapter: AdapterRegistration,
    /// Shown exactly once. Never stored in plaintext, never returned again.
    pub enrollment_secret: String,
}

#[derive(Debug, Serialize)]
pub struct RotateResponse {
    pub adapter_id: AdapterId,
    pub overlap_secs: i64,
    pub enrollment_secret: String,
}

pub async fn register(
    State(st): State<AppState>,
    p: Principal,
    headers: HeaderMap,
    Json(b): Json<RegisterBody>,
) -> Result<(StatusCode, Json<RegisterResponse>), ApiError> {
    p.require_role("tenant_admin")
        .map_err(|e| e.with_request_id(&headers))?;
    if b.capabilities.len() > 16
        || b.allowed_actions.len() > 32
        || b.name.len() > 120
        || b.callback_authority.contains('/')
        || b.callback_authority.is_empty()
    {
        return Err(ApiError::new(
            StatusCode::UNPROCESSABLE_ENTITY,
            "INVALID_ADAPTER",
            "invalid registration",
        )
        .with_request_id(&headers));
    }
    let now = Utc::now();
    let actor_id = p.user.to_string();
    let actor = actor_of(&p, &actor_id);
    let mut tx = st
        .store
        .begin(p.tenant)
        .await
        .map_err(|e| ApiError::from(e).with_request_id(&headers))?;
    let (adapter, secret) = adapters::register(
        &mut tx,
        &st.master,
        &b.agent_id,
        &b.name,
        &b.platform,
        &b.version,
        &b.capabilities,
        &b.allowed_actions,
        &b.callback_authority,
        actor,
        now,
    )
    .await
    .map_err(|e| ApiError::from(e).with_request_id(&headers))?;
    tx.commit()
        .await
        .map_err(|e| ApiError::from(e).with_request_id(&headers))?;
    Ok((
        StatusCode::CREATED,
        Json(RegisterResponse {
            adapter,
            enrollment_secret: secret.expose_secret().to_owned(),
        }),
    ))
}

pub async fn get(
    State(st): State<AppState>,
    p: Principal,
    headers: HeaderMap,
    Path(adapter_id): Path<AdapterId>,
) -> Result<Json<AdapterRegistration>, ApiError> {
    let mut tx = st
        .store
        .begin(p.tenant)
        .await
        .map_err(|e| ApiError::from(e).with_request_id(&headers))?;
    let a = adapters::get(&mut tx, adapter_id)
        .await
        .map_err(|e| ApiError::from(e).with_request_id(&headers))?;
    Ok(Json(a))
}

#[derive(Debug, Deserialize, Default)]
#[serde(deny_unknown_fields)]
pub struct RotateBody {
    /// Seconds the previous secret stays valid. 0 = immediate cutoff. Max 1h.
    #[serde(default)]
    pub overlap_secs: i64,
}

pub async fn rotate(
    State(st): State<AppState>,
    p: Principal,
    headers: HeaderMap,
    Path(adapter_id): Path<AdapterId>,
    body: Option<Json<RotateBody>>,
) -> Result<Json<RotateResponse>, ApiError> {
    p.require_role("tenant_admin")
        .map_err(|e| e.with_request_id(&headers))?;
    let overlap = body.map_or(0, |b| b.0.overlap_secs).clamp(0, 3600);
    let now = Utc::now();
    let actor_id = p.user.to_string();
    let actor = actor_of(&p, &actor_id);
    let mut tx = st
        .store
        .begin(p.tenant)
        .await
        .map_err(|e| ApiError::from(e).with_request_id(&headers))?;
    let secret = adapters::rotate(
        &mut tx,
        &st.master,
        adapter_id,
        Duration::seconds(overlap),
        actor,
        now,
    )
    .await
    .map_err(|e| ApiError::from(e).with_request_id(&headers))?;
    tx.commit()
        .await
        .map_err(|e| ApiError::from(e).with_request_id(&headers))?;
    Ok(Json(RotateResponse {
        adapter_id,
        overlap_secs: overlap,
        enrollment_secret: secret.expose_secret().to_owned(),
    }))
}

pub async fn revoke(
    State(st): State<AppState>,
    p: Principal,
    headers: HeaderMap,
    Path(adapter_id): Path<AdapterId>,
) -> Result<StatusCode, ApiError> {
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
    adapters::revoke(&mut tx, adapter_id, actor, now)
        .await
        .map_err(|e| ApiError::from(e).with_request_id(&headers))?;
    tx.commit()
        .await
        .map_err(|e| ApiError::from(e).with_request_id(&headers))?;
    Ok(StatusCode::NO_CONTENT)
}
