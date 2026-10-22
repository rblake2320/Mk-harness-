//! Dedicated application-outbox authority; not a support impersonation route.
use crate::{auth::Principal, error::ApiError, state::AppState};
use axum::{
    Json,
    extract::State,
    http::{HeaderMap, StatusCode},
};
use serde::Deserialize;
use uuid::Uuid;

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct EraseBody {
    request_id: Uuid,
    subject_kind: mk_store::privacy::SubjectKind,
    subject_id: Uuid,
}

pub async fn erase(
    State(state): State<AppState>,
    principal: Principal,
    headers: HeaderMap,
    Json(body): Json<EraseBody>,
) -> Result<(StatusCode, Json<mk_store::privacy::ErasureReceipt>), ApiError> {
    principal.require_role("privacy_eraser")?;
    let actor_id = principal.user.to_string();
    let actor = mk_store::actions::Actor {
        actor_type: mk_audit::ActorType::System,
        actor_id: &actor_id,
        trace_id: Some(&principal.request_id),
        policy_version: mk_policy::POLICY_VERSION.0,
    };
    let mut tx = state
        .store
        .begin_erasure(principal.tenant)
        .await
        .map_err(|error| ApiError::from(error).with_request_id(&headers))?;
    let receipt = mk_store::privacy::erase(
        &mut tx,
        body.request_id,
        body.subject_kind,
        body.subject_id,
        principal.user,
        actor,
        chrono::Utc::now(),
    )
    .await
    .map_err(|error| ApiError::from(error).with_request_id(&headers))?;
    tx.commit()
        .await
        .map_err(|error| ApiError::from(error).with_request_id(&headers))?;
    Ok((StatusCode::CREATED, Json(receipt)))
}
