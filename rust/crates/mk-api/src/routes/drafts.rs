//! Human edit barrier. A blocked response still commits the version fence.
use crate::{auth::Principal, error::ApiError, routes::actor_of, state::AppState};
use axum::{
    Json,
    extract::{Path, State},
    http::{HeaderMap, StatusCode},
};
use mk_store::drafts;
use uuid::Uuid;

pub async fn invalidate(
    State(st): State<AppState>,
    p: Principal,
    headers: HeaderMap,
    Path(draft): Path<Uuid>,
) -> Result<Json<drafts::Invalidation>, ApiError> {
    let rid = |e: ApiError| e.with_request_id(&headers);
    if !["consultant", "manager", "tenant_admin"]
        .iter()
        .any(|r| p.has_role(r))
    {
        return Err(rid(ApiError::new(
            StatusCode::FORBIDDEN,
            "HUMAN_REQUIRED",
            "Draft editing requires a human principal",
        )));
    }
    let actor_id = p.user.to_string();
    let mut tx = st.store.begin(p.tenant).await.map_err(|e| rid(e.into()))?;
    let result = drafts::invalidate(
        &mut tx,
        draft,
        p.user,
        p.has_role("tenant_admin"),
        actor_of(&p, &actor_id),
        chrono::Utc::now(),
    )
    .await
    .map_err(|e| rid(e.into()))?;
    tx.commit().await.map_err(|e| rid(e.into()))?;
    Ok(Json(result))
}
