//! Contact permissions and suppressions. Revocation and suppression
//! immediately suppress every not-yet-dispatched matching action.

use axum::Json;
use axum::extract::{Path, State};
use axum::http::{HeaderMap, StatusCode};
use chrono::{DateTime, Utc};
use mk_domain::{Channel, ContactId, Transition};
use mk_store::{actions, consent};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

use crate::auth::Principal;
use crate::error::ApiError;
use crate::routes::{actor_of, destination_hash};
use crate::state::AppState;

fn human_only(p: &Principal, headers: &HeaderMap) -> Result<(), ApiError> {
    if p.has_role("agent") && p.roles.len() == 1 {
        return Err(ApiError::new(
            StatusCode::FORBIDDEN,
            "AGENT_CANNOT_CHANGE_CONSENT",
            "Consent changes require a human principal",
        )
        .with_request_id(headers));
    }
    Ok(())
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct GrantBody {
    pub channel: Channel,
    pub scope: Vec<String>,
    pub source: String,
    pub proof_digest: mk_crypto::Digest,
    pub granted_at: DateTime<Utc>,
    pub expires_at: DateTime<Utc>,
}

#[derive(Debug, Serialize)]
pub struct IdResponse {
    pub id: Uuid,
}

pub async fn grant_permission(
    State(st): State<AppState>,
    p: Principal,
    headers: HeaderMap,
    Path(contact_id): Path<ContactId>,
    Json(b): Json<GrantBody>,
) -> Result<(StatusCode, Json<IdResponse>), ApiError> {
    human_only(&p, &headers)?;
    if b.scope.is_empty()
        || b.scope.len() > 16
        || b.expires_at <= b.granted_at
        || b.source.len() > 200
    {
        return Err(ApiError::new(
            StatusCode::UNPROCESSABLE_ENTITY,
            "INVALID_PERMISSION",
            "scope/time window invalid",
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
    let id = consent::grant_permission(
        &mut tx,
        contact_id,
        b.channel,
        &b.scope,
        &b.source,
        &b.proof_digest,
        b.granted_at,
        b.expires_at,
        p.user,
        actor,
        now,
    )
    .await
    .map_err(|e| ApiError::from(e).with_request_id(&headers))?;
    tx.commit()
        .await
        .map_err(|e| ApiError::from(e).with_request_id(&headers))?;
    Ok((StatusCode::CREATED, Json(IdResponse { id })))
}

#[derive(Debug, Serialize)]
pub struct RevokeResponse {
    pub suppressed_actions: usize,
}

pub async fn revoke_permission(
    State(st): State<AppState>,
    p: Principal,
    headers: HeaderMap,
    Path((contact_id, permission_id)): Path<(ContactId, Uuid)>,
) -> Result<Json<RevokeResponse>, ApiError> {
    human_only(&p, &headers)?;
    let now = Utc::now();
    let actor_id = p.user.to_string();
    let actor = actor_of(&p, &actor_id);
    let mut tx = st
        .store
        .begin(p.tenant)
        .await
        .map_err(|e| ApiError::from(e).with_request_id(&headers))?;
    let (c, channel) = consent::revoke_permission(&mut tx, permission_id, actor, now)
        .await
        .map_err(|e| ApiError::from(e).with_request_id(&headers))?;
    if c != contact_id {
        return Err(ApiError::new(
            StatusCode::NOT_FOUND,
            "NOT_FOUND",
            "Permission not found for contact",
        )
        .with_request_id(&headers));
    }
    // Suppress every pending outreach to this contact over this channel.
    let mut n = 0;
    for id in actions::pending_for_destination(&mut tx, Some(channel), None)
        .await
        .map_err(|e| ApiError::from(e).with_request_id(&headers))?
    {
        let a = actions::get(&mut tx, id)
            .await
            .map_err(|e| ApiError::from(e).with_request_id(&headers))?;
        if a.request.resource.id == contact_id.to_string() && a.state.is_suppressible() {
            actions::transition(
                &mut tx,
                id,
                Transition::Suppress,
                Some("contact_permission_revoked"),
                actor,
                now,
            )
            .await
            .map_err(|e| ApiError::from(e).with_request_id(&headers))?;
            n += 1;
        }
    }
    tx.commit()
        .await
        .map_err(|e| ApiError::from(e).with_request_id(&headers))?;
    Ok(Json(RevokeResponse {
        suppressed_actions: n,
    }))
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SuppressionBody {
    pub channel: Option<Channel>,
    /// Raw destination; hashed server-side, never stored.
    pub destination: Option<String>,
    /// Alternatively, the kernel's own destination hash (as returned on inbound
    /// events) — lets the application act on a message without ever holding
    /// the raw number.
    #[serde(default)]
    pub destination_hash: Option<String>,
    pub reason: String,
    pub permanent: bool,
    pub source: String,
}

pub async fn add_suppression(
    State(st): State<AppState>,
    p: Principal,
    headers: HeaderMap,
    Json(b): Json<SuppressionBody>,
) -> Result<(StatusCode, Json<RevokeResponse>), ApiError> {
    human_only(&p, &headers)?;
    if let Some(h) = &b.destination_hash
        && (h.len() != 64 || !h.bytes().all(|c| c.is_ascii_hexdigit()))
    {
        return Err(ApiError::new(StatusCode::UNPROCESSABLE_ENTITY, "INVALID_SUPPRESSION", "destination_hash must be 64 hex chars").with_request_id(&headers));
    }
    if (b.destination.is_some() || b.destination_hash.is_some()) && b.channel.is_none() {
        return Err(ApiError::new(
            StatusCode::UNPROCESSABLE_ENTITY,
            "INVALID_SUPPRESSION",
            "destination suppression requires a channel",
        )
        .with_request_id(&headers));
    }
    let now = Utc::now();
    let actor_id = p.user.to_string();
    let actor = actor_of(&p, &actor_id);
    let dest_hash = match (&b.channel, &b.destination, &b.destination_hash) {
        (Some(c), Some(d), _) => Some(destination_hash(&st.master, p.tenant, *c, d)),
        (Some(_), None, Some(h)) => Some(h.clone()),
        _ => None,
    };
    let mut tx = st
        .store
        .begin(p.tenant)
        .await
        .map_err(|e| ApiError::from(e).with_request_id(&headers))?;
    let scope = if dest_hash.is_some() {
        "destination"
    } else if b.channel.is_some() {
        "channel"
    } else {
        "tenant"
    };
    consent::add_suppression(
        &mut tx,
        b.channel,
        dest_hash.as_deref(),
        scope,
        &b.reason,
        b.permanent,
        &b.source,
        actor,
        now,
    )
    .await
    .map_err(|e| ApiError::from(e).with_request_id(&headers))?;
    let mut n = 0;
    for id in actions::pending_for_destination(&mut tx, b.channel, dest_hash.as_deref())
        .await
        .map_err(|e| ApiError::from(e).with_request_id(&headers))?
    {
        if actions::transition(
            &mut tx,
            id,
            Transition::Suppress,
            Some("suppressed"),
            actor,
            now,
        )
        .await
        .is_ok()
        {
            n += 1;
        }
    }
    tx.commit()
        .await
        .map_err(|e| ApiError::from(e).with_request_id(&headers))?;
    Ok((
        StatusCode::CREATED,
        Json(RevokeResponse {
            suppressed_actions: n,
        }),
    ))
}

/// `DELETE /internal/v1/suppressions/{id}` — lifting a *permanent*
/// suppression requires `tenant_admin`; never reachable by an agent.
pub async fn lift_suppression(
    State(st): State<AppState>,
    p: Principal,
    headers: HeaderMap,
    Path(suppression_id): Path<Uuid>,
) -> Result<StatusCode, ApiError> {
    human_only(&p, &headers)?;
    let now = Utc::now();
    let actor_id = p.user.to_string();
    let actor = actor_of(&p, &actor_id);
    let mut tx = st
        .store
        .begin(p.tenant)
        .await
        .map_err(|e| ApiError::from(e).with_request_id(&headers))?;
    consent::lift_suppression(
        &mut tx,
        suppression_id,
        p.user,
        p.has_role("tenant_admin"),
        actor,
        now,
    )
    .await
    .map_err(|e| ApiError::from(e).with_request_id(&headers))?;
    tx.commit()
        .await
        .map_err(|e| ApiError::from(e).with_request_id(&headers))?;
    Ok(StatusCode::NO_CONTENT)
}
