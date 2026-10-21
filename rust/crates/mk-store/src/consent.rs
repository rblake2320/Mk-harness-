//! Contact permissions and suppressions: kernel-owned projections used at
//! proposal and at dispatch.

use chrono::{DateTime, Utc};
use mk_audit::{EventType, NewEvent};
use mk_crypto::Digest;
use mk_domain::{Channel, ContactId, PermissionStatus, UserId};
use mk_policy::{ContactPermissionFact, SuppressionFact};
use serde_json::json;
use sqlx::Row;
use uuid::Uuid;

use crate::actions::Actor;
use crate::audit::append_event;
use crate::error::StoreError;
use crate::tx::TenantTx;

fn channel_from(s: &str) -> Result<Channel, StoreError> {
    serde_json::from_value(serde_json::Value::String(s.to_owned()))
        .map_err(|_| StoreError::Corrupt("channel"))
}

pub async fn grant_permission(
    tx: &mut TenantTx<'_>,
    contact_id: ContactId,
    channel: Channel,
    scope: &[String],
    source: &str,
    proof_digest: &Digest,
    granted_at: DateTime<Utc>,
    expires_at: DateTime<Utc>,
    recorded_by: UserId,
    actor: Actor<'_>,
    now: DateTime<Utc>,
) -> Result<Uuid, StoreError> {
    let id = Uuid::now_v7();
    sqlx::query(
        "INSERT INTO kernel.contact_permissions (permission_id, tenant_id, contact_id, channel, status, scope, source,
           proof_digest, granted_at, expires_at, recorded_by) VALUES ($1,$2,$3,$4,'granted',$5,$6,$7,$8,$9,$10)",
    )
    .bind(id)
    .bind(tx.tenant().0)
    .bind(contact_id.0)
    .bind(channel.as_str())
    .bind(scope)
    .bind(source)
    .bind(proof_digest.to_string())
    .bind(granted_at)
    .bind(expires_at)
    .bind(recorded_by.0)
    .execute(tx.conn())
    .await?;
    append_event(
        tx,
        NewEvent {
            tenant_id: tx.tenant(),
            occurred_at: now,
            actor_type: actor.actor_type,
            actor_id: actor.actor_id,
            action_id: None,
            event_type: EventType::PermissionGranted,
            payload_redacted: json!({"permission_id": id, "contact_id": contact_id, "channel": channel, "scope": scope, "expires_at": expires_at}),
            trace_id: actor.trace_id,
            policy_version: actor.policy_version,
        },
    )
    .await?;
    Ok(id)
}

pub async fn revoke_permission(
    tx: &mut TenantTx<'_>,
    permission_id: Uuid,
    actor: Actor<'_>,
    now: DateTime<Utc>,
) -> Result<(ContactId, Channel), StoreError> {
    let r = sqlx::query(
        "UPDATE kernel.contact_permissions SET status = 'revoked', revoked_at = $3
         WHERE tenant_id = $1 AND permission_id = $2 AND revoked_at IS NULL RETURNING contact_id, channel",
    )
    .bind(tx.tenant().0)
    .bind(permission_id)
    .bind(now)
    .fetch_optional(tx.conn())
    .await?
    .ok_or(StoreError::NotFound)?;
    let contact = ContactId::from_uuid(r.try_get("contact_id")?);
    let channel = channel_from(r.try_get::<String, _>("channel")?.as_str())?;
    append_event(
        tx,
        NewEvent {
            tenant_id: tx.tenant(),
            occurred_at: now,
            actor_type: actor.actor_type,
            actor_id: actor.actor_id,
            action_id: None,
            event_type: EventType::PermissionRevoked,
            payload_redacted: json!({"permission_id": permission_id, "contact_id": contact, "channel": channel}),
            trace_id: actor.trace_id,
            policy_version: actor.policy_version,
        },
    )
    .await?;
    Ok((contact, channel))
}

pub async fn permissions_for(
    tx: &mut TenantTx<'_>,
    contact_id: ContactId,
    channel: Channel,
) -> Result<Vec<ContactPermissionFact>, StoreError> {
    let tenant = tx.tenant();
    let rows = sqlx::query(
        "SELECT status, scope, granted_at, expires_at, revoked_at FROM kernel.contact_permissions
         WHERE tenant_id = $1 AND contact_id = $2 AND channel = $3",
    )
    .bind(tenant.0)
    .bind(contact_id.0)
    .bind(channel.as_str())
    .fetch_all(tx.conn())
    .await?;
    rows.into_iter()
        .map(|r| {
            let status = match r.try_get::<String, _>("status")?.as_str() {
                "granted" => PermissionStatus::Granted,
                "revoked" => PermissionStatus::Revoked,
                "expired" => PermissionStatus::Expired,
                _ => return Err(StoreError::Corrupt("status")),
            };
            Ok(ContactPermissionFact {
                tenant_id: tenant,
                contact_id,
                channel,
                status,
                scope: r.try_get("scope")?,
                granted_at: r.try_get("granted_at")?,
                expires_at: r.try_get("expires_at")?,
                revoked_at: r.try_get("revoked_at")?,
            })
        })
        .collect()
}

pub async fn add_suppression(
    tx: &mut TenantTx<'_>,
    channel: Option<Channel>,
    destination_hash: Option<&str>,
    scope: &str,
    reason: &str,
    permanent: bool,
    source: &str,
    actor: Actor<'_>,
    now: DateTime<Utc>,
) -> Result<Uuid, StoreError> {
    // C6: suppression and dispatch authorization share one serialized control
    // path per (tenant, channel, destination). Re-entrant within a session.
    if let (Some(ch), Some(d)) = (channel, destination_hash) {
        crate::messaging::lock_control_path(tx, ch.as_str(), d).await?;
    }
    let id = Uuid::now_v7();
    sqlx::query(
        "INSERT INTO kernel.suppressions (suppression_id, tenant_id, normalized_destination_hash, channel, scope, reason, permanent, created_at, source)
         VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9)",
    )
    .bind(id)
    .bind(tx.tenant().0)
    .bind(destination_hash)
    .bind(channel.map(Channel::as_str))
    .bind(scope)
    .bind(reason)
    .bind(permanent)
    .bind(now)
    .bind(source)
    .execute(tx.conn())
    .await?;
    append_event(
        tx,
        NewEvent {
            tenant_id: tx.tenant(),
            occurred_at: now,
            actor_type: actor.actor_type,
            actor_id: actor.actor_id,
            action_id: None,
            event_type: EventType::SuppressionAdded,
            payload_redacted: json!({"suppression_id": id, "channel": channel, "destination_scoped": destination_hash.is_some(), "permanent": permanent, "reason": reason}),
            trace_id: actor.trace_id,
            policy_version: actor.policy_version,
        },
    )
    .await?;
    Ok(id)
}

/// Lift a suppression. Permanent suppressions are refused here; a separate
/// elevated operator path must be used and is never reachable from an
/// agent request.
pub async fn lift_suppression(
    tx: &mut TenantTx<'_>,
    suppression_id: Uuid,
    by: UserId,
    allow_permanent: bool,
    actor: Actor<'_>,
    now: DateTime<Utc>,
) -> Result<(), StoreError> {
    let r = sqlx::query("SELECT permanent FROM kernel.suppressions WHERE tenant_id = $1 AND suppression_id = $2 AND lifted_at IS NULL FOR UPDATE")
        .bind(tx.tenant().0)
        .bind(suppression_id)
        .fetch_optional(tx.conn())
        .await?
        .ok_or(StoreError::NotFound)?;
    let permanent: bool = r.try_get("permanent")?;
    if permanent && !allow_permanent {
        return Err(StoreError::Conflict(
            "permanent suppression requires elevated lift",
        ));
    }
    sqlx::query("UPDATE kernel.suppressions SET lifted_at = $3, lifted_by = $4 WHERE tenant_id = $1 AND suppression_id = $2")
        .bind(tx.tenant().0)
        .bind(suppression_id)
        .bind(now)
        .bind(by.0)
        .execute(tx.conn())
        .await?;
    append_event(
        tx,
        NewEvent {
            tenant_id: tx.tenant(),
            occurred_at: now,
            actor_type: actor.actor_type,
            actor_id: actor.actor_id,
            action_id: None,
            event_type: EventType::SuppressionLifted,
            payload_redacted: json!({"suppression_id": suppression_id, "was_permanent": permanent}),
            trace_id: actor.trace_id,
            policy_version: actor.policy_version,
        },
    )
    .await?;
    Ok(())
}

/// Active suppressions that could apply to a channel/destination.
pub async fn suppressions_for(
    tx: &mut TenantTx<'_>,
    channel: Channel,
    destination_hash: &str,
) -> Result<Vec<SuppressionFact>, StoreError> {
    let tenant = tx.tenant();
    let rows = sqlx::query(
        "SELECT channel, normalized_destination_hash, permanent, created_at, lifted_at FROM kernel.suppressions
         WHERE tenant_id = $1 AND (channel IS NULL OR channel = $2)
           AND (normalized_destination_hash IS NULL OR normalized_destination_hash = $3)",
    )
    .bind(tenant.0)
    .bind(channel.as_str())
    .bind(destination_hash)
    .fetch_all(tx.conn())
    .await?;
    rows.into_iter()
        .map(|r| {
            Ok(SuppressionFact {
                tenant_id: tenant,
                channel: r
                    .try_get::<Option<String>, _>("channel")?
                    .map(|c| channel_from(&c))
                    .transpose()?,
                destination_hash: r.try_get("normalized_destination_hash")?,
                permanent: r.try_get("permanent")?,
                created_at: r.try_get("created_at")?,
                lifted_at: r.try_get("lifted_at")?,
            })
        })
        .collect()
}
