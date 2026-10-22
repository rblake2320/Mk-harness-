//! Short-lived public-webhook checks. Only the worker can issue or confirm;
//! the API may record receipt of an exact authenticated issued generation.
use crate::{StoreError, TenantTx};
use chrono::{DateTime, Utc};
use mk_crypto::Digest;
use uuid::Uuid;

pub async fn due(tx: &mut TenantTx<'_>, now: DateTime<Utc>) -> Result<Vec<Uuid>, StoreError> {
    sqlx::query("INSERT INTO kernel.inbound_probes (tenant_id, sender_identity_id)
        SELECT tenant_id, sender_identity_id FROM kernel.sender_identities WHERE tenant_id = $1 AND status = 'active'
        ON CONFLICT DO NOTHING").bind(tx.tenant().0).execute(tx.conn()).await?;
    Ok(sqlx::query_scalar("SELECT p.sender_identity_id FROM kernel.inbound_probes p
        JOIN kernel.sender_identities s ON s.tenant_id = p.tenant_id AND s.sender_identity_id = p.sender_identity_id
        WHERE p.tenant_id = $1 AND s.status = 'active' AND (p.issued_at IS NULL OR p.issued_at <= $2 - interval '15 seconds')
        ORDER BY p.issued_at NULLS FIRST LIMIT 32 FOR UPDATE OF p SKIP LOCKED")
        .bind(tx.tenant().0).bind(now).fetch_all(tx.conn()).await?)
}

pub async fn issue(
    tx: &mut TenantTx<'_>,
    sender: Uuid,
    id: Uuid,
    digest: &Digest,
    now: DateTime<Utc>,
) -> Result<(), StoreError> {
    sqlx::query(
        "UPDATE kernel.inbound_probes SET probe_id = $3, body_digest = $4, issued_at = $5,
        expires_at = $5 + interval '10 seconds', received_at = NULL, confirmed_at = NULL
        WHERE tenant_id = $1 AND sender_identity_id = $2",
    )
    .bind(tx.tenant().0)
    .bind(sender)
    .bind(id)
    .bind(digest.to_string())
    .bind(now)
    .execute(tx.conn())
    .await?;
    Ok(())
}

pub async fn receive(
    tx: &mut TenantTx<'_>,
    sender: Uuid,
    id: Uuid,
    digest: &Digest,
    now: DateTime<Utc>,
) -> Result<bool, StoreError> {
    let n = sqlx::query(
        "UPDATE kernel.inbound_probes SET received_at = $5
        WHERE tenant_id = $1 AND sender_identity_id = $2 AND probe_id = $3 AND body_digest = $4
          AND issued_at <= $5 AND expires_at >= $5 AND received_at IS NULL",
    )
    .bind(tx.tenant().0)
    .bind(sender)
    .bind(id)
    .bind(digest.to_string())
    .bind(now)
    .execute(tx.conn())
    .await?
    .rows_affected();
    Ok(n == 1)
}

/// Start the short receipt window only after network capacity is acquired.
/// A generation reclaimed by another replica cannot be sent by the old job.
pub async fn start(
    tx: &mut TenantTx<'_>,
    sender: Uuid,
    id: Uuid,
    now: DateTime<Utc>,
) -> Result<bool, StoreError> {
    let n = sqlx::query("UPDATE kernel.inbound_probes SET issued_at = $4, expires_at = $4 + interval '10 seconds'
        WHERE tenant_id = $1 AND sender_identity_id = $2 AND probe_id = $3 AND received_at IS NULL AND confirmed_at IS NULL")
        .bind(tx.tenant().0).bind(sender).bind(id).bind(now).execute(tx.conn()).await?.rows_affected();
    Ok(n == 1)
}

pub async fn confirm(
    tx: &mut TenantTx<'_>,
    sender: Uuid,
    id: Uuid,
    now: DateTime<Utc>,
) -> Result<bool, StoreError> {
    let n = sqlx::query("UPDATE kernel.inbound_probes SET confirmed_at = $4, last_ok_at = received_at, last_error = ''
        WHERE tenant_id = $1 AND sender_identity_id = $2 AND probe_id = $3
          AND received_at IS NOT NULL AND confirmed_at IS NULL AND expires_at >= $4")
        .bind(tx.tenant().0).bind(sender).bind(id).bind(now).execute(tx.conn()).await?.rows_affected();
    Ok(n == 1)
}

pub async fn fail(
    tx: &mut TenantTx<'_>,
    sender: Uuid,
    id: Uuid,
    code: &str,
) -> Result<(), StoreError> {
    sqlx::query("UPDATE kernel.inbound_probes SET last_error = $4 WHERE tenant_id = $1 AND sender_identity_id = $2 AND probe_id = $3")
        .bind(tx.tenant().0).bind(sender).bind(id).bind(code).execute(tx.conn()).await?;
    Ok(())
}

pub async fn all_fresh(tx: &mut TenantTx<'_>, now: DateTime<Utc>) -> Result<bool, StoreError> {
    Ok(sqlx::query_scalar("SELECT NOT EXISTS (SELECT 1 FROM kernel.sender_identities s
        LEFT JOIN kernel.inbound_probes p ON p.tenant_id = s.tenant_id AND p.sender_identity_id = s.sender_identity_id
        WHERE s.tenant_id = $1 AND s.status = 'active' AND
          (p.last_ok_at IS NULL OR p.last_ok_at < $2 - interval '60 seconds' OR p.last_ok_at > $2))")
        .bind(tx.tenant().0).bind(now).fetch_one(tx.conn()).await?)
}

/// Called before refreshing tenant health, preserving the outage latch even if
/// no dispatch happened while the monitor was dead.
pub async fn latch_outage(tx: &mut TenantTx<'_>, now: DateTime<Utc>) -> Result<(), StoreError> {
    let old_health = crate::messaging::inbound_health(tx)
        .await?
        .is_some_and(|h| {
            h.last_ok_at
                .is_some_and(|ok| now < ok || now - ok > chrono::Duration::seconds(60))
        });
    if old_health || !all_fresh(tx, now).await? {
        sqlx::query("INSERT INTO kernel.inbound_health (tenant_id, recovery_required, updated_at) VALUES ($1,true,$2)
            ON CONFLICT (tenant_id) DO UPDATE SET recovery_required = true, updated_at = $2")
            .bind(tx.tenant().0).bind(now).execute(tx.conn()).await?;
    }
    Ok(())
}

pub async fn recover_if_drained(
    tx: &mut TenantTx<'_>,
    now: DateTime<Utc>,
) -> Result<(), StoreError> {
    if all_fresh(tx, now).await? && crate::messaging::pending_inbound_count(tx).await? == 0 {
        sqlx::query("UPDATE kernel.inbound_health SET recovery_required = false, updated_at = $2 WHERE tenant_id = $1")
            .bind(tx.tenant().0).bind(now).execute(tx.conn()).await?;
    }
    Ok(())
}
