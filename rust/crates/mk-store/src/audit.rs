//! Audit append under the per-tenant head lock, and chain reads for the
//! verifier.

use chrono::{DateTime, Utc};
use mk_audit::{AuditEvent, ChainHead, NewEvent, append};
use mk_domain::{ActionId, TenantId};
use sqlx::Row;

use crate::error::StoreError;
use crate::tx::TenantTx;

/// Append an audit event inside the current transaction. Locks the tenant
/// head row (`FOR UPDATE`), creating it on first use, so concurrent writers
/// serialize and `tenant_sequence` stays dense.
pub async fn append_event(
    tx: &mut TenantTx<'_>,
    new: NewEvent<'_>,
) -> Result<AuditEvent, StoreError> {
    tx.assert_tenant(new.tenant_id)?;
    let tenant = tx.tenant();
    // Ensure the head exists (idempotent), then lock it.
    sqlx::query(
        "INSERT INTO kernel.audit_heads (tenant_id) VALUES ($1) ON CONFLICT (tenant_id) DO NOTHING",
    )
    .bind(tenant.0)
    .execute(tx.conn())
    .await?;
    let row = sqlx::query(
        "SELECT last_hash, count FROM kernel.audit_heads WHERE tenant_id = $1 FOR UPDATE",
    )
    .bind(tenant.0)
    .fetch_one(tx.conn())
    .await?;
    let head = ChainHead {
        tenant_id: tenant,
        last_hash: row.try_get("last_hash")?,
        count: row.try_get("count")?,
    };
    let (event, next) = append(&head, new)?;
    sqlx::query(
        "INSERT INTO kernel.audit_events (event_id, tenant_id, tenant_sequence, occurred_at, actor_type, actor_id, action_id,
           event_type, payload_redacted, payload_digest, previous_event_hash, event_hash, trace_id, policy_version)
         VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14)",
    )
    .bind(event.event_id)
    .bind(event.tenant_id.0)
    .bind(event.tenant_sequence)
    .bind(event.occurred_at)
    .bind(serde_plain(&event.actor_type))
    .bind(&event.actor_id)
    .bind(event.action_id.map(|a| a.0))
    .bind(serde_plain(&event.event_type))
    .bind(&event.payload_redacted)
    .bind(event.payload_digest.to_string())
    .bind(&event.previous_event_hash)
    .bind(&event.event_hash)
    .bind(&event.trace_id)
    .bind(&event.policy_version)
    .execute(tx.conn())
    .await?;
    sqlx::query("UPDATE kernel.audit_heads SET last_hash = $2, count = $3, updated_at = now() WHERE tenant_id = $1")
        .bind(tenant.0)
        .bind(&next.last_hash)
        .bind(next.count)
        .execute(tx.conn())
        .await?;
    Ok(event)
}

/// Serialize a `snake_case` enum to its bare string.
fn serde_plain<T: serde::Serialize>(v: &T) -> String {
    serde_json::to_value(v)
        .ok()
        .and_then(|j| j.as_str().map(str::to_owned))
        .unwrap_or_default()
}

fn serde_from<T: serde::de::DeserializeOwned>(s: &str) -> Result<T, StoreError> {
    serde_json::from_value(serde_json::Value::String(s.to_owned()))
        .map_err(|_| StoreError::Corrupt("enum string"))
}

/// Read the head (without locking).
pub async fn head(tx: &mut TenantTx<'_>) -> Result<ChainHead, StoreError> {
    let tenant = tx.tenant();
    let row = sqlx::query("SELECT last_hash, count FROM kernel.audit_heads WHERE tenant_id = $1")
        .bind(tenant.0)
        .fetch_optional(tx.conn())
        .await?;
    Ok(match row {
        Some(r) => ChainHead {
            tenant_id: tenant,
            last_hash: r.try_get("last_hash")?,
            count: r.try_get("count")?,
        },
        None => ChainHead::genesis(tenant),
    })
}

/// Page through events in sequence order.
pub async fn events_from(
    tx: &mut TenantTx<'_>,
    after_sequence: i64,
    limit: i64,
) -> Result<Vec<AuditEvent>, StoreError> {
    let tenant = tx.tenant();
    let rows = sqlx::query(
        "SELECT event_id, tenant_sequence, occurred_at, actor_type, actor_id, action_id, event_type, payload_redacted,
                payload_digest, previous_event_hash, event_hash, trace_id, policy_version
         FROM kernel.audit_events WHERE tenant_id = $1 AND tenant_sequence > $2 ORDER BY tenant_sequence LIMIT $3",
    )
    .bind(tenant.0)
    .bind(after_sequence)
    .bind(limit.clamp(1, 10_000))
    .fetch_all(tx.conn())
    .await?;
    rows.into_iter()
        .map(|r| {
            let occurred_at: DateTime<Utc> = r.try_get("occurred_at")?;
            Ok(AuditEvent {
                event_id: r.try_get("event_id")?,
                tenant_id: tenant,
                tenant_sequence: r.try_get("tenant_sequence")?,
                occurred_at,
                actor_type: serde_from(r.try_get::<String, _>("actor_type")?.as_str())?,
                actor_id: r.try_get("actor_id")?,
                action_id: r
                    .try_get::<Option<uuid::Uuid>, _>("action_id")?
                    .map(ActionId::from_uuid),
                event_type: serde_from(r.try_get::<String, _>("event_type")?.as_str())?,
                payload_redacted: r.try_get("payload_redacted")?,
                payload_digest: r
                    .try_get::<String, _>("payload_digest")?
                    .parse()
                    .map_err(|_| StoreError::Corrupt("payload_digest"))?,
                previous_event_hash: r.try_get("previous_event_hash")?,
                event_hash: r.try_get("event_hash")?,
                trace_id: r.try_get("trace_id")?,
                policy_version: r.try_get("policy_version")?,
            })
        })
        .collect()
}

/// Verify a whole tenant chain. Used by `mk-audit-verifier` daily and by
/// integration tests.
pub async fn verify_tenant(tx: &mut TenantTx<'_>) -> Result<i64, StoreError> {
    let h = head(tx).await?;
    let mut all = Vec::new();
    let mut after = 0i64;
    loop {
        let page = events_from(tx, after, 5000).await?;
        if page.is_empty() {
            break;
        }
        after = page.last().map_or(after, |e| e.tenant_sequence);
        all.extend(page);
    }
    Ok(mk_audit::verify_chain(tx.tenant(), &all, &h)?)
}

/// O(1) tail check for monitoring: the stored head must equal the last
/// event's hash and the event count. Catches truncation, head tampering and a
/// head/events split-brain without walking the chain (that is `verify_tenant`,
/// run by `mk-audit-verifier`). Returns `Ok(true)` when consistent.
pub async fn head_consistent(tx: &mut TenantTx<'_>) -> Result<bool, StoreError> {
    let h = head(tx).await?;
    let last: Option<(i64, String)> = sqlx::query(
        "SELECT tenant_sequence, event_hash FROM kernel.audit_events WHERE tenant_id = $1 ORDER BY tenant_sequence DESC LIMIT 1",
    )
    .bind(tx.tenant().0)
    .fetch_optional(tx.conn())
    .await?
    .map(|r| Ok::<_, StoreError>((r.try_get("tenant_sequence")?, r.try_get("event_hash")?)))
    .transpose()?;
    let n: i64 =
        sqlx::query_scalar("SELECT count(*) FROM kernel.audit_events WHERE tenant_id = $1")
            .bind(tx.tenant().0)
            .fetch_one(tx.conn())
            .await?;
    Ok(match last {
        None => h.count == 0 && n == 0,
        Some((seq, hash)) => h.count == seq && n == seq && h.last_hash == hash,
    })
}

/// Every known tenant id: `kernel.tenant_directory` (migration 0009, not under
/// RLS — readable by every kernel role) plus any audit head visible to the
/// caller (the read-only role's policy). Cross-tenant operator work iterates
/// these and does each tenant's work inside that tenant's transaction.
pub async fn all_tenants(pool: &sqlx::PgPool) -> Result<Vec<TenantId>, StoreError> {
    let rows = sqlx::query(
        "SELECT tenant_id FROM kernel.tenant_directory UNION SELECT tenant_id FROM kernel.audit_heads ORDER BY tenant_id",
    )
        .fetch_all(pool)
        .await?;
    rows.into_iter()
        .map(|r| Ok(TenantId::from_uuid(r.try_get("tenant_id")?)))
        .collect()
}
