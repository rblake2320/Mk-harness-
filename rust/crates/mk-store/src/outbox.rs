//! Transactional outbox, execution leases, and dead letters.

use chrono::{DateTime, Duration, Utc};
use mk_audit::{ActorType, EventType, NewEvent};
use mk_domain::{ActionId, TenantId};
use serde_json::{Value, json};
use sqlx::{PgPool, Row};
use uuid::Uuid;

use crate::audit::append_event;
use crate::error::StoreError;
use crate::tx::TenantTx;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct OutboxRow {
    pub outbox_id: i64,
    pub tenant_id: TenantId,
    pub action_id: ActionId,
    pub event_kind: String,
    pub payload: Value,
    pub attempts: i32,
}

/// Insert an outbox row in the same transaction as the `Enqueue` transition.
pub async fn enqueue(
    tx: &mut TenantTx<'_>,
    action_id: ActionId,
    event_kind: &str,
    available_at: DateTime<Utc>,
    payload: Value,
) -> Result<i64, StoreError> {
    let r = sqlx::query(
        "INSERT INTO kernel.outbox_events (tenant_id, action_id, event_kind, payload, available_at)
         VALUES ($1,$2,$3,$4,$5) RETURNING outbox_id",
    )
    .bind(tx.tenant().0)
    .bind(action_id.0)
    .bind(event_kind)
    .bind(payload)
    .bind(available_at)
    .fetch_one(tx.conn())
    .await?;
    let id: i64 = r.try_get("outbox_id")?;
    append_event(
        tx,
        NewEvent {
            tenant_id: tx.tenant(),
            occurred_at: available_at,
            actor_type: ActorType::System,
            actor_id: "outbox",
            action_id: Some(action_id),
            event_type: EventType::Enqueued,
            payload_redacted: json!({"outbox_id": id, "event_kind": event_kind}),
            trace_id: None,
            policy_version: mk_policy::POLICY_VERSION.0,
        },
    )
    .await?;
    Ok(id)
}

/// Relay side (cross-tenant, runs under the relay role policy): claim a batch
/// with a bounded lease. `SKIP LOCKED` lets several relays run concurrently.
pub async fn claim_batch(
    pool: &PgPool,
    relay_id: &str,
    lease: Duration,
    limit: i64,
    now: DateTime<Utc>,
) -> Result<Vec<OutboxRow>, StoreError> {
    let rows = sqlx::query(
        "WITH c AS (
            SELECT outbox_id FROM kernel.outbox_events
            WHERE published_at IS NULL AND available_at <= $1 AND (leased_until IS NULL OR leased_until < $1)
            ORDER BY available_at, outbox_id LIMIT $2 FOR UPDATE SKIP LOCKED)
         UPDATE kernel.outbox_events o SET leased_until = $3, leased_by = $4, attempts = o.attempts + 1
         FROM c WHERE o.outbox_id = c.outbox_id
         RETURNING o.outbox_id, o.tenant_id, o.action_id, o.event_kind, o.payload, o.attempts",
    )
    .bind(now)
    .bind(limit.clamp(1, 1000))
    .bind(now + lease)
    .bind(relay_id)
    .fetch_all(pool)
    .await?;
    rows.into_iter()
        .map(|r| {
            Ok(OutboxRow {
                outbox_id: r.try_get("outbox_id")?,
                tenant_id: TenantId::from_uuid(r.try_get("tenant_id")?),
                action_id: ActionId::from_uuid(r.try_get("action_id")?),
                event_kind: r.try_get("event_kind")?,
                payload: r.try_get("payload")?,
                attempts: r.try_get("attempts")?,
            })
        })
        .collect()
}

/// Mark published only after the stream append is durable.
pub async fn mark_published(
    pool: &PgPool,
    outbox_id: i64,
    relay_id: &str,
    now: DateTime<Utc>,
) -> Result<bool, StoreError> {
    let res = sqlx::query(
        "UPDATE kernel.outbox_events SET published_at = $2 WHERE outbox_id = $1 AND published_at IS NULL AND leased_by = $3",
    )
    .bind(outbox_id)
    .bind(now)
    .bind(relay_id)
    .execute(pool)
    .await?;
    Ok(res.rows_affected() == 1)
}

/// Depth and oldest age for metrics.
pub async fn backlog(pool: &PgPool, now: DateTime<Utc>) -> Result<(i64, Option<i64>), StoreError> {
    let r = sqlx::query(
        "SELECT count(*) AS depth, EXTRACT(EPOCH FROM ($1 - min(available_at)))::bigint AS oldest_secs
         FROM kernel.outbox_events WHERE published_at IS NULL",
    )
    .bind(now)
    .fetch_one(pool)
    .await?;
    Ok((r.try_get("depth")?, r.try_get("oldest_secs")?))
}

/// Acquire an execution lease for an action. Returns a token on success,
/// `None` if another live lease exists.
pub async fn acquire_lease(
    tx: &mut TenantTx<'_>,
    action_id: ActionId,
    worker_id: &str,
    ttl: Duration,
    now: DateTime<Utc>,
) -> Result<Option<Uuid>, StoreError> {
    let token = Uuid::now_v7();
    let r = sqlx::query(
        "INSERT INTO kernel.execution_leases (tenant_id, action_id, worker_id, lease_token, acquired_at, expires_at)
         VALUES ($1,$2,$3,$4,$5,$6)
         ON CONFLICT (tenant_id, action_id) DO UPDATE
           SET worker_id = EXCLUDED.worker_id, lease_token = EXCLUDED.lease_token, acquired_at = EXCLUDED.acquired_at, expires_at = EXCLUDED.expires_at
           WHERE kernel.execution_leases.expires_at < $5
         RETURNING lease_token",
    )
    .bind(tx.tenant().0)
    .bind(action_id.0)
    .bind(worker_id)
    .bind(token)
    .bind(now)
    .bind(now + ttl)
    .fetch_optional(tx.conn())
    .await?;
    Ok(r.map(|r| r.try_get::<Uuid, _>("lease_token")).transpose()?)
}

pub async fn release_lease(
    tx: &mut TenantTx<'_>,
    action_id: ActionId,
    token: Uuid,
) -> Result<bool, StoreError> {
    let res = sqlx::query("DELETE FROM kernel.execution_leases WHERE tenant_id = $1 AND action_id = $2 AND lease_token = $3")
        .bind(tx.tenant().0)
        .bind(action_id.0)
        .bind(token)
        .execute(tx.conn())
        .await?;
    Ok(res.rows_affected() == 1)
}

/// Release whatever lease exists for an action (housekeeping only).
pub async fn release_lease_any(
    tx: &mut TenantTx<'_>,
    action_id: ActionId,
) -> Result<(), StoreError> {
    sqlx::query("DELETE FROM kernel.execution_leases WHERE tenant_id = $1 AND action_id = $2")
        .bind(tx.tenant().0)
        .bind(action_id.0)
        .execute(tx.conn())
        .await?;
    Ok(())
}

/// Expired leases across tenants (worker sweep under the worker policy).
pub async fn expired_leases(
    pool: &PgPool,
    now: DateTime<Utc>,
    limit: i64,
) -> Result<Vec<(TenantId, ActionId)>, StoreError> {
    let rows = sqlx::query(
        "SELECT tenant_id, action_id FROM kernel.execution_leases WHERE expires_at < $1 LIMIT $2",
    )
    .bind(now)
    .bind(limit)
    .fetch_all(pool)
    .await?;
    rows.into_iter()
        .map(|r| {
            Ok((
                TenantId::from_uuid(r.try_get("tenant_id")?),
                ActionId::from_uuid(r.try_get("action_id")?),
            ))
        })
        .collect()
}

pub async fn dead_letter(
    tx: &mut TenantTx<'_>,
    action_id: ActionId,
    final_state: &str,
    attempts: i32,
    error_code: Option<&str>,
    diagnostics_redacted: Value,
    now: DateTime<Utc>,
) -> Result<(), StoreError> {
    sqlx::query(
        "INSERT INTO kernel.dead_letters (tenant_id, action_id, final_state, attempts, error_code, diagnostics, dead_lettered_at)
         VALUES ($1,$2,$3,$4,$5,$6,$7) ON CONFLICT (tenant_id, action_id) DO NOTHING",
    )
    .bind(tx.tenant().0)
    .bind(action_id.0)
    .bind(final_state)
    .bind(attempts)
    .bind(error_code)
    .bind(&diagnostics_redacted)
    .bind(now)
    .execute(tx.conn())
    .await?;
    append_event(
        tx,
        NewEvent {
            tenant_id: tx.tenant(),
            occurred_at: now,
            actor_type: ActorType::Worker,
            actor_id: "worker",
            action_id: Some(action_id),
            event_type: EventType::DeadLettered,
            payload_redacted: json!({"attempts": attempts, "error_code": error_code}),
            trace_id: None,
            policy_version: mk_policy::POLICY_VERSION.0,
        },
    )
    .await?;
    Ok(())
}

pub async fn record_attempt_start(
    tx: &mut TenantTx<'_>,
    action_id: ActionId,
    attempt: i32,
    worker_id: &str,
    now: DateTime<Utc>,
) -> Result<(), StoreError> {
    sqlx::query(
        "INSERT INTO kernel.action_attempts (tenant_id, action_id, attempt, worker_id, started_at) VALUES ($1,$2,$3,$4,$5)
         ON CONFLICT (tenant_id, action_id, attempt) DO NOTHING",
    )
    .bind(tx.tenant().0)
    .bind(action_id.0)
    .bind(attempt)
    .bind(worker_id)
    .bind(now)
    .execute(tx.conn())
    .await?;
    Ok(())
}

pub async fn record_attempt_end(
    tx: &mut TenantTx<'_>,
    action_id: ActionId,
    attempt: i32,
    outcome: &str,
    error_code: Option<&str>,
    adapter_id: Option<Uuid>,
    external_ref: Option<&str>,
    result_digest: Option<&str>,
    now: DateTime<Utc>,
) -> Result<(), StoreError> {
    sqlx::query(
        "UPDATE kernel.action_attempts SET finished_at = $4, outcome = $5, error_code = $6, adapter_id = $7, external_ref = $8, result_digest = $9
         WHERE tenant_id = $1 AND action_id = $2 AND attempt = $3",
    )
    .bind(tx.tenant().0)
    .bind(action_id.0)
    .bind(attempt)
    .bind(now)
    .bind(outcome)
    .bind(error_code)
    .bind(adapter_id)
    .bind(external_ref)
    .bind(result_digest)
    .execute(tx.conn())
    .await?;
    Ok(())
}

/// Queued actions whose every outbox event was published more than
/// `stranded_after_secs` ago and that hold no lease: the queue lost the
/// message (Redis data loss, consumer group reset). Dispatch is idempotent
/// against state (`not_queued` skip), so re-enqueueing is safe.
///
/// Tenant-scoped (RLS): the worker sweeps each tenant inside its own transaction.
pub async fn stranded_queued(
    tx: &mut TenantTx<'_>,
    now: DateTime<Utc>,
    stranded_after_secs: i64,
    limit: i64,
) -> Result<Vec<ActionId>, StoreError> {
    let cutoff = now - chrono::Duration::seconds(stranded_after_secs);
    let rows = sqlx::query(
        "SELECT a.action_id FROM kernel.actions a
         WHERE a.tenant_id = $4 AND a.state = 'queued'
           AND NOT EXISTS (SELECT 1 FROM kernel.outbox_events o WHERE o.action_id = a.action_id AND (o.published_at IS NULL OR o.published_at > $1))
           AND EXISTS (SELECT 1 FROM kernel.outbox_events o WHERE o.action_id = a.action_id AND o.published_at <= $1)
           AND NOT EXISTS (SELECT 1 FROM kernel.execution_leases l WHERE l.action_id = a.action_id AND l.expires_at > $2)
         ORDER BY a.updated_at LIMIT $3",
    )
    .bind(cutoff)
    .bind(now)
    .bind(limit)
    .bind(tx.tenant().0)
    .fetch_all(tx.conn())
    .await?;
    rows.into_iter()
        .map(|r| Ok(ActionId::from_uuid(r.try_get("action_id")?)))
        .collect()
}
