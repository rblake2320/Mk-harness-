//! Approval records: creation bound to the stored digest, revocation, and
//! single-use atomic consumption.

use chrono::{DateTime, Duration, Utc};
use mk_audit::{ActorType, EventType, NewEvent};
use mk_contracts::{APPROVAL_SCHEMA_VERSION, ApprovalRecord};
use mk_domain::{ActionId, ApprovalDecision, ApprovalId, UserId};
use serde_json::json;
use sqlx::Row;

use crate::actions::{self, Actor};
use crate::audit::append_event;
use crate::error::StoreError;
use crate::tx::TenantTx;

/// Record a human decision. The digest is taken from the *stored* action
/// (not from the request body), so an approval can only ever bind to what
/// the kernel actually holds. The caller has already run
/// `mk_policy::check_approver`.
pub async fn record_decision(
    tx: &mut TenantTx<'_>,
    action_id: ActionId,
    approver: UserId,
    approver_roles: &[String],
    decision: ApprovalDecision,
    reason: Option<&str>,
    ttl_secs: u32,
    session_id: Option<&str>,
    request_ip_hash: Option<&str>,
    now: DateTime<Utc>,
) -> Result<ApprovalRecord, StoreError> {
    let action = actions::get_for_update(tx, action_id).await?;
    let approval_id = ApprovalId::new();
    let expires_at = now + Duration::seconds(i64::from(ttl_secs));
    let decision_s = match decision {
        ApprovalDecision::Approved => "approved",
        ApprovalDecision::Rejected => "rejected",
    };
    sqlx::query(
        "INSERT INTO kernel.approvals (approval_id, tenant_id, action_id, action_digest, approver_id, approver_roles, decision,
           reason, created_at, expires_at, request_ip_hash, session_id)
         VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12)",
    )
    .bind(approval_id.0)
    .bind(tx.tenant().0)
    .bind(action_id.0)
    .bind(action.digest.to_string())
    .bind(approver.0)
    .bind(approver_roles)
    .bind(decision_s)
    .bind(reason)
    .bind(now)
    .bind(expires_at)
    .bind(request_ip_hash)
    .bind(session_id)
    .execute(tx.conn())
    .await
    .map_err(|e| match StoreError::from(e) {
        StoreError::Conflict(_) => StoreError::Conflict("a live approval already exists for this action"),
        other => other,
    })?;
    append_event(
        tx,
        NewEvent {
            tenant_id: tx.tenant(),
            occurred_at: now,
            actor_type: ActorType::User,
            actor_id: &approver.to_string(),
            action_id: Some(action_id),
            event_type: match decision {
                ApprovalDecision::Approved => EventType::ApprovalGranted,
                ApprovalDecision::Rejected => EventType::ApprovalRejected,
            },
            payload_redacted: json!({
                "approval_id": approval_id, "action_digest": action.digest.to_string(),
                "expires_at": expires_at, "roles": approver_roles, "has_reason": reason.is_some(),
            }),
            trace_id: None,
            policy_version: mk_policy::POLICY_VERSION.0,
        },
    )
    .await?;
    get(tx, approval_id).await
}

fn row_to_record(
    tenant: mk_domain::TenantId,
    r: &sqlx::postgres::PgRow,
) -> Result<ApprovalRecord, StoreError> {
    let decision = match r.try_get::<String, _>("decision")?.as_str() {
        "approved" => ApprovalDecision::Approved,
        "rejected" => ApprovalDecision::Rejected,
        _ => return Err(StoreError::Corrupt("decision")),
    };
    Ok(ApprovalRecord {
        schema_version: APPROVAL_SCHEMA_VERSION.into(),
        approval_id: ApprovalId::from_uuid(r.try_get("approval_id")?),
        tenant_id: tenant,
        action_id: ActionId::from_uuid(r.try_get("action_id")?),
        action_digest: r
            .try_get::<String, _>("action_digest")?
            .parse()
            .map_err(|_| StoreError::Corrupt("action_digest"))?,
        approver_id: UserId::from_uuid(r.try_get("approver_id")?),
        approver_roles: r.try_get("approver_roles")?,
        decision,
        reason: r.try_get("reason")?,
        created_at: r.try_get("created_at")?,
        expires_at: r.try_get("expires_at")?,
        consumed_at: r.try_get("consumed_at")?,
        revoked_at: r.try_get("revoked_at")?,
        session_id: r.try_get("session_id")?,
    })
}

const COLS: &str = "approval_id, action_id, action_digest, approver_id, approver_roles, decision, reason, created_at, expires_at, consumed_at, revoked_at, session_id";

pub async fn get(
    tx: &mut TenantTx<'_>,
    approval_id: ApprovalId,
) -> Result<ApprovalRecord, StoreError> {
    let tenant = tx.tenant();
    let q =
        format!("SELECT {COLS} FROM kernel.approvals WHERE tenant_id = $1 AND approval_id = $2");
    let r = sqlx::query(&q)
        .bind(tenant.0)
        .bind(approval_id.0)
        .fetch_optional(tx.conn())
        .await?
        .ok_or(StoreError::NotFound)?;
    row_to_record(tenant, &r)
}

/// The single live (approved, unconsumed, unrevoked) approval for an action,
/// locked for update so a concurrent consumer blocks.
pub async fn live_for_action_locked(
    tx: &mut TenantTx<'_>,
    action_id: ActionId,
) -> Result<Option<ApprovalRecord>, StoreError> {
    let tenant = tx.tenant();
    let q = format!(
        "SELECT {COLS} FROM kernel.approvals WHERE tenant_id = $1 AND action_id = $2
         AND decision = 'approved' AND consumed_at IS NULL AND revoked_at IS NULL FOR UPDATE"
    );
    let r = sqlx::query(&q)
        .bind(tenant.0)
        .bind(action_id.0)
        .fetch_optional(tx.conn())
        .await?;
    r.map(|r| row_to_record(tenant, &r)).transpose()
}

/// Consume exactly once. The `WHERE` clause re-states every validity
/// condition so this is correct even without the prior `FOR UPDATE` read:
/// two concurrent workers cannot both get `rows_affected == 1`.
pub async fn consume(
    tx: &mut TenantTx<'_>,
    approval_id: ApprovalId,
    action_id: ActionId,
    expected_digest: &mk_crypto::Digest,
    consumer: &str,
    now: DateTime<Utc>,
) -> Result<(), StoreError> {
    let res = sqlx::query(
        "UPDATE kernel.approvals SET consumed_at = $5, consumed_by = $6
         WHERE tenant_id = $1 AND approval_id = $2 AND action_id = $3 AND action_digest = $4
           AND decision = 'approved' AND consumed_at IS NULL AND revoked_at IS NULL
           AND expires_at > $5 AND created_at <= $5",
    )
    .bind(tx.tenant().0)
    .bind(approval_id.0)
    .bind(action_id.0)
    .bind(expected_digest.to_string())
    .bind(now)
    .bind(consumer)
    .execute(tx.conn())
    .await?;
    if res.rows_affected() != 1 {
        return Err(StoreError::Conflict("approval not consumable"));
    }
    append_event(
        tx,
        NewEvent {
            tenant_id: tx.tenant(),
            occurred_at: now,
            actor_type: ActorType::Worker,
            actor_id: consumer,
            action_id: Some(action_id),
            event_type: EventType::ApprovalConsumed,
            payload_redacted: json!({"approval_id": approval_id}),
            trace_id: None,
            policy_version: mk_policy::POLICY_VERSION.0,
        },
    )
    .await?;
    Ok(())
}

pub async fn revoke(
    tx: &mut TenantTx<'_>,
    approval_id: ApprovalId,
    by: UserId,
    actor: Actor<'_>,
    now: DateTime<Utc>,
) -> Result<ApprovalRecord, StoreError> {
    let res = sqlx::query(
        "UPDATE kernel.approvals SET revoked_at = $3, revoked_by = $4
         WHERE tenant_id = $1 AND approval_id = $2 AND consumed_at IS NULL AND revoked_at IS NULL",
    )
    .bind(tx.tenant().0)
    .bind(approval_id.0)
    .bind(now)
    .bind(by.0)
    .execute(tx.conn())
    .await?;
    if res.rows_affected() != 1 {
        return Err(StoreError::Conflict("approval not revocable"));
    }
    let rec = get(tx, approval_id).await?;
    append_event(
        tx,
        NewEvent {
            tenant_id: tx.tenant(),
            occurred_at: now,
            actor_type: actor.actor_type,
            actor_id: actor.actor_id,
            action_id: Some(rec.action_id),
            event_type: EventType::ApprovalRevoked,
            payload_redacted: json!({"approval_id": approval_id}),
            trace_id: actor.trace_id,
            policy_version: actor.policy_version,
        },
    )
    .await?;
    Ok(rec)
}

/// The most recent *consumed* approval for an action (retry path).
pub async fn consumed_for_action(
    tx: &mut TenantTx<'_>,
    action_id: ActionId,
) -> Result<Option<ApprovalRecord>, StoreError> {
    let tenant = tx.tenant();
    let q = format!(
        "SELECT {COLS} FROM kernel.approvals WHERE tenant_id = $1 AND action_id = $2
         AND decision = 'approved' AND consumed_at IS NOT NULL ORDER BY created_at DESC LIMIT 1"
    );
    let r = sqlx::query(&q)
        .bind(tenant.0)
        .bind(action_id.0)
        .fetch_optional(tx.conn())
        .await?;
    r.map(|r| row_to_record(tenant, &r)).transpose()
}

/// Actions awaiting approval, oldest first.
pub async fn pending(tx: &mut TenantTx<'_>, limit: i64) -> Result<Vec<ActionId>, StoreError> {
    let rows = sqlx::query(
        "SELECT action_id FROM kernel.actions WHERE tenant_id = $1 AND state = 'approval_required' ORDER BY created_at LIMIT $2",
    )
    .bind(tx.tenant().0)
    .bind(limit.clamp(1, 500))
    .fetch_all(tx.conn())
    .await?;
    rows.into_iter()
        .map(|r| Ok(ActionId::from_uuid(r.try_get("action_id")?)))
        .collect()
}
