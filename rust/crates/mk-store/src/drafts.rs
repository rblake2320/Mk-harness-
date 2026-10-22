//! Version invalidation is serialized with intake, not with the application's
//! best-effort action links. Once fenced, a version can never be proposed again.
use chrono::{DateTime, Utc};
use mk_audit::{EventType, NewEvent};
use mk_contracts::ActionRequest;
use mk_domain::{ActionId, ActionState, ApprovalId, Transition, UserId};
use serde::Serialize;
use serde_json::json;
use sqlx::Row;
use uuid::Uuid;

use crate::{StoreError, TenantTx, actions, approvals, audit::append_event};

fn references(req: &ActionRequest) -> Result<Vec<Uuid>, StoreError> {
    let mut ids = Vec::new();
    for e in &req.evidence {
        if e.evidence_type == "document"
            && let Some(id) = e.id.strip_prefix("draft:")
        {
            ids.push(
                Uuid::parse_str(id).map_err(|_| StoreError::Conflict("invalid draft reference"))?,
            );
        }
    }
    ids.sort_unstable();
    ids.dedup();
    Ok(ids)
}

async fn lock(tx: &mut TenantTx<'_>, draft: Uuid) -> Result<(), StoreError> {
    // Hash collisions only serialize unrelated requests; they cannot grant access.
    sqlx::query("SELECT pg_advisory_xact_lock(hashtextextended($1, 0))")
        .bind(format!("draft:{}:{draft}", tx.tenant()))
        .execute(tx.conn())
        .await?;
    Ok(())
}

/// Must precede idempotency lookup too: an old successful request is no longer
/// an acceptable proposal after the consultant withdraws its version.
pub async fn check_intake(tx: &mut TenantTx<'_>, req: &ActionRequest) -> Result<(), StoreError> {
    tx.assert_tenant(req.tenant_id)?;
    for id in references(req)? {
        lock(tx, id).await?;
        let invalid: bool = sqlx::query_scalar(
            "SELECT EXISTS (SELECT 1 FROM kernel.invalidated_drafts WHERE tenant_id=$1 AND draft_id=$2)")
            .bind(tx.tenant().0).bind(id).fetch_one(tx.conn()).await?;
        if invalid {
            return Err(StoreError::Conflict(
                "draft version was invalidated; create and approve a new version",
            ));
        }
    }
    Ok(())
}

#[derive(Debug, Serialize)]
pub struct Invalidation {
    pub draft_id: Uuid,
    pub edit_permitted: bool,
    pub cancelled_actions: usize,
    pub blocked_actions: Vec<ActionId>,
}

pub async fn invalidate(
    tx: &mut TenantTx<'_>,
    draft: Uuid,
    by: UserId,
    admin: bool,
    actor: actions::Actor<'_>,
    now: DateTime<Utc>,
) -> Result<Invalidation, StoreError> {
    lock(tx, draft).await?;
    let rows = sqlx::query(
        "SELECT a.action_id, a.requested_by FROM kernel.draft_action_refs r
        JOIN kernel.actions a USING (tenant_id, action_id)
        WHERE r.tenant_id=$1 AND r.draft_id=$2 ORDER BY a.action_id",
    )
    .bind(tx.tenant().0)
    .bind(draft)
    .fetch_all(tx.conn())
    .await?;
    for row in &rows {
        if !admin && row.try_get::<Uuid, _>("requested_by")? != by.0 {
            return Err(StoreError::NotFound);
        }
    }
    let inserted = sqlx::query("INSERT INTO kernel.invalidated_drafts
        (tenant_id,draft_id,invalidated_by,invalidated_at) VALUES ($1,$2,$3,$4) ON CONFLICT DO NOTHING")
        .bind(tx.tenant().0).bind(draft).bind(by.0).bind(now).execute(tx.conn()).await?.rows_affected();
    let mut result = Invalidation {
        draft_id: draft,
        edit_permitted: true,
        cancelled_actions: 0,
        blocked_actions: Vec::new(),
    };
    // Acquire every action lock before any audit-head lock; otherwise a worker
    // holding the next action and waiting on the audit head could deadlock us.
    let mut locked = Vec::new();
    for row in rows {
        locked.push(
            actions::get_for_update(tx, ActionId::from_uuid(row.try_get("action_id")?)).await?,
        );
    }
    for action in locked {
        let aid = action.action_id;
        if matches!(
            action.state,
            ActionState::Dispatching | ActionState::Completed | ActionState::ReconciliationRequired
        ) {
            result.blocked_actions.push(aid);
            continue;
        }
        let live: Vec<Uuid> = sqlx::query_scalar("SELECT approval_id FROM kernel.approvals
            WHERE tenant_id=$1 AND action_id=$2 AND consumed_at IS NULL AND revoked_at IS NULL ORDER BY approval_id")
            .bind(tx.tenant().0).bind(aid.0).fetch_all(tx.conn()).await?;
        for id in live {
            approvals::revoke(tx, ApprovalId::from_uuid(id), by, actor, now).await?;
        }
        if action.state.is_cancellable() {
            actions::transition(
                tx,
                aid,
                Transition::Cancel,
                Some("draft_invalidated"),
                actor,
                now,
            )
            .await?;
            result.cancelled_actions += 1;
        }
    }
    result.edit_permitted = result.blocked_actions.is_empty();
    if inserted > 0 {
        append_event(tx, NewEvent {
            tenant_id: tx.tenant(), occurred_at: now, actor_type: actor.actor_type,
            actor_id: actor.actor_id, action_id: None, event_type: EventType::DraftInvalidated,
            payload_redacted: json!({"draft_id":draft,"edit_permitted":result.edit_permitted,
                "cancelled_actions":result.cancelled_actions,"blocked_actions":result.blocked_actions}),
            trace_id: actor.trace_id, policy_version: actor.policy_version,
        }).await?;
    }
    Ok(result)
}
