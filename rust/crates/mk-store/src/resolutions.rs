//! C4: durable human resolution is separate from provider evidence and approval.
use chrono::{DateTime, Utc};
use mk_audit::{ActorType, EventType, NewEvent};
use mk_crypto::Digest;
use mk_domain::{ActionId, ActionState, UserId};
use serde::{Deserialize, Serialize};
use serde_json::json;
use uuid::Uuid;

use crate::{StoreError, TenantTx, actions, audit, fingerprint::Fingerprints, messaging};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Decision {
    ClosedNoReplacement,
    ReplacementPermitted,
}

impl Decision {
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::ClosedNoReplacement => "closed_no_replacement",
            Self::ReplacementPermitted => "replacement_permitted",
        }
    }
    #[must_use]
    pub fn for_state(state: &str) -> Option<Self> {
        match state {
            "provider_accepted" | "sent" | "delivered" => Some(Self::ClosedNoReplacement),
            "failed" => Some(Self::ReplacementPermitted),
            _ => None,
        }
    }
}

pub async fn decision(
    tx: &mut TenantTx<'_>,
    action: ActionId,
) -> Result<Option<String>, StoreError> {
    Ok(sqlx::query_scalar("SELECT decision FROM kernel.submission_resolutions WHERE tenant_id = $1 AND action_id = $2")
        .bind(tx.tenant().0).bind(action.0).fetch_optional(tx.conn()).await?)
}

/// Caller holds the destination control-path lock. New ids, contacts, or
/// idempotency keys cannot bypass an uncertain earlier attempt to this address.
pub async fn blocks_destination(
    tx: &mut TenantTx<'_>,
    action: ActionId,
    channel: &str,
    dest: &Fingerprints,
) -> Result<bool, StoreError> {
    Ok(sqlx::query_scalar(
        "SELECT EXISTS (
        SELECT 1 FROM kernel.actions a
        WHERE a.tenant_id = $1 AND a.action_id <> $2 AND a.channel = $3
          AND a.destination_fingerprints && $4
          AND NOT EXISTS (SELECT 1 FROM kernel.submission_resolutions r
              WHERE r.tenant_id = a.tenant_id AND r.action_id = a.action_id)
          AND (a.state = 'reconciliation_required' OR EXISTS (
              SELECT 1 FROM kernel.message_deliveries d
              WHERE d.tenant_id = a.tenant_id AND d.action_id = a.action_id
                AND d.state IN ('submission_started','submission_unknown','delivery_unknown'))))",
    )
    .bind(tx.tenant().0)
    .bind(action.0)
    .bind(channel)
    .bind(&dest.tagged)
    .fetch_one(tx.conn())
    .await?)
}

#[derive(Debug)]
pub struct Snapshot {
    pub operation_digest: Digest,
    pub action_digest: Digest,
    pub delivery: messaging::DeliveryRecord,
}

pub async fn latest_for_destination(
    tx: &mut TenantTx<'_>,
    channel: &str,
    dest: &Fingerprints,
) -> Result<Option<DateTime<Utc>>, StoreError> {
    Ok(sqlx::query_scalar(
        "SELECT max(r.created_at) FROM kernel.submission_resolutions r
        JOIN kernel.actions a ON a.tenant_id = r.tenant_id AND a.action_id = r.action_id
        WHERE r.tenant_id = $1 AND a.channel = $2 AND a.destination_fingerprints && $3",
    )
    .bind(tx.tenant().0)
    .bind(channel)
    .bind(&dest.tagged)
    .fetch_one(tx.conn())
    .await?)
}

/// Locks the action before reading its delivery, just like authenticated
/// callbacks and reconciliation. Decision and provider observation cannot race.
pub async fn snapshot(
    tx: &mut TenantTx<'_>,
    action: ActionId,
    choice: Decision,
) -> Result<Snapshot, StoreError> {
    let pre = actions::get(tx, action).await?;
    if let (Some(ch), Some(dest)) = (pre.channel, pre.destination_fingerprints_set()) {
        messaging::lock_control_path(tx, ch.as_str(), &dest).await?;
    }
    let a = actions::get_for_update(tx, action).await?;
    if a.state != ActionState::ReconciliationRequired || decision(tx, action).await?.is_some() {
        return Err(StoreError::Conflict("no unresolved ambiguous submission"));
    }
    let d = messaging::delivery_for_action(tx, action)
        .await?
        .ok_or(StoreError::NotFound)?;
    if d.provider_message_id.is_none() || Decision::for_state(&d.state) != Some(choice) {
        return Err(StoreError::Conflict(
            "resolution requires matching authoritative provider evidence",
        ));
    }
    // JSON array framing is unambiguous; no attacker-controlled delimiter joins.
    let binding = json!([
        "mk-submission-resolution:v1",
        tx.tenant(),
        action,
        a.digest.to_string(),
        d.delivery_id,
        d.attempt,
        d.provider_message_id,
        d.state,
        choice
    ]);
    Ok(Snapshot {
        operation_digest: Digest::of(binding.to_string().as_bytes()),
        action_digest: a.digest,
        delivery: d,
    })
}

pub async fn record(
    tx: &mut TenantTx<'_>,
    s: &Snapshot,
    choice: Decision,
    user: UserId,
    credential: Uuid,
    now: DateTime<Utc>,
) -> Result<(), StoreError> {
    sqlx::query(
        "INSERT INTO kernel.submission_resolutions
        (tenant_id, action_id, delivery_id, operation_digest, provider_message_id,
         observed_state, decision, resolved_by, credential_row_id, created_at)
        VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10)",
    )
    .bind(tx.tenant().0)
    .bind(s.delivery.action_id.0)
    .bind(s.delivery.delivery_id)
    .bind(s.operation_digest.to_string())
    .bind(&s.delivery.provider_message_id)
    .bind(&s.delivery.state)
    .bind(choice.as_str())
    .bind(user.0)
    .bind(credential)
    .bind(now)
    .execute(tx.conn())
    .await?;
    audit::append_event(
        tx,
        NewEvent {
            tenant_id: tx.tenant(),
            occurred_at: now,
            actor_type: ActorType::User,
            actor_id: &user.to_string(),
            action_id: Some(s.delivery.action_id),
            event_type: EventType::DeliveryEvent,
            payload_redacted: json!({"kind":"human_submission_resolution", "decision":choice,
            "operation_digest":s.operation_digest.to_string(), "observed_state":s.delivery.state,
            "delivery_id":s.delivery.delivery_id,"credential_row_id":credential}),
            trace_id: None,
            policy_version: mk_policy::POLICY_VERSION.0,
        },
    )
    .await?;
    Ok(())
}
