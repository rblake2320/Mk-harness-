//! Action rows and the only path that changes an action's state.

use chrono::{DateTime, Utc};
use mk_audit::{ActorType, EventType, NewEvent};
use mk_contracts::{ACTION_SCHEMA_VERSION, ActionRequest, ActionResult, Receipt};
use mk_crypto::Digest;
use mk_domain::{ActionId, ActionState, Channel, TenantId, Transition};
use serde_json::json;
use sqlx::Row;

use crate::audit::append_event;
use crate::error::StoreError;
use crate::tx::TenantTx;

#[derive(Debug, Clone)]
pub struct StoredAction {
    pub action_id: ActionId,
    pub tenant_id: TenantId,
    pub state: ActionState,
    pub request: ActionRequest,
    pub digest: Digest,
    pub channel: Option<Channel>,
    pub destination_hash: Option<String>,
    /// `kid:hex` fingerprints of the destination under every key configured
    /// at proposal (plus any added by `fingerprint-rekey`).
    pub destination_fingerprints: Vec<String>,
    pub attempt: i32,
    pub error_code: Option<String>,
    pub replay_of: Option<ActionId>,
    pub expires_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
}

impl StoredAction {
    /// The destination's fingerprint set as stored at proposal (and extended
    /// by rekey). `None` when the action carries no destination.
    #[must_use]
    pub fn destination_fingerprints_set(&self) -> Option<crate::fingerprint::Fingerprints> {
        let primary = self.destination_hash.as_deref()?;
        Some(if self.channel.is_some() {
            crate::fingerprint::Fingerprints::stored(primary, self.destination_fingerprints.clone())
        } else {
            crate::fingerprint::Fingerprints {
                primary: primary.to_owned(),
                tagged: self.destination_fingerprints.clone(),
            }
        })
    }

    #[must_use]
    pub fn to_result(&self, receipt: Option<Receipt>) -> ActionResult {
        ActionResult {
            schema_version: ACTION_SCHEMA_VERSION.into(),
            action_id: self.action_id,
            tenant_id: self.tenant_id,
            state: self.state,
            action_digest: self.digest.clone(),
            attempt: u32::try_from(self.attempt).unwrap_or(0),
            error_code: self.error_code.clone(),
            receipt,
            replay_of: self.replay_of,
            updated_at: self.updated_at,
            // Message-lifecycle vocabulary (contract C3). Customer-message kinds
            // always carry it; a delivery record refines it via `with_delivery`.
            message_state: self
                .request
                .action_kind
                .is_outreach()
                .then(|| mk_contracts::MessageState::derive(self.state, None)),
            read_status: self
                .request
                .action_kind
                .is_outreach()
                .then(|| "unknown".to_owned()),
            provider_message_id: None,
        }
    }
}

/// Who is performing a transition, for the audit record.
#[derive(Debug, Clone, Copy)]
pub struct Actor<'a> {
    pub actor_type: ActorType,
    pub actor_id: &'a str,
    pub trace_id: Option<&'a str>,
    pub policy_version: &'a str,
}

/// Insert a bound request in `Draft` and emit `ActionProposed`. The caller
/// must already have bound `tenant_id`/`requested_by`/`action_id`.
pub async fn insert_draft(
    tx: &mut TenantTx<'_>,
    req: &ActionRequest,
    channel: Option<Channel>,
    destination: Option<&crate::fingerprint::Fingerprints>,
    actor: Actor<'_>,
    now: DateTime<Utc>,
) -> Result<StoredAction, StoreError> {
    tx.assert_tenant(req.tenant_id)?;
    let action_id = req
        .action_id
        .ok_or(StoreError::Corrupt("unbound action_id"))?;
    let canonical = req.canonical_bytes()?;
    let digest = Digest::of(&canonical);
    sqlx::query(
        "INSERT INTO kernel.actions (action_id, tenant_id, requested_by, origin_type, workflow, action_kind, tool_id,
           resource_type, resource_id, channel, purpose, risk, state, canonical_request, action_digest, destination_hash,
           idempotency_key, requested_at, expires_at, created_at, updated_at, destination_fingerprints)
         VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14,$15,$16,$17,$18,$19,$20,$20,$21)",
    )
    .bind(action_id.0)
    .bind(req.tenant_id.0)
    .bind(req.requested_by.0)
    .bind(plain(&req.origin.origin_type))
    .bind(plain(&req.workflow))
    .bind(plain(&req.action_kind))
    .bind(&req.tool_id)
    .bind(plain(&req.resource.resource_type))
    .bind(&req.resource.id)
    .bind(channel.map(Channel::as_str))
    .bind(&req.purpose)
    .bind(plain(&req.risk))
    .bind(ActionState::Draft.as_str())
    .bind(&canonical)
    .bind(digest.to_string())
    .bind(destination.map(|d| d.primary.as_str()))
    .bind(&req.idempotency_key)
    .bind(req.requested_at)
    .bind(req.expires_at)
    .bind(now)
    .bind(destination.map_or_else(Vec::new, |d| d.tagged.clone()))
    .execute(tx.conn())
    .await?;
    append_event(
        tx,
        NewEvent {
            tenant_id: req.tenant_id,
            occurred_at: now,
            actor_type: actor.actor_type,
            actor_id: actor.actor_id,
            action_id: Some(action_id),
            event_type: EventType::ActionProposed,
            payload_redacted: json!({
                "workflow": req.workflow, "action_kind": req.action_kind, "tool_id": req.tool_id,
                "risk": req.risk, "origin_type": req.origin.origin_type, "action_digest": digest.to_string(),
                "resource_type": req.resource.resource_type, "evidence_count": req.evidence.len(),
            }),
            trace_id: actor.trace_id,
            policy_version: actor.policy_version,
        },
    )
    .await?;
    get_for_update(tx, action_id).await
}

fn plain<T: serde::Serialize>(v: &T) -> String {
    serde_json::to_value(v)
        .ok()
        .and_then(|j| j.as_str().map(str::to_owned))
        .unwrap_or_default()
}

fn row_to_action(tenant: TenantId, r: &sqlx::postgres::PgRow) -> Result<StoredAction, StoreError> {
    let canonical: Vec<u8> = r.try_get("canonical_request")?;
    let request: ActionRequest =
        serde_json::from_slice(&canonical).map_err(|_| StoreError::Corrupt("canonical_request"))?;
    let digest: Digest = r
        .try_get::<String, _>("action_digest")?
        .parse()
        .map_err(|_| StoreError::Corrupt("action_digest"))?;
    let channel = r
        .try_get::<Option<String>, _>("channel")?
        .map(|c| serde_json::from_value(serde_json::Value::String(c)))
        .transpose()
        .map_err(|_| StoreError::Corrupt("channel"))?;
    Ok(StoredAction {
        action_id: ActionId::from_uuid(r.try_get("action_id")?),
        tenant_id: tenant,
        state: ActionState::parse(r.try_get::<String, _>("state")?.as_str())
            .map_err(|_| StoreError::Corrupt("state"))?,
        request,
        digest,
        channel,
        destination_hash: r.try_get("destination_hash")?,
        destination_fingerprints: r.try_get("destination_fingerprints")?,
        attempt: r.try_get("attempt")?,
        error_code: r.try_get("error_code")?,
        replay_of: r
            .try_get::<Option<uuid::Uuid>, _>("replay_of")?
            .map(ActionId::from_uuid),
        expires_at: r.try_get("expires_at")?,
        updated_at: r.try_get("updated_at")?,
    })
}

const SELECT: &str = "SELECT action_id, state, canonical_request, action_digest, channel, destination_hash, destination_fingerprints, attempt,
    error_code, replay_of, expires_at, updated_at FROM kernel.actions WHERE tenant_id = $1 AND action_id = $2";

pub async fn get(tx: &mut TenantTx<'_>, action_id: ActionId) -> Result<StoredAction, StoreError> {
    let tenant = tx.tenant();
    let r = sqlx::query(SELECT)
        .bind(tenant.0)
        .bind(action_id.0)
        .fetch_optional(tx.conn())
        .await?
        .ok_or(StoreError::NotFound)?;
    row_to_action(tenant, &r)
}

/// Lock the row for the rest of the transaction.
pub async fn get_for_update(
    tx: &mut TenantTx<'_>,
    action_id: ActionId,
) -> Result<StoredAction, StoreError> {
    let tenant = tx.tenant();
    let q = format!("{SELECT} FOR UPDATE");
    let r = sqlx::query(sqlx::AssertSqlSafe(q))
        .bind(tenant.0)
        .bind(action_id.0)
        .fetch_optional(tx.conn())
        .await?
        .ok_or(StoreError::NotFound)?;
    row_to_action(tenant, &r)
}

/// Apply a transition atomically: lock, run the domain state machine,
/// persist, and append a `StateTransition` audit event in the same
/// transaction. The only function in the codebase that writes `state`.
pub async fn transition(
    tx: &mut TenantTx<'_>,
    action_id: ActionId,
    t: Transition,
    error_code: Option<&str>,
    actor: Actor<'_>,
    now: DateTime<Utc>,
) -> Result<StoredAction, StoreError> {
    let current = get_for_update(tx, action_id).await?;
    let next = current.state.apply(t)?;
    let attempt_delta = i32::from(matches!(t, Transition::StartDispatch));
    sqlx::query(
        "UPDATE kernel.actions SET state = $3, error_code = COALESCE($4, error_code), attempt = attempt + $5, updated_at = $6
         WHERE tenant_id = $1 AND action_id = $2",
    )
    .bind(tx.tenant().0)
    .bind(action_id.0)
    .bind(next.as_str())
    .bind(error_code)
    .bind(attempt_delta)
    .bind(now)
    .execute(tx.conn())
    .await?;
    append_event(
        tx,
        NewEvent {
            tenant_id: tx.tenant(),
            occurred_at: now,
            actor_type: actor.actor_type,
            actor_id: actor.actor_id,
            action_id: Some(action_id),
            event_type: EventType::StateTransition,
            payload_redacted: json!({
                "from": current.state, "to": next, "transition": t, "error_code": error_code,
                "attempt": current.attempt + attempt_delta,
            }),
            trace_id: actor.trace_id,
            policy_version: actor.policy_version,
        },
    )
    .await?;
    get(tx, action_id).await
}

/// Transaction-scoped advisory lock on `(tenant, contact, channel)`. Held
/// until commit/rollback; makes the frequency count + `StartDispatch` of
/// concurrent workers serialize for one contact without blocking others.
pub async fn lock_contact_channel(
    tx: &mut TenantTx<'_>,
    resource_id: &str,
    channel: Channel,
) -> Result<(), StoreError> {
    sqlx::query("SELECT pg_advisory_xact_lock(hashtextextended($1, 0))")
        .bind(format!(
            "{}|{resource_id}|{}",
            tx.tenant().0,
            channel.as_str()
        ))
        .execute(tx.conn())
        .await?;
    Ok(())
}

/// Count outreach actions dispatched to a contact over a channel in the last
/// 24h (frequency limit input).
pub async fn sends_last_24h(
    tx: &mut TenantTx<'_>,
    resource_id: &str,
    channel: Channel,
    now: DateTime<Utc>,
) -> Result<u32, StoreError> {
    let r = sqlx::query(
        "SELECT count(*) AS n FROM kernel.actions WHERE tenant_id = $1 AND resource_id = $2 AND channel = $3
         AND state IN ('dispatching','completed','reconciliation_required') AND updated_at > $4 - interval '24 hours'",
    )
    .bind(tx.tenant().0)
    .bind(resource_id)
    .bind(channel.as_str())
    .bind(now)
    .fetch_one(tx.conn())
    .await?;
    let n: i64 = r.try_get("n")?;
    Ok(u32::try_from(n).unwrap_or(u32::MAX))
}

/// Create a replay: a *new* action linked to a terminal original. The
/// original is untouched.
pub async fn insert_replay(
    tx: &mut TenantTx<'_>,
    original: &StoredAction,
    new_id: ActionId,
    actor: Actor<'_>,
    now: DateTime<Utc>,
) -> Result<StoredAction, StoreError> {
    if !original.state.is_terminal() {
        return Err(StoreError::Conflict("replay requires a terminal original"));
    }
    if original.state == ActionState::ReconciliationRequired
        && crate::resolutions::decision(tx, original.action_id)
            .await?
            .as_deref()
            != Some("replacement_permitted")
    {
        return Err(StoreError::Conflict(
            "replay requires a passkey resolution permitting replacement",
        ));
    }
    let mut req = original.request.clone();
    req.action_id = Some(new_id);
    req.idempotency_key = format!("{}:replay:{}", req.idempotency_key, new_id);
    req.requested_at = now;
    req.expires_at = now + (original.request.expires_at - original.request.requested_at);
    let stored = insert_draft(
        tx,
        &req,
        original.channel,
        original.destination_fingerprints_set().as_ref(),
        actor,
        now,
    )
    .await?;
    sqlx::query("UPDATE kernel.actions SET replay_of = $3 WHERE tenant_id = $1 AND action_id = $2")
        .bind(tx.tenant().0)
        .bind(new_id.0)
        .bind(original.action_id.0)
        .execute(tx.conn())
        .await?;
    append_event(
        tx,
        NewEvent {
            tenant_id: tx.tenant(),
            occurred_at: now,
            actor_type: actor.actor_type,
            actor_id: actor.actor_id,
            action_id: Some(new_id),
            event_type: EventType::Replayed,
            payload_redacted: json!({"replay_of": original.action_id}),
            trace_id: actor.trace_id,
            policy_version: actor.policy_version,
        },
    )
    .await?;
    get(tx, stored.action_id).await
}

/// Actions still waiting that have passed `expires_at`.
pub async fn expired_candidates(
    tx: &mut TenantTx<'_>,
    now: DateTime<Utc>,
    limit: i64,
) -> Result<Vec<ActionId>, StoreError> {
    let rows = sqlx::query(
        "SELECT action_id FROM kernel.actions WHERE tenant_id = $1 AND expires_at <= $2
         AND state IN ('policy_pending','approval_required','approved','queued','failed_retryable') LIMIT $3",
    )
    .bind(tx.tenant().0)
    .bind(now)
    .bind(limit)
    .fetch_all(tx.conn())
    .await?;
    rows.into_iter()
        .map(|r| Ok(ActionId::from_uuid(r.try_get("action_id")?)))
        .collect()
}

/// Not-yet-dispatched outreach actions matching a destination/channel, for
/// suppression-on-revoke.
pub async fn pending_for_destination(
    tx: &mut TenantTx<'_>,
    channel: Option<Channel>,
    destination: Option<&crate::fingerprint::Fingerprints>,
) -> Result<Vec<ActionId>, StoreError> {
    let rows = sqlx::query(
        "SELECT action_id FROM kernel.actions WHERE tenant_id = $1
         AND ($2::text IS NULL OR channel = $2) AND ($3::text[] IS NULL OR destination_fingerprints && $3)
         AND state IN ('policy_pending','approval_required','approved','queued','failed_retryable')",
    )
    .bind(tx.tenant().0)
    .bind(channel.map(Channel::as_str))
    .bind(destination.map(|d| d.tagged.clone()))
    .fetch_all(tx.conn())
    .await?;
    rows.into_iter()
        .map(|r| Ok(ActionId::from_uuid(r.try_get("action_id")?)))
        .collect()
}
