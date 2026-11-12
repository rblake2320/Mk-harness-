//! Subject erasure (contract S13), kernel side.
//!
//! The application erases its own copies and sends the kernel the subject's
//! destination hashes and the action ids it linked. In ONE tenant transaction
//! the kernel:
//!   1. refuses while any matching action is being dispatched (409 — the app
//!      retries; content of a send in flight is never torn out from under it);
//!   2. cancels every matching action that has not reached a terminal state
//!      (normal state machine + audit — nothing about the subject is sent later);
//!   3. replaces the message content of every matching action's canonical
//!      request (`arguments`, `evidence`) with an erased marker, keeping ids,
//!      states, digests and destination hashes (content-free; the audit chain
//!      still verifies — it never covered the plaintext);
//!   4. empties inbound bodies received from those destinations;
//!   5. queues provider-held copies (outbound and inbound message ids) for
//!      deletion through the provider's API (worker);
//!   6. appends one content-free `SubjectErased` audit event.
//!
//! Idempotent per `request_ref`: a repeat returns the first result unchanged.

use chrono::{DateTime, Utc};
use mk_audit::{ActorType, EventType, NewEvent};
use mk_domain::{ActionId, ActionState, Transition, UserId};
use serde::Serialize;
use serde_json::json;
use sqlx::Row;
use uuid::Uuid;

use crate::actions::{self, Actor};
use crate::audit::append_event;
use crate::error::StoreError;
use crate::tx::TenantTx;

pub const MAX_HASHES: usize = 64;
pub const MAX_ACTIONS: usize = 2000;

#[derive(Debug, Clone, Serialize, PartialEq, Eq)]
pub struct ErasureResult {
    pub erasure_id: Uuid,
    pub request_ref: String,
    pub destination_hashes: i32,
    pub actions_erased: i32,
    pub actions_cancelled: i32,
    pub inbound_erased: i32,
    pub provider_copies: i32,
    pub replayed: bool,
}

#[derive(Debug, thiserror::Error)]
pub enum ErasureError {
    #[error("{0} matching action(s) are being dispatched; retry after they finish")]
    InFlight(usize),
    #[error(transparent)]
    Store(#[from] StoreError),
}

impl From<sqlx::Error> for ErasureError {
    fn from(e: sqlx::Error) -> Self {
        Self::Store(StoreError::from(e))
    }
}

async fn existing(
    tx: &mut TenantTx<'_>,
    request_ref: &str,
) -> Result<Option<ErasureResult>, StoreError> {
    let r = sqlx::query(
        "SELECT erasure_id, destination_hashes, actions_erased, actions_cancelled, inbound_erased, provider_copies
         FROM kernel.subject_erasures WHERE tenant_id = $1 AND request_ref = $2",
    )
    .bind(tx.tenant().0)
    .bind(request_ref)
    .fetch_optional(tx.conn())
    .await?;
    r.map(|r| -> Result<ErasureResult, StoreError> {
        Ok(ErasureResult {
            erasure_id: r.try_get("erasure_id")?,
            request_ref: request_ref.to_owned(),
            destination_hashes: r.try_get("destination_hashes")?,
            actions_erased: r.try_get("actions_erased")?,
            actions_cancelled: r.try_get("actions_cancelled")?,
            inbound_erased: r.try_get("inbound_erased")?,
            provider_copies: r.try_get("provider_copies")?,
            replayed: true,
        })
    })
    .transpose()
}

pub async fn erase_subject(
    tx: &mut TenantTx<'_>,
    request_ref: &str,
    by: UserId,
    hashes: &[String],
    action_ids: &[Uuid],
    now: DateTime<Utc>,
) -> Result<ErasureResult, ErasureError> {
    if let Some(prev) = existing(tx, request_ref).await? {
        return Ok(prev);
    }
    let tenant = tx.tenant();
    // Every action addressed to the subject, by link or by destination (current or
    // pre-rotation fingerprint tag), locked for the rest of the transaction.
    let rows = sqlx::query(
        "SELECT action_id, state FROM kernel.actions
         WHERE tenant_id = $1 AND (action_id = ANY($2) OR destination_hash = ANY($3)
                                   OR destination_fingerprints && $3)
         ORDER BY action_id FOR UPDATE",
    )
    .bind(tenant.0)
    .bind(action_ids)
    .bind(hashes)
    .fetch_all(tx.conn())
    .await?;
    let mut states = Vec::with_capacity(rows.len());
    for r in &rows {
        let id: Uuid = r.try_get("action_id")?;
        let s: String = r.try_get("state")?;
        let st = ActionState::parse(&s).map_err(|_| StoreError::Corrupt("state"))?;
        states.push((ActionId::from_uuid(id), st));
    }
    // A send already handed to a transport is in flight even where the state machine
    // would allow `Cancel` (it does from Dispatching): cancelling it would record a
    // message the provider may already have delivered as "cancelled".
    let in_flight = states
        .iter()
        .filter(|(_, s)| {
            *s == ActionState::Dispatching
                || (!s.is_terminal() && s.apply(Transition::Cancel).is_err())
        })
        .count();
    if in_flight > 0 {
        return Err(ErasureError::InFlight(in_flight));
    }
    let actor_id = by.to_string();
    let actor = Actor {
        actor_type: ActorType::User,
        actor_id: &actor_id,
        trace_id: None,
        policy_version: mk_policy::POLICY_VERSION.0,
    };
    let mut cancelled = 0i32;
    for (id, s) in &states {
        if !s.is_terminal() {
            actions::transition(
                tx,
                *id,
                Transition::Cancel,
                Some("subject_erased"),
                actor,
                now,
            )
            .await?;
            cancelled += 1;
        }
    }
    let ids: Vec<Uuid> = states.iter().map(|(id, _)| id.0).collect();
    let erased = sqlx::query(
        "UPDATE kernel.actions
            SET canonical_request = convert_to(
                  jsonb_set(jsonb_set(convert_from(canonical_request, 'UTF8')::jsonb,
                                      '{arguments}', '{\"erased\": true}'::jsonb),
                            '{evidence}', '[]'::jsonb)::text, 'UTF8'),
                erased_at = $3, updated_at = $3
          WHERE tenant_id = $1 AND action_id = ANY($2) AND erased_at IS NULL",
    )
    .bind(tenant.0)
    .bind(&ids)
    .bind(now)
    .execute(tx.conn())
    .await?
    .rows_affected();
    let inbound = sqlx::query(
        "UPDATE kernel.inbound_events
            SET content_sealed = '\\x'::bytea, destination_sealed = NULL, erased_at = $3
          WHERE tenant_id = $1 AND (source_destination_hash = ANY($2) OR destination_fingerprints && $2)
            AND erased_at IS NULL
          RETURNING sender_identity_id, provider, provider_event_id",
    )
    .bind(tenant.0)
    .bind(hashes)
    .bind(now)
    .fetch_all(tx.conn())
    .await?;
    // Permission to contact this subject ends with the erasure; the minimal record
    // (proof digest, scope, times) stays, the sealed raw destination does not.
    let permissions = sqlx::query(
        "UPDATE kernel.contact_permissions
            SET status = CASE WHEN status = 'granted' THEN 'revoked' ELSE status END,
                revoked_at = COALESCE(revoked_at, $3), destination_sealed = NULL
          WHERE tenant_id = $1 AND (destination_hash = ANY($2) OR destination_fingerprints && $2)
            AND (status = 'granted' OR destination_sealed IS NOT NULL)",
    )
    .bind(tenant.0)
    .bind(hashes)
    .bind(now)
    .execute(tx.conn())
    .await?
    .rows_affected();
    let erasure_id: Uuid = Uuid::new_v4();
    // Provider copies: every outbound message id of the erased actions and every
    // inbound message id from the subject's destinations.
    let outbound = sqlx::query(
        "SELECT sender_identity_id, provider, provider_message_id FROM kernel.message_deliveries
          WHERE tenant_id = $1 AND action_id = ANY($2) AND provider_message_id IS NOT NULL",
    )
    .bind(tenant.0)
    .bind(&ids)
    .fetch_all(tx.conn())
    .await?;
    let mut copies: Vec<(Uuid, String, String, &'static str)> = Vec::new();
    for r in &outbound {
        copies.push((
            r.try_get("sender_identity_id")?,
            r.try_get("provider")?,
            r.try_get("provider_message_id")?,
            "outbound",
        ));
    }
    for r in &inbound {
        copies.push((
            r.try_get("sender_identity_id")?,
            r.try_get("provider")?,
            r.try_get("provider_event_id")?,
            "inbound",
        ));
    }
    let result = ErasureResult {
        erasure_id,
        request_ref: request_ref.to_owned(),
        destination_hashes: i32::try_from(hashes.len()).unwrap_or(i32::MAX),
        actions_erased: i32::try_from(erased).unwrap_or(i32::MAX),
        actions_cancelled: cancelled,
        inbound_erased: i32::try_from(inbound.len()).unwrap_or(i32::MAX),
        provider_copies: i32::try_from(copies.len()).unwrap_or(i32::MAX),
        replayed: false,
    };
    sqlx::query(
        "INSERT INTO kernel.subject_erasures (erasure_id, tenant_id, request_ref, requested_by, destination_hashes,
            actions_erased, actions_cancelled, inbound_erased, provider_copies, created_at)
         VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10)",
    )
    .bind(erasure_id)
    .bind(tenant.0)
    .bind(request_ref)
    .bind(by.0)
    .bind(result.destination_hashes)
    .bind(result.actions_erased)
    .bind(result.actions_cancelled)
    .bind(result.inbound_erased)
    .bind(result.provider_copies)
    .bind(now)
    .execute(tx.conn())
    .await?;
    for (sender, provider, msid, direction) in copies {
        sqlx::query(
            "INSERT INTO kernel.provider_erasures (tenant_id, erasure_id, sender_identity_id, provider,
                provider_message_id, direction, next_attempt_at)
             VALUES ($1,$2,$3,$4,$5,$6,$7) ON CONFLICT (tenant_id, provider, provider_message_id) DO NOTHING",
        )
        .bind(tenant.0)
        .bind(erasure_id)
        .bind(sender)
        .bind(provider)
        .bind(msid)
        .bind(direction)
        .bind(now)
        .execute(tx.conn())
        .await?;
    }
    append_event(
        tx,
        NewEvent {
            tenant_id: tenant,
            occurred_at: now,
            actor_type: ActorType::User,
            actor_id: &actor_id,
            action_id: None,
            event_type: EventType::SubjectErased,
            payload_redacted: json!({
                "erasure_id": erasure_id, "destination_hashes": result.destination_hashes,
                "actions_erased": result.actions_erased, "actions_cancelled": cancelled,
                "inbound_erased": result.inbound_erased, "provider_copies": result.provider_copies,
                "permissions_closed": permissions,
            }),
            trace_id: None,
            policy_version: mk_policy::POLICY_VERSION.0,
        },
    )
    .await?;
    Ok(result)
}

/// True when the action's content was erased; replay must refuse it.
#[must_use]
pub fn is_erased_request(req: &mk_contracts::action::ActionRequest) -> bool {
    req.arguments.get("erased") == Some(&serde_json::Value::Bool(true))
}
