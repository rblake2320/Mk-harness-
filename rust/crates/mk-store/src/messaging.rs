//! Provider messaging records (WP07): sender identities, delivery records with
//! monotonic provider evidence, inbound events, inbound health, and the
//! serialized customer/channel control path.

use chrono::{DateTime, Utc};
use mk_audit::{ActorType, EventType, NewEvent};
use mk_crypto::{Digest, Keyring};
use mk_domain::{ActionId, TenantId, UserId};
use secrecy::{ExposeSecret as _, SecretString};
use serde::Serialize;
use serde_json::json;
use sqlx::{PgPool, Row};
use uuid::Uuid;

use crate::audit::append_event;
use crate::error::StoreError;
use crate::tx::TenantTx;

/// Inbound health older than this pauses the tenant's outbound dispatch (C8).
pub const INBOUND_STALE_SECS: i64 = 60;

// ------------------------------------------------------------- control path

/// The one serialized control path per (tenant, channel, destination) (C6).
/// Both dispatch authorization and suppression recording take this lock inside
/// their transaction, so whichever commits first is visible to the other's
/// re-check. Transaction-scoped: released at commit/rollback.
pub async fn lock_control_path(
    tx: &mut TenantTx<'_>,
    channel: &str,
    destination_hash: &str,
) -> Result<(), StoreError> {
    // hashtext() → int4; two int4 keys keep tenant and destination separate.
    sqlx::query("SELECT pg_advisory_xact_lock(hashtext($1), hashtext($2))")
        .bind(tx.tenant().0.to_string())
        .bind(format!("{channel}|{destination_hash}"))
        .execute(tx.conn())
        .await?;
    Ok(())
}

// ------------------------------------------------------------ sender identity

#[derive(Debug, Clone, Serialize)]
pub struct SenderIdentityView {
    pub sender_identity_id: Uuid,
    pub owner_user_id: UserId,
    pub provider: String,
    pub display_name: String,
    pub account_sid_redacted: String,
    pub from_number: Option<String>,
    pub messaging_service_sid: Option<String>,
    pub registration_status: String,
    pub status: String,
    pub created_at: DateTime<Utc>,
}

/// Secret-bearing form, for the worker and webhook verifier only.
pub struct SenderIdentitySecret {
    pub sender_identity_id: Uuid,
    pub tenant_id: TenantId,
    pub owner_user_id: UserId,
    pub account_sid: String,
    pub auth_token: SecretString,
    pub from_number: Option<String>,
    pub messaging_service_sid: Option<String>,
    pub status: String,
}

impl std::fmt::Debug for SenderIdentitySecret {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "SenderIdentitySecret(id={})", self.sender_identity_id)
    }
}

fn aad(tenant: TenantId, id: Uuid) -> String {
    format!("sender:{}:{}", tenant.0, id)
}

#[allow(clippy::too_many_arguments)]
pub async fn register_sender(
    tx: &mut TenantTx<'_>,
    keyring: &Keyring,
    owner: UserId,
    display_name: &str,
    account_sid: &str,
    auth_token: &SecretString,
    from_number: Option<&str>,
    messaging_service_sid: Option<&str>,
    by: UserId,
    now: DateTime<Utc>,
) -> Result<Uuid, StoreError> {
    let id = Uuid::now_v7();
    let sealed = keyring
        .seal(&aad(tx.tenant(), id), auth_token)
        .map_err(|_| StoreError::Crypto)?;
    sqlx::query(
        "INSERT INTO kernel.sender_identities (sender_identity_id, tenant_id, owner_user_id, provider, display_name, account_sid,
           auth_token_sealed, from_number, messaging_service_sid, created_at, updated_at)
         VALUES ($1,$2,$3,'twilio',$4,$5,$6,$7,$8,$9,$9)",
    )
    .bind(id)
    .bind(tx.tenant().0)
    .bind(owner.0)
    .bind(display_name)
    .bind(account_sid)
    .bind(sealed)
    .bind(from_number)
    .bind(messaging_service_sid)
    .bind(now)
    .execute(tx.conn())
    .await
    .map_err(|e| match StoreError::from(e) {
        StoreError::Conflict(_) => StoreError::Conflict("sender number already registered to a business"),
        o => o,
    })?;
    append_event(
        tx,
        NewEvent {
            tenant_id: tx.tenant(),
            occurred_at: now,
            actor_type: ActorType::User,
            actor_id: &by.to_string(),
            action_id: None,
            event_type: EventType::SenderIdentityRegistered,
            payload_redacted: json!({"sender_identity_id": id, "owner_user_id": owner, "provider": "twilio",
                                     "has_number": from_number.is_some(), "has_messaging_service": messaging_service_sid.is_some()}),
            trace_id: None,
            policy_version: mk_policy::POLICY_VERSION.0,
        },
    )
    .await?;
    Ok(id)
}

pub async fn set_registration_status(
    tx: &mut TenantTx<'_>,
    id: Uuid,
    status: &str,
    reference: &str,
    by: UserId,
    now: DateTime<Utc>,
) -> Result<(), StoreError> {
    let res = sqlx::query(
        "UPDATE kernel.sender_identities SET registration_status = $3, registration_ref = $4, version = version + 1, updated_at = $5
         WHERE tenant_id = $1 AND sender_identity_id = $2",
    )
    .bind(tx.tenant().0)
    .bind(id)
    .bind(status)
    .bind(reference)
    .bind(now)
    .execute(tx.conn())
    .await?;
    if res.rows_affected() == 0 {
        return Err(StoreError::NotFound);
    }
    append_event(
        tx,
        NewEvent {
            tenant_id: tx.tenant(),
            occurred_at: now,
            actor_type: ActorType::User,
            actor_id: &by.to_string(),
            action_id: None,
            event_type: EventType::SenderIdentityUpdated,
            payload_redacted: json!({"sender_identity_id": id, "registration_status": status}),
            trace_id: None,
            policy_version: mk_policy::POLICY_VERSION.0,
        },
    )
    .await?;
    Ok(())
}

pub async fn list_senders(tx: &mut TenantTx<'_>) -> Result<Vec<SenderIdentityView>, StoreError> {
    let rows = sqlx::query(
        "SELECT sender_identity_id, owner_user_id, provider, display_name, account_sid, from_number, messaging_service_sid,
                registration_status, status, created_at
         FROM kernel.sender_identities WHERE tenant_id = $1 ORDER BY created_at",
    )
    .bind(tx.tenant().0)
    .fetch_all(tx.conn())
    .await?;
    rows.iter()
        .map(|r| {
            let sid: String = r.try_get("account_sid")?;
            Ok(SenderIdentityView {
                sender_identity_id: r.try_get("sender_identity_id")?,
                owner_user_id: UserId::from_uuid(r.try_get("owner_user_id")?),
                provider: r.try_get("provider")?,
                display_name: r.try_get("display_name")?,
                account_sid_redacted: format!("{}…{}", &sid[..4], &sid[sid.len() - 4..]),
                from_number: r.try_get("from_number")?,
                messaging_service_sid: r.try_get("messaging_service_sid")?,
                registration_status: r.try_get("registration_status")?,
                status: r.try_get("status")?,
                created_at: r.try_get("created_at")?,
            })
        })
        .collect()
}

/// Pool-level (pre-tenant) lookup used by webhooks to bind a URL path to a
/// tenant. Returns the sealed secret; the caller unseals with the master key.
pub async fn sender_secret_by_id(
    pool: &PgPool,
    keyring: &Keyring,
    id: Uuid,
) -> Result<SenderIdentitySecret, StoreError> {
    let r = sqlx::query(
        "SELECT tenant_id, owner_user_id, account_sid, auth_token_sealed, from_number, messaging_service_sid, status
         FROM kernel.sender_identities WHERE sender_identity_id = $1",
    )
    .bind(id)
    .fetch_optional(pool)
    .await?
    .ok_or(StoreError::NotFound)?;
    let tenant = TenantId::from_uuid(r.try_get("tenant_id")?);
    let sealed: Vec<u8> = r.try_get("auth_token_sealed")?;
    let auth_token = keyring
        .unseal(&aad(tenant, id), &sealed)
        .map_err(|_| StoreError::Crypto)?;
    Ok(SenderIdentitySecret {
        sender_identity_id: id,
        tenant_id: tenant,
        owner_user_id: UserId::from_uuid(r.try_get("owner_user_id")?),
        account_sid: r.try_get("account_sid")?,
        auth_token,
        from_number: r.try_get("from_number")?,
        messaging_service_sid: r.try_get("messaging_service_sid")?,
        status: r.try_get("status")?,
    })
}

/// Tenant-scoped secret lookup for the worker's sender resolver.
pub async fn sender_secret(
    tx: &mut TenantTx<'_>,
    keyring: &Keyring,
    id: Uuid,
) -> Result<SenderIdentitySecret, StoreError> {
    let r = sqlx::query(
        "SELECT owner_user_id, account_sid, auth_token_sealed, from_number, messaging_service_sid, status
         FROM kernel.sender_identities WHERE tenant_id = $1 AND sender_identity_id = $2 AND status = 'active'",
    )
    .bind(tx.tenant().0)
    .bind(id)
    .fetch_optional(tx.conn())
    .await?
    .ok_or(StoreError::NotFound)?;
    let sealed: Vec<u8> = r.try_get("auth_token_sealed")?;
    let auth_token = keyring
        .unseal(&aad(tx.tenant(), id), &sealed)
        .map_err(|_| StoreError::Crypto)?;
    Ok(SenderIdentitySecret {
        sender_identity_id: id,
        tenant_id: tx.tenant(),
        owner_user_id: UserId::from_uuid(r.try_get("owner_user_id")?),
        account_sid: r.try_get("account_sid")?,
        auth_token,
        from_number: r.try_get("from_number")?,
        messaging_service_sid: r.try_get("messaging_service_sid")?,
        status: r.try_get("status")?,
    })
}

// ------------------------------------------------------------ deliveries

#[derive(Debug, Clone, Serialize)]
pub struct DeliveryRecord {
    pub delivery_id: Uuid,
    pub action_id: ActionId,
    pub attempt: i32,
    pub sender_identity_id: Uuid,
    pub provider_message_id: Option<String>,
    pub state: String,
    pub provider_error_code: Option<String>,
    pub read_status: String,
    pub submission_started_at: DateTime<Utc>,
    pub last_event_at: Option<DateTime<Utc>>,
    pub reconciled_at: Option<DateTime<Utc>>,
}

fn row_to_delivery(r: &sqlx::postgres::PgRow) -> Result<DeliveryRecord, StoreError> {
    Ok(DeliveryRecord {
        delivery_id: r.try_get("delivery_id")?,
        action_id: ActionId::from_uuid(r.try_get("action_id")?),
        attempt: r.try_get("attempt")?,
        sender_identity_id: r.try_get("sender_identity_id")?,
        provider_message_id: r.try_get("provider_message_id")?,
        state: r.try_get("state")?,
        provider_error_code: r.try_get("provider_error_code")?,
        read_status: r.try_get("read_status")?,
        submission_started_at: r.try_get("submission_started_at")?,
        last_event_at: r.try_get("last_event_at")?,
        reconciled_at: r.try_get("reconciled_at")?,
    })
}

const DCOLS: &str = "delivery_id, action_id, attempt, sender_identity_id, provider_message_id, state, provider_error_code, read_status, submission_started_at, last_event_at, reconciled_at";

/// Record that submission is starting (C4 step 3), *before* the provider
/// request. Idempotent per (action, attempt).
pub async fn record_submission_started(
    tx: &mut TenantTx<'_>,
    action_id: ActionId,
    attempt: i32,
    sender_identity_id: Uuid,
    now: DateTime<Utc>,
) -> Result<Uuid, StoreError> {
    let id: Uuid = sqlx::query_scalar(
        "INSERT INTO kernel.message_deliveries (tenant_id, action_id, attempt, sender_identity_id, provider, state, submission_started_at, created_at, updated_at)
         VALUES ($1,$2,$3,$4,'twilio','submission_started',$5,$5,$5)
         ON CONFLICT (tenant_id, action_id, attempt) DO UPDATE SET updated_at = EXCLUDED.updated_at
         RETURNING delivery_id",
    )
    .bind(tx.tenant().0)
    .bind(action_id.0)
    .bind(attempt)
    .bind(sender_identity_id)
    .bind(now)
    .fetch_one(tx.conn())
    .await?;
    Ok(id)
}

/// Provider acknowledged the submission with a message id.
pub async fn record_provider_accepted(
    tx: &mut TenantTx<'_>,
    action_id: ActionId,
    attempt: i32,
    provider_message_id: &str,
    now: DateTime<Utc>,
) -> Result<(), StoreError> {
    sqlx::query(
        "UPDATE kernel.message_deliveries SET provider_message_id = $4, state = 'provider_accepted', last_event_at = $5, updated_at = $5
         WHERE tenant_id = $1 AND action_id = $2 AND attempt = $3 AND state = 'submission_started'",
    )
    .bind(tx.tenant().0)
    .bind(action_id.0)
    .bind(attempt)
    .bind(provider_message_id)
    .bind(now)
    .execute(tx.conn())
    .await?;
    Ok(())
}

/// The provider request failed or its outcome is unknown.
pub async fn record_submission_outcome(
    tx: &mut TenantTx<'_>,
    action_id: ActionId,
    attempt: i32,
    state: &str,
    error_code: Option<&str>,
    now: DateTime<Utc>,
) -> Result<(), StoreError> {
    if !matches!(state, "failed" | "submission_unknown") {
        return Err(StoreError::Corrupt("submission outcome state"));
    }
    sqlx::query(
        "UPDATE kernel.message_deliveries SET state = $4, provider_error_code = $5, last_event_at = $6, updated_at = $6
         WHERE tenant_id = $1 AND action_id = $2 AND attempt = $3 AND state = 'submission_started'",
    )
    .bind(tx.tenant().0)
    .bind(action_id.0)
    .bind(attempt)
    .bind(state)
    .bind(error_code)
    .bind(now)
    .execute(tx.conn())
    .await?;
    Ok(())
}

pub async fn delivery_for_action(
    tx: &mut TenantTx<'_>,
    action_id: ActionId,
) -> Result<Option<DeliveryRecord>, StoreError> {
    let q = format!(
        "SELECT {DCOLS} FROM kernel.message_deliveries WHERE tenant_id = $1 AND action_id = $2 ORDER BY attempt DESC LIMIT 1"
    );
    let r = sqlx::query(&q)
        .bind(tx.tenant().0)
        .bind(action_id.0)
        .fetch_optional(tx.conn())
        .await?;
    r.as_ref().map(row_to_delivery).transpose()
}

/// Delivery by provider message id, locked for update (callbacks fold into it).
pub async fn delivery_by_provider_id(
    tx: &mut TenantTx<'_>,
    provider_message_id: &str,
) -> Result<Option<DeliveryRecord>, StoreError> {
    let q = format!(
        "SELECT {DCOLS} FROM kernel.message_deliveries WHERE tenant_id = $1 AND provider = 'twilio' AND provider_message_id = $2 FOR UPDATE"
    );
    let r = sqlx::query(&q)
        .bind(tx.tenant().0)
        .bind(provider_message_id)
        .fetch_optional(tx.conn())
        .await?;
    r.as_ref().map(row_to_delivery).transpose()
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum EventOutcome {
    /// First time this provider event was seen; state folded.
    Recorded { state_changed: bool },
    /// Exact duplicate delivery of a known provider event; nothing changed.
    Duplicate,
}

/// Preserve a provider status callback and fold the delivery state
/// monotonically. `folded` is computed by the caller (adapter crate knows the
/// provider's status vocabulary); this function only persists.
#[allow(clippy::too_many_arguments)]
pub async fn record_delivery_event(
    tx: &mut TenantTx<'_>,
    delivery: &DeliveryRecord,
    provider_event_id: &str,
    provider_status: &str,
    provider_error_code: Option<&str>,
    raw_digest: &Digest,
    folded_state: &str,
    read: bool,
    now: DateTime<Utc>,
) -> Result<EventOutcome, StoreError> {
    let inserted = sqlx::query(
        "INSERT INTO kernel.delivery_events (tenant_id, delivery_id, provider, provider_event_id, provider_status, provider_error_code, received_at, authentication_result, raw_event_digest)
         VALUES ($1,$2,'twilio',$3,$4,$5,$6,'verified',$7) ON CONFLICT (tenant_id, provider, provider_event_id) DO NOTHING",
    )
    .bind(tx.tenant().0)
    .bind(delivery.delivery_id)
    .bind(provider_event_id)
    .bind(provider_status)
    .bind(provider_error_code)
    .bind(now)
    .bind(raw_digest.to_string())
    .execute(tx.conn())
    .await?
    .rows_affected();
    if inserted == 0 {
        return Ok(EventOutcome::Duplicate);
    }
    let changed = folded_state != delivery.state || (read && delivery.read_status != "read");
    sqlx::query(
        "UPDATE kernel.message_deliveries SET state = $3, provider_error_code = COALESCE($4, provider_error_code),
                read_status = CASE WHEN $5 THEN 'read' ELSE read_status END, last_event_at = $6, updated_at = $6
         WHERE tenant_id = $1 AND delivery_id = $2",
    )
    .bind(tx.tenant().0)
    .bind(delivery.delivery_id)
    .bind(folded_state)
    .bind(provider_error_code)
    .bind(read)
    .bind(now)
    .execute(tx.conn())
    .await?;
    Ok(EventOutcome::Recorded {
        state_changed: changed,
    })
}

pub async fn record_reconciliation(
    tx: &mut TenantTx<'_>,
    delivery_id: Uuid,
    state: &str,
    provider_message_id: Option<&str>,
    note: &str,
    now: DateTime<Utc>,
) -> Result<(), StoreError> {
    sqlx::query(
        "UPDATE kernel.message_deliveries SET state = $3, provider_message_id = COALESCE($4, provider_message_id),
                reconciled_at = $5, reconciliation_note = $6, updated_at = $5
         WHERE tenant_id = $1 AND delivery_id = $2",
    )
    .bind(tx.tenant().0)
    .bind(delivery_id)
    .bind(state)
    .bind(provider_message_id)
    .bind(now)
    .bind(note)
    .execute(tx.conn())
    .await?;
    Ok(())
}

// ------------------------------------------------------------ inbound

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum InboundOutcome {
    Recorded(Uuid),
    Duplicate(Uuid),
}

/// Durable, deduplicated inbound record (C5 steps 2–5). The body is sealed with
/// AAD `inbound:<tenant>:<event_id>`; the audit event carries only metadata.
#[allow(clippy::too_many_arguments)]
pub async fn record_inbound(
    tx: &mut TenantTx<'_>,
    keyring: &Keyring,
    provider_event_id: &str,
    sender_identity_id: Uuid,
    source_destination_hash: &str,
    provider_timestamp: Option<DateTime<Utc>>,
    body: &SecretString,
    raw_digest: &Digest,
    opt_out_signal: &str,
    disposition: &str,
    now: DateTime<Utc>,
) -> Result<InboundOutcome, StoreError> {
    let id = Uuid::now_v7();
    let sealed = keyring
        .seal(&format!("inbound:{}:{}", tx.tenant().0, id), body)
        .map_err(|_| StoreError::Crypto)?;
    let inserted: Option<Uuid> = sqlx::query_scalar(
        "INSERT INTO kernel.inbound_events (event_id, tenant_id, provider, provider_event_id, sender_identity_id, source_destination_hash,
           received_at, provider_timestamp, content_sealed, content_reference, authentication_result, raw_event_digest, opt_out_signal, disposition)
         VALUES ($1,$2,'twilio',$3,$4,$5,$6,$7,$8,$9,'verified',$10,$11,$12)
         ON CONFLICT (tenant_id, provider, provider_event_id) DO NOTHING RETURNING event_id",
    )
    .bind(id)
    .bind(tx.tenant().0)
    .bind(provider_event_id)
    .bind(sender_identity_id)
    .bind(source_destination_hash)
    .bind(now)
    .bind(provider_timestamp)
    .bind(sealed)
    .bind(format!("sealed:{id}"))
    .bind(raw_digest.to_string())
    .bind(opt_out_signal)
    .bind(disposition)
    .fetch_optional(tx.conn())
    .await?;
    let Some(e) = inserted else {
        let existing: Uuid = sqlx::query_scalar("SELECT event_id FROM kernel.inbound_events WHERE provider = 'twilio' AND provider_event_id = $1")
            .bind(provider_event_id)
            .fetch_one(tx.conn())
            .await?;
        return Ok(InboundOutcome::Duplicate(existing));
    };
    append_event(
        tx,
        NewEvent {
            tenant_id: tx.tenant(),
            occurred_at: now,
            actor_type: ActorType::System,
            actor_id: "twilio-webhook",
            action_id: None,
            event_type: EventType::InboundReceived,
            payload_redacted: json!({"event_id": e, "sender_identity_id": sender_identity_id,
                                     "opt_out_signal": opt_out_signal, "disposition": disposition,
                                     "raw_event_digest": raw_digest.to_string(), "body_chars": body.expose_secret().chars().count()}),
            trace_id: None,
            policy_version: mk_policy::POLICY_VERSION.0,
        },
    )
    .await?;
    Ok(InboundOutcome::Recorded(e))
}

pub async fn mark_inbound_acknowledged(
    tx: &mut TenantTx<'_>,
    event_id: Uuid,
    now: DateTime<Utc>,
) -> Result<(), StoreError> {
    sqlx::query("UPDATE kernel.inbound_events SET acknowledged_at = $3 WHERE tenant_id = $1 AND event_id = $2 AND acknowledged_at IS NULL")
        .bind(tx.tenant().0)
        .bind(event_id)
        .bind(now)
        .execute(tx.conn())
        .await?;
    Ok(())
}

#[derive(Debug, Clone, Serialize)]
pub struct InboundView {
    pub event_id: Uuid,
    pub provider_event_id: String,
    pub sender_identity_id: Uuid,
    pub source_destination_hash: String,
    pub received_at: DateTime<Utc>,
    pub provider_timestamp: Option<DateTime<Utc>>,
    pub opt_out_signal: String,
    pub disposition: String,
    /// Unsealed only for the tenant's authenticated principal; never logged.
    pub body: String,
}

/// Unprocessed inbound events for async meaning processing (C5 step 7).
pub async fn pending_inbound(
    tx: &mut TenantTx<'_>,
    keyring: &Keyring,
    limit: i64,
) -> Result<Vec<InboundView>, StoreError> {
    let rows = sqlx::query(
        "SELECT event_id, provider_event_id, sender_identity_id, source_destination_hash, received_at, provider_timestamp,
                content_sealed, opt_out_signal, disposition
         FROM kernel.inbound_events WHERE tenant_id = $1 AND processed_at IS NULL ORDER BY received_at LIMIT $2",
    )
    .bind(tx.tenant().0)
    .bind(limit)
    .fetch_all(tx.conn())
    .await?;
    let tenant = tx.tenant();
    rows.iter()
        .map(|r| {
            let id: Uuid = r.try_get("event_id")?;
            let sealed: Vec<u8> = r.try_get("content_sealed")?;
            let body = keyring
                .unseal(&format!("inbound:{}:{}", tenant.0, id), &sealed)
                .map_err(|_| StoreError::Crypto)?;
            Ok(InboundView {
                event_id: id,
                provider_event_id: r.try_get("provider_event_id")?,
                sender_identity_id: r.try_get("sender_identity_id")?,
                source_destination_hash: r.try_get("source_destination_hash")?,
                received_at: r.try_get("received_at")?,
                provider_timestamp: r.try_get("provider_timestamp")?,
                opt_out_signal: r.try_get("opt_out_signal")?,
                disposition: r.try_get("disposition")?,
                body: body.expose_secret().to_owned(),
            })
        })
        .collect()
}

pub async fn mark_inbound_processed(
    tx: &mut TenantTx<'_>,
    event_id: Uuid,
    now: DateTime<Utc>,
) -> Result<bool, StoreError> {
    let n = sqlx::query("UPDATE kernel.inbound_events SET processed_at = $3 WHERE tenant_id = $1 AND event_id = $2 AND processed_at IS NULL")
        .bind(tx.tenant().0)
        .bind(event_id)
        .bind(now)
        .execute(tx.conn())
        .await?
        .rows_affected();
    Ok(n == 1)
}

pub async fn pending_inbound_count(tx: &mut TenantTx<'_>) -> Result<i64, StoreError> {
    Ok(sqlx::query_scalar(
        "SELECT count(*) FROM kernel.inbound_events WHERE tenant_id = $1 AND processed_at IS NULL",
    )
    .bind(tx.tenant().0)
    .fetch_one(tx.conn())
    .await?)
}

// ------------------------------------------------------------ inbound health

#[derive(Debug, Clone, Serialize)]
pub struct InboundHealth {
    pub last_ok_at: Option<DateTime<Utc>>,
    pub last_failure_at: Option<DateTime<Utc>>,
    pub last_failure_reason: String,
    pub paused_since: Option<DateTime<Utc>>,
    pub resumed_at: Option<DateTime<Utc>>,
}

pub async fn inbound_health(tx: &mut TenantTx<'_>) -> Result<Option<InboundHealth>, StoreError> {
    let r = sqlx::query("SELECT last_ok_at, last_failure_at, last_failure_reason, paused_since, resumed_at FROM kernel.inbound_health WHERE tenant_id = $1")
        .bind(tx.tenant().0)
        .fetch_optional(tx.conn())
        .await?;
    r.map(|r| {
        Ok(InboundHealth {
            last_ok_at: r.try_get("last_ok_at")?,
            last_failure_at: r.try_get("last_failure_at")?,
            last_failure_reason: r.try_get("last_failure_reason")?,
            paused_since: r.try_get("paused_since")?,
            resumed_at: r.try_get("resumed_at")?,
        })
    })
    .transpose()
}

/// Record a successful inbound-path check (an authenticated webhook arrived, or
/// the probe succeeded). Clears a pause only through `resume_inbound`.
pub async fn inbound_ok(tx: &mut TenantTx<'_>, now: DateTime<Utc>) -> Result<(), StoreError> {
    sqlx::query(
        "INSERT INTO kernel.inbound_health (tenant_id, last_ok_at, updated_at) VALUES ($1,$2,$2)
         ON CONFLICT (tenant_id) DO UPDATE SET last_ok_at = EXCLUDED.last_ok_at, updated_at = EXCLUDED.updated_at",
    )
    .bind(tx.tenant().0)
    .bind(now)
    .execute(tx.conn())
    .await?;
    Ok(())
}

pub async fn inbound_failure(
    tx: &mut TenantTx<'_>,
    reason: &str,
    now: DateTime<Utc>,
) -> Result<(), StoreError> {
    sqlx::query(
        "INSERT INTO kernel.inbound_health (tenant_id, last_failure_at, last_failure_reason, updated_at) VALUES ($1,$2,$3,$2)
         ON CONFLICT (tenant_id) DO UPDATE SET last_failure_at = EXCLUDED.last_failure_at, last_failure_reason = EXCLUDED.last_failure_reason, updated_at = EXCLUDED.updated_at",
    )
    .bind(tx.tenant().0)
    .bind(now)
    .bind(reason)
    .execute(tx.conn())
    .await?;
    Ok(())
}

/// Dispatch gate (C8): paused explicitly, or no successful check within the
/// stale window after at least one failure, or never checked at all when a
/// sender identity exists. Returns the reason when dispatch must not proceed.
pub async fn inbound_dispatch_block(
    tx: &mut TenantTx<'_>,
    now: DateTime<Utc>,
) -> Result<Option<&'static str>, StoreError> {
    let Some(h) = inbound_health(tx).await? else {
        // No health row yet: only block if this tenant actually uses provider messaging.
        let n: i64 = sqlx::query_scalar("SELECT count(*) FROM kernel.sender_identities WHERE tenant_id = $1 AND status = 'active'")
            .bind(tx.tenant().0)
            .fetch_one(tx.conn())
            .await?;
        return Ok((n > 0).then_some("inbound_unverified"));
    };
    if h.paused_since.is_some()
        && h.resumed_at
            .is_none_or(|r| h.paused_since.is_some_and(|p| r < p))
    {
        return Ok(Some("inbound_paused"));
    }
    match (h.last_ok_at, h.last_failure_at) {
        (Some(ok), Some(f)) if f > ok && (now - ok).num_seconds() > INBOUND_STALE_SECS => {
            Ok(Some("inbound_stale"))
        }
        (None, Some(_)) => Ok(Some("inbound_stale")),
        (None, None) => Ok(Some("inbound_unverified")),
        _ => Ok(None),
    }
}

pub async fn pause_inbound(tx: &mut TenantTx<'_>, now: DateTime<Utc>) -> Result<(), StoreError> {
    sqlx::query(
        "INSERT INTO kernel.inbound_health (tenant_id, paused_since, updated_at) VALUES ($1,$2,$2)
         ON CONFLICT (tenant_id) DO UPDATE SET paused_since = EXCLUDED.paused_since, resumed_at = NULL, updated_at = EXCLUDED.updated_at",
    )
    .bind(tx.tenant().0)
    .bind(now)
    .execute(tx.conn())
    .await?;
    Ok(())
}

/// Resume only when a recent check succeeded *and* no inbound events are
/// pending (C8). Returns false (and changes nothing) otherwise.
pub async fn resume_inbound(tx: &mut TenantTx<'_>, now: DateTime<Utc>) -> Result<bool, StoreError> {
    let Some(h) = inbound_health(tx).await? else {
        return Ok(false);
    };
    let fresh = h
        .last_ok_at
        .is_some_and(|ok| (now - ok).num_seconds() <= INBOUND_STALE_SECS);
    let pending = pending_inbound_count(tx).await?;
    if !fresh || pending > 0 {
        return Ok(false);
    }
    sqlx::query("UPDATE kernel.inbound_health SET resumed_at = $2, pending_events_at_resume = 0, updated_at = $2 WHERE tenant_id = $1")
        .bind(tx.tenant().0)
        .bind(now)
        .execute(tx.conn())
        .await?;
    Ok(true)
}
