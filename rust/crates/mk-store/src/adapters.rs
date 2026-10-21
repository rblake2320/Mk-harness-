//! Mobile-adapter registrations, credential lifecycle (register / rotate /
//! revoke), nonce replay table, and callback records.

use chrono::{DateTime, Duration, Utc};
use mk_audit::{EventType, NewEvent};
use mk_crypto::{AdapterSecret, Keyring, generate_secret};
use mk_domain::{ActionId, AdapterId, TenantId};
use secrecy::{ExposeSecret, SecretString};
use serde_json::json;
use sqlx::{PgPool, Row};
use uuid::Uuid;

use crate::actions::Actor;
use crate::audit::append_event;
use crate::error::StoreError;
use crate::tx::TenantTx;

#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize)]
pub struct AdapterRegistration {
    pub adapter_id: AdapterId,
    pub tenant_id: TenantId,
    pub agent_id: String,
    pub name: String,
    pub adapter_kind: String,
    pub platform: String,
    pub version: String,
    pub capabilities: Vec<String>,
    pub allowed_actions: Vec<String>,
    pub callback_authority: String,
    pub verified_on_device: bool,
    pub revoked_at: Option<DateTime<Utc>>,
    pub last_used_at: Option<DateTime<Utc>>,
}

impl AdapterRegistration {
    #[must_use]
    pub fn is_active(&self, now: DateTime<Utc>) -> bool {
        self.revoked_at.is_none_or(|r| r > now)
    }
}

fn aad(tenant: TenantId, adapter: AdapterId, credential: Uuid) -> String {
    format!(
        "mk-adapter-credential:{}:{}:{credential}",
        tenant.0, adapter.0
    )
}

/// Register an adapter and mint its first secret. The plaintext secret is
/// returned **once**; only the sealed form is stored.
pub async fn register(
    tx: &mut TenantTx<'_>,
    keyring: &Keyring,
    agent_id: &str,
    name: &str,
    platform: &str,
    version: &str,
    capabilities: &[String],
    allowed_actions: &[String],
    callback_authority: &str,
    actor: Actor<'_>,
    now: DateTime<Utc>,
) -> Result<(AdapterRegistration, SecretString), StoreError> {
    let adapter_id = AdapterId::new();
    sqlx::query(
        "INSERT INTO kernel.adapter_registrations (adapter_id, tenant_id, agent_id, name, adapter_kind, platform, version,
           capabilities, allowed_actions, callback_authority, verified_on_device, created_at)
         VALUES ($1,$2,$3,$4,'mobile-adapter-v1',$5,$6,$7,$8,$9,false,$10)",
    )
    .bind(adapter_id.0)
    .bind(tx.tenant().0)
    .bind(agent_id)
    .bind(name)
    .bind(platform)
    .bind(version)
    .bind(capabilities)
    .bind(allowed_actions)
    .bind(callback_authority)
    .bind(now)
    .execute(tx.conn())
    .await?;
    let secret = insert_credential(tx, keyring, adapter_id, now).await?;
    append_event(
        tx,
        NewEvent {
            tenant_id: tx.tenant(),
            occurred_at: now,
            actor_type: actor.actor_type,
            actor_id: actor.actor_id,
            action_id: None,
            event_type: EventType::AdapterRegistered,
            payload_redacted: json!({"adapter_id": adapter_id, "agent_id": agent_id, "platform": platform, "capabilities": capabilities, "callback_authority": callback_authority}),
            trace_id: actor.trace_id,
            policy_version: actor.policy_version,
        },
    )
    .await?;
    Ok((get(tx, adapter_id).await?, secret))
}

async fn insert_credential(
    tx: &mut TenantTx<'_>,
    keyring: &Keyring,
    adapter_id: AdapterId,
    now: DateTime<Utc>,
) -> Result<SecretString, StoreError> {
    let credential_id = Uuid::now_v7();
    let secret = generate_secret();
    let sealed = keyring
        .seal(&aad(tx.tenant(), adapter_id, credential_id), &secret)
        .map_err(|_| StoreError::Crypto)?;
    let fp = AdapterSecret::new(secret.expose_secret().to_string()).fingerprint();
    sqlx::query(
        "INSERT INTO kernel.adapter_credentials (credential_id, tenant_id, adapter_id, secret_ciphertext, secret_fingerprint, created_at)
         VALUES ($1,$2,$3,$4,$5,$6)",
    )
    .bind(credential_id)
    .bind(tx.tenant().0)
    .bind(adapter_id.0)
    .bind(&sealed)
    .bind(fp)
    .bind(now)
    .execute(tx.conn())
    .await?;
    Ok(secret)
}

/// Rotate: mint a replacement; the previous live credential(s) stop being
/// valid at `now + overlap`. The overlap is explicit and audited.
pub async fn rotate(
    tx: &mut TenantTx<'_>,
    keyring: &Keyring,
    adapter_id: AdapterId,
    overlap: Duration,
    actor: Actor<'_>,
    now: DateTime<Utc>,
) -> Result<SecretString, StoreError> {
    let reg = get(tx, adapter_id).await?;
    if !reg.is_active(now) {
        return Err(StoreError::Conflict("adapter revoked"));
    }
    sqlx::query(
        "UPDATE kernel.adapter_credentials SET not_after = LEAST(COALESCE(not_after, $3), $3)
         WHERE tenant_id = $1 AND adapter_id = $2 AND revoked_at IS NULL",
    )
    .bind(tx.tenant().0)
    .bind(adapter_id.0)
    .bind(now + overlap)
    .execute(tx.conn())
    .await?;
    let secret = insert_credential(tx, keyring, adapter_id, now).await?;
    append_event(
        tx,
        NewEvent {
            tenant_id: tx.tenant(),
            occurred_at: now,
            actor_type: actor.actor_type,
            actor_id: actor.actor_id,
            action_id: None,
            event_type: EventType::AdapterRotated,
            payload_redacted: json!({"adapter_id": adapter_id, "overlap_secs": overlap.num_seconds()}),
            trace_id: actor.trace_id,
            policy_version: actor.policy_version,
        },
    )
    .await?;
    Ok(secret)
}

/// Revoke: no dispatch, no callbacks, every credential dead immediately.
pub async fn revoke(
    tx: &mut TenantTx<'_>,
    adapter_id: AdapterId,
    actor: Actor<'_>,
    now: DateTime<Utc>,
) -> Result<(), StoreError> {
    let res = sqlx::query("UPDATE kernel.adapter_registrations SET revoked_at = $3 WHERE tenant_id = $1 AND adapter_id = $2 AND revoked_at IS NULL")
        .bind(tx.tenant().0)
        .bind(adapter_id.0)
        .bind(now)
        .execute(tx.conn())
        .await?;
    if res.rows_affected() != 1 {
        return Err(StoreError::NotFound);
    }
    sqlx::query("UPDATE kernel.adapter_credentials SET revoked_at = $3 WHERE tenant_id = $1 AND adapter_id = $2 AND revoked_at IS NULL")
        .bind(tx.tenant().0)
        .bind(adapter_id.0)
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
            action_id: None,
            event_type: EventType::AdapterRevoked,
            payload_redacted: json!({"adapter_id": adapter_id}),
            trace_id: actor.trace_id,
            policy_version: actor.policy_version,
        },
    )
    .await?;
    Ok(())
}

pub async fn get(
    tx: &mut TenantTx<'_>,
    adapter_id: AdapterId,
) -> Result<AdapterRegistration, StoreError> {
    let tenant = tx.tenant();
    let r = sqlx::query(
        "SELECT adapter_id, agent_id, name, adapter_kind, platform, version, capabilities, allowed_actions, callback_authority,
                verified_on_device, revoked_at, last_used_at FROM kernel.adapter_registrations WHERE tenant_id = $1 AND adapter_id = $2",
    )
    .bind(tenant.0)
    .bind(adapter_id.0)
    .fetch_optional(tx.conn())
    .await?
    .ok_or(StoreError::NotFound)?;
    row_to_reg(tenant, &r)
}

pub async fn get_by_agent(
    tx: &mut TenantTx<'_>,
    agent_id: &str,
) -> Result<AdapterRegistration, StoreError> {
    let tenant = tx.tenant();
    let r = sqlx::query(
        "SELECT adapter_id, agent_id, name, adapter_kind, platform, version, capabilities, allowed_actions, callback_authority,
                verified_on_device, revoked_at, last_used_at FROM kernel.adapter_registrations WHERE tenant_id = $1 AND agent_id = $2",
    )
    .bind(tenant.0)
    .bind(agent_id)
    .fetch_optional(tx.conn())
    .await?
    .ok_or(StoreError::NotFound)?;
    row_to_reg(tenant, &r)
}

fn row_to_reg(
    tenant: TenantId,
    r: &sqlx::postgres::PgRow,
) -> Result<AdapterRegistration, StoreError> {
    Ok(AdapterRegistration {
        adapter_id: AdapterId::from_uuid(r.try_get("adapter_id")?),
        tenant_id: tenant,
        agent_id: r.try_get("agent_id")?,
        name: r.try_get("name")?,
        adapter_kind: r.try_get("adapter_kind")?,
        platform: r.try_get("platform")?,
        version: r.try_get("version")?,
        capabilities: r.try_get("capabilities")?,
        allowed_actions: r.try_get("allowed_actions")?,
        callback_authority: r.try_get("callback_authority")?,
        verified_on_device: r.try_get("verified_on_device")?,
        revoked_at: r.try_get("revoked_at")?,
        last_used_at: r.try_get("last_used_at")?,
    })
}

/// All credentials that may validly sign right now (newest first). During a
/// rotation overlap this returns two; after it, one; after revoke, none.
pub async fn live_secrets(
    tx: &mut TenantTx<'_>,
    keyring: &Keyring,
    adapter_id: AdapterId,
    now: DateTime<Utc>,
) -> Result<Vec<AdapterSecret>, StoreError> {
    let tenant = tx.tenant();
    let rows = sqlx::query(
        "SELECT c.credential_id, c.secret_ciphertext FROM kernel.adapter_credentials c
         JOIN kernel.adapter_registrations r ON r.tenant_id = c.tenant_id AND r.adapter_id = c.adapter_id
         WHERE c.tenant_id = $1 AND c.adapter_id = $2 AND c.revoked_at IS NULL AND r.revoked_at IS NULL
           AND (c.not_after IS NULL OR c.not_after > $3) ORDER BY c.created_at DESC, c.credential_id DESC",
    )
    .bind(tenant.0)
    .bind(adapter_id.0)
    .bind(now)
    .fetch_all(tx.conn())
    .await?;
    rows.into_iter()
        .map(|r| {
            let cid: Uuid = r.try_get("credential_id")?;
            let ct: Vec<u8> = r.try_get("secret_ciphertext")?;
            let s = keyring
                .unseal(&aad(tenant, adapter_id, cid), &ct)
                .map_err(|_| StoreError::Crypto)?;
            Ok(AdapterSecret::new(s.expose_secret().to_string()))
        })
        .collect()
}

pub async fn touch_last_used(
    tx: &mut TenantTx<'_>,
    adapter_id: AdapterId,
    now: DateTime<Utc>,
) -> Result<(), StoreError> {
    sqlx::query("UPDATE kernel.adapter_registrations SET last_used_at = $3 WHERE tenant_id = $1 AND adapter_id = $2")
        .bind(tx.tenant().0)
        .bind(adapter_id.0)
        .bind(now)
        .execute(tx.conn())
        .await?;
    Ok(())
}

/// Durable nonce check. Returns `Err(Conflict)` on replay. Must be called in
/// the same transaction as the callback effect so a rolled-back effect also
/// forgets the nonce (and a retried identical request is accepted).
pub async fn record_nonce(
    tx: &mut TenantTx<'_>,
    adapter_id: AdapterId,
    nonce: &str,
    retain: Duration,
    now: DateTime<Utc>,
) -> Result<(), StoreError> {
    sqlx::query("INSERT INTO kernel.adapter_nonces (tenant_id, adapter_id, nonce, seen_at, expires_at) VALUES ($1,$2,$3,$4,$5)")
        .bind(tx.tenant().0)
        .bind(adapter_id.0)
        .bind(nonce)
        .bind(now)
        .bind(now + retain)
        .execute(tx.conn())
        .await
        .map_err(|e| match StoreError::from(e) {
            StoreError::Conflict(_) => StoreError::Conflict("nonce replayed"),
            o => o,
        })?;
    Ok(())
}

/// Purge expired nonces (cross-tenant, worker sweep).
pub async fn purge_nonces(pool: &PgPool, now: DateTime<Utc>) -> Result<u64, StoreError> {
    let res = sqlx::query("DELETE FROM kernel.adapter_nonces WHERE expires_at < $1")
        .bind(now)
        .execute(pool)
        .await?;
    Ok(res.rows_affected())
}

pub async fn record_callback(
    tx: &mut TenantTx<'_>,
    adapter_id: AdapterId,
    action_id: ActionId,
    kind: &str,
    body_digest: &str,
    nonce: &str,
    applied: bool,
    now: DateTime<Utc>,
) -> Result<(), StoreError> {
    sqlx::query(
        "INSERT INTO kernel.adapter_callbacks (tenant_id, adapter_id, action_id, kind, body_digest, nonce, received_at, applied)
         VALUES ($1,$2,$3,$4,$5,$6,$7,$8)",
    )
    .bind(tx.tenant().0)
    .bind(adapter_id.0)
    .bind(action_id.0)
    .bind(kind)
    .bind(body_digest)
    .bind(nonce)
    .bind(now)
    .bind(applied)
    .execute(tx.conn())
    .await?;
    append_event(
        tx,
        NewEvent {
            tenant_id: tx.tenant(),
            occurred_at: now,
            actor_type: mk_audit::ActorType::Adapter,
            actor_id: &adapter_id.to_string(),
            action_id: Some(action_id),
            event_type: EventType::CallbackReceived,
            payload_redacted: json!({"kind": kind, "body_digest": body_digest, "applied": applied}),
            trace_id: None,
            policy_version: mk_policy::POLICY_VERSION.0,
        },
    )
    .await?;
    Ok(())
}

pub async fn record_signature_failure(
    tx: &mut TenantTx<'_>,
    adapter_id: Option<AdapterId>,
    code: &str,
    now: DateTime<Utc>,
) -> Result<(), StoreError> {
    append_event(
        tx,
        NewEvent {
            tenant_id: tx.tenant(),
            occurred_at: now,
            actor_type: mk_audit::ActorType::Adapter,
            actor_id: &adapter_id.map_or_else(|| "unknown".into(), |a| a.to_string()),
            action_id: None,
            event_type: if code == "nonce_replayed" {
                EventType::ReplayRejected
            } else {
                EventType::SignatureFailure
            },
            payload_redacted: json!({"code": code}),
            trace_id: None,
            policy_version: mk_policy::POLICY_VERSION.0,
        },
    )
    .await?;
    Ok(())
}
