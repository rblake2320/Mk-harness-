//! Key versions for envelope encryption (S6). Runtime processes only read;
//! `mk-keyctl` (owner identity) rotates, re-encrypts and retires.

use std::collections::BTreeMap;

use chrono::{DateTime, Utc};
use mk_crypto::{Kek, Keyring, LEGACY_VERSION, MasterKey};
use serde::Serialize;
use sqlx::{PgPool, Row};
use zeroize::Zeroizing;

use crate::error::StoreError;

#[derive(Debug, Clone, Serialize)]
pub struct KeyVersionRow {
    pub version: i32,
    pub kek_id: String,
    pub status: String,
    pub created_at: DateTime<Utc>,
    pub created_by: String,
    pub retired_at: Option<DateTime<Utc>>,
    pub note: String,
}

pub async fn list(pool: &PgPool) -> Result<Vec<KeyVersionRow>, StoreError> {
    let rows = sqlx::query("SELECT version, kek_id, status, created_at, created_by, retired_at, note FROM kernel.key_versions ORDER BY version")
        .fetch_all(pool)
        .await?;
    rows.iter()
        .map(|r| {
            Ok(KeyVersionRow {
                version: r.try_get("version")?,
                kek_id: r.try_get("kek_id")?,
                status: r.try_get("status")?,
                created_at: r.try_get("created_at")?,
                created_by: r.try_get("created_by")?,
                retired_at: r.try_get("retired_at")?,
                note: r.try_get("note")?,
            })
        })
        .collect()
}

/// Build the process keyring: every active/retiring version unwrapped with
/// `kek`, plus the legacy master key as version 0 while `include_legacy`.
/// With no rows at all, the keyring is the legacy master key alone (pre-S6
/// deployments keep working; pre-flight refuses that configuration for
/// production enablement).
pub async fn load_keyring(pool: &PgPool, kek: Option<&dyn Kek>, master: &MasterKey, include_legacy: bool) -> Result<Keyring, StoreError> {
    let rows = sqlx::query("SELECT version, kek_id, wrapped_dek, status FROM kernel.key_versions WHERE status <> 'retired' ORDER BY version")
        .fetch_all(pool)
        .await?;
    if rows.is_empty() {
        return Ok(Keyring::legacy(master));
    }
    let kek = kek.ok_or(StoreError::Corrupt("key versions exist but no KEK is configured (MK_KEK)"))?;
    let mut deks = BTreeMap::new();
    let mut current = None;
    for r in &rows {
        let version: i32 = r.try_get("version")?;
        let kek_id: String = r.try_get("kek_id")?;
        if kek_id != kek.kek_id() {
            return Err(StoreError::Corrupt("key version wrapped by a different KEK than the one configured"));
        }
        let wrapped: Vec<u8> = r.try_get("wrapped_dek")?;
        let v = u32::try_from(version).map_err(|_| StoreError::Corrupt("key version"))?;
        let dek = kek.unwrap(v, &wrapped).map_err(|_| StoreError::Crypto)?;
        deks.insert(v, dek);
        if r.try_get::<String, _>("status")? == "active" {
            current = Some(v);
        }
    }
    if include_legacy {
        let mut m = Zeroizing::new([0u8; 32]);
        m.copy_from_slice(master.as_bytes());
        deks.insert(LEGACY_VERSION, m);
    }
    let current = current.ok_or(StoreError::Corrupt("no active key version"))?;
    Keyring::from_versions(deks, current).map_err(|_| StoreError::Crypto)
}

/// Operator: add a new version wrapped by `kek` and make it active; the
/// previous active version becomes `retiring` (still readable).
pub async fn rotate(pool: &PgPool, kek: &dyn Kek, by: &str, note: &str) -> Result<i32, StoreError> {
    let mut tx = pool.begin().await?;
    let next: i32 = sqlx::query_scalar("SELECT COALESCE(max(version), 0) + 1 FROM kernel.key_versions").fetch_one(&mut *tx).await?;
    let wrapped = Keyring::new_wrapped_version(kek, u32::try_from(next).map_err(|_| StoreError::Corrupt("version"))?).map_err(|_| StoreError::Crypto)?;
    sqlx::query("UPDATE kernel.key_versions SET status = 'retiring' WHERE status = 'active'").execute(&mut *tx).await?;
    sqlx::query("INSERT INTO kernel.key_versions (version, kek_id, wrapped_dek, status, created_by, note) VALUES ($1,$2,$3,'active',$4,$5)")
        .bind(next)
        .bind(kek.kek_id())
        .bind(wrapped)
        .bind(by)
        .bind(note)
        .execute(&mut *tx)
        .await?;
    tx.commit().await?;
    Ok(next)
}

/// Sealed columns that participate in re-encryption: (table, pk column, sealed column, aad builder).
pub const SEALED_COLUMNS: &[(&str, &str, &str)] = &[
    ("kernel.adapter_credentials", "credential_id", "secret_ciphertext"),
    ("kernel.sender_identities", "sender_identity_id", "auth_token_sealed"),
    ("kernel.inbound_events", "event_id", "content_sealed"),
];

/// Operator: count rows still sealed under versions other than the current one.
pub async fn stale_counts(pool: &PgPool, keyring: &Keyring, tenant: Option<mk_domain::TenantId>) -> Result<Vec<(String, u64)>, StoreError> {
    let mut out = Vec::new();
    let filter = tenant.map_or(String::new(), |t| format!(" WHERE tenant_id = '{}'", t.0));
    for (table, pk, col) in SEALED_COLUMNS {
        let rows = sqlx::query(&format!("SELECT {pk}::text AS id, {col} AS sealed FROM {table}{filter}")).fetch_all(pool).await?;
        let stale = rows
            .iter()
            .filter(|r| r.try_get::<Vec<u8>, _>("sealed").map_or(true, |b| Keyring::version_of(&b) != keyring.current_version()))
            .count();
        out.push(((*table).to_owned(), u64::try_from(stale).unwrap_or(u64::MAX)));
    }
    Ok(out)
}

/// Operator: retire a version. Refused while any row is still sealed under it.
pub async fn retire(pool: &PgPool, keyring: &Keyring, version: i32, now: DateTime<Utc>) -> Result<(), StoreError> {
    let v = u32::try_from(version).map_err(|_| StoreError::Corrupt("version"))?;
    if v == keyring.current_version() {
        return Err(StoreError::Conflict("cannot retire the active version"));
    }
    for (table, pk, col) in SEALED_COLUMNS {
        let rows = sqlx::query(&format!("SELECT {pk}::text AS id, {col} AS sealed FROM {table}")).fetch_all(pool).await?;
        if rows.iter().any(|r| r.try_get::<Vec<u8>, _>("sealed").is_ok_and(|b| Keyring::version_of(&b) == v)) {
            return Err(StoreError::Conflict("rows are still sealed under this version; run reencrypt first"));
        }
    }
    let n = sqlx::query("UPDATE kernel.key_versions SET status = 'retired', retired_at = $2 WHERE version = $1 AND status = 'retiring'")
        .bind(version)
        .bind(now)
        .execute(pool)
        .await?
        .rows_affected();
    if n == 0 {
        return Err(StoreError::Conflict("version is not retiring"));
    }
    Ok(())
}


/// Process start-up: build the KEK from `MK_KEK` (base64 32 bytes) / `MK_KEK_ID`
/// (default `kek-1`) and load the keyring. Without a KEK the keyring is the
/// legacy master key only — allowed, logged, and refused by production pre-flight.
pub async fn keyring_from_env(pool: &PgPool, master: &MasterKey) -> Result<Keyring, StoreError> {
    let kek = match std::env::var("MK_KEK") {
        Ok(b64) if !b64.trim().is_empty() => Some(
            mk_crypto::EnvKek::from_base64(std::env::var("MK_KEK_ID").unwrap_or_else(|_| "kek-1".into()), &b64)
                .map_err(|_| StoreError::Corrupt("MK_KEK must be base64 of 32 bytes"))?,
        ),
        _ => None,
    };
    let include_legacy = !std::env::var("MK_LEGACY_SEAL_RETIRED").is_ok_and(|v| v == "1");
    load_keyring(pool, kek.as_ref().map(|k| k as &dyn Kek), master, include_legacy).await
}

/// Outcome of a re-encryption pass. `unreadable` rows could not be unsealed
/// with the loaded keyring (foreign/lost key material): they are left as they
/// are and reported — never deleted, never silently skipped.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct ReencryptReport {
    pub resealed: u64,
    pub unreadable: u64,
}

/// Operator: re-seal every row not under the current version. Each row is
/// updated in its own statement with the AAD the owning module uses, so a
/// crash mid-way leaves a mix of versions that is still fully readable (the
/// old version stays `retiring` until `retire`).
pub async fn reencrypt(pool: &PgPool, keyring: &Keyring, tenant: Option<mk_domain::TenantId>) -> Result<ReencryptReport, StoreError> {
    let mut rep = ReencryptReport::default();
    let filter = tenant.map_or(String::new(), |t| format!(" WHERE tenant_id = '{}'", t.0));
    // adapter_credentials: AAD = tenant:adapter:credential (see adapters::aad)
    let rows = sqlx::query(&format!("SELECT tenant_id, adapter_id, credential_id, secret_ciphertext FROM kernel.adapter_credentials{filter}")).fetch_all(pool).await?;
    for r in rows {
        let (t, a, c): (uuid::Uuid, uuid::Uuid, uuid::Uuid) = (r.try_get("tenant_id")?, r.try_get("adapter_id")?, r.try_get("credential_id")?);
        let sealed: Vec<u8> = r.try_get("secret_ciphertext")?;
        match keyring.reseal(&format!("mk-adapter-credential:{t}:{a}:{c}"), &sealed) {
            Ok(Some(new)) => {
                sqlx::query("UPDATE kernel.adapter_credentials SET secret_ciphertext = $3 WHERE tenant_id = $1 AND credential_id = $2")
                    .bind(t).bind(c).bind(new).execute(pool).await?;
                rep.resealed += 1;
            }
            Ok(None) => {}
            Err(_) => rep.unreadable += 1,
        }
    }
    // sender_identities: AAD = sender:tenant:id
    let rows = sqlx::query(&format!("SELECT tenant_id, sender_identity_id, auth_token_sealed FROM kernel.sender_identities{filter}")).fetch_all(pool).await?;
    for r in rows {
        let (t, id): (uuid::Uuid, uuid::Uuid) = (r.try_get("tenant_id")?, r.try_get("sender_identity_id")?);
        let sealed: Vec<u8> = r.try_get("auth_token_sealed")?;
        match keyring.reseal(&format!("sender:{t}:{id}"), &sealed) {
            Ok(Some(new)) => {
                sqlx::query("UPDATE kernel.sender_identities SET auth_token_sealed = $3 WHERE tenant_id = $1 AND sender_identity_id = $2")
                    .bind(t).bind(id).bind(new).execute(pool).await?;
                rep.resealed += 1;
            }
            Ok(None) => {}
            Err(_) => rep.unreadable += 1,
        }
    }
    // inbound_events: AAD = inbound:tenant:event
    let rows = sqlx::query(&format!("SELECT tenant_id, event_id, content_sealed FROM kernel.inbound_events{filter}")).fetch_all(pool).await?;
    for r in rows {
        let (t, id): (uuid::Uuid, uuid::Uuid) = (r.try_get("tenant_id")?, r.try_get("event_id")?);
        let sealed: Vec<u8> = r.try_get("content_sealed")?;
        match keyring.reseal(&format!("inbound:{t}:{id}"), &sealed) {
            Ok(Some(new)) => {
                sqlx::query("UPDATE kernel.inbound_events SET content_sealed = $3 WHERE tenant_id = $1 AND event_id = $2")
                    .bind(t).bind(id).bind(new).execute(pool).await?;
                rep.resealed += 1;
            }
            Ok(None) => {}
            Err(_) => rep.unreadable += 1,
        }
    }
    Ok(rep)
}
