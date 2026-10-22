//! Versioned destination fingerprints (contract S6: rotation must not orphan
//! opt-outs or consent).
//!
//! A destination fingerprint is `HMAC-SHA256(key, tenant|channel|normalized)`.
//! Every row that refers to a destination stores the hash under the *current*
//! key in its legacy hash column and, in `destination_fingerprints`, one
//! `kid:hex` entry per configured key. Lookups match on array overlap against
//! the caller's full tagged set, so a suppression written before a rotation
//! still blocks after it, and an operator can roll keys in this order:
//!
//!   1. add the new key as a non-current entry everywhere
//!      (`MK_FINGERPRINT_KEYS=m0=<old>,k2=<new>` — the FIRST entry is current);
//!   2. make it current (`k2=<new>,m0=<old>`);
//!   3. `mk-keyctl fingerprint-rekey` — adds the new tag to every row from its
//!      sealed destination (suppressions, permissions, inbound) or canonical
//!      arguments (actions);
//!   4. `mk-keyctl fingerprint-status` must report 0 rows lacking the current
//!      kid before the old key is removed from the list.
//!
//! Without `MK_FINGERPRINT_KEYS` the single key `m0` = the master key is used,
//! which is byte-identical to the pre-0008 hash and to the Python vector.
//!
//! Control-path locks (C6) are taken on every tagged value, sorted, so two
//! transactions that share any fingerprint serialize and never deadlock.

use hmac::{Hmac, Mac};
use mk_crypto::MasterKey;
use mk_domain::{Channel, TenantId};
use sha2::Sha256;
use zeroize::Zeroizing;

use crate::error::StoreError;

/// The kid assigned to the master-key fingerprint (pre-0008 rows are backfilled with it).
pub const LEGACY_KID: &str = "m0";

/// One destination's fingerprints under every configured key.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Fingerprints {
    /// Hex hash under the current key — stored in the legacy hash column and
    /// handed to policy as the destination's identity.
    pub primary: String,
    /// `kid:hex` under every configured key, current first.
    pub tagged: Vec<String>,
}

impl Fingerprints {
    /// A fingerprint known only as a bare hash under the legacy key (tests,
    /// hash-only operator input that matches no stored row).
    #[must_use]
    pub fn legacy(hash: &str) -> Self {
        Self {
            primary: hash.to_owned(),
            tagged: vec![format!("{LEGACY_KID}:{hash}")],
        }
    }

    /// Reassemble from a stored row.
    #[must_use]
    pub fn stored(primary: &str, tagged: Vec<String>) -> Self {
        if tagged.is_empty() {
            return Self::legacy(primary);
        }
        Self {
            primary: primary.to_owned(),
            tagged,
        }
    }

    /// Lock keys for the C6 control path: every tagged value, sorted, deduped.
    #[must_use]
    pub fn lock_keys(&self) -> Vec<String> {
        let mut v = self.tagged.clone();
        v.sort();
        v.dedup();
        v
    }

    /// Union another set's tags into this one (rekey).
    #[must_use]
    pub fn union(&self, other: &[String]) -> Vec<String> {
        let mut v = self.tagged.clone();
        for t in other {
            if !v.contains(t) {
                v.push(t.clone());
            }
        }
        v
    }
}

/// Configured fingerprint keys; the first is current.
pub struct FingerprintKeys {
    keys: Vec<(String, Zeroizing<Vec<u8>>)>,
}

impl std::fmt::Debug for FingerprintKeys {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("FingerprintKeys")
            .field("kids", &self.kids())
            .finish()
    }
}

impl FingerprintKeys {
    /// Single legacy key: the master key under kid `m0`.
    #[must_use]
    pub fn from_master(master: &MasterKey) -> Self {
        Self {
            keys: vec![(
                LEGACY_KID.to_owned(),
                Zeroizing::new(master.as_bytes().to_vec()),
            )],
        }
    }

    /// Parse `kid=base64(32 bytes)[,kid=...]`. Kids are `[a-z0-9_-]{1,16}`,
    /// unique; `m0` may be given as the literal `m0=master` to mean the master key.
    pub fn parse(spec: &str, master: &MasterKey) -> Result<Self, StoreError> {
        use base64::Engine as _;
        let mut keys: Vec<(String, Zeroizing<Vec<u8>>)> = Vec::new();
        for part in spec.split(',').map(str::trim).filter(|s| !s.is_empty()) {
            let (kid, b64) = part.split_once('=').ok_or(StoreError::Corrupt(
                "MK_FINGERPRINT_KEYS entry must be kid=base64",
            ))?;
            let kid = kid.trim();
            if kid.is_empty()
                || kid.len() > 16
                || !kid
                    .chars()
                    .all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || c == '_' || c == '-')
            {
                return Err(StoreError::Corrupt(
                    "MK_FINGERPRINT_KEYS kid must be [a-z0-9_-]{1,16}",
                ));
            }
            if keys.iter().any(|(k, _)| k == kid) {
                return Err(StoreError::Corrupt("MK_FINGERPRINT_KEYS kid repeated"));
            }
            let bytes = if b64.trim() == "master" {
                master.as_bytes().to_vec()
            } else {
                base64::engine::general_purpose::STANDARD
                    .decode(b64.trim())
                    .map_err(|_| StoreError::Corrupt("MK_FINGERPRINT_KEYS key must be base64"))?
            };
            if bytes.len() != 32 {
                return Err(StoreError::Corrupt(
                    "MK_FINGERPRINT_KEYS key must be 32 bytes",
                ));
            }
            keys.push((kid.to_owned(), Zeroizing::new(bytes)));
        }
        if keys.is_empty() {
            return Err(StoreError::Corrupt("MK_FINGERPRINT_KEYS is empty"));
        }
        Ok(Self { keys })
    }

    /// `MK_FINGERPRINT_KEYS` if set, else the master key as `m0`.
    pub fn from_env(master: &MasterKey) -> Result<Self, StoreError> {
        match std::env::var("MK_FINGERPRINT_KEYS") {
            Ok(s) if !s.trim().is_empty() => Self::parse(&s, master),
            _ => Ok(Self::from_master(master)),
        }
    }

    #[must_use]
    pub fn current_kid(&self) -> &str {
        &self.keys[0].0
    }

    #[must_use]
    pub fn kids(&self) -> Vec<&str> {
        self.keys.iter().map(|(k, _)| k.as_str()).collect()
    }

    /// Fingerprints of a raw destination under every configured key.
    #[must_use]
    pub fn compute(&self, tenant: TenantId, channel: Channel, destination: &str) -> Fingerprints {
        let normalized = format!(
            "{}|{}|{}",
            tenant.0,
            channel.as_str(),
            normalize_destination(channel, destination)
        );
        let tagged: Vec<String> = self
            .keys
            .iter()
            .map(|(kid, key)| format!("{kid}:{}", hmac_hex(key, &normalized)))
            .collect();
        let primary = hmac_hex(&self.keys[0].1, &normalized);
        Fingerprints { primary, tagged }
    }
}

fn hmac_hex(key: &[u8], msg: &str) -> String {
    #[allow(clippy::expect_used)] // HMAC accepts any key length; 32 bytes enforced at parse.
    let mut mac = Hmac::<Sha256>::new_from_slice(key).expect("hmac key");
    mac.update(msg.as_bytes());
    hex::encode(mac.finalize().into_bytes())
}

/// Phone numbers: digits and `+` only; emails and handles: trimmed, leading
/// `@` stripped, lowercase.
#[must_use]
pub fn normalize_destination(channel: Channel, d: &str) -> String {
    match channel {
        Channel::Sms => d
            .chars()
            .filter(|c| c.is_ascii_digit() || *c == '+')
            .collect(),
        _ => d.trim().trim_start_matches('@').to_ascii_lowercase(),
    }
}

/// AAD binding a sealed raw destination to its row.
#[must_use]
pub fn destination_aad(table: &str, tenant: TenantId, id: uuid::Uuid) -> String {
    format!("destination:{table}:{}:{id}", tenant.0)
}

/// Marker tag on a row created from a bare hash whose key could not be
/// established (hash-only operator input matching no stored row). No lookup
/// ever produces it; `status` counts such rows as `unverified` and blocks key
/// removal until `rekey` recovers the raw destination (or an operator re-files
/// the suppression with the destination itself). `!` is not a valid kid char.
pub const UNVERIFIED: &str = "!unverified";

impl FingerprintKeys {
    /// Bare hash of unknown key version: tag it under EVERY configured kid (so it
    /// keeps matching whichever key produced it while that key is listed) and mark
    /// the row unverified so it can never silently survive the removal of its key.
    #[must_use]
    pub fn tag_unverified(&self, hash: &str) -> Fingerprints {
        let mut tagged: Vec<String> = self.kids().iter().map(|k| format!("{k}:{hash}")).collect();
        tagged.push(UNVERIFIED.to_owned());
        Fingerprints {
            primary: hash.to_owned(),
            tagged,
        }
    }
}

/// Every tag already stored for a bare hash (operator hash-only input): the
/// union of fingerprint sets of rows whose hash column equals it or that carry
/// it under any configured kid (array overlap — uses the GIN indexes).
/// Empty when nothing in the tenant refers to it.
pub async fn tags_for_hash(
    tx: &mut crate::tx::TenantTx<'_>,
    keys: &FingerprintKeys,
    hash: &str,
) -> Result<Vec<String>, StoreError> {
    let t = tx.tenant().0;
    let cands: Vec<String> = keys.kids().iter().map(|k| format!("{k}:{hash}")).collect();
    let rows: Vec<Vec<String>> = sqlx::query_scalar(
        "SELECT destination_fingerprints FROM kernel.inbound_events WHERE tenant_id = $1 AND (source_destination_hash = $2 OR destination_fingerprints && $3)
         UNION ALL SELECT destination_fingerprints FROM kernel.actions WHERE tenant_id = $1 AND channel IS NOT NULL AND (destination_hash = $2 OR destination_fingerprints && $3)
         UNION ALL SELECT destination_fingerprints FROM kernel.suppressions WHERE tenant_id = $1 AND (normalized_destination_hash = $2 OR destination_fingerprints && $3)
         UNION ALL SELECT destination_fingerprints FROM kernel.contact_permissions WHERE tenant_id = $1 AND (destination_hash = $2 OR destination_fingerprints && $3)",
    )
    .bind(t)
    .bind(hash)
    .bind(&cands)
    .fetch_all(tx.conn())
    .await?;
    let mut out: Vec<String> = Vec::new();
    for f in rows.into_iter().flatten() {
        if f != UNVERIFIED && !out.contains(&f) {
            out.push(f);
        }
    }
    Ok(out)
}

/// Tables holding destination fingerprints: (table, pk, primary-hash column).
pub const FINGERPRINT_TABLES: &[(&str, &str, &str)] = &[
    ("actions", "action_id", "destination_hash"),
    ("inbound_events", "event_id", "source_destination_hash"),
    (
        "suppressions",
        "suppression_id",
        "normalized_destination_hash",
    ),
    ("contact_permissions", "permission_id", "destination_hash"),
    // Hash-only privacy fences must block retirement when the replacement
    // key cannot match them. Never silently omit them from orphan checks.
    (
        "privacy_destination_fences",
        "request_id",
        "destination_hash",
    ),
];

/// Per-table rotation status (summed over the tenants scanned).
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct TableStatus {
    pub table: &'static str,
    /// Destination rows with no tag under the current key: rekey before retiring anything.
    pub lacking_current: u64,
    /// Destination rows with no tag under ANY configured key: they no longer
    /// match any lookup. Must be 0; a non-zero value means a key was removed
    /// before rekey finished (restore it to `MK_FINGERPRINT_KEYS`).
    pub orphaned: u64,
    /// Rows created from a bare hash of unknown key version (`UNVERIFIED`).
    pub unverified: u64,
    /// Tenants scanned (from `kernel.tenant_directory`); 0 means nothing was checked.
    pub tenants: u64,
}

impl TableStatus {
    #[must_use]
    pub fn blocking(&self) -> u64 {
        self.lacking_current + self.orphaned + self.unverified
    }
}

fn dest_filter(table: &str, hash_col: &str) -> String {
    match table {
        "actions" => format!("{hash_col} IS NOT NULL AND channel IS NOT NULL"),
        _ => format!("{hash_col} IS NOT NULL"),
    }
}

/// Tenants to operate on: one, or every tenant in the directory.
async fn tenants_for(
    pool: &sqlx::PgPool,
    tenant: Option<TenantId>,
) -> Result<Vec<TenantId>, StoreError> {
    match tenant {
        Some(t) => Ok(vec![t]),
        None => crate::audit::all_tenants(pool).await,
    }
}

async fn status_in(
    tx: &mut crate::tx::TenantTx<'_>,
    keys: &FingerprintKeys,
) -> Result<Vec<TableStatus>, StoreError> {
    let kids: Vec<String> = keys.kids().iter().map(|k| (*k).to_owned()).collect();
    let t = tx.tenant().0;
    let mut out = Vec::new();
    for (table, _, hash_col) in FINGERPRINT_TABLES {
        let filter = dest_filter(table, hash_col);
        let (lacking, orphaned, unverified): (i64, i64, i64) =
            sqlx::query_as(sqlx::AssertSqlSafe(format!(
                "SELECT
               count(*) FILTER (WHERE NOT EXISTS (SELECT 1 FROM unnest(destination_fingerprints) x WHERE split_part(x, ':', 1) = $1)),
               count(*) FILTER (WHERE NOT EXISTS (SELECT 1 FROM unnest(destination_fingerprints) x WHERE split_part(x, ':', 1) = ANY($2))),
               count(*) FILTER (WHERE $4 = ANY(destination_fingerprints))
             FROM kernel.{table} WHERE tenant_id = $3 AND {filter}"
            )))
            .bind(keys.current_kid())
            .bind(&kids)
            .bind(t)
            .bind(UNVERIFIED)
            .fetch_one(tx.conn())
            .await?;
        out.push(TableStatus {
            table,
            lacking_current: u64::try_from(lacking).unwrap_or(0),
            orphaned: u64::try_from(orphaned).unwrap_or(0),
            unverified: u64::try_from(unverified).unwrap_or(0),
            tenants: 1,
        });
    }
    Ok(out)
}

/// Operator: rotation status per table, summed over tenants. Each tenant is
/// read inside its own tenant transaction, so row-level security is satisfied
/// for any login with the table grants — no BYPASSRLS, never a vacuous count.
pub async fn status(
    pool: &sqlx::PgPool,
    keys: &FingerprintKeys,
    tenant: Option<TenantId>,
) -> Result<Vec<TableStatus>, StoreError> {
    let store = crate::Store::from_pool(pool.clone());
    let mut sum: Vec<TableStatus> = FINGERPRINT_TABLES
        .iter()
        .map(|(t, _, _)| TableStatus {
            table: t,
            ..TableStatus::default()
        })
        .collect();
    for t in tenants_for(pool, tenant).await? {
        let mut tx = store.begin(t).await?;
        for (acc, row) in sum.iter_mut().zip(status_in(&mut tx, keys).await?) {
            acc.lacking_current += row.lacking_current;
            acc.orphaned += row.orphaned;
            acc.unverified += row.unverified;
            acc.tenants += 1;
        }
        tx.commit().await?;
    }
    Ok(sum)
}

/// Result of a rekey pass.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct RekeyReport {
    pub updated: u64,
    /// Rows whose raw destination could not be recovered (no sealed copy and
    /// no action/inbound row sharing a fingerprint) or whose recovered raw
    /// value does not reproduce any stored tag. Left untouched; they keep
    /// blocking retirement via `status`.
    pub unresolved: u64,
    pub tenants: u64,
}

/// Operator: add every configured key's tag to every destination row, one
/// tenant transaction per tenant. Idempotent and resumable; never removes a
/// valid tag. The recovered raw destination is accepted only if it reproduces
/// a tag the row already holds, so a wrong match can never re-point a row;
/// an `UNVERIFIED` row whose raw destination is recovered and verified is
/// rewritten to the verified tags (its guessed tags dropped).
pub async fn rekey(
    pool: &sqlx::PgPool,
    keyring: &mk_crypto::Keyring,
    keys: &FingerprintKeys,
    tenant: Option<TenantId>,
) -> Result<RekeyReport, StoreError> {
    let store = crate::Store::from_pool(pool.clone());
    let mut rep = RekeyReport::default();
    for t in tenants_for(pool, tenant).await? {
        let mut tx = store.begin(t).await?;
        rekey_tenant(&mut tx, keyring, keys, &mut rep).await?;
        tx.commit().await?;
        rep.tenants += 1;
    }
    Ok(rep)
}

async fn rekey_tenant(
    tx: &mut crate::tx::TenantTx<'_>,
    keyring: &mk_crypto::Keyring,
    keys: &FingerprintKeys,
    rep: &mut RekeyReport,
) -> Result<(), StoreError> {
    use secrecy::ExposeSecret as _;
    use sqlx::Row as _;
    use std::collections::HashMap;
    let tenant = tx.tenant();
    // tag → raw destination, learned from actions (canonical `to`) and inbound
    // (sealed `From`); used for suppression/permission rows without a sealed copy.
    let mut known: HashMap<(String, String), String> = HashMap::new();
    let channel_of = |s: &str| -> Option<Channel> {
        serde_json::from_value(serde_json::Value::String(s.to_owned())).ok()
    };
    let unseal = |table: &str, id: uuid::Uuid, b: Vec<u8>| {
        keyring
            .unseal(&destination_aad(table, tenant, id), &b)
            .ok()
            .map(|s| s.expose_secret().to_owned())
    };

    // Pass 1: actions.
    let rows = sqlx::query(
        "SELECT action_id, channel, canonical_request, destination_fingerprints FROM kernel.actions
         WHERE tenant_id = $1 AND destination_hash IS NOT NULL AND channel IS NOT NULL",
    )
    .bind(tenant.0)
    .fetch_all(tx.conn())
    .await?;
    for r in rows {
        let id: uuid::Uuid = r.try_get("action_id")?;
        let ch_s: String = r.try_get("channel")?;
        let tags: Vec<String> = r.try_get("destination_fingerprints")?;
        let canonical: Vec<u8> = r.try_get("canonical_request")?;
        let raw = serde_json::from_slice::<serde_json::Value>(&canonical)
            .ok()
            .and_then(|v| v.get("arguments")?.get("to")?.as_str().map(str::to_owned));
        let (Some(ch), Some(raw)) = (channel_of(&ch_s), raw) else {
            rep.unresolved += u64::from(!complete(&tags, keys));
            continue;
        };
        apply(
            tx,
            "actions",
            "action_id",
            id,
            ch,
            &ch_s,
            &raw,
            &tags,
            keys,
            &mut known,
            rep,
        )
        .await?;
    }
    // Pass 2: inbound events (sms).
    let rows = sqlx::query(
        "SELECT event_id, destination_sealed, destination_fingerprints FROM kernel.inbound_events
         WHERE tenant_id = $1 AND source_destination_hash IS NOT NULL",
    )
    .bind(tenant.0)
    .fetch_all(tx.conn())
    .await?;
    for r in rows {
        let id: uuid::Uuid = r.try_get("event_id")?;
        let tags: Vec<String> = r.try_get("destination_fingerprints")?;
        let sealed: Option<Vec<u8>> = r.try_get("destination_sealed")?;
        let Some(raw) = sealed.and_then(|b| unseal("inbound_events", id, b)) else {
            rep.unresolved += u64::from(!complete(&tags, keys));
            continue;
        };
        apply(
            tx,
            "inbound_events",
            "event_id",
            id,
            Channel::Sms,
            "sms",
            &raw,
            &tags,
            keys,
            &mut known,
            rep,
        )
        .await?;
    }
    // Pass 3/4: suppressions and permissions — sealed raw, else a learned one.
    for (table, pk, hash_col) in [
        (
            "suppressions",
            "suppression_id",
            "normalized_destination_hash",
        ),
        ("contact_permissions", "permission_id", "destination_hash"),
    ] {
        let rows = sqlx::query(sqlx::AssertSqlSafe(format!(
            "SELECT {pk} AS id, channel, destination_sealed, destination_fingerprints FROM kernel.{table}
             WHERE tenant_id = $1 AND {hash_col} IS NOT NULL AND channel IS NOT NULL
             ORDER BY (destination_sealed IS NULL)" // sealed rows first: they teach unsealed ones
        )))
        .bind(tenant.0)
        .fetch_all(tx.conn())
        .await?;
        for r in rows {
            let id: uuid::Uuid = r.try_get("id")?;
            let ch_s: String = r.try_get("channel")?;
            let tags: Vec<String> = r.try_get("destination_fingerprints")?;
            let sealed: Option<Vec<u8>> = r.try_get("destination_sealed")?;
            let raw = sealed.and_then(|b| unseal(table, id, b)).or_else(|| {
                tags.iter()
                    .filter(|t| *t != UNVERIFIED)
                    .find_map(|tag| known.get(&(ch_s.clone(), tag.clone())).cloned())
            });
            let (Some(ch), Some(raw)) = (channel_of(&ch_s), raw) else {
                rep.unresolved += u64::from(!complete(&tags, keys));
                continue;
            };
            apply(
                tx, table, pk, id, ch, &ch_s, &raw, &tags, keys, &mut known, rep,
            )
            .await?;
        }
    }
    Ok(())
}

/// Operator: after the old key has been removed from `MK_FINGERPRINT_KEYS`,
/// strip its tags and rewrite each row's hash column to the current key's
/// value — so a compromised key's HMACs no longer sit in the database.
/// Refused while any tenant has a row lacking the current kid, orphaned, or
/// unverified, or if `kid` is still configured. Per tenant, the check and the
/// update run in ONE transaction, and the update only touches rows that carry
/// a current-kid tag (a row without one is never blanked). Returns rows changed.
pub async fn prune(
    pool: &sqlx::PgPool,
    keys: &FingerprintKeys,
    kid: &str,
    tenant: Option<TenantId>,
) -> Result<u64, StoreError> {
    if keys.kids().contains(&kid) {
        return Err(StoreError::Conflict(
            "kid is still configured; remove it from MK_FINGERPRINT_KEYS first",
        ));
    }
    if status(pool, keys, tenant)
        .await?
        .iter()
        .any(|t| t.blocking() > 0)
    {
        return Err(StoreError::Conflict(
            "rows lack the current kid or are unverified; run fingerprint-rekey first",
        ));
    }
    let store = crate::Store::from_pool(pool.clone());
    let mut n = 0;
    for t in tenants_for(pool, tenant).await? {
        let mut tx = store.begin(t).await?;
        if status_in(&mut tx, keys)
            .await?
            .iter()
            .any(|s| s.blocking() > 0)
        {
            return Err(StoreError::Conflict(
                "a row lost its current-kid tag during prune; nothing changed for this tenant",
            ));
        }
        for (table, _, hash_col) in FINGERPRINT_TABLES {
            let filter = dest_filter(table, hash_col);
            n += sqlx::query(sqlx::AssertSqlSafe(format!(
                "UPDATE kernel.{table} SET
                   destination_fingerprints = ARRAY(SELECT x FROM unnest(destination_fingerprints) x WHERE split_part(x, ':', 1) <> $1),
                   {hash_col} = (SELECT split_part(x, ':', 2) FROM unnest(destination_fingerprints) x WHERE split_part(x, ':', 1) = $2 LIMIT 1)
                 WHERE tenant_id = $3 AND {filter}
                   AND EXISTS (SELECT 1 FROM unnest(destination_fingerprints) x WHERE split_part(x, ':', 1) = $2)
                   AND (EXISTS (SELECT 1 FROM unnest(destination_fingerprints) x WHERE split_part(x, ':', 1) = $1)
                        OR {hash_col} IS DISTINCT FROM (SELECT split_part(x, ':', 2) FROM unnest(destination_fingerprints) x WHERE split_part(x, ':', 1) = $2 LIMIT 1))"
            )))
            .bind(kid)
            .bind(keys.current_kid())
            .bind(t.0)
            .execute(tx.conn())
            .await?
            .rows_affected();
        }
        tx.commit().await?;
    }
    Ok(n)
}

fn has_all(tags: &[String], keys: &FingerprintKeys) -> bool {
    keys.kids()
        .iter()
        .all(|k| tags.iter().any(|t| t.split(':').next() == Some(*k)))
}

/// Nothing for rekey to do: every kid tagged and no unverified marker.
fn complete(tags: &[String], keys: &FingerprintKeys) -> bool {
    has_all(tags, keys) && !tags.iter().any(|t| t == UNVERIFIED)
}

#[allow(clippy::too_many_arguments)]
async fn apply(
    tx: &mut crate::tx::TenantTx<'_>,
    table: &str,
    pk: &str,
    id: uuid::Uuid,
    channel: Channel,
    channel_s: &str,
    raw: &str,
    tags: &[String],
    keys: &FingerprintKeys,
    known: &mut std::collections::HashMap<(String, String), String>,
    rep: &mut RekeyReport,
) -> Result<(), StoreError> {
    let done = complete(tags, keys);
    let fresh = keys.compute(tx.tenant(), channel, raw);
    let real: Vec<String> = tags.iter().filter(|t| *t != UNVERIFIED).cloned().collect();
    // The recovered raw value must reproduce a stored tag (or the row has none yet).
    if !real.is_empty() && !fresh.tagged.iter().any(|f| real.contains(f)) {
        // A complete row needs nothing; never count or touch it.
        rep.unresolved += u64::from(!done);
        return Ok(());
    }
    for tag in real.iter().chain(fresh.tagged.iter()) {
        known.insert((channel_s.to_owned(), tag.clone()), raw.to_owned());
    }
    if done {
        return Ok(());
    }
    let merged: Vec<String> = if tags.iter().any(|t| t == UNVERIFIED) {
        // Verified now: keep only tags the raw value reproduces, plus tags of kids
        // no longer configured (they are pruned separately).
        let kids = keys.kids();
        let mut m = fresh.tagged.clone();
        for t in &real {
            let kid = t.split(':').next().unwrap_or("");
            if !kids.contains(&kid) && !m.contains(t) {
                m.push(t.clone());
            }
        }
        m
    } else {
        Fingerprints {
            primary: fresh.primary.clone(),
            tagged: real.clone(),
        }
        .union(&fresh.tagged)
    };
    if merged != tags {
        sqlx::query(sqlx::AssertSqlSafe(format!(
            "UPDATE kernel.{table} SET destination_fingerprints = $3 WHERE tenant_id = $1 AND {pk} = $2"
        )))
        .bind(tx.tenant().0)
        .bind(id)
        .bind(&merged)
        .execute(tx.conn())
        .await?;
        rep.updated += 1;
    }
    Ok(())
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
mod tests {
    use super::*;

    fn tenant() -> TenantId {
        TenantId::from_uuid(uuid::Uuid::parse_str("00000000-0000-4000-8000-000000000001").unwrap())
    }

    #[test]
    fn default_key_reproduces_the_python_vector() {
        let master = MasterKey::from_bytes(&[1u8; 32]).unwrap();
        let fp = FingerprintKeys::from_master(&master).compute(
            tenant(),
            Channel::Sms,
            "+1 (555) 555-0100",
        );
        let v = "0973a4c021bc296b195a6ab4533e067bebeb6f33f901c3b400cdfb83805de8ed";
        assert_eq!(fp.primary, v);
        assert_eq!(fp.tagged, vec![format!("m0:{v}")]);
    }

    #[test]
    fn rotated_set_keeps_the_old_tag_and_switches_primary() {
        use base64::Engine as _;
        let master = MasterKey::from_bytes(&[1u8; 32]).unwrap();
        let k2 = base64::engine::general_purpose::STANDARD.encode([2u8; 32]);
        let before =
            FingerprintKeys::from_master(&master).compute(tenant(), Channel::Sms, "+15555550100");
        let keys = FingerprintKeys::parse(&format!("k2={k2},m0=master"), &master).unwrap();
        let after = keys.compute(tenant(), Channel::Sms, "+1 555-555-0100");
        assert_eq!(keys.current_kid(), "k2");
        assert_ne!(after.primary, before.primary);
        assert!(
            after.tagged.contains(&before.tagged[0]),
            "old tag must still match"
        );
        assert!(after.tagged[0].starts_with("k2:"));
    }

    #[test]
    fn parse_rejects_bad_specs() {
        let master = MasterKey::from_bytes(&[1u8; 32]).unwrap();
        for bad in [
            "",
            "k2",
            "K2=master",
            "k2=master,k2=master",
            "k2=AAAA",
            "k2=!!!",
            "waytoolongkidname01=master",
        ] {
            assert!(
                FingerprintKeys::parse(bad, &master).is_err(),
                "{bad:?} accepted"
            );
        }
    }

    #[test]
    fn lock_keys_are_sorted_and_deduped() {
        let f = Fingerprints {
            primary: "b".into(),
            tagged: vec!["m0:b".into(), "k2:a".into(), "m0:b".into()],
        };
        assert_eq!(f.lock_keys(), vec!["k2:a".to_owned(), "m0:b".to_owned()]);
    }

    #[test]
    fn debug_never_prints_key_material() {
        let master = MasterKey::from_bytes(&[7u8; 32]).unwrap();
        let s = format!("{:?}", FingerprintKeys::from_master(&master));
        assert!(!s.contains("7, 7"));
        assert!(s.contains("m0"));
    }
}
