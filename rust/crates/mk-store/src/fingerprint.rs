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

    /// Tag a bare hash supplied by a caller (hash-only suppression input) as
    /// the current key's value. Used only when no stored row identifies it.
    #[must_use]
    pub fn tag_current(&self, hash: &str) -> Fingerprints {
        Fingerprints {
            primary: hash.to_owned(),
            tagged: vec![format!("{}:{hash}", self.current_kid())],
        }
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

/// Every tag already stored for a bare hash (operator hash-only input): the
/// union of fingerprint sets of rows whose hash column, or any tag, equals it.
/// Empty when nothing in the tenant refers to it.
pub async fn tags_for_hash(
    tx: &mut crate::tx::TenantTx<'_>,
    hash: &str,
) -> Result<Vec<String>, StoreError> {
    let t = tx.tenant().0;
    let rows: Vec<Vec<String>> = sqlx::query_scalar(
        "WITH m AS (
           SELECT destination_fingerprints f, source_destination_hash h FROM kernel.inbound_events WHERE tenant_id = $1
           UNION ALL SELECT destination_fingerprints, destination_hash FROM kernel.actions WHERE tenant_id = $1 AND channel IS NOT NULL
           UNION ALL SELECT destination_fingerprints, normalized_destination_hash FROM kernel.suppressions WHERE tenant_id = $1
           UNION ALL SELECT destination_fingerprints, destination_hash FROM kernel.contact_permissions WHERE tenant_id = $1)
         SELECT f FROM m WHERE h = $2 OR EXISTS (SELECT 1 FROM unnest(f) x WHERE split_part(x, ':', 2) = $2)",
    )
    .bind(t)
    .bind(hash)
    .fetch_all(tx.conn())
    .await?;
    let mut out: Vec<String> = Vec::new();
    for f in rows.into_iter().flatten() {
        if !out.contains(&f) {
            out.push(f);
        }
    }
    Ok(out)
}

/// Tables holding destination fingerprints: (table, pk, primary-hash column, has sealed raw).
pub const FINGERPRINT_TABLES: &[(&str, &str, &str)] = &[
    ("actions", "action_id", "destination_hash"),
    ("inbound_events", "event_id", "source_destination_hash"),
    (
        "suppressions",
        "suppression_id",
        "normalized_destination_hash",
    ),
    ("contact_permissions", "permission_id", "destination_hash"),
];

/// Per-table rotation status.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct TableStatus {
    pub table: &'static str,
    /// Destination rows with no tag under the current key: rekey before retiring anything.
    pub lacking_current: u64,
    /// Destination rows with no tag under ANY configured key: they no longer
    /// match any lookup. Must be 0; a non-zero value means a key was removed
    /// before rekey finished (restore it to `MK_FINGERPRINT_KEYS`).
    pub orphaned: u64,
}

fn tenant_filter(tenant: Option<TenantId>) -> String {
    tenant.map_or(String::new(), |t| format!(" AND tenant_id = '{}'", t.0))
}

fn dest_filter(table: &str, hash_col: &str) -> String {
    match table {
        "actions" => format!("{hash_col} IS NOT NULL AND channel IS NOT NULL"),
        _ => format!("{hash_col} IS NOT NULL"),
    }
}

/// Operator (owner role, all tenants): rotation status per table.
pub async fn status(
    pool: &sqlx::PgPool,
    keys: &FingerprintKeys,
    tenant: Option<TenantId>,
) -> Result<Vec<TableStatus>, StoreError> {
    let kids: Vec<String> = keys.kids().iter().map(|k| (*k).to_owned()).collect();
    let mut out = Vec::new();
    for (table, _, hash_col) in FINGERPRINT_TABLES {
        let filter = dest_filter(table, hash_col) + &tenant_filter(tenant);
        let (lacking, orphaned): (i64, i64) = sqlx::query_as(&format!(
            "SELECT
               count(*) FILTER (WHERE NOT EXISTS (SELECT 1 FROM unnest(destination_fingerprints) x WHERE split_part(x, ':', 1) = $1)),
               count(*) FILTER (WHERE NOT EXISTS (SELECT 1 FROM unnest(destination_fingerprints) x WHERE split_part(x, ':', 1) = ANY($2)))
             FROM kernel.{table} WHERE {filter}"
        ))
        .bind(keys.current_kid())
        .bind(&kids)
        .fetch_one(pool)
        .await?;
        out.push(TableStatus {
            table,
            lacking_current: u64::try_from(lacking).unwrap_or(0),
            orphaned: u64::try_from(orphaned).unwrap_or(0),
        });
    }
    Ok(out)
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
}

/// Operator (owner role, all tenants): add every configured key's tag to
/// every destination row. Idempotent and resumable; never removes a tag.
/// The recovered raw destination is accepted only if it reproduces a tag the
/// row already holds, so a wrong match can never re-point a row.
pub async fn rekey(
    pool: &sqlx::PgPool,
    keyring: &mk_crypto::Keyring,
    keys: &FingerprintKeys,
    tenant: Option<TenantId>,
) -> Result<RekeyReport, StoreError> {
    use secrecy::ExposeSecret as _;
    use sqlx::Row as _;
    use std::collections::HashMap;
    let tf = tenant_filter(tenant);

    let mut rep = RekeyReport::default();
    // tag → raw destination, learned from actions (canonical `to`) and inbound
    // (sealed `From`); used for suppression/permission rows without a sealed copy.
    let mut known: HashMap<(uuid::Uuid, String, String), String> = HashMap::new();

    let channel_of = |s: &str| -> Option<Channel> {
        serde_json::from_value(serde_json::Value::String(s.to_owned())).ok()
    };

    // Pass 1: actions.
    let rows = sqlx::query(&format!(
        "SELECT tenant_id, action_id, channel, canonical_request, destination_fingerprints FROM kernel.actions
         WHERE destination_hash IS NOT NULL AND channel IS NOT NULL{tf}"
    ))
    .fetch_all(pool)
    .await?;
    for r in rows {
        let (t, id): (uuid::Uuid, uuid::Uuid) = (r.try_get("tenant_id")?, r.try_get("action_id")?);
        let ch_s: String = r.try_get("channel")?;
        let tags: Vec<String> = r.try_get("destination_fingerprints")?;
        let canonical: Vec<u8> = r.try_get("canonical_request")?;
        let raw = serde_json::from_slice::<serde_json::Value>(&canonical)
            .ok()
            .and_then(|v| v.get("arguments")?.get("to")?.as_str().map(str::to_owned));
        let (Some(ch), Some(raw)) = (channel_of(&ch_s), raw) else {
            rep.unresolved += 1;
            continue;
        };
        apply(
            pool,
            "actions",
            "action_id",
            t,
            id,
            ch,
            &ch_s,
            &raw,
            &tags,
            keys,
            &mut known,
            &mut rep,
        )
        .await?;
    }
    // Pass 2: inbound events (sms).
    let rows = sqlx::query(&format!(
        "SELECT tenant_id, event_id, destination_sealed, destination_fingerprints FROM kernel.inbound_events
         WHERE source_destination_hash IS NOT NULL{tf}"
    ))
    .fetch_all(pool)
    .await?;
    for r in rows {
        let (t, id): (uuid::Uuid, uuid::Uuid) = (r.try_get("tenant_id")?, r.try_get("event_id")?);
        let tags: Vec<String> = r.try_get("destination_fingerprints")?;
        let sealed: Option<Vec<u8>> = r.try_get("destination_sealed")?;
        let raw = sealed.and_then(|b| {
            keyring
                .unseal(
                    &destination_aad("inbound_events", TenantId::from_uuid(t), id),
                    &b,
                )
                .ok()
                .map(|s| s.expose_secret().to_owned())
        });
        let Some(raw) = raw else {
            rep.unresolved += u64::from(!has_all(&tags, keys));
            continue;
        };
        apply(
            pool,
            "inbound_events",
            "event_id",
            t,
            id,
            Channel::Sms,
            "sms",
            &raw,
            &tags,
            keys,
            &mut known,
            &mut rep,
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
        let rows = sqlx::query(&format!(
            "SELECT tenant_id, {pk} AS id, channel, destination_sealed, destination_fingerprints FROM kernel.{table}
             WHERE {hash_col} IS NOT NULL AND channel IS NOT NULL{tf}"
        ))
        .fetch_all(pool)
        .await?;
        for r in rows {
            let (t, id): (uuid::Uuid, uuid::Uuid) = (r.try_get("tenant_id")?, r.try_get("id")?);
            let ch_s: String = r.try_get("channel")?;
            let tags: Vec<String> = r.try_get("destination_fingerprints")?;
            let sealed: Option<Vec<u8>> = r.try_get("destination_sealed")?;
            let raw = sealed
                .and_then(|b| {
                    keyring
                        .unseal(&destination_aad(table, TenantId::from_uuid(t), id), &b)
                        .ok()
                        .map(|s| s.expose_secret().to_owned())
                })
                .or_else(|| {
                    tags.iter()
                        .find_map(|tag| known.get(&(t, ch_s.clone(), tag.clone())).cloned())
                });
            let (Some(ch), Some(raw)) = (channel_of(&ch_s), raw) else {
                rep.unresolved += u64::from(!has_all(&tags, keys));
                continue;
            };
            apply(
                pool, table, pk, t, id, ch, &ch_s, &raw, &tags, keys, &mut known, &mut rep,
            )
            .await?;
        }
    }
    Ok(rep)
}

/// Operator (owner role): after the old key has been removed from
/// `MK_FINGERPRINT_KEYS`, strip its tags and rewrite each row's hash column to
/// the current key's value — so a compromised key's HMACs no longer sit in
/// the database. Refused while any row lacks the current kid or is orphaned,
/// or if `kid` is still configured. Returns rows changed.
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
    let st = status(pool, keys, tenant).await?;
    if st.iter().any(|t| t.lacking_current > 0 || t.orphaned > 0) {
        return Err(StoreError::Conflict(
            "rows lack the current kid; run fingerprint-rekey first",
        ));
    }
    let mut n = 0;
    for (table, _, hash_col) in FINGERPRINT_TABLES {
        let filter = dest_filter(table, hash_col) + &tenant_filter(tenant);
        n += sqlx::query(&format!(
            "UPDATE kernel.{table} SET
               destination_fingerprints = ARRAY(SELECT x FROM unnest(destination_fingerprints) x WHERE split_part(x, ':', 1) <> $1),
               {hash_col} = (SELECT split_part(x, ':', 2) FROM unnest(destination_fingerprints) x WHERE split_part(x, ':', 1) = $2 LIMIT 1)
             WHERE {filter} AND (
               EXISTS (SELECT 1 FROM unnest(destination_fingerprints) x WHERE split_part(x, ':', 1) = $1)
               OR {hash_col} IS DISTINCT FROM (SELECT split_part(x, ':', 2) FROM unnest(destination_fingerprints) x WHERE split_part(x, ':', 1) = $2 LIMIT 1))"
        ))
        .bind(kid)
        .bind(keys.current_kid())
        .execute(pool)
        .await?
        .rows_affected();
    }
    Ok(n)
}

fn has_all(tags: &[String], keys: &FingerprintKeys) -> bool {
    keys.kids()
        .iter()
        .all(|k| tags.iter().any(|t| t.split(':').next() == Some(*k)))
}

#[allow(clippy::too_many_arguments)]
async fn apply(
    pool: &sqlx::PgPool,
    table: &str,
    pk: &str,
    tenant: uuid::Uuid,
    id: uuid::Uuid,
    channel: Channel,
    channel_s: &str,
    raw: &str,
    tags: &[String],
    keys: &FingerprintKeys,
    known: &mut std::collections::HashMap<(uuid::Uuid, String, String), String>,
    rep: &mut RekeyReport,
) -> Result<(), StoreError> {
    let complete = has_all(tags, keys);
    let fresh = keys.compute(TenantId::from_uuid(tenant), channel, raw);
    // The recovered raw value must reproduce a stored tag (or the row has none yet).
    if !tags.is_empty() && !fresh.tagged.iter().any(|f| tags.contains(f)) {
        // A complete row needs nothing; never count or touch it.
        rep.unresolved += u64::from(!complete);
        return Ok(());
    }
    for tag in tags.iter().chain(fresh.tagged.iter()) {
        known.insert((tenant, channel_s.to_owned(), tag.clone()), raw.to_owned());
    }
    if complete {
        return Ok(());
    }
    let merged = Fingerprints {
        primary: fresh.primary.clone(),
        tagged: tags.to_vec(),
    }
    .union(&fresh.tagged);
    if merged.len() != tags.len() {
        sqlx::query(&format!(
            "UPDATE kernel.{table} SET destination_fingerprints = $3 WHERE tenant_id = $1 AND {pk} = $2"
        ))
        .bind(tenant)
        .bind(id)
        .bind(&merged)
        .execute(pool)
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
