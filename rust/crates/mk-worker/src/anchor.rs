//! External anchoring of audit roots (contract S14).
//!
//! The per-tenant hash chain detects edits *inside* the database, but an operator
//! with database-owner access could rewrite a tenant's whole chain consistently.
//! An anchor fixes each tenant's `(count, last_hash)` at a point in time in a
//! destination the database operator cannot rewrite:
//!
//! * one leaf per tenant: `tenant_ref` (SHA-256 of a domain tag and the tenant id,
//!   so the published root carries no raw tenant identifier — S12), `count`,
//!   `last_hash` (content-free: a digest of digests);
//! * an RFC 6962-style Merkle root over the leaves;
//! * an Ed25519 signature over the canonical anchor by a key the database never
//!   holds (`MK_ANCHOR_SIGNING_KEY`);
//! * written to an S3 bucket with Object Lock in COMPLIANCE mode (retention set
//!   per object), or appended to a file for development.
//!
//! `verify` re-derives every anchored leaf from the live database: the event at
//! `tenant_sequence = count` must still carry `last_hash`, and the chain must not
//! have shrunk. Any rewrite of anchored history is reported.

use base64::Engine as _;
use chrono::{DateTime, Utc};
use ed25519_dalek::{Signer as _, SigningKey, Verifier as _, VerifyingKey};
use hmac::{Hmac, Mac};
use serde::{Deserialize, Serialize};
use sha2::{Digest as _, Sha256};

pub const VERSION: u32 = 1;
const B64: base64::engine::GeneralPurpose = base64::engine::general_purpose::URL_SAFE_NO_PAD;

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Leaf {
    pub tenant_ref: String,
    pub count: i64,
    pub last_hash: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Anchor {
    pub version: u32,
    pub anchored_at: DateTime<Utc>,
    pub key_id: String,
    pub merkle_root: String,
    pub leaves: Vec<Leaf>,
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub signature: String,
}

#[must_use]
pub fn tenant_ref(tenant: uuid::Uuid) -> String {
    hex::encode(Sha256::digest(
        format!("mk-anchor-tenant-v1:{tenant}").as_bytes(),
    ))
}

fn leaf_hash(l: &Leaf) -> [u8; 32] {
    let mut h = Sha256::new();
    h.update([0u8]);
    h.update(l.tenant_ref.as_bytes());
    h.update([0u8]);
    h.update(l.count.to_be_bytes());
    h.update(l.last_hash.as_bytes());
    h.finalize().into()
}

/// RFC 6962 Merkle tree hash over leaves sorted by `tenant_ref` (order-independent
/// input, deterministic root). Empty tree = SHA-256 of nothing.
#[must_use]
pub fn merkle_root(leaves: &[Leaf]) -> String {
    let mut sorted: Vec<&Leaf> = leaves.iter().collect();
    sorted.sort_by(|a, b| a.tenant_ref.cmp(&b.tenant_ref));
    let mut level: Vec<[u8; 32]> = sorted.into_iter().map(leaf_hash).collect();
    if level.is_empty() {
        return hex::encode(Sha256::digest([]));
    }
    while level.len() > 1 {
        level = level
            .chunks(2)
            .map(|c| match c {
                [l, r] => {
                    let mut h = Sha256::new();
                    h.update([1u8]);
                    h.update(l);
                    h.update(r);
                    h.finalize().into()
                }
                [only] => *only, // RFC 6962: an unpaired node is promoted
                _ => unreachable!(),
            })
            .collect();
    }
    hex::encode(level[0])
}

fn signing_bytes(a: &Anchor) -> Vec<u8> {
    let mut u = a.clone();
    u.signature = String::new();
    let mut leaves = u.leaves.clone();
    leaves.sort_by(|x, y| x.tenant_ref.cmp(&y.tenant_ref));
    u.leaves = leaves;
    mk_crypto::canonicalize(&serde_json::to_value(&u).unwrap_or_default()).unwrap_or_default()
}

#[must_use]
pub fn build(leaves: Vec<Leaf>, key_id: &str, key: &SigningKey, now: DateTime<Utc>) -> Anchor {
    let mut a = Anchor {
        version: VERSION,
        anchored_at: now,
        key_id: key_id.to_owned(),
        merkle_root: merkle_root(&leaves),
        leaves,
        signature: String::new(),
    };
    a.signature = B64.encode(key.sign(&signing_bytes(&a)).to_bytes());
    a
}

#[derive(Debug, thiserror::Error, PartialEq, Eq)]
pub enum AnchorError {
    #[error("unknown anchor key id {0}")]
    UnknownKey(String),
    #[error("anchor signature does not verify")]
    BadSignature,
    #[error("merkle root does not match the leaves")]
    BadRoot,
    #[error("unsupported anchor version {0}")]
    Version(u32),
}

/// Signature and root check (no database). `keys`: key id → public key.
pub fn check(a: &Anchor, keys: &[(String, VerifyingKey)]) -> Result<(), AnchorError> {
    if a.version != VERSION {
        return Err(AnchorError::Version(a.version));
    }
    let key = keys
        .iter()
        .find(|(k, _)| *k == a.key_id)
        .map(|(_, v)| v)
        .ok_or_else(|| AnchorError::UnknownKey(a.key_id.clone()))?;
    let sig = B64
        .decode(&a.signature)
        .ok()
        .and_then(|b| ed25519_dalek::Signature::from_slice(&b).ok())
        .ok_or(AnchorError::BadSignature)?;
    key.verify(&signing_bytes(a), &sig)
        .map_err(|_| AnchorError::BadSignature)?;
    if merkle_root(&a.leaves) != a.merkle_root {
        return Err(AnchorError::BadRoot);
    }
    Ok(())
}

// --------------------------------------------------------------------------- database

/// Every tenant's chain head (`tenant_id`, `count`, `last_hash`). Read-only identity.
pub async fn heads(pool: &sqlx::PgPool) -> Result<Vec<(uuid::Uuid, i64, String)>, sqlx::Error> {
    use sqlx::Row as _;
    let rows = sqlx::query(
        "SELECT tenant_id, count, last_hash FROM kernel.audit_heads ORDER BY tenant_id",
    )
    .fetch_all(pool)
    .await?;
    rows.iter()
        .map(|r| {
            Ok((
                r.try_get("tenant_id")?,
                r.try_get("count")?,
                r.try_get("last_hash")?,
            ))
        })
        .collect()
}

/// Check every anchor (signature, root) and every anchored leaf against the live
/// database. Returns one line per failure (content-free); empty = all consistent.
pub async fn verify_against(
    pool: &sqlx::PgPool,
    anchors: &[Anchor],
    keys: &[(String, VerifyingKey)],
) -> Result<Vec<String>, sqlx::Error> {
    let live: std::collections::HashMap<String, (uuid::Uuid, i64)> = heads(pool)
        .await?
        .into_iter()
        .map(|(t, c, _)| (tenant_ref(t), (t, c)))
        .collect();
    let mut out = Vec::new();
    for a in anchors {
        if let Err(e) = check(a, keys) {
            out.push(format!("anchor {} ({}): {e}", a.anchored_at, a.merkle_root));
            continue;
        }
        for l in &a.leaves {
            let Some((tenant, count_now)) = live.get(&l.tenant_ref) else {
                out.push(format!(
                    "anchor {}: an anchored tenant chain no longer exists",
                    a.anchored_at
                ));
                continue;
            };
            if *count_now < l.count {
                out.push(format!(
                    "anchor {}: tenant chain shrank ({count_now} < {})",
                    a.anchored_at, l.count
                ));
                continue;
            }
            if l.count == 0 {
                continue;
            }
            let h: Option<String> = sqlx::query_scalar(
                "SELECT event_hash FROM kernel.audit_events WHERE tenant_id = $1 AND tenant_sequence = $2",
            )
            .bind(tenant)
            .bind(l.count)
            .fetch_optional(pool)
            .await?;
            if h.as_deref() != Some(l.last_hash.as_str()) {
                out.push(format!(
                    "anchor {}: event {} of an anchored chain was rewritten",
                    a.anchored_at, l.count
                ));
            }
        }
    }
    Ok(out)
}

// --------------------------------------------------------------------------- S3

/// AWS Signature Version 4 for one S3 request. Pure; unit-tested against AWS's
/// published example. Returns the `Authorization` header value.
#[allow(clippy::too_many_arguments)]
#[must_use]
pub fn sigv4_authorization(
    method: &str,
    host: &str,
    path: &str,
    headers: &[(String, String)], // lowercase names, include host + x-amz-* + others to sign
    payload_sha256_hex: &str,
    access_key: &str,
    secret_key: &str,
    region: &str,
    amz_date: &str, // YYYYMMDD'T'HHMMSS'Z'
) -> String {
    let _ = host;
    let mut hs: Vec<(String, String)> = headers
        .iter()
        .map(|(k, v)| (k.to_ascii_lowercase(), v.trim().to_owned()))
        .collect();
    hs.sort();
    let canonical_headers: String = hs.iter().map(|(k, v)| format!("{k}:{v}\n")).collect();
    let signed: String = hs
        .iter()
        .map(|(k, _)| k.as_str())
        .collect::<Vec<_>>()
        .join(";");
    let canonical =
        format!("{method}\n{path}\n\n{canonical_headers}\n{signed}\n{payload_sha256_hex}");
    let date = &amz_date[..8];
    let scope = format!("{date}/{region}/s3/aws4_request");
    let to_sign = format!(
        "AWS4-HMAC-SHA256\n{amz_date}\n{scope}\n{}",
        hex::encode(Sha256::digest(canonical.as_bytes()))
    );
    let mac = |k: &[u8], d: &str| -> Vec<u8> {
        let mut m = <Hmac<Sha256> as Mac>::new_from_slice(k).unwrap_or_else(|_| unreachable!());
        m.update(d.as_bytes());
        m.finalize().into_bytes().to_vec()
    };
    let k = mac(format!("AWS4{secret_key}").as_bytes(), date);
    let k = mac(&k, region);
    let k = mac(&k, "s3");
    let k = mac(&k, "aws4_request");
    let sig = hex::encode(mac(&k, &to_sign));
    format!(
        "AWS4-HMAC-SHA256 Credential={access_key}/{scope}, SignedHeaders={signed}, Signature={sig}"
    )
}

/// Write one anchor object under Object Lock COMPLIANCE retention. The bucket must
/// have Object Lock enabled; a bucket without it rejects the lock headers (the
/// write fails loudly rather than storing an unprotected anchor).
#[allow(clippy::too_many_arguments)]
pub async fn put_s3(
    client: &reqwest::Client,
    endpoint: &str, // https://<bucket>.s3.<region>.amazonaws.com
    key: &str,
    body: &[u8],
    retain_until: DateTime<Utc>,
    access_key: &str,
    secret_key: &str,
    session_token: Option<&str>,
    region: &str,
    now: DateTime<Utc>,
) -> anyhow::Result<()> {
    let url = url::Url::parse(endpoint)?.join(key)?;
    anyhow::ensure!(url.scheme() == "https", "anchor endpoint must be https");
    let host = url.host_str().unwrap_or_default().to_owned();
    let amz_date = now.format("%Y%m%dT%H%M%SZ").to_string();
    let payload = hex::encode(Sha256::digest(body));
    let checksum = base64::engine::general_purpose::STANDARD.encode(Sha256::digest(body));
    let mut headers = vec![
        ("host".to_owned(), host.clone()),
        ("x-amz-content-sha256".to_owned(), payload.clone()),
        ("x-amz-date".to_owned(), amz_date.clone()),
        ("x-amz-checksum-sha256".to_owned(), checksum),
        (
            "x-amz-sdk-checksum-algorithm".to_owned(),
            "SHA256".to_owned(),
        ),
        ("x-amz-object-lock-mode".to_owned(), "COMPLIANCE".to_owned()),
        (
            "x-amz-object-lock-retain-until-date".to_owned(),
            retain_until.format("%Y-%m-%dT%H:%M:%SZ").to_string(),
        ),
        ("content-type".to_owned(), "application/json".to_owned()),
    ];
    if let Some(t) = session_token {
        headers.push(("x-amz-security-token".to_owned(), t.to_owned()));
    }
    let auth = sigv4_authorization(
        "PUT",
        &host,
        url.path(),
        &headers,
        &payload,
        access_key,
        secret_key,
        region,
        &amz_date,
    );
    let mut req = client.put(url).body(body.to_vec());
    for (k, v) in &headers {
        if k != "host" {
            req = req.header(k, v);
        }
    }
    let resp = req.header("authorization", auth).send().await?;
    anyhow::ensure!(
        resp.status().is_success(),
        "anchor PUT refused: HTTP {}",
        resp.status()
    );
    Ok(())
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use super::*;

    fn leaf(i: u8, count: i64) -> Leaf {
        Leaf {
            tenant_ref: tenant_ref(uuid::Uuid::from_bytes([i; 16])),
            count,
            last_hash: hex::encode([i; 32]),
        }
    }

    #[test]
    fn sigv4_matches_the_aws_published_get_object_example() {
        // AWS docs, "Signature Calculations for the Authorization Header", GET Object example.
        let empty = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855";
        let auth = sigv4_authorization(
            "GET",
            "examplebucket.s3.amazonaws.com",
            "/test.txt",
            &[
                ("host".into(), "examplebucket.s3.amazonaws.com".into()),
                ("range".into(), "bytes=0-9".into()),
                ("x-amz-content-sha256".into(), empty.into()),
                ("x-amz-date".into(), "20130524T000000Z".into()),
            ],
            empty,
            "AKIAIOSFODNN7EXAMPLE",
            "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY",
            "us-east-1",
            "20130524T000000Z",
        );
        assert_eq!(
            auth,
            "AWS4-HMAC-SHA256 Credential=AKIAIOSFODNN7EXAMPLE/20130524/us-east-1/s3/aws4_request, \
             SignedHeaders=host;range;x-amz-content-sha256;x-amz-date, \
             Signature=f0e8bdb87c964420e857bd35b5d6ed310bd44f0170aba48dd91039c6036bdb41"
        );
    }

    #[test]
    fn merkle_root_is_order_independent_and_binds_every_field() {
        let a = vec![leaf(1, 5), leaf(2, 9), leaf(3, 1)];
        let b = vec![leaf(3, 1), leaf(1, 5), leaf(2, 9)];
        assert_eq!(merkle_root(&a), merkle_root(&b));
        let mut c = a.clone();
        c[1].count = 8;
        assert_ne!(merkle_root(&a), merkle_root(&c));
        let mut d = a.clone();
        d[0].last_hash = hex::encode([7u8; 32]);
        assert_ne!(merkle_root(&a), merkle_root(&d));
        assert_ne!(merkle_root(&a), merkle_root(&a[..2])); // dropping a tenant changes the root
    }

    #[test]
    fn signed_anchor_verifies_and_every_tamper_is_caught() {
        let key = SigningKey::from_bytes(&[5u8; 32]);
        let keys = vec![("a1".to_owned(), key.verifying_key())];
        let now = DateTime::parse_from_rfc3339("2026-11-12T00:00:00Z")
            .unwrap()
            .with_timezone(&Utc);
        let a = build(vec![leaf(1, 5), leaf(2, 9)], "a1", &key, now);
        assert_eq!(check(&a, &keys), Ok(()));
        // Round-trips through JSON (what the sink stores).
        let back: Anchor = serde_json::from_str(&serde_json::to_string(&a).unwrap()).unwrap();
        assert_eq!(check(&back, &keys), Ok(()));
        let mut t = a.clone();
        t.leaves[0].count = 4;
        assert_eq!(check(&t, &keys), Err(AnchorError::BadSignature));
        let mut t = a.clone();
        t.anchored_at = now + chrono::Duration::seconds(1);
        assert_eq!(check(&t, &keys), Err(AnchorError::BadSignature));
        let mut t = a.clone();
        t.key_id = "other".into();
        assert!(matches!(check(&t, &keys), Err(AnchorError::UnknownKey(_))));
        let other = SigningKey::from_bytes(&[6u8; 32]);
        let forged = build(vec![leaf(1, 5)], "a1", &other, now);
        assert_eq!(check(&forged, &keys), Err(AnchorError::BadSignature));
        let mut t = a;
        t.signature = "!!".into();
        assert_eq!(check(&t, &keys), Err(AnchorError::BadSignature));
    }

    #[test]
    fn tenant_refs_are_not_raw_ids() {
        let t = uuid::Uuid::from_bytes([9; 16]);
        let r = tenant_ref(t);
        assert_eq!(r.len(), 64);
        assert!(!r.contains(&t.simple().to_string()));
    }
}
