#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::missing_panics_doc,
    clippy::too_many_lines,
    clippy::unreadable_literal,
    clippy::cast_possible_truncation
)]
//! Cross-language conformance: every vector in
//! `contracts/mobile/v1/hmac-vectors.json` must sign and verify identically
//! in Rust. The Python test suite runs the same file.

use mk_crypto::{AdapterSecret, HmacError, VerifyParams, sign_hmac, verify_hmac};
use serde::Deserialize;

const VECTORS: &str = include_str!("../../../../contracts/mobile/v1/hmac-vectors.json");

#[derive(Deserialize)]
struct File {
    algorithm: String,
    vectors: Vec<Vector>,
}

#[derive(Deserialize)]
struct Vector {
    name: String,
    secret: String,
    method: String,
    path: String,
    timestamp: String,
    nonce: String,
    body_utf8: String,
    body_sha256: String,
    signature_hex: String,
}

fn load() -> File {
    serde_json::from_str(VECTORS).unwrap_or_else(|e| panic!("vectors file malformed: {e}"))
}

#[test]
fn algorithm_is_pinned() {
    assert_eq!(load().algorithm, mk_crypto::hmac_sig::ALGORITHM);
}

#[test]
fn every_vector_signs_identically() {
    let f = load();
    assert!(f.vectors.len() >= 6);
    for v in &f.vectors {
        assert_eq!(
            mk_crypto::sha256_hex(v.body_utf8.as_bytes()),
            v.body_sha256,
            "{}",
            v.name
        );
        let h = sign_hmac(
            &AdapterSecret::new(v.secret.clone()),
            &v.method,
            &v.path,
            &v.timestamp,
            &v.nonce,
            v.body_utf8.as_bytes(),
        )
        .unwrap_or_else(|e| panic!("{}: {e}", v.name));
        assert_eq!(h.signature_hex, v.signature_hex, "{}", v.name);
    }
}

#[test]
fn every_vector_verifies_and_every_mutation_fails() {
    let f = load();
    for v in &f.vectors {
        let secret = AdapterSecret::new(v.secret.clone());
        let now: i64 = v.timestamp.parse().unwrap_or_default();
        let base = |sig: &'static str, body: &'static str, path: &'static str| VerifyParams {
            method: &v.method,
            path: if path.is_empty() { &v.path } else { path },
            timestamp: &v.timestamp,
            nonce: &v.nonce,
            signature_hex: if sig.is_empty() {
                &v.signature_hex
            } else {
                sig
            },
            body: if body.is_empty() && !v.body_utf8.is_empty() {
                v.body_utf8.as_bytes()
            } else {
                body.as_bytes()
            },
            now_unix: now,
            tolerance_secs: 120,
        };
        assert_eq!(verify_hmac(&secret, base("", "", "")), Ok(()), "{}", v.name);
        // altered body
        let mut p = base("", "", "");
        let altered = format!("{}x", v.body_utf8);
        p.body = altered.as_bytes();
        assert_eq!(
            verify_hmac(&secret, p),
            Err(HmacError::SignatureMismatch),
            "{} altered body",
            v.name
        );
        // stale timestamp (+121s)
        let mut p = base("", "", "");
        p.now_unix = now + 121;
        assert_eq!(
            verify_hmac(&secret, p),
            Err(HmacError::TimestampOutOfWindow),
            "{} stale",
            v.name
        );
        // wrong path
        let wrong = format!("{}/x", v.path);
        let mut p = base("", "", "");
        p.path = &wrong;
        assert_eq!(
            verify_hmac(&secret, p),
            Err(HmacError::SignatureMismatch),
            "{} path",
            v.name
        );
        // uppercase signature
        let upper = v.signature_hex.to_uppercase();
        let mut p = base("", "", "");
        p.signature_hex = &upper;
        assert_eq!(
            verify_hmac(&secret, p),
            Err(HmacError::SignatureMalformed),
            "{} upper",
            v.name
        );
        // wrong secret
        assert_eq!(
            verify_hmac(&AdapterSecret::new("rotated"), base("", "", "")),
            Err(HmacError::SignatureMismatch),
            "{} secret",
            v.name
        );
    }
}
