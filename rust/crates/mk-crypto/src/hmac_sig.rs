//! Mobile-adapter request signing: `hmac-sha256-v1`.
//!
//! Canonical input (byte-exact, preserved from the published contract):
//!
//! ```text
//! UPPERCASE_METHOD "\n" PATH_ONLY "\n" TIMESTAMP "\n" NONCE "\n" LOWERCASE_SHA256_BODY_HEX
//! ```
//!
//! Signature = lowercase hex HMAC-SHA256(secret, canonical input). The
//! signature covers the exact bytes transmitted, never a re-serialized object.
//! Verification is constant-time and checks timestamp window before touching
//! the MAC so the error ordering never depends on secret material.

use hmac::{Hmac, Mac};
use sha2::Sha256;

use crate::digest::sha256_hex;
use crate::secret::{AdapterSecret, constant_time_eq};

type HmacSha256 = Hmac<Sha256>;

pub const ALGORITHM: &str = "hmac-sha256-v1";
/// Kernel default. The legacy Python agent_ops path used 300s; this is
/// configurable per deployment via [`VerifyParams::tolerance_secs`].
pub const DEFAULT_TIMESTAMP_TOLERANCE_SECS: i64 = 120;
pub const MAX_NONCE_LEN: usize = 80;

pub const HDR_AGENT: &str = "x-mobile-agent";
pub const HDR_TENANT: &str = "x-mobile-tenant";
pub const HDR_TIMESTAMP: &str = "x-mobile-timestamp";
pub const HDR_NONCE: &str = "x-mobile-nonce";
pub const HDR_SIGNATURE: &str = "x-mobile-signature";

#[derive(Debug, thiserror::Error, Clone, Copy, PartialEq, Eq)]
pub enum HmacError {
    #[error("timestamp is not an unsigned integer")]
    TimestampMalformed,
    #[error("timestamp outside tolerance window")]
    TimestampOutOfWindow,
    #[error("nonce missing, too long, or contains control characters")]
    NonceMalformed,
    #[error("signature is not 64 lowercase hex characters")]
    SignatureMalformed,
    #[error("signature mismatch")]
    SignatureMismatch,
    #[error("path must be absolute and contain no query or fragment")]
    PathMalformed,
}

impl HmacError {
    /// Stable code for audit events and metrics.
    #[must_use]
    pub const fn code(self) -> &'static str {
        match self {
            Self::TimestampMalformed => "timestamp_malformed",
            Self::TimestampOutOfWindow => "timestamp_out_of_window",
            Self::NonceMalformed => "nonce_malformed",
            Self::SignatureMalformed => "signature_malformed",
            Self::SignatureMismatch => "signature_mismatch",
            Self::PathMalformed => "path_malformed",
        }
    }
}

/// Build the canonical signing input bytes.
#[must_use]
pub fn canonical_signing_input(
    method: &str,
    path: &str,
    timestamp: &str,
    nonce: &str,
    body: &[u8],
) -> Vec<u8> {
    let mut out = String::with_capacity(method.len() + path.len() + 160);
    out.push_str(&method.to_ascii_uppercase());
    out.push('\n');
    out.push_str(path);
    out.push('\n');
    out.push_str(timestamp);
    out.push('\n');
    out.push_str(nonce);
    out.push('\n');
    out.push_str(&sha256_hex(body));
    out.into_bytes()
}

/// Headers produced by signing. Timestamp and nonce are echoed so the caller
/// can send exactly what was signed.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SignedHeaders {
    pub timestamp: String,
    pub nonce: String,
    pub signature_hex: String,
}

/// Sign a request. Callers supply timestamp and nonce explicitly so signing
/// is deterministic and testable; production callers pass `now` and a fresh
/// random nonce.
pub fn sign_hmac(
    secret: &AdapterSecret,
    method: &str,
    path: &str,
    timestamp: &str,
    nonce: &str,
    body: &[u8],
) -> Result<SignedHeaders, HmacError> {
    validate_path(path)?;
    validate_nonce(nonce)?;
    let input = canonical_signing_input(method, path, timestamp, nonce, body);
    let mut mac = HmacSha256::new_from_slice(secret.expose_bytes())
        .map_err(|_| HmacError::SignatureMalformed)?;
    mac.update(&input);
    Ok(SignedHeaders {
        timestamp: timestamp.to_owned(),
        nonce: nonce.to_owned(),
        signature_hex: hex::encode(mac.finalize().into_bytes()),
    })
}

#[derive(Debug, Clone, Copy)]
pub struct VerifyParams<'a> {
    pub method: &'a str,
    pub path: &'a str,
    pub timestamp: &'a str,
    pub nonce: &'a str,
    pub signature_hex: &'a str,
    pub body: &'a [u8],
    /// Receiver's current Unix time.
    pub now_unix: i64,
    pub tolerance_secs: i64,
}

/// Verify a signed request. Does **not** check nonce replay — that needs
/// storage; see [`crate::nonce::ReplayGuard`]. Callers must run the replay
/// check *after* this returns `Ok` and before acting.
pub fn verify_hmac(secret: &AdapterSecret, p: VerifyParams<'_>) -> Result<(), HmacError> {
    validate_path(p.path)?;
    validate_nonce(p.nonce)?;
    let ts = parse_timestamp(p.timestamp)?;
    if (p.now_unix - ts).abs() > p.tolerance_secs {
        return Err(HmacError::TimestampOutOfWindow);
    }
    if p.signature_hex.len() != 64
        || !p
            .signature_hex
            .bytes()
            .all(|b| matches!(b, b'0'..=b'9' | b'a'..=b'f'))
    {
        return Err(HmacError::SignatureMalformed);
    }
    let expected = sign_hmac(secret, p.method, p.path, p.timestamp, p.nonce, p.body)?;
    if constant_time_eq(
        expected.signature_hex.as_bytes(),
        p.signature_hex.as_bytes(),
    ) {
        Ok(())
    } else {
        Err(HmacError::SignatureMismatch)
    }
}

fn parse_timestamp(s: &str) -> Result<i64, HmacError> {
    if s.is_empty() || s.len() > 12 || !s.bytes().all(|b| b.is_ascii_digit()) {
        return Err(HmacError::TimestampMalformed);
    }
    s.parse::<i64>().map_err(|_| HmacError::TimestampMalformed)
}

fn validate_nonce(n: &str) -> Result<(), HmacError> {
    if n.is_empty() || n.len() > MAX_NONCE_LEN || !n.bytes().all(|b| b.is_ascii_graphic()) {
        return Err(HmacError::NonceMalformed);
    }
    Ok(())
}

fn validate_path(p: &str) -> Result<(), HmacError> {
    if !p.starts_with('/') || p.contains('?') || p.contains('#') || p.contains('\n') {
        return Err(HmacError::PathMalformed);
    }
    Ok(())
}

#[cfg(test)]
#[allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::unreadable_literal,
    clippy::cast_possible_truncation,
    clippy::float_cmp
)]
mod tests {
    use super::*;

    fn secret() -> AdapterSecret {
        AdapterSecret::new("not-a-real-secret-for-test-vector")
    }

    const PATH: &str = "/api/agent-ops/tasks/00000000-0000-4000-8000-000000000001/result";
    const BODY: &str = "{\"error_code\":\"\",\"result\":{},\"schema\":\"consultant-studio.mobile-execution-state.v1\",\"status\":\"executing\"}";
    const SIG: &str = "5c8ac10a0857250b58286cf0a72c74a9211a56d4c6bb232004da0cee4d37c09a";

    #[test]
    fn published_vector_execution_started_v1() {
        let h = sign_hmac(
            &secret(),
            "post",
            PATH,
            "1783728000",
            "test-nonce-0001",
            BODY.as_bytes(),
        )
        .unwrap_or_else(|_| SignedHeaders {
            timestamp: String::new(),
            nonce: String::new(),
            signature_hex: String::new(),
        });
        assert_eq!(h.signature_hex, SIG);
        assert_eq!(
            sha256_hex(BODY.as_bytes()),
            "69d8c277719c163c249d2a6371fe39eafd4ae2e9720079bd3cca24d18087f430"
        );
    }

    fn params<'a>(sig: &'a str, body: &'a str, path: &'a str, now: i64) -> VerifyParams<'a> {
        VerifyParams {
            method: "POST",
            path,
            timestamp: "1783728000",
            nonce: "test-nonce-0001",
            signature_hex: sig,
            body: body.as_bytes(),
            now_unix: now,
            tolerance_secs: DEFAULT_TIMESTAMP_TOLERANCE_SECS,
        }
    }

    #[test]
    fn verify_accepts_within_window() {
        assert_eq!(
            verify_hmac(&secret(), params(SIG, BODY, PATH, 1_783_728_000)),
            Ok(())
        );
        assert_eq!(
            verify_hmac(&secret(), params(SIG, BODY, PATH, 1_783_728_120)),
            Ok(())
        );
        assert_eq!(
            verify_hmac(&secret(), params(SIG, BODY, PATH, 1_783_727_880)),
            Ok(())
        );
    }

    #[test]
    fn verify_rejects_stale_by_one_second() {
        assert_eq!(
            verify_hmac(&secret(), params(SIG, BODY, PATH, 1_783_728_121)),
            Err(HmacError::TimestampOutOfWindow)
        );
        assert_eq!(
            verify_hmac(&secret(), params(SIG, BODY, PATH, 1_783_727_879)),
            Err(HmacError::TimestampOutOfWindow)
        );
    }

    #[test]
    fn verify_rejects_altered_body() {
        let altered = BODY.replace("executing", "complete");
        assert_eq!(
            verify_hmac(&secret(), params(SIG, &altered, PATH, 1_783_728_000)),
            Err(HmacError::SignatureMismatch)
        );
    }

    #[test]
    fn verify_rejects_wrong_path_and_wrong_secret() {
        let other = PATH.replace("/result", "/callbacks");
        assert_eq!(
            verify_hmac(&secret(), params(SIG, BODY, &other, 1_783_728_000)),
            Err(HmacError::SignatureMismatch)
        );
        assert_eq!(
            verify_hmac(
                &AdapterSecret::new("rotated"),
                params(SIG, BODY, PATH, 1_783_728_000)
            ),
            Err(HmacError::SignatureMismatch)
        );
    }

    #[test]
    fn verify_rejects_uppercase_signature_and_malformed_inputs() {
        let upper = SIG.to_uppercase();
        assert_eq!(
            verify_hmac(&secret(), params(&upper, BODY, PATH, 1_783_728_000)),
            Err(HmacError::SignatureMalformed)
        );
        let mut p = params(SIG, BODY, PATH, 1_783_728_000);
        p.timestamp = "1783728000.5";
        assert_eq!(
            verify_hmac(&secret(), p),
            Err(HmacError::TimestampMalformed)
        );
        let mut p = params(SIG, BODY, PATH, 1_783_728_000);
        p.timestamp = "-1";
        assert_eq!(
            verify_hmac(&secret(), p),
            Err(HmacError::TimestampMalformed)
        );
        let mut p = params(SIG, BODY, PATH, 1_783_728_000);
        p.nonce = "";
        assert_eq!(verify_hmac(&secret(), p), Err(HmacError::NonceMalformed));
        let long = "n".repeat(81);
        let mut p = params(SIG, BODY, PATH, 1_783_728_000);
        p.nonce = &long;
        assert_eq!(verify_hmac(&secret(), p), Err(HmacError::NonceMalformed));
        let mut p = params(SIG, BODY, PATH, 1_783_728_000);
        p.path = "/x?y=1";
        assert_eq!(verify_hmac(&secret(), p), Err(HmacError::PathMalformed));
    }

    #[test]
    fn method_is_case_insensitive_but_signed_uppercase() {
        let a = sign_hmac(&secret(), "post", "/p", "1", "n", b"").map(|h| h.signature_hex);
        let b = sign_hmac(&secret(), "POST", "/p", "1", "n", b"").map(|h| h.signature_hex);
        assert_eq!(a, b);
    }
}
