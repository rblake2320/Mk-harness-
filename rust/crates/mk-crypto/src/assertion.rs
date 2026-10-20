//! Short-lived actor assertions: FastAPI → kernel.
//!
//! FastAPI authenticates the end user, then mints a per-request assertion
//! signed with Ed25519. The kernel holds only public keys. The assertion is
//! *not* a session token: it is bound to one request, lives ≤ 60 seconds, and
//! its `jti` is single-use for write requests.
//!
//! Wire format is a compact JWS-style token
//! `b64url(header) "." b64url(payload) "." b64url(signature)` with header
//! `{"alg":"EdDSA","typ":"mk-assertion+v1","kid":"<key id>"}`. Only this exact
//! header is accepted; `alg:none`, HS256, RS256 and so on are rejected before
//! any signature check.

use std::collections::HashMap;

use base64::Engine as _;
use ed25519_dalek::{Signature, Signer, SigningKey, Verifier, VerifyingKey};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

pub const ISSUER: &str = "mk-fastapi";
pub const AUDIENCE: &str = "mk-action-kernel";
pub const TYP: &str = "mk-assertion+v1";
pub const MAX_LIFETIME_SECS: i64 = 60;
/// Allowed clock skew between issuer and kernel.
pub const CLOCK_SKEW_SECS: i64 = 5;
const MAX_TOKEN_LEN: usize = 8 * 1024;

const B64: base64::engine::GeneralPurpose = base64::engine::general_purpose::URL_SAFE_NO_PAD;

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ActorAssertion {
    pub iss: String,
    pub aud: String,
    pub sub: Uuid,
    pub tenant_id: Uuid,
    pub roles: Vec<String>,
    pub session_id: String,
    pub request_id: String,
    pub iat: i64,
    pub exp: i64,
    pub jti: Uuid,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Header {
    alg: String,
    typ: String,
    kid: String,
}

#[derive(Debug, thiserror::Error, Clone, PartialEq, Eq)]
pub enum AssertionError {
    #[error("token malformed")]
    Malformed,
    #[error("unsupported algorithm or type")]
    UnsupportedHeader,
    #[error("unknown key id")]
    UnknownKey,
    #[error("signature invalid")]
    BadSignature,
    #[error("wrong issuer")]
    WrongIssuer,
    #[error("wrong audience")]
    WrongAudience,
    #[error("assertion expired")]
    Expired,
    #[error("assertion issued in the future")]
    IssuedInFuture,
    #[error("assertion lifetime exceeds maximum")]
    LifetimeTooLong,
    #[error("missing or empty claim: {0}")]
    MissingClaim(&'static str),
}

impl AssertionError {
    #[must_use]
    pub const fn code(&self) -> &'static str {
        match self {
            Self::Malformed => "assertion_malformed",
            Self::UnsupportedHeader => "assertion_unsupported_header",
            Self::UnknownKey => "assertion_unknown_key",
            Self::BadSignature => "assertion_bad_signature",
            Self::WrongIssuer => "assertion_wrong_issuer",
            Self::WrongAudience => "assertion_wrong_audience",
            Self::Expired => "assertion_expired",
            Self::IssuedInFuture => "assertion_issued_in_future",
            Self::LifetimeTooLong => "assertion_lifetime_too_long",
            Self::MissingClaim(_) => "assertion_missing_claim",
        }
    }
}

/// Issuer side. Lives in FastAPI in production; included here so the Rust
/// test suite and the shadow-mode comparison harness can mint tokens.
pub struct AssertionSigner {
    kid: String,
    key: SigningKey,
}

impl std::fmt::Debug for AssertionSigner {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "AssertionSigner(kid={})", self.kid)
    }
}

impl AssertionSigner {
    #[must_use]
    pub fn new(kid: impl Into<String>, key: SigningKey) -> Self {
        Self {
            kid: kid.into(),
            key,
        }
    }

    #[must_use]
    pub fn generate(kid: impl Into<String>) -> Self {
        let key = SigningKey::generate(&mut rand::rngs::OsRng);
        Self::new(kid, key)
    }

    #[must_use]
    pub fn verifying_key(&self) -> VerifyingKey {
        self.key.verifying_key()
    }

    #[must_use]
    pub fn kid(&self) -> &str {
        &self.kid
    }

    pub fn sign(&self, claims: &ActorAssertion) -> Result<String, AssertionError> {
        let header = Header {
            alg: "EdDSA".into(),
            typ: TYP.into(),
            kid: self.kid.clone(),
        };
        let h = B64.encode(serde_json::to_vec(&header).map_err(|_| AssertionError::Malformed)?);
        let p = B64.encode(serde_json::to_vec(claims).map_err(|_| AssertionError::Malformed)?);
        let signing_input = format!("{h}.{p}");
        let sig = self.key.sign(signing_input.as_bytes());
        Ok(format!("{signing_input}.{}", B64.encode(sig.to_bytes())))
    }
}

/// Kernel side. Holds public keys by `kid`; supports overlapping keys during
/// rotation.
#[derive(Clone)]
pub struct AssertionVerifier {
    keys: HashMap<String, VerifyingKey>,
}

impl std::fmt::Debug for AssertionVerifier {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let mut kids: Vec<&String> = self.keys.keys().collect();
        kids.sort();
        write!(f, "AssertionVerifier(kids={kids:?})")
    }
}

impl AssertionVerifier {
    #[must_use]
    pub fn new(keys: HashMap<String, VerifyingKey>) -> Self {
        Self { keys }
    }

    /// Load from `kid=<base64url 32-byte public key>` pairs.
    pub fn from_pairs<'a>(
        pairs: impl IntoIterator<Item = (&'a str, &'a str)>,
    ) -> Result<Self, AssertionError> {
        let mut keys = HashMap::new();
        for (kid, b64) in pairs {
            let raw = B64.decode(b64).map_err(|_| AssertionError::Malformed)?;
            let arr: [u8; 32] = raw.try_into().map_err(|_| AssertionError::Malformed)?;
            let vk = VerifyingKey::from_bytes(&arr).map_err(|_| AssertionError::Malformed)?;
            keys.insert(kid.to_owned(), vk);
        }
        Ok(Self { keys })
    }

    /// Verify signature and all claim invariants. Does **not** check `jti`
    /// single-use; the caller does that against durable storage for writes.
    pub fn verify(&self, token: &str, now_unix: i64) -> Result<ActorAssertion, AssertionError> {
        if token.len() > MAX_TOKEN_LEN || !token.is_ascii() {
            return Err(AssertionError::Malformed);
        }
        let mut parts = token.split('.');
        let (Some(h), Some(p), Some(s), None) =
            (parts.next(), parts.next(), parts.next(), parts.next())
        else {
            return Err(AssertionError::Malformed);
        };
        let header: Header =
            serde_json::from_slice(&B64.decode(h).map_err(|_| AssertionError::Malformed)?)
                .map_err(|_| AssertionError::Malformed)?;
        if header.alg != "EdDSA" || header.typ != TYP {
            return Err(AssertionError::UnsupportedHeader);
        }
        let key = self
            .keys
            .get(&header.kid)
            .ok_or(AssertionError::UnknownKey)?;
        let sig_bytes = B64.decode(s).map_err(|_| AssertionError::Malformed)?;
        let sig = Signature::from_slice(&sig_bytes).map_err(|_| AssertionError::Malformed)?;
        // Verify the signature over the exact transmitted bytes *before*
        // parsing claims, so a forged payload is never deserialized.
        let signing_input = format!("{h}.{p}");
        key.verify(signing_input.as_bytes(), &sig)
            .map_err(|_| AssertionError::BadSignature)?;

        let claims: ActorAssertion =
            serde_json::from_slice(&B64.decode(p).map_err(|_| AssertionError::Malformed)?)
                .map_err(|_| AssertionError::Malformed)?;
        Self::check_claims(&claims, now_unix)?;
        Ok(claims)
    }

    fn check_claims(c: &ActorAssertion, now: i64) -> Result<(), AssertionError> {
        if c.iss != ISSUER {
            return Err(AssertionError::WrongIssuer);
        }
        if c.aud != AUDIENCE {
            return Err(AssertionError::WrongAudience);
        }
        if c.session_id.is_empty() {
            return Err(AssertionError::MissingClaim("session_id"));
        }
        if c.request_id.is_empty() {
            return Err(AssertionError::MissingClaim("request_id"));
        }
        if c.roles.is_empty() {
            return Err(AssertionError::MissingClaim("roles"));
        }
        if c.sub.is_nil() || c.tenant_id.is_nil() || c.jti.is_nil() {
            return Err(AssertionError::MissingClaim("sub/tenant_id/jti"));
        }
        if c.exp - c.iat > MAX_LIFETIME_SECS || c.exp <= c.iat {
            return Err(AssertionError::LifetimeTooLong);
        }
        if c.iat > now + CLOCK_SKEW_SECS {
            return Err(AssertionError::IssuedInFuture);
        }
        if now > c.exp + CLOCK_SKEW_SECS {
            return Err(AssertionError::Expired);
        }
        Ok(())
    }
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

    fn claims(now: i64) -> ActorAssertion {
        ActorAssertion {
            iss: ISSUER.into(),
            aud: AUDIENCE.into(),
            sub: Uuid::now_v7(),
            tenant_id: Uuid::now_v7(),
            roles: vec!["consultant".into()],
            session_id: "sess".into(),
            request_id: Uuid::now_v7().to_string(),
            iat: now,
            exp: now + 60,
            jti: Uuid::now_v7(),
        }
    }

    fn pair() -> (AssertionSigner, AssertionVerifier) {
        let s = AssertionSigner::generate("k1");
        let v = AssertionVerifier::new(HashMap::from([("k1".to_string(), s.verifying_key())]));
        (s, v)
    }

    #[test]
    fn roundtrip() {
        let (s, v) = pair();
        let c = claims(1_000_000);
        let tok = s.sign(&c).unwrap_or_default();
        assert_eq!(v.verify(&tok, 1_000_030), Ok(c));
    }

    #[test]
    fn rejects_expired_future_and_long_lived() {
        let (s, v) = pair();
        let c = claims(1_000_000);
        let tok = s.sign(&c).unwrap_or_default();
        assert_eq!(v.verify(&tok, 1_000_066), Err(AssertionError::Expired));
        assert_eq!(v.verify(&tok, 999_990), Err(AssertionError::IssuedInFuture));
        let mut long = claims(1_000_000);
        long.exp = long.iat + 61;
        let tok = s.sign(&long).unwrap_or_default();
        assert_eq!(
            v.verify(&tok, 1_000_000),
            Err(AssertionError::LifetimeTooLong)
        );
    }

    #[test]
    fn rejects_wrong_iss_aud_and_missing_claims() {
        let (s, v) = pair();
        let mut c = claims(1_000_000);
        c.aud = "someone-else".into();
        assert_eq!(
            v.verify(&s.sign(&c).unwrap_or_default(), 1_000_000),
            Err(AssertionError::WrongAudience)
        );
        let mut c = claims(1_000_000);
        c.iss = "evil".into();
        assert_eq!(
            v.verify(&s.sign(&c).unwrap_or_default(), 1_000_000),
            Err(AssertionError::WrongIssuer)
        );
        let mut c = claims(1_000_000);
        c.roles.clear();
        assert_eq!(
            v.verify(&s.sign(&c).unwrap_or_default(), 1_000_000),
            Err(AssertionError::MissingClaim("roles"))
        );
    }

    #[test]
    fn rejects_tampered_payload_and_wrong_key() {
        let (s, v) = pair();
        let c = claims(1_000_000);
        let tok = s.sign(&c).unwrap_or_default();
        let mut parts: Vec<&str> = tok.split('.').collect();
        let mut evil = c.clone();
        evil.roles = vec!["admin".into()];
        let p = B64.encode(serde_json::to_vec(&evil).unwrap_or_default());
        parts[1] = &p;
        let forged = parts.join(".");
        assert_eq!(
            v.verify(&forged, 1_000_000),
            Err(AssertionError::BadSignature)
        );

        let other = AssertionSigner::generate("k1"); // same kid, different key
        let tok2 = other.sign(&c).unwrap_or_default();
        assert_eq!(
            v.verify(&tok2, 1_000_000),
            Err(AssertionError::BadSignature)
        );

        let unknown = AssertionSigner::generate("k9");
        let tok3 = unknown.sign(&c).unwrap_or_default();
        assert_eq!(v.verify(&tok3, 1_000_000), Err(AssertionError::UnknownKey));
    }

    #[test]
    fn rejects_alg_none_and_other_algs() {
        let (s, v) = pair();
        let c = claims(1_000_000);
        let tok = s.sign(&c).unwrap_or_default();
        let parts: Vec<&str> = tok.split('.').collect();
        for alg in ["none", "HS256", "RS256", "ES256"] {
            let h = B64.encode(format!(
                "{{\"alg\":\"{alg}\",\"typ\":\"{TYP}\",\"kid\":\"k1\"}}"
            ));
            let t = format!("{h}.{}.{}", parts[1], parts[2]);
            assert_eq!(
                v.verify(&t, 1_000_000),
                Err(AssertionError::UnsupportedHeader),
                "{alg}"
            );
        }
        // Extra header field → deny_unknown_fields → malformed.
        let h = B64.encode(format!(
            "{{\"alg\":\"EdDSA\",\"typ\":\"{TYP}\",\"kid\":\"k1\",\"jku\":\"x\"}}"
        ));
        let t = format!("{h}.{}.{}", parts[1], parts[2]);
        assert_eq!(v.verify(&t, 1_000_000), Err(AssertionError::Malformed));
    }

    #[test]
    fn rejects_garbage_shapes() {
        let (_, v) = pair();
        assert_eq!(v.verify("", 0), Err(AssertionError::Malformed));
        assert_eq!(v.verify("a.b", 0), Err(AssertionError::Malformed));
        assert_eq!(v.verify("a.b.c.d", 0), Err(AssertionError::Malformed));
        assert_eq!(
            v.verify(&"x".repeat(MAX_TOKEN_LEN + 1), 0),
            Err(AssertionError::Malformed)
        );
    }

    #[test]
    fn key_rotation_overlap() {
        let old = AssertionSigner::generate("k1");
        let new = AssertionSigner::generate("k2");
        let v = AssertionVerifier::new(HashMap::from([
            ("k1".to_string(), old.verifying_key()),
            ("k2".to_string(), new.verifying_key()),
        ]));
        let c = claims(5);
        assert!(v.verify(&old.sign(&c).unwrap_or_default(), 5).is_ok());
        assert!(v.verify(&new.sign(&c).unwrap_or_default(), 5).is_ok());
        let v2 = AssertionVerifier::new(HashMap::from([("k2".to_string(), new.verifying_key())]));
        assert_eq!(
            v2.verify(&old.sign(&c).unwrap_or_default(), 5),
            Err(AssertionError::UnknownKey)
        );
    }
}
