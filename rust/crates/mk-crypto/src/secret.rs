//! Secret material handling: generation, zeroization, constant-time compare.

use rand::RngCore;
use secrecy::{ExposeSecret, SecretString};
use subtle::ConstantTimeEq;
use zeroize::Zeroizing;

/// Constant-time byte comparison. Returns `false` for differing lengths
/// without leaking which prefix matched.
#[must_use]
pub fn constant_time_eq(a: &[u8], b: &[u8]) -> bool {
    if a.len() != b.len() {
        return false;
    }
    a.ct_eq(b).into()
}

/// Generate a 256-bit random secret, base64url encoded without padding
/// (43 characters). Used for adapter enrollment and rotation.
#[must_use]
pub fn generate_secret() -> SecretString {
    use base64::Engine as _;
    let mut raw = Zeroizing::new([0u8; 32]);
    rand::rngs::OsRng.fill_bytes(raw.as_mut());
    let encoded = base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(raw.as_ref());
    SecretString::from(encoded)
}

/// A shared secret for HMAC signing. Wraps `SecretString`; `Debug` is
/// redacted; bytes are zeroized on drop.
#[derive(Clone)]
pub struct AdapterSecret(SecretString);

impl AdapterSecret {
    #[must_use]
    pub fn new(s: impl Into<String>) -> Self {
        Self(SecretString::from(s.into()))
    }

    /// Borrow the raw bytes for a MAC computation. Keep the borrow short.
    #[must_use]
    pub fn expose_bytes(&self) -> &[u8] {
        self.0.expose_secret().as_bytes()
    }

    /// A stable, non-reversible fingerprint for logs and audit (never the
    /// secret itself).
    #[must_use]
    pub fn fingerprint(&self) -> String {
        let h = crate::digest::sha256_hex(self.expose_bytes());
        format!("fp_{}", &h[..16])
    }
}

impl std::fmt::Debug for AdapterSecret {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "AdapterSecret([REDACTED] {})", self.fingerprint())
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

    #[test]
    fn generated_secrets_are_unique_and_long() {
        let a = generate_secret();
        let b = generate_secret();
        assert_ne!(a.expose_secret(), b.expose_secret());
        assert_eq!(a.expose_secret().len(), 43);
    }

    #[test]
    fn debug_never_leaks() {
        let s = AdapterSecret::new("super-secret-value");
        let dbg = format!("{s:?}");
        assert!(!dbg.contains("super-secret-value"));
        assert!(dbg.contains("REDACTED"));
    }

    #[test]
    fn ct_eq_semantics() {
        assert!(constant_time_eq(b"abc", b"abc"));
        assert!(!constant_time_eq(b"abc", b"abd"));
        assert!(!constant_time_eq(b"abc", b"abcd"));
        assert!(constant_time_eq(b"", b""));
    }
}
