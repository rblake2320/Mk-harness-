//! Envelope encryption for secrets at rest (adapter HMAC secrets).
//!
//! AES-256-GCM with a 96-bit random nonce. The AAD binds the ciphertext to
//! `tenant:adapter:credential`, so a row copied to another scope will not
//! decrypt — the same property the Python `crypto.py` layer provides for
//! provider keys.

use aes_gcm::aead::{Aead, KeyInit, Payload};
use aes_gcm::{Aes256Gcm, Nonce};
use rand::RngCore;
use secrecy::{ExposeSecret, SecretString};
use zeroize::Zeroizing;

#[derive(Debug, thiserror::Error, Clone, Copy, PartialEq, Eq)]
pub enum SealError {
    #[error("master key must be 32 bytes")]
    BadKey,
    #[error("ciphertext malformed or authentication failed")]
    Unseal,
}

/// 32-byte master key. `Debug` is redacted; zeroized on drop.
#[derive(Clone)]
pub struct MasterKey(Zeroizing<[u8; 32]>);

impl std::fmt::Debug for MasterKey {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("MasterKey([REDACTED])")
    }
}

impl MasterKey {
    pub fn from_bytes(b: &[u8]) -> Result<Self, SealError> {
        let arr: [u8; 32] = b.try_into().map_err(|_| SealError::BadKey)?;
        Ok(Self(Zeroizing::new(arr)))
    }

    /// Base64 (standard) encoded 32 bytes, matching the FastAPI `MASTER_KEY`.
    pub fn from_base64(s: &str) -> Result<Self, SealError> {
        use base64::Engine as _;
        let raw = base64::engine::general_purpose::STANDARD
            .decode(s.trim())
            .map_err(|_| SealError::BadKey)?;
        Self::from_bytes(&raw)
    }

    /// Raw key bytes for keyed derivations (destination fingerprints). The
    /// borrow must not be stored.
    #[must_use]
    pub fn as_bytes(&self) -> &[u8] {
        self.0.as_ref()
    }

    #[must_use]
    pub fn generate() -> Self {
        let mut k = Zeroizing::new([0u8; 32]);
        rand::rngs::OsRng.fill_bytes(k.as_mut());
        Self(k)
    }
}

const NONCE_LEN: usize = 12;

/// Seal `plaintext` under `aad`. Output = nonce || ciphertext||tag.
pub fn seal(key: &MasterKey, aad: &str, plaintext: &SecretString) -> Result<Vec<u8>, SealError> {
    let cipher = Aes256Gcm::new_from_slice(key.0.as_ref()).map_err(|_| SealError::BadKey)?;
    let mut nonce = [0u8; NONCE_LEN];
    rand::rngs::OsRng.fill_bytes(&mut nonce);
    let ct = cipher
        .encrypt(
            Nonce::from_slice(&nonce),
            Payload {
                msg: plaintext.expose_secret().as_bytes(),
                aad: aad.as_bytes(),
            },
        )
        .map_err(|_| SealError::Unseal)?;
    let mut out = Vec::with_capacity(NONCE_LEN + ct.len());
    out.extend_from_slice(&nonce);
    out.extend_from_slice(&ct);
    Ok(out)
}

pub fn unseal(key: &MasterKey, aad: &str, sealed: &[u8]) -> Result<SecretString, SealError> {
    if sealed.len() < NONCE_LEN + 16 {
        return Err(SealError::Unseal);
    }
    let cipher = Aes256Gcm::new_from_slice(key.0.as_ref()).map_err(|_| SealError::BadKey)?;
    let (nonce, ct) = sealed.split_at(NONCE_LEN);
    let pt = cipher
        .decrypt(
            Nonce::from_slice(nonce),
            Payload {
                msg: ct,
                aad: aad.as_bytes(),
            },
        )
        .map_err(|_| SealError::Unseal)?;
    let pt = Zeroizing::new(pt);
    let s = String::from_utf8(pt.to_vec()).map_err(|_| SealError::Unseal)?;
    Ok(SecretString::from(s))
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
    fn roundtrip_and_aad_binding() {
        let k = MasterKey::generate();
        let s = SecretString::from("adapter-secret".to_string());
        let sealed = seal(&k, "t1:a1:c1", &s).unwrap_or_default();
        assert_eq!(
            unseal(&k, "t1:a1:c1", &sealed).map(|x| x.expose_secret().to_string()),
            Ok("adapter-secret".into())
        );
        assert_eq!(
            unseal(&k, "t2:a1:c1", &sealed).err(),
            Some(SealError::Unseal),
            "copied to another tenant"
        );
        assert_eq!(
            unseal(&MasterKey::generate(), "t1:a1:c1", &sealed).err(),
            Some(SealError::Unseal)
        );
        let mut tampered = sealed.clone();
        tampered[NONCE_LEN + 2] ^= 1;
        assert_eq!(
            unseal(&k, "t1:a1:c1", &tampered).err(),
            Some(SealError::Unseal)
        );
        assert_eq!(
            unseal(&k, "t1:a1:c1", &sealed[..5]).err(),
            Some(SealError::Unseal)
        );
    }

    #[test]
    fn fresh_nonce_per_seal() {
        let k = MasterKey::generate();
        let s = SecretString::from("x".to_string());
        assert_ne!(seal(&k, "a", &s), seal(&k, "a", &s));
    }

    #[test]
    fn base64_key_parsing() {
        assert!(MasterKey::from_base64("c2hvcnQ=").is_err());
        assert!(MasterKey::from_base64(&base64_of(&[7u8; 32])).is_ok());
    }

    fn base64_of(b: &[u8]) -> String {
        use base64::Engine as _;
        base64::engine::general_purpose::STANDARD.encode(b)
    }
}
