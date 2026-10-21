//! Versioned envelope encryption (contract row S6).
//!
//! Data at rest is sealed under a **data encryption key (DEK)** identified by a
//! version number. DEKs are stored wrapped by a **key-encryption key (KEK)**
//! that lives outside the database (`kernel.key_versions`). The process loads
//! every non-retired version at start, seals with the *current* one, and can
//! unseal anything sealed under any loaded version — so rotation is: add a
//! version → re-encrypt rows → retire the old version. The fingerprint HMAC key
//! (`MasterKey`) is separate and stable: fingerprints are lookup keys, and
//! rotating them is a full re-fingerprint migration, not a seal rotation.
//!
//! Wire format v2: `b"MKS2" ‖ version:u32be ‖ nonce(12) ‖ AES-256-GCM(ct‖tag)`.
//! Legacy format (pre-S6): `nonce(12) ‖ ct‖tag` under the master key; still
//! readable as version 0 so no data is stranded; `reencrypt` upgrades it.
//!
//! KEK providers: [`EnvKek`] (a 32-byte key from the environment/secret store;
//! self-hosted and development) is implemented and tested here. A cloud KMS
//! provider implements the same [`Kek`] trait; it is **not** included in this
//! crate and its use is Not demonstrated until an integration test runs
//! against a real KMS (see `docs/production-acceptance.md` S6).

use std::collections::BTreeMap;

use aes_gcm::aead::{Aead, KeyInit, Payload};
use aes_gcm::{Aes256Gcm, Nonce};
use rand::RngCore;
use secrecy::{ExposeSecret, SecretString};
use zeroize::Zeroizing;

use crate::seal::{MasterKey, SealError};

const MAGIC: &[u8; 4] = b"MKS2";
const NONCE_LEN: usize = 12;
/// Version 0 is reserved for the legacy single master key.
pub const LEGACY_VERSION: u32 = 0;

/// A key-encryption key: wraps and unwraps 32-byte DEKs. Implementations must
/// bind the wrapped blob to `(kek_id, version)` so a blob cannot be replayed
/// as a different version.
pub trait Kek: Send + Sync + std::fmt::Debug {
    fn kek_id(&self) -> &str;
    fn wrap(&self, version: u32, dek: &[u8; 32]) -> Result<Vec<u8>, SealError>;
    fn unwrap(&self, version: u32, wrapped: &[u8]) -> Result<Zeroizing<[u8; 32]>, SealError>;
}

/// KEK held as a 32-byte secret (environment / secrets manager). AES-256-GCM
/// with AAD `kek_id:version`.
#[derive(Clone)]
pub struct EnvKek {
    id: String,
    key: Zeroizing<[u8; 32]>,
}

impl std::fmt::Debug for EnvKek {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "EnvKek(id={})", self.id)
    }
}

impl EnvKek {
    pub fn new(id: impl Into<String>, key: &[u8]) -> Result<Self, SealError> {
        let arr: [u8; 32] = key.try_into().map_err(|_| SealError::BadKey)?;
        Ok(Self {
            id: id.into(),
            key: Zeroizing::new(arr),
        })
    }
    pub fn from_base64(id: impl Into<String>, b64: &str) -> Result<Self, SealError> {
        use base64::Engine as _;
        let raw = base64::engine::general_purpose::STANDARD
            .decode(b64.trim())
            .map_err(|_| SealError::BadKey)?;
        Self::new(id, &raw)
    }
}

impl Kek for EnvKek {
    fn kek_id(&self) -> &str {
        &self.id
    }
    fn wrap(&self, version: u32, dek: &[u8; 32]) -> Result<Vec<u8>, SealError> {
        let cipher = Aes256Gcm::new_from_slice(self.key.as_ref()).map_err(|_| SealError::BadKey)?;
        let mut nonce = [0u8; NONCE_LEN];
        rand::rngs::OsRng.fill_bytes(&mut nonce);
        let aad = format!("{}:{version}", self.id);
        let ct = cipher
            .encrypt(
                Nonce::from_slice(&nonce),
                Payload {
                    msg: dek,
                    aad: aad.as_bytes(),
                },
            )
            .map_err(|_| SealError::Unseal)?;
        let mut out = nonce.to_vec();
        out.extend_from_slice(&ct);
        Ok(out)
    }
    fn unwrap(&self, version: u32, wrapped: &[u8]) -> Result<Zeroizing<[u8; 32]>, SealError> {
        if wrapped.len() != NONCE_LEN + 32 + 16 {
            return Err(SealError::Unseal);
        }
        let cipher = Aes256Gcm::new_from_slice(self.key.as_ref()).map_err(|_| SealError::BadKey)?;
        let (nonce, ct) = wrapped.split_at(NONCE_LEN);
        let aad = format!("{}:{version}", self.id);
        let pt = cipher
            .decrypt(
                Nonce::from_slice(nonce),
                Payload {
                    msg: ct,
                    aad: aad.as_bytes(),
                },
            )
            .map_err(|_| SealError::Unseal)?;
        let arr: [u8; 32] = pt.as_slice().try_into().map_err(|_| SealError::Unseal)?;
        Ok(Zeroizing::new(arr))
    }
}

/// Loaded DEKs by version plus the current sealing version.
#[derive(Clone)]
pub struct Keyring {
    deks: BTreeMap<u32, Zeroizing<[u8; 32]>>,
    current: u32,
}

impl std::fmt::Debug for Keyring {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "Keyring(versions={:?}, current={})",
            self.deks.keys().collect::<Vec<_>>(),
            self.current
        )
    }
}

impl Keyring {
    /// Legacy/dev keyring: the master key is the only DEK, as version 0.
    #[must_use]
    pub fn legacy(master: &MasterKey) -> Self {
        let mut deks = BTreeMap::new();
        let mut k = Zeroizing::new([0u8; 32]);
        k.copy_from_slice(master.as_bytes());
        deks.insert(LEGACY_VERSION, k);
        Self {
            deks,
            current: LEGACY_VERSION,
        }
    }

    /// Build from unwrapped versions. `current` must be present and non-legacy
    /// unless it is the only version. Version 0 (legacy master) may be included
    /// so old rows remain readable during migration.
    pub fn from_versions(
        deks: BTreeMap<u32, Zeroizing<[u8; 32]>>,
        current: u32,
    ) -> Result<Self, SealError> {
        if !deks.contains_key(&current) {
            return Err(SealError::BadKey);
        }
        Ok(Self { deks, current })
    }

    #[must_use]
    pub fn current_version(&self) -> u32 {
        self.current
    }

    #[must_use]
    pub fn versions(&self) -> Vec<u32> {
        self.deks.keys().copied().collect()
    }

    /// Generate a fresh DEK and wrap it for storage. Does not add it to this
    /// keyring (the caller persists it, then reloads).
    pub fn new_wrapped_version(kek: &dyn Kek, version: u32) -> Result<Vec<u8>, SealError> {
        let mut dek = Zeroizing::new([0u8; 32]);
        rand::rngs::OsRng.fill_bytes(dek.as_mut());
        kek.wrap(version, &dek)
    }

    pub fn seal(&self, aad: &str, plaintext: &SecretString) -> Result<Vec<u8>, SealError> {
        let dek = self.deks.get(&self.current).ok_or(SealError::BadKey)?;
        let cipher = Aes256Gcm::new_from_slice(dek.as_ref()).map_err(|_| SealError::BadKey)?;
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
        let mut out = Vec::with_capacity(4 + 4 + NONCE_LEN + ct.len());
        out.extend_from_slice(MAGIC);
        out.extend_from_slice(&self.current.to_be_bytes());
        out.extend_from_slice(&nonce);
        out.extend_from_slice(&ct);
        Ok(out)
    }

    /// Which version a blob was sealed under (`LEGACY_VERSION` for legacy format).
    #[must_use]
    pub fn version_of(sealed: &[u8]) -> u32 {
        if sealed.len() >= 8 + NONCE_LEN + 16 && &sealed[..4] == MAGIC {
            u32::from_be_bytes([sealed[4], sealed[5], sealed[6], sealed[7]])
        } else {
            LEGACY_VERSION
        }
    }

    pub fn unseal(&self, aad: &str, sealed: &[u8]) -> Result<SecretString, SealError> {
        let (version, body) = if sealed.len() >= 8 + NONCE_LEN + 16 && &sealed[..4] == MAGIC {
            (
                u32::from_be_bytes([sealed[4], sealed[5], sealed[6], sealed[7]]),
                &sealed[8..],
            )
        } else {
            (LEGACY_VERSION, sealed)
        };
        if body.len() < NONCE_LEN + 16 {
            return Err(SealError::Unseal);
        }
        let dek = self.deks.get(&version).ok_or(SealError::Unseal)?;
        let cipher = Aes256Gcm::new_from_slice(dek.as_ref()).map_err(|_| SealError::BadKey)?;
        let (nonce, ct) = body.split_at(NONCE_LEN);
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
        String::from_utf8(pt.to_vec())
            .map(SecretString::from)
            .map_err(|_| SealError::Unseal)
    }

    /// Re-seal under the current version if sealed under an older one.
    /// Returns `None` when already current.
    pub fn reseal(&self, aad: &str, sealed: &[u8]) -> Result<Option<Vec<u8>>, SealError> {
        if Self::version_of(sealed) == self.current {
            return Ok(None);
        }
        let pt = self.unseal(aad, sealed)?;
        self.seal(aad, &pt).map(Some)
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;

    #[test]
    fn legacy_blobs_remain_readable_and_upgrade_on_reseal() {
        let master = MasterKey::generate();
        let legacy_blob =
            crate::seal::seal(&master, "t:a", &SecretString::from("secret".to_string())).unwrap();
        let kek = EnvKek::new("kek-test", &[9u8; 32]).unwrap();
        let wrapped = Keyring::new_wrapped_version(&kek, 1).unwrap();
        let mut deks = BTreeMap::new();
        let mut m = Zeroizing::new([0u8; 32]);
        m.copy_from_slice(master.as_bytes());
        deks.insert(0, m);
        deks.insert(1, kek.unwrap(1, &wrapped).unwrap());
        let ring = Keyring::from_versions(deks, 1).unwrap();
        assert_eq!(Keyring::version_of(&legacy_blob), 0);
        assert_eq!(
            ring.unseal("t:a", &legacy_blob).unwrap().expose_secret(),
            "secret"
        );
        let upgraded = ring.reseal("t:a", &legacy_blob).unwrap().unwrap();
        assert_eq!(Keyring::version_of(&upgraded), 1);
        assert_eq!(
            ring.unseal("t:a", &upgraded).unwrap().expose_secret(),
            "secret"
        );
        assert!(
            ring.reseal("t:a", &upgraded).unwrap().is_none(),
            "already current"
        );
        // A ring without version 0 cannot read legacy rows: retiring too early is loud, not silent.
        let mut only1 = BTreeMap::new();
        only1.insert(1, kek.unwrap(1, &wrapped).unwrap());
        let ring1 = Keyring::from_versions(only1, 1).unwrap();
        assert_eq!(
            ring1.unseal("t:a", &legacy_blob).err(),
            Some(SealError::Unseal)
        );
        assert_eq!(
            ring1.unseal("t:a", &upgraded).unwrap().expose_secret(),
            "secret"
        );
    }

    #[test]
    fn wrapped_dek_is_bound_to_kek_id_and_version() {
        let kek = EnvKek::new("kek-a", &[1u8; 32]).unwrap();
        let wrapped = Keyring::new_wrapped_version(&kek, 3).unwrap();
        assert!(kek.unwrap(3, &wrapped).is_ok());
        assert_eq!(
            kek.unwrap(4, &wrapped).err(),
            Some(SealError::Unseal),
            "version transplant"
        );
        let other = EnvKek::new("kek-b", &[1u8; 32]).unwrap();
        assert_eq!(
            other.unwrap(3, &wrapped).err(),
            Some(SealError::Unseal),
            "kek id transplant"
        );
        let wrong = EnvKek::new("kek-a", &[2u8; 32]).unwrap();
        assert_eq!(wrong.unwrap(3, &wrapped).err(), Some(SealError::Unseal));
        let mut t = wrapped.clone();
        t[20] ^= 1;
        assert_eq!(kek.unwrap(3, &t).err(), Some(SealError::Unseal));
    }

    #[test]
    fn aad_binding_and_tamper_detection_hold_for_v2() {
        let ring = Keyring::legacy(&MasterKey::generate());
        let mut deks = BTreeMap::new();
        deks.insert(7, Zeroizing::new([5u8; 32]));
        let ring7 = Keyring::from_versions(deks, 7).unwrap();
        let s = ring7
            .seal("tenant:x", &SecretString::from("body".to_string()))
            .unwrap();
        assert_eq!(&s[..4], b"MKS2");
        assert_eq!(ring7.unseal("tenant:y", &s).err(), Some(SealError::Unseal));
        let mut tampered = s.clone();
        *tampered.last_mut().unwrap() ^= 1;
        assert_eq!(
            ring7.unseal("tenant:x", &tampered).err(),
            Some(SealError::Unseal)
        );
        assert_eq!(
            ring.unseal("tenant:x", &s).err(),
            Some(SealError::Unseal),
            "unknown version"
        );
        assert!(Keyring::from_versions(BTreeMap::new(), 1).is_err());
    }
}
