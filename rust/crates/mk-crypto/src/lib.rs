//! Cryptographic primitives for the MK action kernel.
//!
//! Rules enforced by this crate:
//! * Secrets are wrapped in [`secrecy::SecretString`] / zeroizing buffers and
//!   never implement `Display`/`Debug` with their contents.
//! * Every comparison of a MAC or digest is constant-time.
//! * Canonicalization is RFC 8785 (JCS) so a digest is stable across
//!   languages and key orderings.
//! * Nothing in this crate logs.

pub mod assertion;
pub mod canonical;
pub mod digest;
pub mod hmac_sig;
pub mod keyring;
pub mod nonce;
pub mod seal;
pub mod secret;
pub mod webauthn;

pub use assertion::{ActorAssertion, AssertionError, AssertionSigner, AssertionVerifier};
pub use canonical::{CanonicalError, canonicalize};
pub use digest::{Digest, sha256_hex};
pub use hmac_sig::{
    HmacError, SignedHeaders, VerifyParams, canonical_signing_input, sign_hmac, verify_hmac,
};
pub use keyring::{EnvKek, Kek, Keyring, LEGACY_VERSION};
pub use nonce::{NonceError, NonceWindow, ReplayGuard};
pub use seal::{MasterKey, SealError, seal, unseal};
pub use secret::{AdapterSecret, constant_time_eq, generate_secret};
pub use webauthn::{CoseAlg, CredentialPublicKey, RegisteredCredential, WebAuthnError};
