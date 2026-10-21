//! Transaction-bound WebAuthn verification for human approvals (contract WP06, row H6).
//!
//! Threat model: the proposal service (FastAPI) is assumed compromised. It holds
//! the actor-assertion signing key and can therefore present any *principal* to
//! the kernel, but it does not hold any user's passkey private key. An approval
//! is accepted only with a WebAuthn assertion whose challenge the kernel itself
//! derived from the action digest, so a forged principal without the human's
//! authenticator cannot mint an approval, and an approval cannot be replayed
//! against a different action or a changed action.
//!
//! Scope — deliberately narrow and auditable, pure Rust:
//! * Registration: attestation format `none` (what the RP requests) and
//!   `packed` self-attestation. Anything else is refused.
//! * Credential algorithms: ES256 (COSE -7), EdDSA/Ed25519 (COSE -8), RS256 (COSE -257).
//! * Assertion: `type == "webauthn.get"`, challenge equals the kernel's expected
//!   value byte-for-byte, origin is on the allowlist, `rpIdHash == SHA-256(rp_id)`,
//!   user-present and user-verified flags set, sign counter strictly increasing
//!   when the authenticator uses one, signature over `authData || SHA-256(clientDataJSON)`.
//!
//! Nothing here touches the network, logs, or allocates secrets.

use base64::Engine as _;
use serde::{Deserialize, Serialize};
use sha2::{Digest as _, Sha256};

use rsa::pkcs1::EncodeRsaPublicKey as _;

use crate::digest::Digest;

const B64: base64::engine::GeneralPurpose = base64::engine::general_purpose::URL_SAFE_NO_PAD;
const FLAG_UP: u8 = 0x01;
const FLAG_UV: u8 = 0x04;
const FLAG_AT: u8 = 0x40;
const FLAG_ED: u8 = 0x80;
const MAX_BLOB: usize = 64 * 1024;
const CHALLENGE_DOMAIN: &[u8] = b"mk-approval-challenge-v1\0";

#[derive(Debug, thiserror::Error, Clone, PartialEq, Eq)]
pub enum WebAuthnError {
    #[error("input malformed: {0}")]
    Malformed(&'static str),
    #[error("unsupported: {0}")]
    Unsupported(&'static str),
    #[error("client data type mismatch")]
    WrongType,
    #[error("challenge mismatch")]
    ChallengeMismatch,
    #[error("origin not allowed")]
    OriginNotAllowed,
    #[error("rpIdHash mismatch")]
    RpIdMismatch,
    #[error("user presence flag missing")]
    UserNotPresent,
    #[error("user verification flag missing")]
    UserNotVerified,
    #[error("sign counter did not increase (cloned authenticator?)")]
    CounterRegression,
    #[error("signature invalid")]
    BadSignature,
    #[error("credential id mismatch")]
    CredentialMismatch,
}

impl WebAuthnError {
    #[must_use]
    pub const fn code(&self) -> &'static str {
        match self {
            Self::Malformed(_) => "webauthn_malformed",
            Self::Unsupported(_) => "webauthn_unsupported",
            Self::WrongType => "webauthn_wrong_type",
            Self::ChallengeMismatch => "webauthn_challenge_mismatch",
            Self::OriginNotAllowed => "webauthn_origin_not_allowed",
            Self::RpIdMismatch => "webauthn_rp_id_mismatch",
            Self::UserNotPresent => "webauthn_user_not_present",
            Self::UserNotVerified => "webauthn_user_not_verified",
            Self::CounterRegression => "webauthn_counter_regression",
            Self::BadSignature => "webauthn_bad_signature",
            Self::CredentialMismatch => "webauthn_credential_mismatch",
        }
    }
}

/// COSE algorithm identifiers we accept.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum CoseAlg {
    /// ECDSA w/ SHA-256 on P-256 (COSE -7).
    Es256,
    /// Ed25519 (COSE -8).
    EdDsa,
    /// RSASSA-PKCS1-v1_5 w/ SHA-256 (COSE -257).
    Rs256,
}

impl CoseAlg {
    #[must_use]
    pub const fn cose_id(self) -> i64 {
        match self {
            Self::Es256 => -7,
            Self::EdDsa => -8,
            Self::Rs256 => -257,
        }
    }
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Es256 => "ES256",
            Self::EdDsa => "EdDSA",
            Self::Rs256 => "RS256",
        }
    }
    pub fn parse(s: &str) -> Result<Self, WebAuthnError> {
        match s {
            "ES256" => Ok(Self::Es256),
            "EdDSA" => Ok(Self::EdDsa),
            "RS256" => Ok(Self::Rs256),
            _ => Err(WebAuthnError::Unsupported("algorithm")),
        }
    }
}

/// A verified, stored credential public key.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CredentialPublicKey {
    pub alg: CoseAlg,
    /// Raw key material: SEC1 uncompressed point (65 bytes) for ES256,
    /// 32-byte Ed25519 public key for EdDSA, PKCS#1 DER for RS256.
    pub key: Vec<u8>,
}

/// What a registration ceremony yields.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RegisteredCredential {
    pub credential_id: Vec<u8>,
    pub public_key: CredentialPublicKey,
    pub sign_count: u32,
    pub aaguid: [u8; 16],
    pub attestation_format: String,
    pub user_verified: bool,
}

#[derive(Debug, Deserialize)]
struct ClientData {
    #[serde(rename = "type")]
    typ: String,
    challenge: String,
    origin: String,
}

struct AuthData<'a> {
    rp_id_hash: [u8; 32],
    flags: u8,
    sign_count: u32,
    attested: Option<(
        /*aaguid*/ [u8; 16],
        /*cred id*/ &'a [u8],
        /*cose key*/ &'a [u8],
    )>,
}

fn parse_auth_data(bytes: &[u8]) -> Result<AuthData<'_>, WebAuthnError> {
    if bytes.len() > MAX_BLOB || bytes.len() < 37 {
        return Err(WebAuthnError::Malformed("authenticatorData length"));
    }
    let mut rp_id_hash = [0u8; 32];
    rp_id_hash.copy_from_slice(&bytes[..32]);
    let flags = bytes[32];
    let sign_count = u32::from_be_bytes([bytes[33], bytes[34], bytes[35], bytes[36]]);
    let mut rest = &bytes[37..];
    let mut attested = None;
    if flags & FLAG_AT != 0 {
        if rest.len() < 18 {
            return Err(WebAuthnError::Malformed("attestedCredentialData"));
        }
        let mut aaguid = [0u8; 16];
        aaguid.copy_from_slice(&rest[..16]);
        let id_len = usize::from(u16::from_be_bytes([rest[16], rest[17]]));
        rest = &rest[18..];
        if id_len == 0 || id_len > 1023 || rest.len() < id_len {
            return Err(WebAuthnError::Malformed("credentialId length"));
        }
        let (cred_id, after) = rest.split_at(id_len);
        // The COSE key is a CBOR map; determine its encoded length by parsing it.
        let key_len = cbor_item_len(after)?;
        let (cose, tail) = after.split_at(key_len);
        attested = Some((aaguid, cred_id, cose));
        rest = tail;
    }
    if flags & FLAG_ED != 0 {
        // Extensions present: must be exactly one CBOR map and nothing after.
        let n = cbor_item_len(rest)?;
        rest = &rest[n..];
    }
    if !rest.is_empty() {
        return Err(WebAuthnError::Malformed(
            "trailing bytes in authenticatorData",
        ));
    }
    Ok(AuthData {
        rp_id_hash,
        flags,
        sign_count,
        attested,
    })
}

/// Length in bytes of the first CBOR item in `b`, by decoding it with
/// ciborium and re-locating the end via a counting reader.
fn cbor_item_len(b: &[u8]) -> Result<usize, WebAuthnError> {
    struct Counting<'a> {
        inner: &'a [u8],
        pos: usize,
    }
    impl std::io::Read for Counting<'_> {
        fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
            let n = buf.len().min(self.inner.len() - self.pos);
            buf[..n].copy_from_slice(&self.inner[self.pos..self.pos + n]);
            self.pos += n;
            Ok(n)
        }
    }
    let mut r = Counting { inner: b, pos: 0 };
    let _: ciborium::Value =
        ciborium::from_reader(&mut r).map_err(|_| WebAuthnError::Malformed("cbor"))?;
    Ok(r.pos)
}

fn cbor_get(map: &[(ciborium::Value, ciborium::Value)], key: i128) -> Option<&ciborium::Value> {
    map.iter()
        .find(|(k, _)| matches!(k, ciborium::Value::Integer(i) if i128::from(*i) == key))
        .map(|(_, v)| v)
}

fn cbor_get_text<'v>(
    map: &'v [(ciborium::Value, ciborium::Value)],
    key: &str,
) -> Option<&'v ciborium::Value> {
    map.iter()
        .find(|(k, _)| matches!(k, ciborium::Value::Text(t) if t == key))
        .map(|(_, v)| v)
}

/// Parse a COSE_Key into one of the supported public keys.
pub fn parse_cose_key(cose: &[u8]) -> Result<CredentialPublicKey, WebAuthnError> {
    let v: ciborium::Value =
        ciborium::from_reader(cose).map_err(|_| WebAuthnError::Malformed("cose key cbor"))?;
    let ciborium::Value::Map(m) = v else {
        return Err(WebAuthnError::Malformed("cose key not a map"));
    };
    let int = |k: i128| -> Option<i128> {
        match cbor_get(&m, k) {
            Some(ciborium::Value::Integer(i)) => Some(i128::from(*i)),
            _ => None,
        }
    };
    let bytes = |k: i128| -> Option<&[u8]> {
        match cbor_get(&m, k) {
            Some(ciborium::Value::Bytes(b)) => Some(b.as_slice()),
            _ => None,
        }
    };
    let kty = int(1).ok_or(WebAuthnError::Malformed("cose kty"))?;
    let alg = int(3).ok_or(WebAuthnError::Malformed("cose alg"))?;
    match (kty, alg) {
        (2, -7) => {
            // EC2, crv(-1) must be P-256 (1); x(-2), y(-3) 32 bytes each.
            if int(-1) != Some(1) {
                return Err(WebAuthnError::Unsupported("EC curve"));
            }
            let x = bytes(-2).ok_or(WebAuthnError::Malformed("cose x"))?;
            let y = bytes(-3).ok_or(WebAuthnError::Malformed("cose y"))?;
            if x.len() != 32 || y.len() != 32 {
                return Err(WebAuthnError::Malformed("cose coordinate length"));
            }
            let mut sec1 = Vec::with_capacity(65);
            sec1.push(0x04);
            sec1.extend_from_slice(x);
            sec1.extend_from_slice(y);
            // Reject points not on the curve now rather than at verify time.
            p256::ecdsa::VerifyingKey::from_sec1_bytes(&sec1)
                .map_err(|_| WebAuthnError::Malformed("EC point"))?;
            Ok(CredentialPublicKey {
                alg: CoseAlg::Es256,
                key: sec1,
            })
        }
        (1, -8) => {
            if int(-1) != Some(6) {
                return Err(WebAuthnError::Unsupported("OKP curve"));
            }
            let x = bytes(-2).ok_or(WebAuthnError::Malformed("cose x"))?;
            let arr: [u8; 32] = x
                .try_into()
                .map_err(|_| WebAuthnError::Malformed("ed25519 length"))?;
            ed25519_dalek::VerifyingKey::from_bytes(&arr)
                .map_err(|_| WebAuthnError::Malformed("ed25519 point"))?;
            Ok(CredentialPublicKey {
                alg: CoseAlg::EdDsa,
                key: arr.to_vec(),
            })
        }
        (3, -257) => {
            let n = bytes(-1).ok_or(WebAuthnError::Malformed("rsa n"))?;
            let e = bytes(-2).ok_or(WebAuthnError::Malformed("rsa e"))?;
            if n.len() < 256 || n.len() > 512 {
                return Err(WebAuthnError::Unsupported("RSA modulus size"));
            }
            let pk = rsa::RsaPublicKey::new(
                rsa::BigUint::from_bytes_be(n),
                rsa::BigUint::from_bytes_be(e),
            )
            .map_err(|_| WebAuthnError::Malformed("rsa key"))?;
            let der = pk
                .to_pkcs1_der()
                .map_err(|_| WebAuthnError::Malformed("rsa der"))?;
            Ok(CredentialPublicKey {
                alg: CoseAlg::Rs256,
                key: der.as_bytes().to_vec(),
            })
        }
        _ => Err(WebAuthnError::Unsupported("algorithm")),
    }
}

fn verify_sig(pk: &CredentialPublicKey, msg: &[u8], sig: &[u8]) -> Result<(), WebAuthnError> {
    match pk.alg {
        CoseAlg::Es256 => {
            use p256::ecdsa::signature::Verifier as _;
            let vk = p256::ecdsa::VerifyingKey::from_sec1_bytes(&pk.key)
                .map_err(|_| WebAuthnError::Malformed("EC key"))?;
            // WebAuthn ES256 signatures are ASN.1 DER.
            let s =
                p256::ecdsa::Signature::from_der(sig).map_err(|_| WebAuthnError::BadSignature)?;
            vk.verify(msg, &s).map_err(|_| WebAuthnError::BadSignature)
        }
        CoseAlg::EdDsa => {
            use ed25519_dalek::Verifier as _;
            let arr: [u8; 32] = pk
                .key
                .as_slice()
                .try_into()
                .map_err(|_| WebAuthnError::Malformed("ed key"))?;
            let vk = ed25519_dalek::VerifyingKey::from_bytes(&arr)
                .map_err(|_| WebAuthnError::Malformed("ed key"))?;
            let s = ed25519_dalek::Signature::from_slice(sig)
                .map_err(|_| WebAuthnError::BadSignature)?;
            vk.verify(msg, &s).map_err(|_| WebAuthnError::BadSignature)
        }
        CoseAlg::Rs256 => {
            use rsa::pkcs1::DecodeRsaPublicKey as _;
            let pk = rsa::RsaPublicKey::from_pkcs1_der(&pk.key)
                .map_err(|_| WebAuthnError::Malformed("rsa key"))?;
            let hashed = Sha256::digest(msg);
            pk.verify(rsa::Pkcs1v15Sign::new::<Sha256>(), &hashed, sig)
                .map_err(|_| WebAuthnError::BadSignature)
        }
    }
}

fn parse_client_data(
    raw: &[u8],
    expected_type: &str,
    expected_challenge: &[u8],
    allowed_origins: &[String],
) -> Result<[u8; 32], WebAuthnError> {
    if raw.len() > MAX_BLOB {
        return Err(WebAuthnError::Malformed("clientDataJSON length"));
    }
    let cd: ClientData =
        serde_json::from_slice(raw).map_err(|_| WebAuthnError::Malformed("clientDataJSON"))?;
    if cd.typ != expected_type {
        return Err(WebAuthnError::WrongType);
    }
    let got = B64
        .decode(cd.challenge.as_bytes())
        .map_err(|_| WebAuthnError::Malformed("challenge encoding"))?;
    if !crate::secret::constant_time_eq(&got, expected_challenge) {
        return Err(WebAuthnError::ChallengeMismatch);
    }
    if !allowed_origins.iter().any(|o| o == &cd.origin) {
        return Err(WebAuthnError::OriginNotAllowed);
    }
    Ok(Sha256::digest(raw).into())
}

fn check_rp(ad: &AuthData<'_>, rp_id: &str) -> Result<(), WebAuthnError> {
    let expected: [u8; 32] = Sha256::digest(rp_id.as_bytes()).into();
    if !crate::secret::constant_time_eq(&ad.rp_id_hash, &expected) {
        return Err(WebAuthnError::RpIdMismatch);
    }
    Ok(())
}

/// Registration ceremony verification (`navigator.credentials.create`).
///
/// `attestation_object` is the CBOR `{fmt, attStmt, authData}`. Formats
/// accepted: `none`, and `packed` **self**-attestation (no x5c), which is
/// verified with the credential's own key. Both are what consumer passkeys
/// return when the RP asks for `attestation: "none"`.
pub fn verify_registration(
    client_data_json: &[u8],
    attestation_object: &[u8],
    expected_challenge: &[u8],
    rp_id: &str,
    allowed_origins: &[String],
    require_uv: bool,
) -> Result<RegisteredCredential, WebAuthnError> {
    if attestation_object.len() > MAX_BLOB {
        return Err(WebAuthnError::Malformed("attestationObject length"));
    }
    let client_hash = parse_client_data(
        client_data_json,
        "webauthn.create",
        expected_challenge,
        allowed_origins,
    )?;
    let v: ciborium::Value = ciborium::from_reader(attestation_object)
        .map_err(|_| WebAuthnError::Malformed("attestationObject cbor"))?;
    let ciborium::Value::Map(m) = v else {
        return Err(WebAuthnError::Malformed("attestationObject not a map"));
    };
    let fmt = match cbor_get_text(&m, "fmt") {
        Some(ciborium::Value::Text(t)) => t.clone(),
        _ => return Err(WebAuthnError::Malformed("fmt")),
    };
    let auth_data = match cbor_get_text(&m, "authData") {
        Some(ciborium::Value::Bytes(b)) => b.as_slice(),
        _ => return Err(WebAuthnError::Malformed("authData")),
    };
    let ad = parse_auth_data(auth_data)?;
    check_rp(&ad, rp_id)?;
    if ad.flags & FLAG_UP == 0 {
        return Err(WebAuthnError::UserNotPresent);
    }
    if require_uv && ad.flags & FLAG_UV == 0 {
        return Err(WebAuthnError::UserNotVerified);
    }
    let (aaguid, cred_id, cose) = ad
        .attested
        .ok_or(WebAuthnError::Malformed("no attested credential data"))?;
    let public_key = parse_cose_key(cose)?;
    match fmt.as_str() {
        "none" => {}
        "packed" => {
            let ciborium::Value::Map(st) =
                cbor_get_text(&m, "attStmt").ok_or(WebAuthnError::Malformed("attStmt"))?
            else {
                return Err(WebAuthnError::Malformed("attStmt"));
            };
            if cbor_get_text(st, "x5c").is_some() || cbor_get_text(st, "ecdaaKeyId").is_some() {
                return Err(WebAuthnError::Unsupported(
                    "packed attestation with certificate chain",
                ));
            }
            let alg = match cbor_get_text(st, "alg") {
                Some(ciborium::Value::Integer(i)) => i128::from(*i),
                _ => return Err(WebAuthnError::Malformed("attStmt alg")),
            };
            if alg != i128::from(public_key.alg.cose_id()) {
                return Err(WebAuthnError::Malformed(
                    "attStmt alg differs from credential alg",
                ));
            }
            let sig = match cbor_get_text(st, "sig") {
                Some(ciborium::Value::Bytes(b)) => b.as_slice(),
                _ => return Err(WebAuthnError::Malformed("attStmt sig")),
            };
            let mut msg = Vec::with_capacity(auth_data.len() + 32);
            msg.extend_from_slice(auth_data);
            msg.extend_from_slice(&client_hash);
            verify_sig(&public_key, &msg, sig)?;
        }
        _ => return Err(WebAuthnError::Unsupported("attestation format")),
    }
    Ok(RegisteredCredential {
        credential_id: cred_id.to_vec(),
        public_key,
        sign_count: ad.sign_count,
        aaguid,
        attestation_format: fmt,
        user_verified: ad.flags & FLAG_UV != 0,
    })
}

/// Authentication ceremony verification (`navigator.credentials.get`).
/// Returns the new sign counter to persist.
pub fn verify_assertion(
    client_data_json: &[u8],
    authenticator_data: &[u8],
    signature: &[u8],
    expected_challenge: &[u8],
    rp_id: &str,
    allowed_origins: &[String],
    credential: &CredentialPublicKey,
    stored_sign_count: u32,
    require_uv: bool,
) -> Result<u32, WebAuthnError> {
    let client_hash = parse_client_data(
        client_data_json,
        "webauthn.get",
        expected_challenge,
        allowed_origins,
    )?;
    let ad = parse_auth_data(authenticator_data)?;
    check_rp(&ad, rp_id)?;
    if ad.flags & FLAG_UP == 0 {
        return Err(WebAuthnError::UserNotPresent);
    }
    if require_uv && ad.flags & FLAG_UV == 0 {
        return Err(WebAuthnError::UserNotVerified);
    }
    // Sign counter: if either side uses one, it must strictly increase.
    if (ad.sign_count != 0 || stored_sign_count != 0) && ad.sign_count <= stored_sign_count {
        return Err(WebAuthnError::CounterRegression);
    }
    let mut msg = Vec::with_capacity(authenticator_data.len() + 32);
    msg.extend_from_slice(authenticator_data);
    msg.extend_from_slice(&client_hash);
    verify_sig(credential, &msg, signature)?;
    Ok(ad.sign_count)
}

/// The kernel-derived challenge for approving one exact action version.
///
/// `nonce` is fresh per challenge issuance (stored, single-use, short-lived).
/// Binding the digest into the challenge means a signature over it cannot be
/// transplanted to another action or to the same action after any edit.
#[must_use]
pub fn approval_challenge(
    tenant_id: &[u8; 16],
    user_id: &[u8; 16],
    action_id: &[u8; 16],
    action_digest: &Digest,
    nonce: &[u8; 32],
) -> [u8; 32] {
    let mut h = Sha256::new();
    h.update(CHALLENGE_DOMAIN);
    h.update(tenant_id);
    h.update(user_id);
    h.update(action_id);
    h.update(action_digest.as_bytes());
    h.update(nonce);
    h.finalize().into()
}

/// base64url (no padding) as used in `clientDataJSON.challenge`.
#[must_use]
pub fn b64url(bytes: &[u8]) -> String {
    B64.encode(bytes)
}

pub fn b64url_decode(s: &str) -> Result<Vec<u8>, WebAuthnError> {
    if s.len() > MAX_BLOB {
        return Err(WebAuthnError::Malformed("base64url length"));
    }
    B64.decode(s.as_bytes())
        .map_err(|_| WebAuthnError::Malformed("base64url"))
}

// ---------------------------------------------------------------------------
// Software authenticator — test equipment for the kernel's own tests, the live
// smoke, and the browser-less e2e. NOT a product component. Produces exactly
// the byte formats a platform authenticator does, so the verifier above is
// exercised on real encodings rather than hand-built fixtures.
pub mod softauthn {
    use super::*;
    use p256::ecdsa::signature::Signer as _;

    #[derive(Debug)]
    pub enum Key {
        Es256(p256::ecdsa::SigningKey),
        EdDsa(ed25519_dalek::SigningKey),
    }

    /// One registered software credential.
    pub struct SoftAuthenticator {
        pub credential_id: Vec<u8>,
        pub aaguid: [u8; 16],
        pub counter: u32,
        pub uv: bool,
        key: Key,
    }

    impl std::fmt::Debug for SoftAuthenticator {
        fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
            write!(
                f,
                "SoftAuthenticator(cred={}, counter={})",
                hex::encode(&self.credential_id),
                self.counter
            )
        }
    }

    fn cbor_bytes(v: &ciborium::Value) -> Vec<u8> {
        let mut out = Vec::new();
        // Serialising a Value we built ourselves cannot fail.
        if ciborium::into_writer(v, &mut out).is_err() {
            out.clear();
        }
        out
    }

    impl SoftAuthenticator {
        #[must_use]
        pub fn new_es256() -> Self {
            Self::with_key(Key::Es256(p256::ecdsa::SigningKey::random(
                &mut rand::rngs::OsRng,
            )))
        }
        #[must_use]
        pub fn new_ed25519() -> Self {
            Self::with_key(Key::EdDsa(ed25519_dalek::SigningKey::generate(
                &mut rand::rngs::OsRng,
            )))
        }
        fn with_key(key: Key) -> Self {
            use rand::RngCore as _;
            let mut id = vec![0u8; 32];
            rand::rngs::OsRng.fill_bytes(&mut id);
            Self {
                credential_id: id,
                aaguid: [0xA5; 16],
                counter: 0,
                uv: true,
                key,
            }
        }

        /// Serialise for a multi-invocation CLI (test equipment only; the
        /// secret is written in the clear to a file the operator controls).
        #[must_use]
        pub fn export(&self) -> String {
            let (alg, secret) = match &self.key {
                Key::Es256(sk) => ("ES256", hex::encode(sk.to_bytes())),
                Key::EdDsa(sk) => ("EdDSA", hex::encode(sk.to_bytes())),
            };
            serde_json::json!({"alg": alg, "secret_hex": secret, "credential_id_hex": hex::encode(&self.credential_id),
                               "counter": self.counter, "uv": self.uv})
            .to_string()
        }

        pub fn import(state: &str) -> Result<Self, WebAuthnError> {
            let v: serde_json::Value =
                serde_json::from_str(state).map_err(|_| WebAuthnError::Malformed("state"))?;
            let secret = hex::decode(v["secret_hex"].as_str().unwrap_or(""))
                .map_err(|_| WebAuthnError::Malformed("state secret"))?;
            let key = match v["alg"].as_str() {
                Some("ES256") => Key::Es256(
                    p256::ecdsa::SigningKey::from_slice(&secret)
                        .map_err(|_| WebAuthnError::Malformed("state key"))?,
                ),
                Some("EdDSA") => {
                    let arr: [u8; 32] = secret
                        .as_slice()
                        .try_into()
                        .map_err(|_| WebAuthnError::Malformed("state key"))?;
                    Key::EdDsa(ed25519_dalek::SigningKey::from_bytes(&arr))
                }
                _ => return Err(WebAuthnError::Unsupported("state alg")),
            };
            Ok(Self {
                credential_id: hex::decode(v["credential_id_hex"].as_str().unwrap_or(""))
                    .map_err(|_| WebAuthnError::Malformed("state cred"))?,
                aaguid: [0xA5; 16],
                counter: u32::try_from(v["counter"].as_u64().unwrap_or(0)).unwrap_or(0),
                uv: v["uv"].as_bool().unwrap_or(true),
                key,
            })
        }

        fn cose_key(&self) -> ciborium::Value {
            use ciborium::Value as V;
            match &self.key {
                Key::Es256(sk) => {
                    let p = sk.verifying_key().to_encoded_point(false);
                    V::Map(vec![
                        (V::Integer(1.into()), V::Integer(2.into())),
                        (V::Integer(3.into()), V::Integer((-7).into())),
                        (V::Integer((-1).into()), V::Integer(1.into())),
                        (
                            V::Integer((-2).into()),
                            V::Bytes(p.x().map(|x| x.to_vec()).unwrap_or_default()),
                        ),
                        (
                            V::Integer((-3).into()),
                            V::Bytes(p.y().map(|y| y.to_vec()).unwrap_or_default()),
                        ),
                    ])
                }
                Key::EdDsa(sk) => V::Map(vec![
                    (V::Integer(1.into()), V::Integer(1.into())),
                    (V::Integer(3.into()), V::Integer((-8).into())),
                    (V::Integer((-1).into()), V::Integer(6.into())),
                    (
                        V::Integer((-2).into()),
                        V::Bytes(sk.verifying_key().to_bytes().to_vec()),
                    ),
                ]),
            }
        }

        fn flags(&self, attested: bool) -> u8 {
            let mut f = FLAG_UP;
            if self.uv {
                f |= FLAG_UV;
            }
            if attested {
                f |= FLAG_AT;
            }
            f
        }

        fn sign(&self, msg: &[u8]) -> Vec<u8> {
            match &self.key {
                Key::Es256(sk) => {
                    let s: p256::ecdsa::Signature = sk.sign(msg);
                    s.to_der().as_bytes().to_vec()
                }
                Key::EdDsa(sk) => {
                    use ed25519_dalek::Signer as _;
                    sk.sign(msg).to_bytes().to_vec()
                }
            }
        }

        fn client_data(typ: &str, challenge: &[u8], origin: &str) -> Vec<u8> {
            serde_json::to_vec(&serde_json::json!({
                "type": typ, "challenge": b64url(challenge), "origin": origin, "crossOrigin": false
            }))
            .unwrap_or_default()
        }

        /// `(clientDataJSON, attestationObject)` for a `none`-format registration.
        pub fn register(
            &mut self,
            challenge: &[u8],
            rp_id: &str,
            origin: &str,
        ) -> (Vec<u8>, Vec<u8>) {
            use ciborium::Value as V;
            self.counter += 1;
            let cd = Self::client_data("webauthn.create", challenge, origin);
            let mut ad = Vec::new();
            ad.extend_from_slice(&Sha256::digest(rp_id.as_bytes()));
            ad.push(self.flags(true));
            ad.extend_from_slice(&self.counter.to_be_bytes());
            ad.extend_from_slice(&self.aaguid);
            ad.extend_from_slice(
                &u16::try_from(self.credential_id.len())
                    .unwrap_or(0)
                    .to_be_bytes(),
            );
            ad.extend_from_slice(&self.credential_id);
            ad.extend_from_slice(&cbor_bytes(&self.cose_key()));
            let att = V::Map(vec![
                (V::Text("fmt".into()), V::Text("none".into())),
                (V::Text("attStmt".into()), V::Map(vec![])),
                (V::Text("authData".into()), V::Bytes(ad)),
            ]);
            (cd, cbor_bytes(&att))
        }

        /// `(clientDataJSON, authenticatorData, signature)` for an assertion.
        pub fn assert(
            &mut self,
            challenge: &[u8],
            rp_id: &str,
            origin: &str,
        ) -> (Vec<u8>, Vec<u8>, Vec<u8>) {
            self.counter += 1;
            let cd = Self::client_data("webauthn.get", challenge, origin);
            let mut ad = Vec::new();
            ad.extend_from_slice(&Sha256::digest(rp_id.as_bytes()));
            ad.push(self.flags(false));
            ad.extend_from_slice(&self.counter.to_be_bytes());
            let mut msg = ad.clone();
            msg.extend_from_slice(&Sha256::digest(&cd));
            let sig = self.sign(&msg);
            (cd, ad, sig)
        }
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::panic)]
mod tests {
    use super::softauthn::SoftAuthenticator;
    use super::*;

    const RP: &str = "approve.example.com";
    fn origins() -> Vec<String> {
        vec!["https://approve.example.com".into()]
    }

    fn registered(a: &mut SoftAuthenticator) -> RegisteredCredential {
        let ch = [7u8; 32];
        let (cd, att) = a.register(&ch, RP, "https://approve.example.com");
        verify_registration(&cd, &att, &ch, RP, &origins(), true).unwrap()
    }

    #[test]
    fn register_and_assert_es256_and_ed25519() {
        for mut a in [
            SoftAuthenticator::new_es256(),
            SoftAuthenticator::new_ed25519(),
        ] {
            let cred = registered(&mut a);
            assert_eq!(cred.credential_id, a.credential_id);
            let ch = [9u8; 32];
            let (cd, ad, sig) = a.assert(&ch, RP, "https://approve.example.com");
            let n = verify_assertion(
                &cd,
                &ad,
                &sig,
                &ch,
                RP,
                &origins(),
                &cred.public_key,
                cred.sign_count,
                true,
            )
            .unwrap();
            assert_eq!(n, cred.sign_count + 1);
        }
    }

    #[test]
    fn wrong_challenge_is_rejected() {
        let mut a = SoftAuthenticator::new_es256();
        let cred = registered(&mut a);
        let (cd, ad, sig) = a.assert(&[1u8; 32], RP, "https://approve.example.com");
        assert_eq!(
            verify_assertion(
                &cd,
                &ad,
                &sig,
                &[2u8; 32],
                RP,
                &origins(),
                &cred.public_key,
                cred.sign_count,
                true
            ),
            Err(WebAuthnError::ChallengeMismatch)
        );
    }

    #[test]
    fn digest_change_changes_challenge() {
        let t = [1u8; 16];
        let d1 = Digest::of(b"hello");
        let d2 = Digest::of(b"hellp");
        assert_ne!(
            approval_challenge(&t, &t, &t, &d1, &[0; 32]),
            approval_challenge(&t, &t, &t, &d2, &[0; 32])
        );
        assert_ne!(
            approval_challenge(&t, &t, &t, &d1, &[0; 32]),
            approval_challenge(&t, &t, &t, &d1, &[1; 32])
        );
    }

    #[test]
    fn wrong_origin_rp_type_flags_are_rejected() {
        let mut a = SoftAuthenticator::new_es256();
        let cred = registered(&mut a);
        let ch = [3u8; 32];
        let (cd, ad, sig) = a.assert(&ch, RP, "https://evil.example.com");
        assert_eq!(
            verify_assertion(
                &cd,
                &ad,
                &sig,
                &ch,
                RP,
                &origins(),
                &cred.public_key,
                1,
                true
            ),
            Err(WebAuthnError::OriginNotAllowed)
        );
        let (cd, ad, sig) = a.assert(&ch, "other.example.com", "https://approve.example.com");
        assert_eq!(
            verify_assertion(
                &cd,
                &ad,
                &sig,
                &ch,
                RP,
                &origins(),
                &cred.public_key,
                1,
                true
            ),
            Err(WebAuthnError::RpIdMismatch)
        );
        // Registration clientData presented as an assertion → wrong type.
        let (cd, att) = a.register(&ch, RP, "https://approve.example.com");
        assert_eq!(
            verify_assertion(
                &cd,
                &att,
                &[0u8; 8],
                &ch,
                RP,
                &origins(),
                &cred.public_key,
                1,
                true
            ),
            Err(WebAuthnError::WrongType)
        );
        // No UV when required.
        a.uv = false;
        let (cd, ad, sig) = a.assert(&ch, RP, "https://approve.example.com");
        assert_eq!(
            verify_assertion(
                &cd,
                &ad,
                &sig,
                &ch,
                RP,
                &origins(),
                &cred.public_key,
                1,
                true
            ),
            Err(WebAuthnError::UserNotVerified)
        );
    }

    #[test]
    fn tampered_byte_and_wrong_key_fail() {
        let mut a = SoftAuthenticator::new_es256();
        let cred = registered(&mut a);
        let ch = [4u8; 32];
        let (cd, mut ad, sig) = a.assert(&ch, RP, "https://approve.example.com");
        ad[33] ^= FLAG_ED; // flip a flag bit after signing → trailing/sig failure
        assert!(
            verify_assertion(
                &cd,
                &ad,
                &sig,
                &ch,
                RP,
                &origins(),
                &cred.public_key,
                1,
                true
            )
            .is_err()
        );
        let mut b = SoftAuthenticator::new_es256();
        let other = registered(&mut b);
        let (cd, ad, sig) = a.assert(&ch, RP, "https://approve.example.com");
        assert_eq!(
            verify_assertion(
                &cd,
                &ad,
                &sig,
                &ch,
                RP,
                &origins(),
                &other.public_key,
                1,
                true
            ),
            Err(WebAuthnError::BadSignature)
        );
    }

    #[test]
    fn counter_regression_is_rejected() {
        let mut a = SoftAuthenticator::new_es256();
        let cred = registered(&mut a);
        let ch = [5u8; 32];
        let (cd, ad, sig) = a.assert(&ch, RP, "https://approve.example.com");
        let n = verify_assertion(
            &cd,
            &ad,
            &sig,
            &ch,
            RP,
            &origins(),
            &cred.public_key,
            cred.sign_count,
            true,
        )
        .unwrap();
        // Replaying the same assertion against the updated counter fails.
        assert_eq!(
            verify_assertion(
                &cd,
                &ad,
                &sig,
                &ch,
                RP,
                &origins(),
                &cred.public_key,
                n,
                true
            ),
            Err(WebAuthnError::CounterRegression)
        );
    }

    #[test]
    fn unsupported_attestation_and_algorithms_are_refused() {
        use ciborium::Value as V;
        let mut a = SoftAuthenticator::new_es256();
        let ch = [6u8; 32];
        let (cd, att) = a.register(&ch, RP, "https://approve.example.com");
        let v: V = ciborium::from_reader(att.as_slice()).unwrap();
        let V::Map(mut m) = v else { panic!() };
        for (k, val) in &mut m {
            if matches!(k, V::Text(t) if t == "fmt") {
                *val = V::Text("tpm".into());
            }
        }
        let mut out = Vec::new();
        ciborium::into_writer(&V::Map(m), &mut out).unwrap();
        assert_eq!(
            verify_registration(&cd, &out, &ch, RP, &origins(), true),
            Err(WebAuthnError::Unsupported("attestation format"))
        );
        // RS1 / ES384 keys are refused at parse time.
        let mut k = Vec::new();
        ciborium::into_writer(
            &V::Map(vec![
                (V::Integer(1.into()), V::Integer(2.into())),
                (V::Integer(3.into()), V::Integer((-35).into())),
            ]),
            &mut k,
        )
        .unwrap();
        assert_eq!(
            parse_cose_key(&k),
            Err(WebAuthnError::Unsupported("algorithm"))
        );
    }

    #[test]
    fn oversized_and_truncated_inputs_are_malformed() {
        let cred = CredentialPublicKey {
            alg: CoseAlg::EdDsa,
            key: vec![0; 32],
        };
        assert!(matches!(
            verify_assertion(
                b"{}",
                &[0u8; 10],
                b"",
                &[0; 32],
                RP,
                &origins(),
                &cred,
                0,
                true
            ),
            Err(WebAuthnError::Malformed(_))
        ));
        let big = vec![b'a'; MAX_BLOB + 1];
        assert!(matches!(
            verify_assertion(
                &big,
                &[0u8; 37],
                b"",
                &[0; 32],
                RP,
                &origins(),
                &cred,
                0,
                true
            ),
            Err(WebAuthnError::Malformed(_))
        ));
    }
}
