//! SHA-256 digests with a stable `sha256:<hex>` textual form.

use serde::{Deserialize, Serialize};
use sha2::{Digest as _, Sha256};

/// Lowercase hex SHA-256 of arbitrary bytes.
#[must_use]
pub fn sha256_hex(bytes: &[u8]) -> String {
    hex::encode(Sha256::digest(bytes))
}

/// A SHA-256 digest carried as `sha256:<64 lowercase hex>`. Parsing rejects
/// any other shape, including uppercase hex, so a digest string can never be
/// "almost right".
#[derive(Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(try_from = "String", into = "String")]
pub struct Digest([u8; 32]);

impl Digest {
    #[must_use]
    pub fn of(bytes: &[u8]) -> Self {
        Self(Sha256::digest(bytes).into())
    }

    #[must_use]
    pub const fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }

    #[must_use]
    pub fn hex(&self) -> String {
        hex::encode(self.0)
    }

    /// Constant-time equality.
    #[must_use]
    pub fn ct_eq(&self, other: &Self) -> bool {
        use subtle::ConstantTimeEq;
        self.0.ct_eq(&other.0).into()
    }
}

impl schemars::JsonSchema for Digest {
    fn schema_name() -> std::borrow::Cow<'static, str> {
        "Digest".into()
    }
    fn json_schema(_: &mut schemars::SchemaGenerator) -> schemars::Schema {
        schemars::json_schema!({
            "type": "string",
            "pattern": "^sha256:[0-9a-f]{64}$"
        })
    }
}

impl std::fmt::Debug for Digest {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "Digest(sha256:{}…)", &self.hex()[..12])
    }
}

impl std::fmt::Display for Digest {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "sha256:{}", self.hex())
    }
}

#[derive(Debug, thiserror::Error, Clone, PartialEq, Eq)]
#[error("malformed digest: expected sha256:<64 lowercase hex>")]
pub struct DigestParseError;

impl std::str::FromStr for Digest {
    type Err = DigestParseError;
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let hexpart = s.strip_prefix("sha256:").ok_or(DigestParseError)?;
        if hexpart.len() != 64
            || !hexpart
                .bytes()
                .all(|b| matches!(b, b'0'..=b'9' | b'a'..=b'f'))
        {
            return Err(DigestParseError);
        }
        let mut out = [0u8; 32];
        hex::decode_to_slice(hexpart, &mut out).map_err(|_| DigestParseError)?;
        Ok(Self(out))
    }
}

impl TryFrom<String> for Digest {
    type Error = DigestParseError;
    fn try_from(s: String) -> Result<Self, Self::Error> {
        s.parse()
    }
}

impl From<Digest> for String {
    fn from(d: Digest) -> Self {
        d.to_string()
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
    fn known_vector() {
        // SHA-256("") — the empty-body case in the HMAC vectors.
        assert_eq!(
            sha256_hex(b""),
            "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
        );
    }

    #[test]
    fn parse_rejects_near_misses() {
        let good = Digest::of(b"x").to_string();
        assert!(good.parse::<Digest>().is_ok());
        assert!(good.to_uppercase().parse::<Digest>().is_err());
        assert!(good[7..].parse::<Digest>().is_err());
        assert!(format!("{good}0").parse::<Digest>().is_err());
        assert!("sha1:abcd".parse::<Digest>().is_err());
    }

    #[test]
    fn debug_does_not_print_full_value() {
        let d = Digest::of(b"x");
        assert!(format!("{d:?}").len() < 40);
    }
}
