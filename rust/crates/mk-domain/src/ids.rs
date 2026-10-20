//! Strongly typed identifiers. Each newtype wraps a UUID so a `TenantId` can
//! never be passed where an `ActionId` is expected. Public IDs are UUIDv7 so
//! they sort by creation time.

use serde::{Deserialize, Serialize};
use uuid::Uuid;

macro_rules! id_type {
    ($name:ident, $doc:literal) => {
        #[doc = $doc]
        #[derive(
            Debug,
            Clone,
            Copy,
            PartialEq,
            Eq,
            Hash,
            PartialOrd,
            Ord,
            Serialize,
            Deserialize,
            schemars::JsonSchema,
        )]
        #[serde(transparent)]
        pub struct $name(pub Uuid);

        impl $name {
            /// Generate a new time-ordered (v7) identifier.
            #[must_use]
            pub fn new() -> Self {
                Self(Uuid::now_v7())
            }

            /// Wrap an existing UUID (e.g. loaded from storage).
            #[must_use]
            pub const fn from_uuid(uuid: Uuid) -> Self {
                Self(uuid)
            }

            #[must_use]
            pub const fn as_uuid(&self) -> &Uuid {
                &self.0
            }
        }

        impl Default for $name {
            fn default() -> Self {
                Self::new()
            }
        }

        impl std::fmt::Display for $name {
            fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
                write!(f, "{}", self.0)
            }
        }

        impl std::str::FromStr for $name {
            type Err = uuid::Error;
            fn from_str(s: &str) -> Result<Self, Self::Err> {
                Uuid::parse_str(s).map(Self)
            }
        }

        impl From<Uuid> for $name {
            fn from(u: Uuid) -> Self {
                Self(u)
            }
        }
    };
}

id_type!(
    TenantId,
    "Tenant boundary. Every tenant-scoped row carries one."
);
id_type!(UserId, "Human or service principal inside a tenant.");
id_type!(
    ActionId,
    "One governed action. Replays create a *new* ActionId linked to the original."
);
id_type!(
    ApprovalId,
    "One human approval record, bound to an exact action digest."
);
id_type!(
    AdapterId,
    "A registered outbound adapter (e.g. a mobile device agent)."
);
id_type!(ContactId, "A contact owned by exactly one tenant.");

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
    fn ids_are_v7_and_ordered() {
        let a = ActionId::new();
        let b = ActionId::new();
        assert_eq!(a.0.get_version_num(), 7);
        assert!(a <= b, "v7 ids are monotonic within a process");
    }

    #[test]
    fn id_roundtrips_through_json_as_bare_string() {
        let id = TenantId::new();
        let json = serde_json::to_string(&id).unwrap_or_default();
        assert!(json.starts_with('"'));
        let back: TenantId = serde_json::from_str(&json).unwrap_or_default();
        assert_eq!(id, back);
    }

    #[test]
    fn rejects_garbage() {
        assert!("not-a-uuid".parse::<ActionId>().is_err());
    }
}
