pub mod actions;
pub mod adapters;
pub mod approvals;
pub mod callbacks;
pub mod consent;
pub mod drafts;
pub mod human_approval;
pub mod messaging;
pub mod ops;
pub mod privacy;
pub mod reconciliation;

use mk_audit::ActorType;
use mk_crypto::MasterKey;
use mk_domain::{Channel, TenantId};
use mk_store::actions::Actor;

use crate::auth::Principal;

pub use mk_store::fingerprint::normalize_destination;

/// Stable, non-reversible destination fingerprint under one key:
/// `HMAC-SHA256(key, tenant|channel|normalized_destination)`. Matches the
/// Python `destination_fingerprint` so imported suppressions line up. Request
/// paths use [`mk_store::fingerprint::FingerprintKeys::compute`], which
/// produces this value for every configured key version.
#[must_use]
pub fn destination_hash(
    master: &MasterKey,
    tenant: TenantId,
    channel: Channel,
    destination: &str,
) -> String {
    mk_store::fingerprint::FingerprintKeys::from_master(master)
        .compute(tenant, channel, destination)
        .primary
}

pub(crate) fn actor_of<'a>(p: &'a Principal, actor_id: &'a str) -> Actor<'a> {
    Actor {
        actor_type: if p.has_role("agent") && p.roles.len() == 1 {
            ActorType::Agent
        } else {
            ActorType::User
        },
        actor_id,
        trace_id: Some(&p.request_id),
        policy_version: mk_policy::POLICY_VERSION.0,
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
mod tests {
    use super::*;

    /// Cross-language vector: `backend/app/foundation.py::fingerprint` must
    /// produce the same value so application suppressions line up with the
    /// kernel's destination hash. Key = 32×0x01, tenant
    /// 00000000-0000-4000-8000-000000000001, sms, "+1 (555) 555-0100".
    #[test]
    fn destination_hash_matches_python_vector() {
        let master = MasterKey::from_bytes(&[1u8; 32]).unwrap();
        let tenant = TenantId::from_uuid(
            uuid::Uuid::parse_str("00000000-0000-4000-8000-000000000001").unwrap(),
        );
        assert_eq!(
            destination_hash(&master, tenant, Channel::Sms, "+1 (555) 555-0100"),
            "0973a4c021bc296b195a6ab4533e067bebeb6f33f901c3b400cdfb83805de8ed"
        );
        assert_eq!(
            normalize_destination(Channel::Email, "  @Angela@Example.COM "),
            "angela@example.com"
        );
    }
}
