//! Contact permission and suppression rules.
//!
//! Permission records are *operator-attested* facts — the kernel enforces
//! them; it does not decide whether they are legally sufficient. The caller
//! loads the facts for `(tenant, contact, channel)` and this module decides.
//! Suppression always wins over permission.

use chrono::{DateTime, Utc};
use mk_domain::{Channel, ContactId, PermissionStatus, TenantId};

use crate::decision::DenyCode;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ContactPermissionFact {
    pub tenant_id: TenantId,
    pub contact_id: ContactId,
    pub channel: Channel,
    pub status: PermissionStatus,
    /// Purposes this permission covers, e.g. `["customer_requested_follow_up"]`.
    /// An empty scope covers nothing (fail closed).
    pub scope: Vec<String>,
    pub granted_at: DateTime<Utc>,
    pub expires_at: DateTime<Utc>,
    pub revoked_at: Option<DateTime<Utc>>,
    /// Fingerprint of the destination the consent evidence covers (same HMAC the
    /// suppression ledger uses). `None` = recorded before migration 0007; such a
    /// permission no longer authorizes outreach to any destination (fail closed).
    pub destination_hash: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SuppressionFact {
    pub tenant_id: TenantId,
    /// `None` = applies to every channel.
    pub channel: Option<Channel>,
    /// `None` = tenant-wide; `Some` = this destination fingerprint only.
    pub destination_hash: Option<String>,
    pub permanent: bool,
    pub created_at: DateTime<Utc>,
    pub lifted_at: Option<DateTime<Utc>>,
}

impl SuppressionFact {
    #[must_use]
    pub fn is_active(&self, now: DateTime<Utc>) -> bool {
        self.lifted_at.is_none_or(|l| l > now) && self.created_at <= now
    }

    #[must_use]
    pub fn applies_to(&self, channel: Channel, destination_hash: &str, now: DateTime<Utc>) -> bool {
        self.is_active(now)
            && self.channel.is_none_or(|c| c == channel)
            && self
                .destination_hash
                .as_deref()
                .is_none_or(|d| d == destination_hash)
    }
}

#[derive(Debug, thiserror::Error, Clone, Copy, PartialEq, Eq)]
#[error("consent check failed: {code:?}")]
pub struct ConsentError {
    pub code: DenyCode,
}

/// Inputs for one outreach eligibility check.
#[derive(Debug, Clone)]
pub struct ConsentQuery<'a> {
    pub tenant_id: TenantId,
    pub contact_id: ContactId,
    pub channel: Channel,
    pub purpose: &'a str,
    pub destination_hash: &'a str,
    pub permissions: &'a [ContactPermissionFact],
    pub suppressions: &'a [SuppressionFact],
    pub now: DateTime<Utc>,
}

/// Decide whether outreach to `contact` over `channel` for `purpose` is
/// currently permitted. Order matters and is deliberate:
/// 1. Any applicable active suppression denies (suppression > permission).
/// 2. A permission must exist for this tenant+contact+channel.
/// 3. It must not be revoked, must not be expired, must be `granted`.
/// 4. Its scope must cover the purpose.
pub fn check_outreach_consent(q: &ConsentQuery<'_>) -> Result<(), ConsentError> {
    if q.suppressions
        .iter()
        .any(|s| s.tenant_id == q.tenant_id && s.applies_to(q.channel, q.destination_hash, q.now))
    {
        return Err(ConsentError {
            code: DenyCode::Suppressed,
        });
    }

    let relevant: Vec<&ContactPermissionFact> = q
        .permissions
        .iter()
        .filter(|p| {
            p.tenant_id == q.tenant_id && p.contact_id == q.contact_id && p.channel == q.channel
        })
        .collect();
    if relevant.is_empty() {
        return Err(ConsentError {
            code: DenyCode::ContactPermissionMissing,
        });
    }

    // Prefer the *most restrictive* interpretation: if any relevant record is
    // revoked, treat the contact as revoked even if an older grant looks open.
    if relevant
        .iter()
        .any(|p| p.status == PermissionStatus::Revoked || p.revoked_at.is_some_and(|r| r <= q.now))
    {
        return Err(ConsentError {
            code: DenyCode::ContactPermissionRevoked,
        });
    }

    let current: Vec<&&ContactPermissionFact> = relevant
        .iter()
        .filter(|p| {
            p.status == PermissionStatus::Granted && p.granted_at <= q.now && p.expires_at > q.now
        })
        .collect();
    if current.is_empty() {
        return Err(ConsentError {
            code: DenyCode::ContactPermissionExpired,
        });
    }

    if !current
        .iter()
        .any(|p| p.scope.iter().any(|s| s == q.purpose))
    {
        return Err(ConsentError {
            code: DenyCode::ContactPermissionScopeMismatch,
        });
    }
    // The permission must cover THIS destination: consent evidence is for a number
    // or address, not for "any SMS to this contact". An empty query hash (no
    // destination in the action) never matches.
    if q.destination_hash.is_empty()
        || !current.iter().any(|p| {
            p.destination_hash.as_deref() == Some(q.destination_hash)
                && p.scope.iter().any(|s| s == q.purpose)
        })
    {
        return Err(ConsentError {
            code: DenyCode::ContactPermissionDestinationMismatch,
        });
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
    use chrono::TimeZone;

    fn t(h: u32) -> DateTime<Utc> {
        Utc.with_ymd_and_hms(2026, 10, 19, h, 0, 0)
            .single()
            .unwrap_or_default()
    }

    fn perm(tenant: TenantId, contact: ContactId) -> ContactPermissionFact {
        ContactPermissionFact {
            tenant_id: tenant,
            contact_id: contact,
            channel: Channel::Sms,
            status: PermissionStatus::Granted,
            scope: vec!["customer_requested_follow_up".into()],
            granted_at: t(1),
            expires_at: t(23),
            revoked_at: None,
            destination_hash: Some("dest-abc".into()),
        }
    }

    fn query<'a>(
        tenant: TenantId,
        contact: ContactId,
        perms: &'a [ContactPermissionFact],
        sups: &'a [SuppressionFact],
        now: DateTime<Utc>,
    ) -> ConsentQuery<'a> {
        ConsentQuery {
            tenant_id: tenant,
            contact_id: contact,
            channel: Channel::Sms,
            purpose: "customer_requested_follow_up",
            destination_hash: "dest-abc",
            permissions: perms,
            suppressions: sups,
            now,
        }
    }

    #[test]
    fn granted_in_scope_passes() {
        let (tn, c) = (TenantId::new(), ContactId::new());
        let p = [perm(tn, c)];
        assert_eq!(
            check_outreach_consent(&query(tn, c, &p, &[], t(12))),
            Ok(())
        );
    }

    #[test]
    fn missing_expired_revoked_scope() {
        let (tn, c) = (TenantId::new(), ContactId::new());
        assert_eq!(
            check_outreach_consent(&query(tn, c, &[], &[], t(12))).map_err(|e| e.code),
            Err(DenyCode::ContactPermissionMissing)
        );
        let p = [perm(tn, c)];
        assert_eq!(
            check_outreach_consent(&query(tn, c, &p, &[], t(23))).map_err(|e| e.code),
            Err(DenyCode::ContactPermissionExpired),
            "expiry boundary is exclusive"
        );
        let mut r = perm(tn, c);
        r.revoked_at = Some(t(6));
        assert_eq!(
            check_outreach_consent(&query(tn, c, &[r], &[], t(12))).map_err(|e| e.code),
            Err(DenyCode::ContactPermissionRevoked)
        );
        let mut s = perm(tn, c);
        s.scope = vec!["marketing".into()];
        assert_eq!(
            check_outreach_consent(&query(tn, c, &[s], &[], t(12))).map_err(|e| e.code),
            Err(DenyCode::ContactPermissionScopeMismatch)
        );
        let mut e = perm(tn, c);
        e.scope.clear();
        assert!(
            check_outreach_consent(&query(tn, c, &[e], &[], t(12))).is_err(),
            "empty scope covers nothing"
        );
    }

    #[test]
    fn revocation_beats_a_parallel_grant() {
        let (tn, c) = (TenantId::new(), ContactId::new());
        let mut revoked = perm(tn, c);
        revoked.status = PermissionStatus::Revoked;
        let p = [perm(tn, c), revoked];
        assert_eq!(
            check_outreach_consent(&query(tn, c, &p, &[], t(12))).map_err(|e| e.code),
            Err(DenyCode::ContactPermissionRevoked)
        );
    }

    #[test]
    fn suppression_beats_permission_and_scopes_correctly() {
        let (tn, c) = (TenantId::new(), ContactId::new());
        let p = [perm(tn, c)];
        let dest = SuppressionFact {
            tenant_id: tn,
            channel: Some(Channel::Sms),
            destination_hash: Some("dest-abc".into()),
            permanent: true,
            created_at: t(2),
            lifted_at: None,
        };
        assert_eq!(
            check_outreach_consent(&query(tn, c, &p, std::slice::from_ref(&dest), t(12)))
                .map_err(|e| e.code),
            Err(DenyCode::Suppressed)
        );
        // Different channel → not applicable.
        let mut other = dest.clone();
        other.channel = Some(Channel::Email);
        assert_eq!(
            check_outreach_consent(&query(tn, c, &p, &[other], t(12))),
            Ok(())
        );
        // Tenant-wide, all channels.
        let wide = SuppressionFact {
            channel: None,
            destination_hash: None,
            ..dest.clone()
        };
        assert!(check_outreach_consent(&query(tn, c, &p, &[wide], t(12))).is_err());
        // Lifted in the past → inactive.
        let lifted = SuppressionFact {
            lifted_at: Some(t(5)),
            ..dest.clone()
        };
        assert_eq!(
            check_outreach_consent(&query(tn, c, &p, &[lifted], t(12))),
            Ok(())
        );
        // Another tenant's suppression never leaks across.
        let foreign = SuppressionFact {
            tenant_id: TenantId::new(),
            ..dest
        };
        assert_eq!(
            check_outreach_consent(&query(tn, c, &p, &[foreign], t(12))),
            Ok(())
        );
    }

    #[test]
    fn cross_tenant_permission_never_authorizes() {
        let (tn, c) = (TenantId::new(), ContactId::new());
        let foreign = perm(TenantId::new(), c);
        assert_eq!(
            check_outreach_consent(&query(tn, c, &[foreign], &[], t(12))).map_err(|e| e.code),
            Err(DenyCode::ContactPermissionMissing)
        );
    }

    #[test]
    fn permission_for_another_destination_does_not_authorize_this_one() {
        let (tenant, contact) = (TenantId::new(), ContactId::new());
        let mut p = perm(tenant, contact);
        p.destination_hash = Some("dest-other".into());
        let r = check_outreach_consent(&query(tenant, contact, &[p], &[], t(10)));
        assert_eq!(
            r.map_err(|e| e.code),
            Err(DenyCode::ContactPermissionDestinationMismatch)
        );
    }

    #[test]
    fn legacy_permission_without_destination_fails_closed() {
        let (tenant, contact) = (TenantId::new(), ContactId::new());
        let mut p = perm(tenant, contact);
        p.destination_hash = None;
        let r = check_outreach_consent(&query(tenant, contact, &[p], &[], t(10)));
        assert_eq!(
            r.map_err(|e| e.code),
            Err(DenyCode::ContactPermissionDestinationMismatch)
        );
    }

    #[test]
    fn action_without_destination_never_matches() {
        let (tenant, contact) = (TenantId::new(), ContactId::new());
        let p = perm(tenant, contact);
        let perms = [p];
        let mut q = query(tenant, contact, &perms, &[], t(10));
        q.destination_hash = "";
        assert_eq!(
            check_outreach_consent(&q).map_err(|e| e.code),
            Err(DenyCode::ContactPermissionDestinationMismatch)
        );
    }

    #[test]
    fn scope_and_destination_must_be_on_the_same_permission() {
        // One grant covers the purpose for destination A, another covers a different
        // purpose for destination B: outreach to B for the first purpose is refused.
        let (tenant, contact) = (TenantId::new(), ContactId::new());
        let a = perm(tenant, contact);
        let mut b = perm(tenant, contact);
        b.destination_hash = Some("dest-b".into());
        b.scope = vec!["order_status".into()];
        let perms = [a, b];
        let mut q = query(tenant, contact, &perms, &[], t(10));
        q.destination_hash = "dest-b";
        assert_eq!(
            check_outreach_consent(&q).map_err(|e| e.code),
            Err(DenyCode::ContactPermissionDestinationMismatch)
        );
    }
}
