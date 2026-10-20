//! Replay protection.
//!
//! A nonce is unique per `(tenant, adapter)` and must be retained for at
//! least the signature tolerance window on both sides of "now" (so a request
//! signed slightly in the future cannot be replayed once the clock catches
//! up). The durable implementation lives in `mk-store`
//! (`kernel.adapter_nonces`, unique on tenant+adapter+nonce). This module
//! provides the policy (`NonceWindow`) and an in-memory `ReplayGuard` for
//! tests and single-process simulators.

use std::collections::{BTreeMap, HashSet};

#[derive(Debug, thiserror::Error, Clone, Copy, PartialEq, Eq)]
pub enum NonceError {
    #[error("nonce already used within the replay window")]
    Replayed,
}

/// How long a nonce must be remembered, derived from the signature tolerance.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct NonceWindow {
    pub retain_secs: i64,
}

impl NonceWindow {
    /// Retain for twice the tolerance plus a safety margin so that a request
    /// signed at `now + tolerance` is still remembered when its timestamp
    /// finally falls out of the window.
    #[must_use]
    pub const fn from_tolerance(tolerance_secs: i64) -> Self {
        Self {
            retain_secs: tolerance_secs * 2 + 60,
        }
    }

    /// Unix time after which a nonce observed at `observed_at` may be purged.
    #[must_use]
    pub const fn expires_at(self, observed_at: i64) -> i64 {
        observed_at + self.retain_secs
    }
}

/// Process-local replay guard. Not for multi-instance production use.
#[derive(Debug, Default)]
pub struct ReplayGuard {
    seen: HashSet<(String, String)>,
    by_expiry: BTreeMap<i64, Vec<(String, String)>>,
}

impl ReplayGuard {
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Record `nonce` for `scope` (e.g. `"tenant:adapter"`). Fails if it was
    /// already recorded and has not expired.
    pub fn check_and_record(
        &mut self,
        scope: &str,
        nonce: &str,
        now_unix: i64,
        window: NonceWindow,
    ) -> Result<(), NonceError> {
        self.purge(now_unix);
        let key = (scope.to_owned(), nonce.to_owned());
        if !self.seen.insert(key.clone()) {
            return Err(NonceError::Replayed);
        }
        self.by_expiry
            .entry(window.expires_at(now_unix))
            .or_default()
            .push(key);
        Ok(())
    }

    fn purge(&mut self, now_unix: i64) {
        let expired: Vec<i64> = self.by_expiry.range(..=now_unix).map(|(k, _)| *k).collect();
        for k in expired {
            if let Some(keys) = self.by_expiry.remove(&k) {
                for key in keys {
                    self.seen.remove(&key);
                }
            }
        }
    }

    #[must_use]
    pub fn len(&self) -> usize {
        self.seen.len()
    }

    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.seen.is_empty()
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
    fn replay_rejected_and_scoped() {
        let w = NonceWindow::from_tolerance(120);
        let mut g = ReplayGuard::new();
        assert_eq!(g.check_and_record("t1:a1", "n1", 1000, w), Ok(()));
        assert_eq!(
            g.check_and_record("t1:a1", "n1", 1001, w),
            Err(NonceError::Replayed)
        );
        // Same nonce, different adapter: allowed.
        assert_eq!(g.check_and_record("t1:a2", "n1", 1001, w), Ok(()));
    }

    #[test]
    fn nonce_outlives_tolerance_window() {
        let w = NonceWindow::from_tolerance(120);
        let mut g = ReplayGuard::new();
        g.check_and_record("s", "n", 1000, w).unwrap_or(());
        // At tolerance edge, still remembered.
        assert_eq!(
            g.check_and_record("s", "n", 1120, w),
            Err(NonceError::Replayed)
        );
        assert_eq!(
            g.check_and_record("s", "n", 1240, w),
            Err(NonceError::Replayed)
        );
        // After retention, forgotten (the signature would be stale anyway).
        assert_eq!(
            g.check_and_record("s", "n", 1000 + w.retain_secs, w),
            Ok(())
        );
    }
}
