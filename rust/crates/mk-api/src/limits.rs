//! Capacity protection (contract O2): per-tenant request limits and graceful
//! rejection above replica capacity.
//!
//! * **Per-tenant token buckets**, one for reads (GET) and one for writes,
//!   charged after the actor assertion's signature verifies (so an
//!   unauthenticated caller can never spend a tenant's budget) and before the
//!   jti is consumed (so a refused request costs no database write). Over the
//!   limit → `429 TENANT_RATE_LIMITED` with `Retry-After`.
//! * **Replica in-flight cap** on `/internal/v1/*`: when every permit is in
//!   use the request is refused immediately with `503 OVER_CAPACITY` and
//!   `Retry-After: 1` — never queued into the timeout.
//! * **Never shed**: provider webhooks (an inbound STOP must be recorded),
//!   adapter callbacks (they settle outcomes of sends already made) and the
//!   health/metrics endpoints. They are bounded by the body limit and the
//!   request timeout only.
//!
//! Limits are per API replica; the published envelope (`docs/load/limits.md`)
//! states the effective totals for the deployed replica count.

use std::collections::HashMap;
use std::sync::{Arc, Mutex};
use std::time::Instant;

use axum::http::StatusCode;
use axum::response::{IntoResponse, Response};
use tokio::sync::Semaphore;
use uuid::Uuid;

/// Configuration, from env with conservative defaults sized to the O2 envelope.
#[derive(Debug, Clone, Copy, PartialEq)]
pub struct LimitConfig {
    /// `MK_TENANT_READ_RPS` / `MK_TENANT_READ_BURST`.
    pub read_rps: f64,
    pub read_burst: f64,
    /// `MK_TENANT_WRITE_RPS` / `MK_TENANT_WRITE_BURST`.
    pub write_rps: f64,
    pub write_burst: f64,
    /// `MK_MAX_INFLIGHT`: concurrent `/internal/v1` requests per replica.
    pub max_inflight: usize,
}

impl Default for LimitConfig {
    fn default() -> Self {
        Self {
            read_rps: 20.0,
            read_burst: 40.0,
            write_rps: 5.0,
            write_burst: 10.0,
            max_inflight: 256,
        }
    }
}

impl LimitConfig {
    pub fn from_env() -> Result<Self, String> {
        Self::from_lookup(|k| std::env::var(k).ok())
    }

    pub fn from_lookup(get: impl Fn(&str) -> Option<String>) -> Result<Self, String> {
        let d = Self::default();
        let num = |k: &str, dflt: f64| -> Result<f64, String> {
            match get(k).filter(|v| !v.trim().is_empty()) {
                None => Ok(dflt),
                Some(v) => v
                    .trim()
                    .parse::<f64>()
                    .ok()
                    .filter(|x| x.is_finite() && *x > 0.0)
                    .ok_or_else(|| format!("{k} must be a positive number")),
            }
        };
        let cfg = Self {
            read_rps: num("MK_TENANT_READ_RPS", d.read_rps)?,
            read_burst: num("MK_TENANT_READ_BURST", d.read_burst)?,
            write_rps: num("MK_TENANT_WRITE_RPS", d.write_rps)?,
            write_burst: num("MK_TENANT_WRITE_BURST", d.write_burst)?,
            max_inflight: match get("MK_MAX_INFLIGHT").filter(|v| !v.trim().is_empty()) {
                None => d.max_inflight,
                Some(v) => v
                    .trim()
                    .parse::<usize>()
                    .ok()
                    .filter(|n| *n > 0)
                    .ok_or("MK_MAX_INFLIGHT must be a positive integer")?,
            },
        };
        if cfg.read_burst < 1.0 || cfg.write_burst < 1.0 {
            return Err("burst values must be ≥ 1".into());
        }
        Ok(cfg)
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Class {
    Read,
    Write,
}

#[derive(Debug, Clone, Copy)]
struct Bucket {
    tokens: f64,
    at: Instant,
}

/// Per-tenant buckets plus the replica in-flight semaphore.
#[derive(Debug, Clone)]
pub struct Limiter {
    cfg: LimitConfig,
    buckets: Arc<Mutex<HashMap<(Uuid, Class), Bucket>>>,
    inflight: Arc<Semaphore>,
}

/// Bound on remembered buckets; idle (full) buckets are dropped beyond it.
const MAX_BUCKETS: usize = 50_000;

impl Limiter {
    #[must_use]
    pub fn new(cfg: LimitConfig) -> Self {
        Self {
            cfg,
            buckets: Arc::new(Mutex::new(HashMap::new())),
            inflight: Arc::new(Semaphore::new(cfg.max_inflight)),
        }
    }

    #[must_use]
    pub fn config(&self) -> LimitConfig {
        self.cfg
    }

    /// Charge one request for `tenant`. `Err(seconds)` = refused; retry after.
    pub fn charge(&self, tenant: Uuid, class: Class, now: Instant) -> Result<(), u64> {
        let (rate, burst) = match class {
            Class::Read => (self.cfg.read_rps, self.cfg.read_burst),
            Class::Write => (self.cfg.write_rps, self.cfg.write_burst),
        };
        // A poisoned lock only means another request panicked mid-update;
        // the map is still structurally valid. Never fail open or closed on it.
        let mut map = self
            .buckets
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        if map.len() >= MAX_BUCKETS {
            map.retain(|_, b| {
                let refill = now.saturating_duration_since(b.at).as_secs_f64();
                b.tokens + refill * rate < burst
            });
        }
        let b = map.entry((tenant, class)).or_insert(Bucket {
            tokens: burst,
            at: now,
        });
        let elapsed = now.saturating_duration_since(b.at).as_secs_f64();
        b.tokens = (b.tokens + elapsed * rate).min(burst);
        b.at = now;
        if b.tokens >= 1.0 {
            b.tokens -= 1.0;
            Ok(())
        } else {
            let wait = (1.0 - b.tokens) / rate;
            #[allow(clippy::cast_possible_truncation, clippy::cast_sign_loss)]
            Err(wait.ceil().max(1.0) as u64)
        }
    }

    /// Try to take an in-flight permit; `None` = over capacity.
    #[must_use]
    pub fn try_enter(&self) -> Option<tokio::sync::OwnedSemaphorePermit> {
        Arc::clone(&self.inflight).try_acquire_owned().ok()
    }

    #[must_use]
    pub fn inflight_available(&self) -> usize {
        self.inflight.available_permits()
    }
}

/// `503 OVER_CAPACITY` (problem+json) with `Retry-After: 1`.
#[must_use]
pub fn over_capacity(headers: &axum::http::HeaderMap) -> Response {
    crate::error::ApiError::new(
        StatusCode::SERVICE_UNAVAILABLE,
        "OVER_CAPACITY",
        "The kernel is at capacity; retry shortly",
    )
    .with_request_id(headers)
    .with_retry_after(1)
    .into_response()
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
mod tests {
    use super::*;
    use std::time::Duration;

    fn lim(read: f64, burst: f64) -> Limiter {
        Limiter::new(LimitConfig {
            read_rps: read,
            read_burst: burst,
            write_rps: 1.0,
            write_burst: 2.0,
            max_inflight: 2,
        })
    }

    #[test]
    fn burst_then_refuse_then_refill() {
        let l = lim(10.0, 3.0);
        let t = Uuid::new_v4();
        let t0 = Instant::now();
        for _ in 0..3 {
            assert!(l.charge(t, Class::Read, t0).is_ok());
        }
        assert_eq!(l.charge(t, Class::Read, t0), Err(1));
        // 0.1 s at 10 rps refills one token.
        assert!(
            l.charge(t, Class::Read, t0 + Duration::from_millis(100))
                .is_ok()
        );
        assert!(
            l.charge(t, Class::Read, t0 + Duration::from_millis(100))
                .is_err()
        );
    }

    #[test]
    fn tenants_and_classes_are_isolated() {
        let l = lim(1.0, 1.0);
        let (a, b) = (Uuid::new_v4(), Uuid::new_v4());
        let now = Instant::now();
        assert!(l.charge(a, Class::Read, now).is_ok());
        assert!(l.charge(a, Class::Read, now).is_err(), "a exhausted");
        assert!(
            l.charge(b, Class::Read, now).is_ok(),
            "a noisy tenant never starves b"
        );
        assert!(
            l.charge(a, Class::Write, now).is_ok(),
            "reads never starve writes"
        );
    }

    #[test]
    fn retry_after_reflects_the_refill_time() {
        let l = Limiter::new(LimitConfig {
            write_rps: 0.2,
            write_burst: 1.0,
            ..LimitConfig::default()
        });
        let t = Uuid::new_v4();
        let now = Instant::now();
        assert!(l.charge(t, Class::Write, now).is_ok());
        assert_eq!(l.charge(t, Class::Write, now), Err(5));
    }

    #[test]
    fn clock_going_backwards_never_mints_tokens() {
        let l = lim(10.0, 1.0);
        let t = Uuid::new_v4();
        let later = Instant::now() + Duration::from_secs(5);
        assert!(l.charge(t, Class::Read, later).is_ok());
        assert!(
            l.charge(
                t,
                Class::Read,
                later.checked_sub(Duration::from_secs(4)).unwrap()
            )
            .is_err()
        );
    }

    #[test]
    fn inflight_cap_refuses_without_queueing() {
        let l = lim(1.0, 1.0);
        let p1 = l.try_enter().unwrap();
        let _p2 = l.try_enter().unwrap();
        assert!(l.try_enter().is_none());
        drop(p1);
        assert!(l.try_enter().is_some());
    }

    #[test]
    fn bucket_map_is_bounded() {
        let l = lim(1000.0, 1.0);
        let now = Instant::now();
        for _ in 0..(MAX_BUCKETS + 10) {
            let _ = l.charge(Uuid::new_v4(), Class::Read, now);
        }
        let later = now + Duration::from_secs(1);
        let _ = l.charge(Uuid::new_v4(), Class::Read, later);
        assert!(l.buckets.lock().unwrap().len() < MAX_BUCKETS);
    }

    #[test]
    fn config_rejects_nonsense() {
        let env = |pairs: &'static [(&'static str, &'static str)]| {
            move |k: &str| {
                pairs
                    .iter()
                    .find(|(a, _)| *a == k)
                    .map(|(_, v)| (*v).to_owned())
            }
        };
        assert_eq!(
            LimitConfig::from_lookup(|_| None).unwrap(),
            LimitConfig::default()
        );
        for bad in [
            &[("MK_TENANT_READ_RPS", "0")][..],
            &[("MK_TENANT_WRITE_RPS", "-1")][..],
            &[("MK_TENANT_READ_RPS", "NaN")][..],
            &[("MK_TENANT_READ_RPS", "inf")][..],
            &[("MK_MAX_INFLIGHT", "0")][..],
            &[("MK_MAX_INFLIGHT", "x")][..],
            &[("MK_TENANT_WRITE_BURST", "0.5")][..],
        ] {
            assert!(LimitConfig::from_lookup(env(bad)).is_err(), "{bad:?}");
        }
    }
}
