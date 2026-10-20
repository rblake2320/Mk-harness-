//! Retry classification and exponential backoff with full jitter.

use std::time::Duration;

/// How an adapter error should be treated. Adapters return a typed class;
/// the worker never guesses from message text.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RetryClass {
    /// Transient: network, 5xx, timeout, adapter busy. Retry with backoff.
    Transient,
    /// Permanent: invalid input, unsupported action, auth failure. Dead-letter.
    Permanent,
    /// Unknown whether the side effect happened. Reconcile before any retry.
    Ambiguous,
    /// Rate-limited; retry after the hinted delay (seconds), capped by policy.
    RateLimited { retry_after_secs: u32 },
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct RetryPolicy {
    pub base: Duration,
    pub max_delay: Duration,
    pub max_attempts: u32,
}

impl Default for RetryPolicy {
    fn default() -> Self {
        Self {
            base: Duration::from_secs(5),
            max_delay: Duration::from_mins(15),
            max_attempts: 6,
        }
    }
}

/// Decide the next step for a failed attempt.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Next {
    RetryAfter(Duration),
    DeadLetter,
    Reconcile,
}

#[must_use]
pub fn classify(class: RetryClass, attempt: u32, policy: &RetryPolicy, jitter: f64) -> Next {
    match class {
        RetryClass::Permanent => Next::DeadLetter,
        RetryClass::Ambiguous => Next::Reconcile,
        RetryClass::Transient => {
            if attempt >= policy.max_attempts {
                Next::DeadLetter
            } else {
                Next::RetryAfter(next_delay(attempt, policy, jitter))
            }
        }
        RetryClass::RateLimited { retry_after_secs } => {
            if attempt >= policy.max_attempts {
                Next::DeadLetter
            } else {
                let hinted = Duration::from_secs(u64::from(retry_after_secs));
                Next::RetryAfter(
                    hinted
                        .max(next_delay(attempt, policy, jitter))
                        .min(policy.max_delay),
                )
            }
        }
    }
}

/// Full-jitter exponential backoff: `rand(0, min(max, base * 2^attempt))`,
/// with a floor of `base/2` so retries never storm. `jitter` ∈ [0,1] is
/// injected so tests are deterministic.
#[must_use]
pub fn next_delay(attempt: u32, policy: &RetryPolicy, jitter: f64) -> Duration {
    let exp = policy.base.saturating_mul(1u32 << attempt.min(16));
    let cap = exp.min(policy.max_delay);
    let floor = policy.base / 2;
    let span = cap.saturating_sub(floor);
    floor + span.mul_f64(jitter.clamp(0.0, 1.0))
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
    use proptest::prelude::*;

    #[test]
    fn classes() {
        let p = RetryPolicy::default();
        assert_eq!(
            classify(RetryClass::Permanent, 0, &p, 0.5),
            Next::DeadLetter
        );
        assert_eq!(classify(RetryClass::Ambiguous, 0, &p, 0.5), Next::Reconcile);
        assert!(matches!(
            classify(RetryClass::Transient, 0, &p, 0.5),
            Next::RetryAfter(_)
        ));
        assert_eq!(
            classify(RetryClass::Transient, 6, &p, 0.5),
            Next::DeadLetter
        );
        assert_eq!(
            classify(
                RetryClass::RateLimited {
                    retry_after_secs: 120
                },
                0,
                &p,
                0.0
            ),
            Next::RetryAfter(Duration::from_mins(2))
        );
        assert_eq!(
            classify(
                RetryClass::RateLimited {
                    retry_after_secs: 99_999
                },
                0,
                &p,
                0.0
            ),
            Next::RetryAfter(p.max_delay)
        );
    }

    proptest! {
        #[test]
        fn delay_is_bounded_and_monotone_in_cap(attempt in 0u32..40, jitter in 0.0f64..=1.0) {
            let p = RetryPolicy::default();
            let d = next_delay(attempt, &p, jitter);
            prop_assert!(d >= p.base / 2);
            prop_assert!(d <= p.max_delay);
        }
    }
}
