//! The action state machine.
//!
//! This is the single source of truth for which transitions are legal. The
//! store layer calls [`ActionState::apply`] inside a transaction and refuses
//! to persist anything the machine rejects. No other crate may mutate state
//! directly.
//!
//! ```text
//! DRAFT -> POLICY_PENDING -> DENIED
//!                         -> APPROVAL_REQUIRED -> APPROVED -> QUEUED -> DISPATCHING -> COMPLETED
//!                         -> APPROVED (low-risk auto-allow)             |              -> FAILED_RETRYABLE -> QUEUED
//!                                                                       |              -> FAILED_FINAL
//!                                                                       |              -> RECONCILIATION_REQUIRED
//! any active state -> CANCELLED | EXPIRED | SUPPRESSED
//! ```
//!
//! Terminal states never return to active states. A replay is a *new* action
//! that records `replay_of`; the original stays terminal.

use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum ActionState {
    Draft,
    PolicyPending,
    Denied,
    ApprovalRequired,
    Approved,
    Queued,
    Dispatching,
    Completed,
    FailedRetryable,
    FailedFinal,
    Cancelled,
    Expired,
    Suppressed,
    /// A cancellation or failure raced with a side effect that may already
    /// have happened. Never silently reported as cancelled or failed.
    ReconciliationRequired,
}

impl ActionState {
    pub const ALL: [Self; 14] = [
        Self::Draft,
        Self::PolicyPending,
        Self::Denied,
        Self::ApprovalRequired,
        Self::Approved,
        Self::Queued,
        Self::Dispatching,
        Self::Completed,
        Self::FailedRetryable,
        Self::FailedFinal,
        Self::Cancelled,
        Self::Expired,
        Self::Suppressed,
        Self::ReconciliationRequired,
    ];

    /// True for states from which no further automatic progress is possible.
    #[must_use]
    pub const fn is_terminal(self) -> bool {
        matches!(
            self,
            Self::Denied
                | Self::Completed
                | Self::FailedFinal
                | Self::Cancelled
                | Self::Expired
                | Self::Suppressed
                | Self::ReconciliationRequired
        )
    }

    /// States in which a cancellation request wins outright (no side effect
    /// has started).
    #[must_use]
    pub const fn is_cancellable(self) -> bool {
        matches!(
            self,
            Self::Draft
                | Self::PolicyPending
                | Self::ApprovalRequired
                | Self::Approved
                | Self::Queued
                | Self::FailedRetryable
        )
    }

    /// States in which a permission revocation or suppression must suppress
    /// the action before dispatch.
    #[must_use]
    pub const fn is_suppressible(self) -> bool {
        self.is_cancellable()
    }

    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Draft => "draft",
            Self::PolicyPending => "policy_pending",
            Self::Denied => "denied",
            Self::ApprovalRequired => "approval_required",
            Self::Approved => "approved",
            Self::Queued => "queued",
            Self::Dispatching => "dispatching",
            Self::Completed => "completed",
            Self::FailedRetryable => "failed_retryable",
            Self::FailedFinal => "failed_final",
            Self::Cancelled => "cancelled",
            Self::Expired => "expired",
            Self::Suppressed => "suppressed",
            Self::ReconciliationRequired => "reconciliation_required",
        }
    }

    /// Parse the storage representation. Unknown strings fail closed.
    pub fn parse(s: &str) -> Result<Self, TransitionError> {
        Self::ALL
            .iter()
            .copied()
            .find(|v| v.as_str() == s)
            .ok_or(TransitionError::UnknownState)
    }

    /// Apply a transition. Returns the next state or a typed error. This is
    /// the *only* function allowed to decide legality.
    pub fn apply(self, t: Transition) -> Result<Self, TransitionError> {
        use ActionState as S;
        use Transition as T;
        let next = match (self, t) {
            (S::Draft, T::SubmitForPolicy) => S::PolicyPending,
            (S::PolicyPending, T::PolicyDeny) => S::Denied,
            (S::PolicyPending, T::PolicyRequireApproval) => S::ApprovalRequired,
            (S::PolicyPending, T::PolicyAllow) => S::Approved,
            (S::ApprovalRequired, T::Approve) => S::Approved,
            (S::ApprovalRequired, T::Reject) => S::Denied,
            (S::Approved, T::Enqueue) => S::Queued,
            (S::Queued, T::StartDispatch) => S::Dispatching,
            (S::FailedRetryable, T::Enqueue) => S::Queued,
            (S::Dispatching, T::Complete) => S::Completed,
            (S::Dispatching, T::FailRetryable) => S::FailedRetryable,
            (S::Dispatching, T::FailFinal) => S::FailedFinal,
            (S::Dispatching, T::RequireReconciliation) => S::ReconciliationRequired,
            // FailedRetryable exhausted its budget: dead-letter it.
            (S::FailedRetryable, T::FailFinal) => S::FailedFinal,
            (s, T::Cancel) if s.is_cancellable() => S::Cancelled,
            // Cancelling mid-flight cannot claim the effect did not happen.
            (S::Dispatching, T::Cancel) => S::ReconciliationRequired,
            (s, T::Expire) if s.is_cancellable() => S::Expired,
            (s, T::Suppress) if s.is_suppressible() => S::Suppressed,
            (from, transition) => {
                return Err(TransitionError::Illegal { from, transition });
            }
        };
        Ok(next)
    }
}

impl std::fmt::Display for ActionState {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.as_str())
    }
}

/// Events that attempt to move an action. Named for *what happened*, not for
/// the target state, so the machine stays the authority on the result.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum Transition {
    SubmitForPolicy,
    PolicyDeny,
    PolicyRequireApproval,
    PolicyAllow,
    Approve,
    Reject,
    Enqueue,
    StartDispatch,
    Complete,
    FailRetryable,
    FailFinal,
    RequireReconciliation,
    Cancel,
    Expire,
    Suppress,
}

impl Transition {
    pub const ALL: [Self; 15] = [
        Self::SubmitForPolicy,
        Self::PolicyDeny,
        Self::PolicyRequireApproval,
        Self::PolicyAllow,
        Self::Approve,
        Self::Reject,
        Self::Enqueue,
        Self::StartDispatch,
        Self::Complete,
        Self::FailRetryable,
        Self::FailFinal,
        Self::RequireReconciliation,
        Self::Cancel,
        Self::Expire,
        Self::Suppress,
    ];
}

#[derive(Debug, thiserror::Error, Clone, PartialEq, Eq)]
pub enum TransitionError {
    #[error("illegal transition {transition:?} from {from}")]
    Illegal {
        from: ActionState,
        transition: Transition,
    },
    #[error("unknown state string")]
    UnknownState,
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
    fn happy_path_sms() {
        let s = ActionState::Draft;
        let s = s
            .apply(Transition::SubmitForPolicy)
            .unwrap_or(ActionState::Draft);
        let s = s
            .apply(Transition::PolicyRequireApproval)
            .unwrap_or(ActionState::Draft);
        let s = s.apply(Transition::Approve).unwrap_or(ActionState::Draft);
        let s = s.apply(Transition::Enqueue).unwrap_or(ActionState::Draft);
        let s = s
            .apply(Transition::StartDispatch)
            .unwrap_or(ActionState::Draft);
        let s = s.apply(Transition::Complete).unwrap_or(ActionState::Draft);
        assert_eq!(s, ActionState::Completed);
    }

    #[test]
    fn approval_cannot_jump_to_dispatching() {
        assert!(
            ActionState::ApprovalRequired
                .apply(Transition::StartDispatch)
                .is_err()
        );
        assert!(
            ActionState::Approved
                .apply(Transition::StartDispatch)
                .is_err()
        );
    }

    #[test]
    fn draft_cannot_be_approved_or_dispatched() {
        for t in [
            Transition::Approve,
            Transition::Enqueue,
            Transition::StartDispatch,
            Transition::Complete,
        ] {
            assert!(ActionState::Draft.apply(t).is_err(), "{t:?}");
        }
    }

    #[test]
    fn cancel_during_dispatch_requires_reconciliation() {
        assert_eq!(
            ActionState::Dispatching.apply(Transition::Cancel),
            Ok(ActionState::ReconciliationRequired)
        );
    }

    #[test]
    fn retry_loop_then_dead_letter() {
        let s = ActionState::Dispatching
            .apply(Transition::FailRetryable)
            .unwrap_or(ActionState::Draft);
        assert_eq!(s, ActionState::FailedRetryable);
        assert_eq!(s.apply(Transition::Enqueue), Ok(ActionState::Queued));
        assert_eq!(s.apply(Transition::FailFinal), Ok(ActionState::FailedFinal));
    }

    #[test]
    fn suppression_wins_before_dispatch_only() {
        assert_eq!(
            ActionState::Queued.apply(Transition::Suppress),
            Ok(ActionState::Suppressed)
        );
        assert_eq!(
            ActionState::Approved.apply(Transition::Suppress),
            Ok(ActionState::Suppressed)
        );
        assert!(
            ActionState::Dispatching
                .apply(Transition::Suppress)
                .is_err()
        );
        assert!(ActionState::Completed.apply(Transition::Suppress).is_err());
    }

    #[test]
    fn terminal_states_reject_everything() {
        for s in ActionState::ALL.iter().copied().filter(|s| s.is_terminal()) {
            for t in Transition::ALL {
                assert!(s.apply(t).is_err(), "{s} must reject {t:?}");
            }
        }
    }

    #[test]
    fn storage_roundtrip() {
        for s in ActionState::ALL {
            assert_eq!(ActionState::parse(s.as_str()), Ok(s));
        }
        assert!(ActionState::parse("APPROVED").is_err());
        assert!(ActionState::parse("approved=true").is_err());
    }

    fn arb_transition() -> impl Strategy<Value = Transition> {
        prop::sample::select(Transition::ALL.to_vec())
    }

    proptest! {
        #![proptest_config(ProptestConfig::with_cases(2000))]

        /// No sequence of transitions, legal or not, can leave a terminal
        /// state, and legality is total (never panics).
        #[test]
        fn terminal_is_absorbing(seq in prop::collection::vec(arb_transition(), 0..40)) {
            let mut s = ActionState::Draft;
            let mut became_terminal_at: Option<usize> = None;
            for (i, t) in seq.iter().enumerate() {
                if let Ok(next) = s.apply(*t) {
                    prop_assert!(became_terminal_at.is_none(), "left terminal state {s} via {t:?}");
                    s = next;
                    if s.is_terminal() && became_terminal_at.is_none() {
                        became_terminal_at = Some(i);
                    }
                }
            }
        }

        /// Completion is only reachable through Dispatching, which is only
        /// reachable through Queued, which is only reachable through Approved.
        #[test]
        fn completion_implies_approval_path(seq in prop::collection::vec(arb_transition(), 0..40)) {
            let mut s = ActionState::Draft;
            let mut saw_approved = false;
            let mut saw_queued = false;
            let mut saw_dispatching = false;
            for t in seq {
                if let Ok(next) = s.apply(t) {
                    s = next;
                    match s {
                        ActionState::Approved => saw_approved = true,
                        ActionState::Queued => saw_queued = true,
                        ActionState::Dispatching => saw_dispatching = true,
                        ActionState::Completed => {
                            prop_assert!(saw_approved && saw_queued && saw_dispatching);
                        }
                        _ => {}
                    }
                }
            }
        }
    }
}
