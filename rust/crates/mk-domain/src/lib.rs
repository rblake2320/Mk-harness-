//! Domain types for the MK action kernel.
//!
//! This crate is pure: no database, no network, no clock. Everything here is
//! deterministic and unit-testable. Other crates build on these types; none
//! of them may redefine the state machine.

pub mod ids;
pub mod state;
pub mod vocab;

pub use ids::{ActionId, AdapterId, ApprovalId, ContactId, TenantId, UserId};
pub use state::{ActionState, Transition, TransitionError};
pub use vocab::{
    ActionKind, ApprovalDecision, Channel, OriginType, PermissionStatus, ResourceType, Risk,
    Workflow,
};

/// Domain-level error codes. Stable identifiers surface in problem details and
/// audit payloads; the human text is informational only.
#[derive(Debug, thiserror::Error, Clone, PartialEq, Eq)]
pub enum DomainError {
    #[error("illegal state transition")]
    Transition(#[from] TransitionError),
    #[error("tenant mismatch")]
    TenantMismatch,
    #[error("value out of bounds: {0}")]
    OutOfBounds(&'static str),
}
