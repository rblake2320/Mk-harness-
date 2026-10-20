//! Deterministic authorization for the MK action kernel.
//!
//! **Models propose; this crate authorizes.** Every function here is pure:
//! it receives facts (already loaded by the caller) and a clock value, and
//! returns a decision. It never reads a database, never calls a model, and
//! never parses free-form text for intent.
//!
//! Three evaluation points use this crate:
//! 1. **Proposal** — [`evaluate`] decides Deny / RequireApproval / Allow.
//! 2. **Dispatch recheck** — [`recheck_at_dispatch`] re-runs the permission,
//!    suppression, expiry, and approval-binding checks immediately before a
//!    side effect, with fresh facts.
//! 3. **Approval authority** — [`approval::check_approver`] decides whether a
//!    human may approve a given action.

pub mod approval;
pub mod consent;
pub mod decision;
pub mod engine;
pub mod tools;

pub use approval::{ApprovalBindingError, ApproverContext, check_approver};
pub use consent::{ConsentError, ContactPermissionFact, SuppressionFact};
pub use decision::{Decision, DenyCode, Obligation, PolicyVersion};
pub use engine::{
    PolicyInput, RecheckInput, TenantPolicy, evaluate, local_hour_with_offset, recheck_at_dispatch,
};
pub use tools::{ToolAllowlist, ToolEntry};

/// The policy version stamped on every audit event produced from a decision.
/// Bump on any semantic change to `evaluate`, `recheck_at_dispatch`, or the
/// consent rules.
pub const POLICY_VERSION: PolicyVersion = PolicyVersion("mk-policy/2026.10.1");
