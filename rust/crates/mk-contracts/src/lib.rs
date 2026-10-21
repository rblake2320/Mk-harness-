//! Wire contracts for the MK action kernel.
//!
//! The JSON Schemas under `contracts/` in the repository root are the
//! authority. This crate embeds them at compile time, validates inbound
//! payloads against them *before* deserializing into typed structs, and
//! computes the canonical action digest that approvals bind to.
//!
//! Nothing here decides whether an action is allowed.

pub mod action;
pub mod message_state;
pub mod mobile;
pub mod problem;
pub mod schema;

pub use action::{
    ACTION_SCHEMA_VERSION, APPROVAL_SCHEMA_VERSION, ActionRequest, ActionResult, ApprovalRecord,
    Evidence, Origin, Receipt, Resource,
};
pub use message_state::MessageState;
pub use mobile::{
    MOBILE_WORK_ORDER_SCHEMA, MobileCallback, MobilePing, MobileWorkOrder, WorkOrderStep,
};
pub use problem::ProblemDetails;
pub use schema::{ContractError, SchemaId, validate};
