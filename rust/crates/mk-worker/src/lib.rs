//! The worker: the only process that calls an adapter.
//!
//! Dispatch of one message (see [`dispatch::dispatch_one`]):
//! 1. Lock the action; if it is no longer `Queued`, ack and stop (duplicate).
//! 2. Acquire the execution lease; if held elsewhere, leave the message for
//!    `XAUTOCLAIM` and stop.
//! 3. Load fresh policy, kill switches, consent facts and the live approval
//!    (locked); run [`mk_policy::recheck_at_dispatch`].
//! 4. Consume the approval atomically, transition `StartDispatch`, record the
//!    attempt, **commit** — dispatch intent is durable before any network call.
//! 5. Call the adapter.
//! 6. In a new transaction persist the outcome (complete / retry / dead-letter /
//!    reconcile), release the lease, commit, then ack.

pub mod config;
pub mod dispatch;
pub mod housekeeping;
pub mod inbound_probe;
pub mod metrics;
pub mod privacy;
pub mod reconciliation;
pub mod resolver;

pub use dispatch::{DispatchError, DispatchOutcome, WorkerContext, dispatch_one};
