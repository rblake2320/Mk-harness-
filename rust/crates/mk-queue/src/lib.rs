//! Durable execution for the MK action kernel.
//!
//! ```text
//! API tx: action -> QUEUED + outbox row        (PostgreSQL, atomic)
//! relay : claim outbox rows (lease) -> XADD    (Redis Streams, tenant-sharded)
//!         -> mark published
//! worker: XREADGROUP -> lease action in PG -> recheck -> execute -> persist -> XACK
//! ```
//!
//! Redis is a *delivery accelerator*, not the source of truth: an unpublished
//! outbox row survives Redis loss, and a published-but-unacked message is
//! reclaimed with `XAUTOCLAIM`. Every path assumes at-least-once delivery.

pub mod backoff;
pub mod relay;
pub mod stream;

pub use backoff::{RetryClass, RetryPolicy, classify, next_delay};
pub use relay::{RelayConfig, RelayStats, run_relay_once};
pub use stream::{CONSUMER_GROUP, DispatchMessage, StreamClient, StreamError};
