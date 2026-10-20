//! Outbox relay: PostgreSQL → Redis Streams.
//!
//! Crash semantics (tested in `tests/redis_postgres.rs`):
//! * crash after claim, before XADD → lease expires, row reclaimed, published later;
//! * crash after XADD, before `mark_published` → row republished → duplicate
//!   stream entry → worker idempotency (lease + approval consume) absorbs it.

use std::time::Duration;

use chrono::Utc;
use mk_store::{Store, outbox};

use crate::stream::{DispatchMessage, StreamClient, StreamError};

#[derive(Debug, Clone)]
pub struct RelayConfig {
    pub relay_id: String,
    pub batch: i64,
    pub lease: Duration,
}

impl Default for RelayConfig {
    fn default() -> Self {
        Self {
            relay_id: format!("relay-{}", uuid::Uuid::now_v7()),
            batch: 100,
            lease: Duration::from_secs(30),
        }
    }
}

#[derive(Debug, Default, Clone, Copy, PartialEq, Eq)]
pub struct RelayStats {
    pub claimed: usize,
    pub published: usize,
    pub failed: usize,
}

#[derive(Debug, thiserror::Error)]
pub enum RelayError {
    #[error(transparent)]
    Store(#[from] mk_store::StoreError),
    #[error(transparent)]
    Stream(#[from] StreamError),
}

/// One relay iteration. Publishes each claimed row then marks it published.
/// A stream failure leaves the row leased; it is retried after lease expiry.
pub async fn run_relay_once(
    store: &Store,
    stream: &StreamClient,
    cfg: &RelayConfig,
) -> Result<RelayStats, RelayError> {
    let now = Utc::now();
    let lease =
        chrono::Duration::from_std(cfg.lease).unwrap_or_else(|_| chrono::Duration::seconds(30));
    let rows = outbox::claim_batch(store.pool(), &cfg.relay_id, lease, cfg.batch, now).await?;
    let mut stats = RelayStats {
        claimed: rows.len(),
        ..RelayStats::default()
    };
    for row in rows {
        let msg = DispatchMessage {
            tenant_id: row.tenant_id,
            action_id: row.action_id,
            outbox_id: row.outbox_id,
            event_kind: row.event_kind.clone(),
        };
        match stream.publish(&msg).await {
            Ok(_) => {
                if outbox::mark_published(store.pool(), row.outbox_id, &cfg.relay_id, Utc::now())
                    .await?
                {
                    stats.published += 1;
                } else {
                    // Lease was lost to another relay after we published:
                    // the other relay will publish again (duplicate) and the
                    // worker's idempotency absorbs it. Count as failed here.
                    stats.failed += 1;
                }
            }
            Err(e) => {
                tracing::warn!(outbox_id = row.outbox_id, error = %e, "publish failed; row stays leased");
                stats.failed += 1;
            }
        }
    }
    Ok(stats)
}
