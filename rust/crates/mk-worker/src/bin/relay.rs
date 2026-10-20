//! `mk-outbox-relay`: PostgreSQL outbox → Redis Streams.

use std::time::Duration;

use mk_queue::{RelayConfig, StreamClient, run_relay_once};
use mk_store::Store;
use mk_worker::config::{Config, init_tracing};
use secrecy::ExposeSecret;

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    init_tracing();
    let cfg = Config::from_env()?;
    let store = Store::connect(cfg.database_url.expose_secret(), 4).await?;
    let stream = StreamClient::connect(cfg.redis_url.expose_secret(), "mk").await?;
    stream.ensure_groups().await?;
    let relay = RelayConfig {
        relay_id: cfg.worker_id.replace("worker", "relay"),
        batch: 200,
        lease: Duration::from_secs(30),
    };
    tracing::info!(relay_id = %relay.relay_id, "relay started");
    loop {
        match run_relay_once(&store, &stream, &relay).await {
            Ok(stats) if stats.claimed > 0 => tracing::info!(?stats, "relayed"),
            Ok(_) => tokio::time::sleep(Duration::from_millis(500)).await,
            Err(e) => {
                tracing::error!(error = %e, "relay iteration failed");
                tokio::time::sleep(Duration::from_secs(2)).await;
            }
        }
    }
}
