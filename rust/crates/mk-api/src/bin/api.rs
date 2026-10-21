//! `mk-action-api`: the internal HTTP API process.

use std::sync::Arc;

use mk_api::metrics::Metrics;
use mk_api::{AppState, router};
use mk_crypto::{AssertionVerifier, MasterKey};
use mk_policy::ToolAllowlist;
use mk_store::Store;

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    use tracing_subscriber::EnvFilter;
    let _ = tracing_subscriber::fmt()
        .json()
        .with_env_filter(
            EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new("info")),
        )
        .try_init();

    let db = mk_store::database_url_from_env()?;
    let master = MasterKey::from_base64(&std::env::var("MK_MASTER_KEY")?)
        .map_err(|e| anyhow::anyhow!("MK_MASTER_KEY: {e}"))?;
    // MK_ASSERTION_KEYS = "kid1=<b64url pubkey>,kid2=<b64url pubkey>"
    let keys_env = std::env::var("MK_ASSERTION_KEYS")?;
    let pairs: Vec<(&str, &str)> = keys_env
        .split(',')
        .filter_map(|p| p.split_once('='))
        .collect();
    let verifier = AssertionVerifier::from_pairs(pairs)
        .map_err(|e| anyhow::anyhow!("MK_ASSERTION_KEYS: {e}"))?;
    let store = Store::connect(&db, 16).await?;
    if std::env::var("MK_RUN_MIGRATIONS").is_ok_and(|v| v == "1") {
        store.migrate().await?;
        tracing::info!("kernel migrations applied");
    }
    // One-shot migration container: migrate and exit 0 (compose init job).
    if std::env::var("MK_MIGRATE_ONLY").is_ok_and(|v| v == "1") {
        store.migrate().await?;
        tracing::info!("migrate-only run complete; exiting");
        return Ok(());
    }
    let keyring = mk_store::keys::keyring_from_env(store.pool(), &master).await?;
    if keyring.versions() == [mk_crypto::LEGACY_VERSION] {
        tracing::warn!(
            "sealing with the legacy single master key (no MK_KEK / key versions); pre-flight refuses this for production"
        );
    } else {
        tracing::info!(current = keyring.current_version(), versions = ?keyring.versions(), "envelope keyring loaded");
    }
    let state = AppState {
        store,
        verifier,
        fingerprints: std::sync::Arc::new(
            mk_store::fingerprint::FingerprintKeys::from_env(&master)
                .map_err(|e| anyhow::anyhow!("MK_FINGERPRINT_KEYS: {e}"))?,
        ),
        limiter: mk_api::limits::Limiter::new(
            mk_api::limits::LimitConfig::from_env().map_err(|e| anyhow::anyhow!(e))?,
        ),
        master,
        keyring,
        tools: Arc::new(ToolAllowlist::v1()),
        metrics: Arc::new(Metrics::new()),
        callback_tolerance_secs: std::env::var("MK_CALLBACK_TOLERANCE_SECS")
            .ok()
            .and_then(|v| v.parse().ok())
            .unwrap_or(120),
        rust_kernel_enabled: std::env::var("RUST_ACTION_KERNEL_ENABLED").is_ok_and(|v| v == "1"),
        approval_rp: mk_api::ApprovalRp::from_env().map_err(|e| anyhow::anyhow!(e))?,
        public_webhook_base: std::env::var("MK_PUBLIC_WEBHOOK_BASE")
            .ok()
            .filter(|s| !s.trim().is_empty())
            .map(|s| {
                let s = s.trim().trim_end_matches('/').to_owned();
                if !(s.starts_with("https://")
                    || s.starts_with("http://localhost")
                    || s.starts_with("http://127.0.0.1"))
                {
                    tracing::warn!(
                        "MK_PUBLIC_WEBHOOK_BASE is not https; acceptable only for local testing"
                    );
                }
                s
            }),
    };
    if state.approval_rp.is_none() {
        tracing::warn!(
            "MK_ALLOW_UNBOUND_APPROVAL=1: approvals are NOT human-bound; never run production like this"
        );
    }
    let bind = std::env::var("MK_BIND").unwrap_or_else(|_| "127.0.0.1:8090".into());
    let listener = tokio::net::TcpListener::bind(&bind).await?;
    tracing::info!(%bind, enabled = state.rust_kernel_enabled, "mk-action-api listening (private network only)");
    axum::serve(listener, router(state))
        .with_graceful_shutdown(async {
            let _ = tokio::signal::ctrl_c().await;
        })
        .await?;
    Ok(())
}
