//! `mk-audit-verifier`: scans every tenant's audit chain and reports breaks.
//! Exit code is non-zero when any chain fails verification.

use mk_store::Store;
use mk_worker::config::{Config, init_tracing};
use secrecy::ExposeSecret;

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    init_tracing();
    let cfg = Config::from_env()?;
    let store = Store::connect(cfg.database_url.expose_secret(), 4).await?;
    let tenants = mk_store::audit::all_tenants(store.pool()).await?;
    let mut failures = 0usize;
    for t in tenants {
        let mut tx = store.begin(t).await?;
        match mk_store::audit::verify_tenant(&mut tx).await {
            Ok(n) => {
                let head = mk_store::audit::head(&mut tx).await?;
                tracing::info!(tenant = %t, events = n, root = %head.root_commitment(), "chain ok");
            }
            Err(e) => {
                failures += 1;
                tracing::error!(tenant = %t, error = %e, "AUDIT CHAIN BROKEN");
            }
        }
    }
    if failures > 0 {
        anyhow::bail!("{failures} tenant chain(s) failed verification");
    }
    Ok(())
}
