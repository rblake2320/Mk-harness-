//! `mk-audit-verifier`: scans every tenant's audit chain and reports breaks.
//! Exit code is non-zero when any chain fails verification.
//!
//! Needs only the read-only identity's database URL (`MK_DATABASE_URL`, or the
//! `MK_DB_*` parts `mk_store::database_url_from_env` composes). It deliberately does
//! not load the worker `Config`: a verifier must not require the master key
//! or Redis, and must run under `mk_kernel_readonly`.

use mk_store::Store;
use mk_worker::config::init_tracing;

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    init_tracing();
    // MK_DATABASE_URL, or MK_DB_HOST/MK_DB_USER/MK_DB_PASSWORD as the orchestrator injects them.
    let db = mk_store::database_url_from_env().map_err(|e| anyhow::anyhow!("database url: {e}"))?;
    let store = Store::connect(&db, 4).await?;
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
