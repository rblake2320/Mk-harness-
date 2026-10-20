//! `mk-simulator`: standalone mobile-adapter contract simulator.
//! Env: MK_SIM_SECRET (enrollment secret), MK_SIM_TENANT, MK_SIM_AGENT,
//! MK_SIM_MODE (accept|fail_once|reject|unsupported_actions),
//! MK_SIM_BIND (default 127.0.0.1:8787), MK_SIM_CALLBACK_BASE (e.g.
//! http://127.0.0.1:8090) to post signed callbacks back to the kernel.
//! Not a device: never changes `verified_on_device` evidence.

use mk_adapters::simulator::{SimMode, Simulator, post_callbacks};
use mk_crypto::AdapterSecret;

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let secret = AdapterSecret::new(std::env::var("MK_SIM_SECRET")?);
    let tenant = std::env::var("MK_SIM_TENANT")?;
    let agent = std::env::var("MK_SIM_AGENT").unwrap_or_else(|_| "simulator-1".into());
    let mode = match std::env::var("MK_SIM_MODE")
        .unwrap_or_else(|_| "accept".into())
        .as_str()
    {
        "fail_once" => SimMode::FailOnce,
        "reject" => SimMode::Reject,
        "unsupported_actions" => SimMode::UnsupportedActions,
        _ => SimMode::Accept,
    };
    let bind = std::env::var("MK_SIM_BIND").unwrap_or_else(|_| "127.0.0.1:8787".into());
    let callback_base = std::env::var("MK_SIM_CALLBACK_BASE").ok();
    let mut sim = Simulator::start_on(&bind, secret.clone(), &tenant, &agent, mode).await?;
    eprintln!(
        "mk-simulator listening on {} (mode {mode:?}); intake {}",
        sim.addr,
        sim.intake_url()
    );
    while let Some(order) = sim.received.recv().await {
        eprintln!(
            "received work order task_id={} workflow={} steps={}",
            order.task_id,
            order.workflow,
            order.steps.len()
        );
        if let Some(base) = &callback_base {
            match post_callbacks(&order, &secret, &tenant, base, None).await {
                Ok(st) => eprintln!("callbacks posted: {st:?}"),
                Err(e) => eprintln!("callback failed: {e}"),
            }
        }
    }
    Ok(())
}
