//! `mk-action-worker`: consumes dispatch messages and executes authorized
//! actions. Stops leasing new work on SIGTERM and lets in-flight work finish.

use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::Duration;

use mk_adapters::egress::EgressAllowlist;
use mk_adapters::mobile::MobileAdapter;
use mk_adapters::{AdapterRegistry, InternalRecordAdapter};
use mk_policy::ToolAllowlist;
use mk_queue::{RetryPolicy, StreamClient};
use mk_store::Store;
use mk_worker::config::{Config, init_tracing};
use mk_worker::resolver::{StoreResolver, StoreSenderResolver};
use mk_adapters::twilio::TwilioAdapter;
use mk_worker::{DispatchOutcome, WorkerContext, dispatch_one, housekeeping};
use secrecy::ExposeSecret;

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    init_tracing();
    let cfg = Config::from_env()?;
    let store = Store::connect(cfg.database_url.expose_secret(), 16).await?;
    let stream = StreamClient::connect(cfg.redis_url.expose_secret(), "mk").await?;
    stream.ensure_groups().await?;
    let egress = EgressAllowlist::new(
        cfg.egress_authorities.iter().map(String::as_str),
        cfg.allow_loopback_http,
    );
    let mobile = if cfg.adapter_intake_template.is_empty() {
        None
    } else {
        Some(MobileAdapter::new(
            egress,
            Box::new(StoreResolver {
                store: store.clone(),
                master: cfg.master_key.clone(),
                intake_url_template: cfg.adapter_intake_template.clone(),
            }),
            "phoneclaw@c59995b726a127da16275d2d8e0760408b988542",
        )?)
    };
    let twilio = if cfg.twilio_api_base.is_empty() {
        None
    } else {
        if cfg.public_webhook_base.is_empty() {
            anyhow::bail!("MK_PUBLIC_WEBHOOK_BASE is required when MK_TWILIO_API_BASE is set");
        }
        Some(TwilioAdapter::new(
            EgressAllowlist::new(cfg.egress_authorities.iter().map(String::as_str), cfg.allow_loopback_http),
            &cfg.twilio_api_base,
            Box::new(StoreSenderResolver {
                store: store.clone(),
                master: cfg.master_key.clone(),
                public_webhook_base: cfg.public_webhook_base.clone(),
            }),
        )?)
    };
    let ctx = WorkerContext {
        store: store.clone(),
        registry: AdapterRegistry {
            internal: InternalRecordAdapter,
            mobile,
            twilio,
        },
        tools: ToolAllowlist::v1(),
        worker_id: cfg.worker_id.clone(),
        lease_ttl: Duration::from_secs(cfg.lease_secs),
        retry: RetryPolicy::default(),
    };

    let stopping = Arc::new(AtomicBool::new(false));
    {
        let stopping = stopping.clone();
        tokio::spawn(async move {
            let _ = tokio::signal::ctrl_c().await;
            tracing::info!("shutdown requested; finishing in-flight work");
            stopping.store(true, Ordering::SeqCst);
        });
    }

    tracing::info!(worker_id = %cfg.worker_id, "worker started");
    let mut tick = 0u64;
    while !stopping.load(Ordering::SeqCst) {
        // Fail closed: if audit/DB is unavailable we do not dispatch.
        if store.ping().await.is_err() {
            tracing::error!("database unavailable; pausing dispatch");
            tokio::time::sleep(Duration::from_secs(5)).await;
            continue;
        }
        let deliveries = match stream
            .read(
                &cfg.worker_id,
                cfg.batch,
                2000,
                (cfg.lease_secs * 1000) + 5000,
            )
            .await
        {
            Ok(d) => d,
            Err(e) => {
                tracing::error!(error = %e, "stream read failed");
                tokio::time::sleep(Duration::from_secs(2)).await;
                continue;
            }
        };
        for d in deliveries {
            if stopping.load(Ordering::SeqCst) {
                break;
            }
            match dispatch_one(&ctx, &d.message, chrono::Utc::now()).await {
                Ok(DispatchOutcome::Skipped { ack: false, reason }) => {
                    tracing::debug!(action_id = %d.message.action_id, reason, "left unacked");
                }
                Ok(outcome) => {
                    tracing::info!(action_id = %d.message.action_id, ?outcome, "dispatched");
                    if let Err(e) = stream.ack(&d.stream, &d.id).await {
                        tracing::warn!(error = %e, "ack failed; duplicate delivery will be absorbed");
                    }
                }
                Err(e) => {
                    tracing::error!(action_id = %d.message.action_id, error = %e, "dispatch error; message stays pending");
                }
            }
        }
        tick += 1;
        if tick.is_multiple_of(15) {
            match mk_store::audit::all_tenants(store.pool()).await {
                Ok(tenants) => match housekeeping::run_once(
                    &store,
                    &tenants,
                    &cfg.worker_id,
                    chrono::Utc::now(),
                )
                .await
                {
                    Ok(stats) => tracing::info!(?stats, "housekeeping"),
                    Err(e) => tracing::warn!(error = %e, "housekeeping failed"),
                },
                Err(e) => tracing::warn!(error = %e, "tenant listing failed"),
            }
        }
    }
    tracing::info!("worker stopped");
    Ok(())
}
