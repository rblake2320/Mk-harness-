//! Leased provider cleanup, independent of Redis and browser sessions. Network
//! I/O never holds a transaction. Provider backups are not certified here.
use chrono::{DateTime, Utc};
use mk_audit::{ActorType, EventType, NewEvent};
use mk_crypto::Digest;
use mk_domain::TenantId;
use mk_store::{StoreError, audit, privacy};
use serde_json::json;

use crate::WorkerContext;

#[derive(Debug, Default)]
pub struct PrivacyStats {
    pub checked: usize,
    pub active_deleted: usize,
    pub pending: usize,
    pub stale_lease: usize,
}

pub async fn run_once(
    ctx: &WorkerContext,
    tenants: &[TenantId],
    now: DateTime<Utc>,
) -> Result<PrivacyStats, StoreError> {
    let mut stats = PrivacyStats::default();
    let Some(adapter) = &ctx.registry.twilio else {
        return Ok(stats);
    };
    let started = std::time::Instant::now();
    let clock = || now + chrono::Duration::from_std(started.elapsed()).unwrap_or_default();
    for tenant in tenants {
        for _ in 0..20 {
            let mut tx = ctx.store.begin(*tenant).await?;
            let job = privacy::claim_provider_deletion(&mut tx, clock()).await?;
            tx.commit().await?;
            let Some(job) = job else {
                break;
            };
            stats.checked += 1;
            let result = if job.provider == "twilio" {
                adapter
                    .erase_message(*tenant, job.sender_identity_id, &job.provider_message_id)
                    .await
            } else {
                Err(mk_adapters::AdapterError::permanent(
                    "provider_erasure_unsupported",
                ))
            };
            let observed_at = clock();
            let digest = result.as_ref().ok().map(|r| {
                Digest::of(
                    format!(
                        "mk:provider-erasure:v1:{tenant}:{}:{}:{}:{}",
                        job.request_id,
                        job.deletion_id,
                        r.digest,
                        observed_at.to_rfc3339()
                    )
                    .as_bytes(),
                )
            });
            let error = result.as_ref().err().map(|e| e.code);
            let mut tx = ctx.store.begin(*tenant).await?;
            let wrote = privacy::finish_provider_deletion(
                &mut tx,
                &job,
                digest.as_ref(),
                error,
                observed_at,
            )
            .await?;
            if !wrote {
                stats.stale_lease += 1;
            } else if let (Ok(receipt), Some(digest)) = (&result, &digest) {
                audit::append_event(&mut tx, NewEvent {
                    tenant_id:*tenant, occurred_at:observed_at, actor_type:ActorType::Worker, actor_id:&ctx.worker_id,
                    action_id:None, event_type:EventType::ProviderContentErased,
                    payload_redacted:json!({"request_id":job.request_id,"deletion_id":job.deletion_id,
                        "receipt_digest":digest,"delete_status":receipt.delete_status,"readback_status":receipt.readback_status,
                        "backup_status":"pending"}), trace_id:None, policy_version:mk_policy::POLICY_VERSION.0,
                }).await?;
                stats.active_deleted += 1;
            } else {
                stats.pending += 1;
            }
            tx.commit().await?;
        }
    }
    Ok(stats)
}
