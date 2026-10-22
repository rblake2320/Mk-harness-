//! C4: scheduled, read-only provider reconciliation. Never submits or retries a
//! message. Missing provider ids and failed GETs remain explicitly uncertain.
use chrono::{DateTime, Utc};
use mk_adapters::twilio::DeliveryState;
use mk_audit::{ActorType, EventType, NewEvent};
use mk_domain::{ActionState, TenantId, Transition};
use mk_store::{StoreError, actions, audit, messaging as ms, outbox};
use serde_json::json;

use crate::WorkerContext;

#[derive(Debug, Default)]
pub struct ReconciliationStats {
    pub checked: usize,
    pub observed: usize,
    pub unavailable: usize,
}

pub async fn run_once(
    ctx: &WorkerContext,
    tenants: &[TenantId],
    now: DateTime<Utc>,
) -> Result<ReconciliationStats, StoreError> {
    let mut stats = ReconciliationStats::default();
    let Some(adapter) = &ctx.registry.twilio else {
        return Ok(stats);
    };
    for tenant in tenants {
        let mut tx = ctx.store.begin(*tenant).await?;
        let candidates = ms::claim_reconciliation_checks(&mut tx, now, 20).await?;
        tx.commit().await?;
        for candidate in candidates {
            stats.checked += 1;
            let mut tx = ctx.store.begin(*tenant).await?;
            let action = actions::get(&mut tx, candidate.action_id).await?;
            tx.commit().await?;
            let to = action
                .request
                .arguments
                .get("to")
                .and_then(serde_json::Value::as_str)
                .unwrap_or_default();
            let Some(sid) = candidate.provider_message_id.as_deref() else {
                continue;
            };
            let observation = adapter
                .observe_message(*tenant, candidate.sender_identity_id, sid, to)
                .await;
            let mut tx = ctx.store.begin(*tenant).await?;
            // Same lock order as dispatch: action first, then delivery. Re-read
            // after the GET so an intervening terminal callback cannot regress.
            let action = actions::get_for_update(&mut tx, candidate.action_id).await?;
            let Some(delivery) = ms::delivery_by_provider_id(&mut tx, sid).await? else {
                continue;
            };
            if delivery.delivery_id != candidate.delivery_id {
                continue;
            }
            let observation = match observation {
                Ok(o) => o,
                Err(e) => {
                    stats.unavailable += 1;
                    audit::append_event(&mut tx, NewEvent {
                        tenant_id: *tenant, occurred_at: now, actor_type: ActorType::Worker,
                        actor_id: &ctx.worker_id, action_id: Some(delivery.action_id),
                        event_type: EventType::DeliveryEvent,
                        payload_redacted: json!({"source":"provider_reconciliation", "outcome":"unknown", "code":e.code}),
                        trace_id: None, policy_version: mk_policy::POLICY_VERSION.0,
                    }).await?;
                    tx.commit().await?;
                    continue;
                }
            };
            let current = match delivery.state.as_str() {
                "provider_accepted" => DeliveryState::ProviderAccepted,
                "sent" => DeliveryState::Sent,
                "delivered" => DeliveryState::Delivered,
                "failed" => DeliveryState::Failed,
                "delivery_unknown" => DeliveryState::DeliveryUnknown,
                _ => DeliveryState::SubmissionStarted,
            };
            let Some(evidence) = DeliveryState::from_twilio_status(&observation.status) else {
                stats.unavailable += 1;
                continue;
            };
            let folded = DeliveryState::fold(current, evidence);
            let error_code = observation.error_code.map(|e| e.to_string());
            ms::record_delivery_event(
                &mut tx,
                &delivery,
                &format!("get:{sid}:{}", observation.digest),
                &observation.status,
                error_code.as_deref(),
                &observation.digest,
                folded.as_str(),
                observation.status == "read",
                now,
            )
            .await?;
            ms::record_reconciliation(
                &mut tx,
                delivery.delivery_id,
                folded.as_str(),
                None,
                "verified_provider_resource",
                now,
            )
            .await?;
            let actor = actions::Actor {
                actor_type: ActorType::Worker,
                actor_id: &ctx.worker_id,
                trace_id: None,
                policy_version: mk_policy::POLICY_VERSION.0,
            };
            if action.state == ActionState::Dispatching
                && matches!(
                    folded,
                    DeliveryState::Sent | DeliveryState::Delivered | DeliveryState::Failed
                )
            {
                let failed = folded == DeliveryState::Failed;
                actions::transition(
                    &mut tx,
                    action.action_id,
                    if failed {
                        Transition::FailFinal
                    } else {
                        Transition::Complete
                    },
                    error_code.as_deref(),
                    actor,
                    now,
                )
                .await?;
                outbox::record_attempt_end(
                    &mut tx,
                    action.action_id,
                    action.attempt,
                    if failed { "failed_final" } else { "completed" },
                    error_code.as_deref(),
                    Some(delivery.sender_identity_id),
                    Some(sid),
                    Some(&observation.digest.to_string()),
                    now,
                )
                .await?;
                outbox::release_lease_any(&mut tx, action.action_id).await?;
            }
            if folded == DeliveryState::Failed && current != DeliveryState::Failed {
                outbox::dead_letter(
                    &mut tx,
                    action.action_id,
                    "provider_reconciled_failure",
                    action.attempt,
                    error_code.as_deref(),
                    json!({"source":"provider_reconciliation"}),
                    now,
                )
                .await?;
            }
            audit::append_event(&mut tx, NewEvent {
                tenant_id: *tenant, occurred_at: now, actor_type: ActorType::Worker,
                actor_id: &ctx.worker_id, action_id: Some(delivery.action_id), event_type: EventType::DeliveryEvent,
                payload_redacted: json!({"source":"provider_reconciliation", "provider_status":observation.status,
                    "folded_state":folded.as_str(), "raw_event_digest":observation.digest.to_string()}),
                trace_id: None, policy_version: mk_policy::POLICY_VERSION.0,
            }).await?;
            tx.commit().await?;
            stats.observed += 1;
        }
    }
    Ok(stats)
}
