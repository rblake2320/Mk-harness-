//! Dispatch one queued action.

use std::time::Duration;

use chrono::{DateTime, Utc};
use mk_adapters::{ActionAdapter, AdapterRegistry, AuthorizedAction};
use mk_audit::ActorType;
use mk_domain::{ActionId, ActionState, Channel, ContactId, TenantId, Transition};
use mk_policy::{
    DenyCode, POLICY_VERSION, RecheckInput, ToolAllowlist, local_hour_in_zone, recheck_at_dispatch,
};
use mk_queue::backoff::Next;
use mk_queue::{DispatchMessage, RetryPolicy, classify};
use mk_store::actions::{self, Actor};
use mk_store::{Store, StoreError, approvals, consent, human_approval, messaging, outbox, policy};
use serde_json::json;

#[derive(Debug)]
pub struct WorkerContext {
    pub store: Store,
    pub registry: AdapterRegistry,
    pub tools: ToolAllowlist,
    pub worker_id: String,
    pub lease_ttl: Duration,
    pub retry: RetryPolicy,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum DispatchOutcome {
    /// Side effect committed (or accepted pending callback). Ack.
    Dispatched { pending_callback: bool },
    /// Rechecks failed; action moved to a terminal/suppressed state. Ack.
    Blocked { code: DenyCode, state: ActionState },
    /// Inbound path unhealthy (C8): left queued, re-delivered later. Ack.
    Deferred { reason: &'static str },
    /// Adapter failed; retry scheduled through the outbox. Ack.
    RetryScheduled { delay: Duration, attempt: u32 },
    /// Adapter failed permanently or exhausted retries. Ack.
    DeadLettered { code: &'static str },
    /// Side effect uncertain; operator reconciliation required. Ack.
    ReconciliationRequired,
    /// Not ours right now (duplicate delivery or lease held). Ack only if
    /// `ack` is true.
    Skipped { ack: bool, reason: &'static str },
}

#[derive(Debug, thiserror::Error)]
pub enum DispatchError {
    #[error(transparent)]
    Store(#[from] StoreError),
    #[error("adapter kind not registered: {0}")]
    NoAdapter(String),
}

fn actor(worker_id: &str) -> Actor<'_> {
    Actor {
        actor_type: ActorType::Worker,
        actor_id: worker_id,
        trace_id: None,
        policy_version: POLICY_VERSION.0,
    }
}

/// Process one message. Infrastructure errors propagate (the message is
/// left unacked and reclaimed later); every policy outcome is persisted.
pub async fn dispatch_one(
    ctx: &WorkerContext,
    msg: &DispatchMessage,
    now: DateTime<Utc>,
) -> Result<DispatchOutcome, DispatchError> {
    let tenant: TenantId = msg.tenant_id;
    let action_id: ActionId = msg.action_id;
    let store = &ctx.store;
    let worker_actor = actor(&ctx.worker_id);

    // ---- Phase 1: lock, lease, recheck, consume, mark dispatching. --------
    let mut tx = store.begin(tenant).await?;
    let action = match actions::get_for_update(&mut tx, action_id).await {
        Ok(a) => a,
        Err(StoreError::NotFound) => {
            return Ok(DispatchOutcome::Skipped {
                ack: true,
                reason: "unknown_action",
            });
        }
        Err(e) => return Err(e.into()),
    };
    if action.state != ActionState::Queued {
        // Duplicate delivery after we already dispatched, or a cancel won.
        return Ok(DispatchOutcome::Skipped {
            ack: true,
            reason: "not_queued",
        });
    }
    let lease_ttl =
        chrono::Duration::from_std(ctx.lease_ttl).unwrap_or_else(|_| chrono::Duration::seconds(60));
    let Some(lease) =
        outbox::acquire_lease(&mut tx, action_id, &ctx.worker_id, lease_ttl, now).await?
    else {
        return Ok(DispatchOutcome::Skipped {
            ack: false,
            reason: "lease_held",
        });
    };

    let (tenant_policy, tz_offset) = policy::load(&mut tx).await?;
    let global = policy::global_dispatch_enabled(store.pool()).await?;
    let (permissions, suppressions, sends_last_24h) = match (
        action.channel,
        action.destination_hash.as_deref(),
        action.request.resource.id.parse::<ContactId>(),
    ) {
        (Some(ch), Some(dest), Ok(contact)) if action.request.action_kind.is_outreach() => {
            // Serialize concurrent dispatches to the same contact+channel so
            // the frequency count below is exact, not a racy snapshot.
            actions::lock_contact_channel(&mut tx, &action.request.resource.id, ch).await?;
            // C6: the one control path shared with suppression recording. An
            // opt-out committed before this lock is granted is visible below;
            // one that arrives after waits for this transaction to finish and
            // then finds the action already past authorization (non-retractable
            // once submitted) or still cancellable (queued) — never both.
            messaging::lock_control_path(&mut tx, ch.as_str(), dest).await?;
            (
                consent::permissions_for(&mut tx, contact, ch).await?,
                consent::suppressions_for(&mut tx, ch, dest).await?,
                actions::sends_last_24h(&mut tx, &action.request.resource.id, ch, now).await?,
            )
        }
        _ => (Vec::new(), Vec::new(), 0),
    };
    let approval = approvals::live_for_action_locked(&mut tx, action_id).await?;
    // On a retry the live row is gone (consumed); load the consumed one.
    let approval = match approval {
        Some(a) => Some(a),
        None if action.attempt > 0 => approvals::consumed_for_action(&mut tx, action_id).await?,
        None => None,
    };
    // Row H9: an approval whose approver (user or the approving session) was
    // revoked after approving must not dispatch, even if the approval row was
    // not yet marked revoked. Treated exactly like a revoked approval.
    if let Some(a) = &approval
        && human_approval::approver_revoked_since(&mut tx, a.approver_id, a.session_id.as_deref(), a.created_at).await?
    {
        let t = actions::transition(
            &mut tx,
            action_id,
            Transition::Cancel,
            Some(DenyCode::ApprovalRevoked.as_str()),
            worker_actor,
            now,
        )
        .await?;
        outbox::release_lease(&mut tx, action_id, lease).await?;
        tx.commit().await?;
        return Ok(DispatchOutcome::Blocked {
            code: DenyCode::ApprovalRevoked,
            state: t.state,
        });
    }
    // C8: a stale or paused inbound path defers provider dispatch for this
    // tenant. The action stays queued; it is re-delivered later.
    let adapter_kind_early = ctx.tools.get(&action.request.tool_id).map_or("", |t| t.adapter_kind);
    if adapter_kind_early == mk_adapters::twilio::ADAPTER_KIND
        && let Some(reason) = messaging::inbound_dispatch_block(&mut tx, now).await?
    {
        outbox::enqueue(&mut tx, action_id, "retry", now + chrono::Duration::seconds(30), json!({"deferred": reason})).await?;
        outbox::release_lease(&mut tx, action_id, lease).await?;
        tx.commit().await?;
        return Ok(DispatchOutcome::Deferred { reason });
    }
    let attempt = u32::try_from(action.attempt).unwrap_or(0);
    let recheck = RecheckInput {
        action_id,
        tenant_id: tenant,
        request: &action.request,
        stored_digest: &action.digest,
        approval: approval.as_ref(),
        tenant_policy: &tenant_policy,
        global_dispatch_enabled: global,
        channel: action.channel,
        destination_hash: action.destination_hash.as_deref().unwrap_or_default(),
        permissions: &permissions,
        suppressions: &suppressions,
        local_hour: local_hour_in_zone(
            now,
            mk_policy::contact_zone(&action.request.arguments, &tenant_policy.contact_tz).unwrap_or(&tenant_policy.contact_tz),
            tz_offset,
        ),
        sends_last_24h,
        attempt,
        now,
    };
    if let Err(code) = recheck_at_dispatch(&recheck) {
        let t = if code.is_consent_change() {
            Transition::Suppress
        } else if code == DenyCode::ActionExpired {
            Transition::Expire
        } else {
            Transition::Cancel
        };
        let a = actions::transition(
            &mut tx,
            action_id,
            t,
            Some(code.as_str()),
            worker_actor,
            now,
        )
        .await?;
        outbox::release_lease(&mut tx, action_id, lease).await?;
        tx.commit().await?;
        return Ok(DispatchOutcome::Blocked {
            code,
            state: a.state,
        });
    }
    if attempt == 0
        && let Some(a) = &approval
    {
        approvals::consume(
            &mut tx,
            a.approval_id,
            action_id,
            &action.digest,
            &ctx.worker_id,
            now,
        )
        .await?;
    }
    let a = actions::transition(
        &mut tx,
        action_id,
        Transition::StartDispatch,
        None,
        worker_actor,
        now,
    )
    .await?;
    outbox::record_attempt_start(&mut tx, action_id, a.attempt, &ctx.worker_id, now).await?;
    // C4 step 3: record that submission is starting, durably, before the
    // provider request. Only for provider-backed message kinds.
    let sender_identity_id = (adapter_kind_early == mk_adapters::twilio::ADAPTER_KIND)
        .then(|| {
            action
                .request
                .arguments
                .get("sender_identity_id")
                .and_then(serde_json::Value::as_str)
                .and_then(|v| v.parse::<uuid::Uuid>().ok())
        })
        .flatten();
    if let Some(sid) = sender_identity_id {
        messaging::record_submission_started(&mut tx, action_id, a.attempt, sid, now).await?;
    }
    tx.commit().await?;
    let attempt_no = a.attempt;

    // ---- Phase 2: the side effect (no transaction held). ------------------
    let adapter_kind = ctx
        .tools
        .get(&action.request.tool_id)
        .map_or("", |t| t.adapter_kind);
    let adapter: &dyn ActionAdapter = ctx
        .registry
        .get(adapter_kind)
        .ok_or_else(|| DispatchError::NoAdapter(adapter_kind.to_owned()))?;
    let authorized = AuthorizedAction {
        tenant_id: tenant,
        action_id,
        attempt: u32::try_from(attempt_no).unwrap_or(0),
        request: action.request.clone(),
        action_digest: action.digest.clone(),
    };
    let result = match adapter.validate(&authorized).await {
        Ok(()) => adapter.execute(&authorized).await,
        Err(e) => Err(e),
    };

    // ---- Phase 3: persist the outcome. ------------------------------------
    let now2 = Utc::now().max(now);
    let mut tx = store.begin(tenant).await?;
    let outcome = match result {
        Ok(receipt) => {
            if sender_identity_id.is_some()
                && let Some(pmid) = receipt.external_ref.as_deref()
            {
                messaging::record_provider_accepted(&mut tx, action_id, attempt_no, pmid, now2).await?;
            }
            let st = if receipt.pending_callback {
                "started"
            } else {
                "completed"
            };
            outbox::record_attempt_end(
                &mut tx,
                action_id,
                attempt_no,
                st,
                None,
                receipt.adapter_id,
                receipt.external_ref.as_deref(),
                receipt
                    .result_digest
                    .as_ref()
                    .map(ToString::to_string)
                    .as_deref(),
                now2,
            )
            .await?;
            if receipt.pending_callback {
                // Stay in Dispatching; the authenticated callback completes it
                // and releases the lease. The lease TTL bounds how long we wait.
                mk_store::audit::append_event(&mut tx, mk_audit::NewEvent {
                    tenant_id: tenant, occurred_at: now2, actor_type: ActorType::Worker, actor_id: &ctx.worker_id, action_id: Some(action_id),
                    event_type: mk_audit::EventType::DispatchStarted,
                    payload_redacted: json!({"attempt": attempt_no, "adapter_kind": adapter_kind, "external_ref_present": receipt.external_ref.is_some()}),
                    trace_id: None, policy_version: POLICY_VERSION.0,
                }).await?;
                DispatchOutcome::Dispatched {
                    pending_callback: true,
                }
            } else {
                actions::transition(
                    &mut tx,
                    action_id,
                    Transition::Complete,
                    None,
                    worker_actor,
                    now2,
                )
                .await?;
                outbox::release_lease(&mut tx, action_id, lease).await?;
                DispatchOutcome::Dispatched {
                    pending_callback: false,
                }
            }
        }
        Err(e) => {
            if sender_identity_id.is_some() {
                let st = if e.class == mk_queue::RetryClass::Ambiguous { "submission_unknown" } else { "failed" };
                messaging::record_submission_outcome(&mut tx, action_id, attempt_no, st, Some(e.code), now2).await?;
            }
            // Provider-side opt-out (e.g. Twilio 21610): the recipient told the
            // carrier to stop. Record the suppression here, under the control
            // path, so no further proposal to this destination is authorized.
            if e.code == "provider_opt_out"
                && let (Some(ch), Some(dest)) = (action.channel, action.destination_hash.as_deref())
            {
                messaging::lock_control_path(&mut tx, ch.as_str(), dest).await?;
                consent::add_suppression(&mut tx, Some(ch), Some(dest), "destination", "provider_opt_out", true, "provider", worker_actor, now2).await?;
            }
            let jitter: f64 = rand::random();
            match classify(
                e.class,
                u32::try_from(attempt_no).unwrap_or(u32::MAX),
                &ctx.retry,
                jitter,
            ) {
                Next::RetryAfter(delay) => {
                    outbox::record_attempt_end(
                        &mut tx,
                        action_id,
                        attempt_no,
                        "failed_retryable",
                        Some(e.code),
                        None,
                        None,
                        None,
                        now2,
                    )
                    .await?;
                    actions::transition(
                        &mut tx,
                        action_id,
                        Transition::FailRetryable,
                        Some(e.code),
                        worker_actor,
                        now2,
                    )
                    .await?;
                    actions::transition(
                        &mut tx,
                        action_id,
                        Transition::Enqueue,
                        None,
                        worker_actor,
                        now2,
                    )
                    .await?;
                    let available = now2
                        + chrono::Duration::from_std(delay)
                            .unwrap_or_else(|_| chrono::Duration::seconds(60));
                    outbox::enqueue(
                        &mut tx,
                        action_id,
                        "retry",
                        available,
                        json!({"attempt": attempt_no, "code": e.code}),
                    )
                    .await?;
                    outbox::release_lease(&mut tx, action_id, lease).await?;
                    DispatchOutcome::RetryScheduled {
                        delay,
                        attempt: u32::try_from(attempt_no).unwrap_or(0),
                    }
                }
                Next::DeadLetter => {
                    outbox::record_attempt_end(
                        &mut tx,
                        action_id,
                        attempt_no,
                        "failed_final",
                        Some(e.code),
                        None,
                        None,
                        None,
                        now2,
                    )
                    .await?;
                    actions::transition(
                        &mut tx,
                        action_id,
                        Transition::FailFinal,
                        Some(e.code),
                        worker_actor,
                        now2,
                    )
                    .await?;
                    outbox::dead_letter(
                        &mut tx,
                        action_id,
                        "failed_final",
                        attempt_no,
                        Some(e.code),
                        json!({"class": e.class, "code": e.code}),
                        now2,
                    )
                    .await?;
                    outbox::release_lease(&mut tx, action_id, lease).await?;
                    DispatchOutcome::DeadLettered { code: e.code }
                }
                Next::Reconcile => {
                    outbox::record_attempt_end(
                        &mut tx,
                        action_id,
                        attempt_no,
                        "reconciliation_required",
                        Some(e.code),
                        None,
                        None,
                        None,
                        now2,
                    )
                    .await?;
                    actions::transition(
                        &mut tx,
                        action_id,
                        Transition::RequireReconciliation,
                        Some(e.code),
                        worker_actor,
                        now2,
                    )
                    .await?;
                    outbox::release_lease(&mut tx, action_id, lease).await?;
                    DispatchOutcome::ReconciliationRequired
                }
            }
        }
    };
    tx.commit().await?;
    Ok(outcome)
}

/// Resolve the channel for a stored action (used by callback handling).
#[must_use]
pub fn channel_of(action: &actions::StoredAction) -> Option<Channel> {
    action
        .channel
        .or_else(|| action.request.action_kind.channel())
}
