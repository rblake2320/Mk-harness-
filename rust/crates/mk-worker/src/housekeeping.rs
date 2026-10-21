//! Periodic maintenance run by the worker between batches.

use chrono::{DateTime, Utc};
use mk_audit::ActorType;
use mk_domain::{ActionState, TenantId, Transition};
use mk_policy::POLICY_VERSION;
use mk_store::actions::{self, Actor};
use mk_store::{Store, StoreError, adapters, assertions, outbox};

/// A queued action whose dispatch message was published this long ago with no
/// lease since is treated as lost in the queue.
pub const STRANDED_AFTER_SECS: i64 = 30;

#[derive(Debug, Default, Clone, Copy, PartialEq, Eq)]
pub struct HousekeepingStats {
    pub expired: usize,
    pub leases_recovered: usize,
    pub nonces_purged: u64,
    pub jtis_purged: u64,
    pub challenges_purged: u64,
    /// Queued actions re-enqueued after the queue lost their message (O5: Redis data loss).
    pub stranded_requeued: usize,
}

/// Expire overdue actions for one tenant, recover expired leases (moving a
/// stuck `Dispatching` action to reconciliation rather than guessing), and
/// purge old nonces.
pub async fn run_once(
    store: &Store,
    tenants: &[TenantId],
    worker_id: &str,
    now: DateTime<Utc>,
) -> Result<HousekeepingStats, StoreError> {
    let actor = Actor {
        actor_type: ActorType::Worker,
        actor_id: worker_id,
        trace_id: None,
        policy_version: POLICY_VERSION.0,
    };
    let mut stats = HousekeepingStats::default();
    for tenant in tenants {
        let mut tx = store.begin(*tenant).await?;
        for id in actions::expired_candidates(&mut tx, now, 200).await? {
            if actions::transition(
                &mut tx,
                id,
                Transition::Expire,
                Some("action_expired"),
                actor,
                now,
            )
            .await
            .is_ok()
            {
                stats.expired += 1;
            }
        }
        tx.commit().await?;
    }
    for (tenant, action_id) in outbox::expired_leases(store.pool(), now, 200).await? {
        let mut tx = store.begin(tenant).await?;
        let a = actions::get_for_update(&mut tx, action_id).await?;
        // Worker died mid-call or a callback never came: the effect may
        // have happened. Never silently retry.
        if a.state == ActionState::Dispatching {
            actions::transition(
                &mut tx,
                action_id,
                Transition::RequireReconciliation,
                Some("lease_expired"),
                actor,
                now,
            )
            .await?;
        }
        // Drop the stale lease regardless of state.
        sqlx_release(&mut tx, action_id).await?;
        tx.commit().await?;
        stats.leases_recovered += 1;
    }
    // Queue loss: an action can be `queued` with every outbox event published
    // and nobody holding a lease. Re-enqueue; dispatch skips anything that has
    // moved on, so this can never double-execute.
    for tenant in tenants {
        let mut tx = store.begin(*tenant).await?;
        for action_id in outbox::stranded_queued(&mut tx, now, STRANDED_AFTER_SECS, 100).await? {
            let a = actions::get_for_update(&mut tx, action_id).await?;
            if a.state == ActionState::Queued {
                outbox::enqueue(&mut tx, action_id, "dispatch", now, serde_json::json!({"requeued": "stranded"})).await?;
                stats.stranded_requeued += 1;
            }
        }
        tx.commit().await?;
    }
    stats.nonces_purged = adapters::purge_nonces(store.pool(), now).await?;
    stats.jtis_purged = assertions::purge_jtis(store.pool(), now).await?;
    stats.challenges_purged = mk_store::human_approval::purge_challenges(store.pool(), now).await?;
    Ok(stats)
}

async fn sqlx_release(
    tx: &mut mk_store::TenantTx<'_>,
    action_id: mk_domain::ActionId,
) -> Result<(), StoreError> {
    outbox::release_lease_any(tx, action_id).await
}
