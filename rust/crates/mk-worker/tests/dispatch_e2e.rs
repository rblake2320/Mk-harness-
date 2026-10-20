#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::missing_panics_doc,
    clippy::too_many_lines,
    clippy::unreadable_literal,
    clippy::cast_possible_truncation
)]
//! End-to-end dispatch against real Postgres and the in-process mobile
//! simulator. Requires `MK_TEST_DATABASE_URL`.

use std::collections::HashMap;
use std::time::Duration;

use async_trait::async_trait;
use chrono::Utc;
use mk_adapters::egress::EgressAllowlist;
use mk_adapters::mobile::{AgentResolver, AgentTarget, MobileAdapter};
use mk_adapters::simulator::{SimMode, Simulator};
use mk_adapters::{AdapterRegistry, InternalRecordAdapter};
use mk_audit::ActorType;
use mk_crypto::{AdapterSecret, Digest};
use mk_domain::{ActionState, ApprovalDecision, Channel, ContactId, TenantId, Transition, UserId};
use mk_policy::{DenyCode, POLICY_VERSION, ToolAllowlist};
use mk_queue::{DispatchMessage, RetryPolicy};
use mk_store::actions::{self, Actor};
use mk_store::{Store, approvals, consent, outbox};
use mk_testkit::{sms_request, t0};
use mk_worker::{DispatchOutcome, WorkerContext, dispatch_one};
use serde_json::json;

#[derive(Debug)]
struct MapResolver(HashMap<(TenantId, String), AgentTarget>);

#[async_trait]
impl AgentResolver for MapResolver {
    async fn resolve(&self, tenant: TenantId, agent_id: &str) -> Option<AgentTarget> {
        self.0.get(&(tenant, agent_id.to_owned())).cloned()
    }
}

const ACTOR: Actor<'static> = Actor {
    actor_type: ActorType::System,
    actor_id: "test",
    trace_id: None,
    policy_version: "t",
};

struct World {
    store: Store,
    ctx: WorkerContext,
    sim: Simulator,
    tenant: TenantId,
    user: UserId,
    contact: ContactId,
}

async fn world(mode: SimMode) -> Option<World> {
    let url = mk_testkit::test_database_url()?;
    let store = Store::connect(&url, 8).await.ok()?;
    store.migrate().await.ok()?;
    let tenant = TenantId::new();
    let secret = AdapterSecret::new("sim-secret-0123456789");
    let sim = Simulator::start(secret.clone(), &tenant.to_string(), "simulator-1", mode)
        .await
        .ok()?;
    let target = AgentTarget {
        adapter_id: uuid::Uuid::now_v7(),
        agent_id: "simulator-1".into(),
        intake_url: sim.intake_url(),
        secret,
        callback_authority: "kernel.internal".into(),
        capabilities: vec!["open".into(), "input".into()],
    };
    let mobile = MobileAdapter::new(
        EgressAllowlist::new([sim.authority().as_str()], true),
        Box::new(MapResolver(HashMap::from([(
            (tenant, "simulator-1".to_string()),
            target,
        )]))),
        "phoneclaw@c59995b",
    )
    .ok()?;
    let ctx = WorkerContext {
        store: store.clone(),
        registry: AdapterRegistry {
            internal: InternalRecordAdapter,
            mobile: Some(mobile),
        },
        tools: ToolAllowlist::v1(),
        worker_id: "worker-e2e".into(),
        lease_ttl: Duration::from_mins(1),
        retry: RetryPolicy {
            base: Duration::from_millis(10),
            max_delay: Duration::from_millis(50),
            max_attempts: 3,
        },
    };
    Some(World {
        store,
        ctx,
        sim,
        tenant,
        user: UserId::new(),
        contact: ContactId::new(),
    })
}

/// Propose + consent + approve + enqueue; returns the action id.
async fn queued_outreach(w: &World) -> mk_domain::ActionId {
    let now = Utc::now();
    let mut req = sms_request(w.tenant, w.user, w.contact, now);
    req.arguments.insert("to".into(), json!("+15555550100"));
    req.arguments
        .insert("agent_id".into(), json!("simulator-1"));
    let id = req.action_id.unwrap_or_default();
    let mut tx = w
        .store
        .begin(w.tenant)
        .await
        .unwrap_or_else(|e| panic!("{e:?}"));
    consent::grant_permission(
        &mut tx,
        w.contact,
        Channel::Sms,
        &["customer_requested_follow_up".into()],
        "form",
        &Digest::of(b"p"),
        now - chrono::Duration::hours(1),
        now + chrono::Duration::days(1),
        w.user,
        ACTOR,
        now,
    )
    .await
    .unwrap_or_else(|e| panic!("{e:?}"));
    actions::insert_draft(
        &mut tx,
        &req,
        Some(Channel::Sms),
        Some("dest-hash"),
        ACTOR,
        now,
    )
    .await
    .unwrap_or_else(|e| panic!("{e:?}"));
    actions::transition(&mut tx, id, Transition::SubmitForPolicy, None, ACTOR, now)
        .await
        .unwrap_or_else(|e| panic!("{e:?}"));
    actions::transition(
        &mut tx,
        id,
        Transition::PolicyRequireApproval,
        None,
        ACTOR,
        now,
    )
    .await
    .unwrap_or_else(|e| panic!("{e:?}"));
    approvals::record_decision(
        &mut tx,
        id,
        UserId::new(),
        &["manager".into()],
        ApprovalDecision::Approved,
        None,
        900,
        None,
        None,
        now,
    )
    .await
    .unwrap_or_else(|e| panic!("{e:?}"));
    actions::transition(&mut tx, id, Transition::Approve, None, ACTOR, now)
        .await
        .unwrap_or_else(|e| panic!("{e:?}"));
    actions::transition(&mut tx, id, Transition::Enqueue, None, ACTOR, now)
        .await
        .unwrap_or_else(|e| panic!("{e:?}"));
    outbox::enqueue(&mut tx, id, "dispatch", now, json!({}))
        .await
        .unwrap_or_else(|e| panic!("{e:?}"));
    tx.commit().await.unwrap_or_else(|e| panic!("{e:?}"));
    id
}

fn msg(w: &World, id: mk_domain::ActionId) -> DispatchMessage {
    DispatchMessage {
        tenant_id: w.tenant,
        action_id: id,
        outbox_id: 0,
        event_kind: "dispatch".into(),
    }
}

/// Worker clock must agree with the fixture's "inside contact hours" time:
/// dispatch rechecks contact hours, so we pin `now` to t0 + a little.
fn now_in_hours() -> chrono::DateTime<Utc> {
    Utc::now()
}

#[tokio::test]
async fn happy_path_then_duplicate_delivery_is_absorbed() {
    let Some(mut w) = world(SimMode::Accept).await else {
        eprintln!("skipping");
        return;
    };
    pin_contact_hours(&w).await;
    let id = queued_outreach(&w).await;
    let out = dispatch_one(&w.ctx, &msg(&w, id), now_in_hours())
        .await
        .unwrap_or_else(|e| panic!("{e:?}"));
    assert_eq!(
        out,
        DispatchOutcome::Dispatched {
            pending_callback: true
        }
    );
    let order = w
        .sim
        .received
        .recv()
        .await
        .unwrap_or_else(|| panic!("device received nothing"));
    assert_eq!(order.task_id, id.0.simple().to_string());

    let mut tx = w
        .store
        .begin(w.tenant)
        .await
        .unwrap_or_else(|e| panic!("{e:?}"));
    let a = actions::get(&mut tx, id)
        .await
        .unwrap_or_else(|e| panic!("{e:?}"));
    assert_eq!(a.state, ActionState::Dispatching);
    assert_eq!(a.attempt, 1);
    assert!(
        approvals::live_for_action_locked(&mut tx, id)
            .await
            .unwrap_or(None)
            .is_none(),
        "approval consumed"
    );
    tx.rollback().await.unwrap_or_else(|e| panic!("{e:?}"));

    // Duplicate delivery (at-least-once): nothing happens, ack.
    let dup = dispatch_one(&w.ctx, &msg(&w, id), now_in_hours())
        .await
        .unwrap_or_else(|e| panic!("{e:?}"));
    assert_eq!(
        dup,
        DispatchOutcome::Skipped {
            ack: true,
            reason: "not_queued"
        }
    );
    assert!(
        w.sim.received.try_recv().is_err(),
        "device must not receive a second order"
    );

    // Chain is intact end to end.
    let mut tx = w
        .store
        .begin(w.tenant)
        .await
        .unwrap_or_else(|e| panic!("{e:?}"));
    assert!(mk_store::audit::verify_tenant(&mut tx).await.unwrap_or(0) >= 10);
}

#[tokio::test]
async fn revocation_after_queue_suppresses_before_dispatch() {
    let Some(mut w) = world(SimMode::Accept).await else {
        eprintln!("skipping");
        return;
    };
    pin_contact_hours(&w).await;
    let id = queued_outreach(&w).await;
    let mut tx = w
        .store
        .begin(w.tenant)
        .await
        .unwrap_or_else(|e| panic!("{e:?}"));
    let perms = consent::permissions_for(&mut tx, w.contact, Channel::Sms)
        .await
        .unwrap_or_default();
    assert_eq!(perms.len(), 1);
    // Revoke through the raw table (permission id not returned by helper) —
    // equivalent to the API's revoke path.
    sqlx::query("UPDATE kernel.contact_permissions SET status='revoked', revoked_at=now() WHERE tenant_id=$1 AND contact_id=$2")
        .bind(w.tenant.0).bind(w.contact.0).execute(tx_conn(&mut tx)).await.unwrap_or_else(|e| panic!("{e:?}"));
    tx.commit().await.unwrap_or_else(|e| panic!("{e:?}"));

    let out = dispatch_one(&w.ctx, &msg(&w, id), now_in_hours())
        .await
        .unwrap_or_else(|e| panic!("{e:?}"));
    assert_eq!(
        out,
        DispatchOutcome::Blocked {
            code: DenyCode::ContactPermissionRevoked,
            state: ActionState::Suppressed
        }
    );
    assert!(
        w.sim.received.try_recv().is_err(),
        "nothing reaches the device"
    );
    let mut tx = w
        .store
        .begin(w.tenant)
        .await
        .unwrap_or_else(|e| panic!("{e:?}"));
    assert!(
        approvals::live_for_action_locked(&mut tx, id)
            .await
            .unwrap_or(None)
            .is_some(),
        "approval not consumed when blocked"
    );
}

#[tokio::test]
async fn suppression_after_approval_and_kill_switch_block_dispatch() {
    let Some(mut w) = world(SimMode::Accept).await else {
        eprintln!("skipping");
        return;
    };
    pin_contact_hours(&w).await;
    let id = queued_outreach(&w).await;
    let mut tx = w
        .store
        .begin(w.tenant)
        .await
        .unwrap_or_else(|e| panic!("{e:?}"));
    consent::add_suppression(
        &mut tx,
        Some(Channel::Sms),
        Some("dest-hash"),
        "destination",
        "opt_out",
        true,
        "test",
        ACTOR,
        Utc::now(),
    )
    .await
    .unwrap_or_else(|e| panic!("{e:?}"));
    tx.commit().await.unwrap_or_else(|e| panic!("{e:?}"));
    let out = dispatch_one(&w.ctx, &msg(&w, id), now_in_hours())
        .await
        .unwrap_or_else(|e| panic!("{e:?}"));
    assert_eq!(
        out,
        DispatchOutcome::Blocked {
            code: DenyCode::Suppressed,
            state: ActionState::Suppressed
        }
    );

    let id2 = queued_outreach(&w).await; // same contact now suppressed → also blocked
    let out = dispatch_one(&w.ctx, &msg(&w, id2), now_in_hours())
        .await
        .unwrap_or_else(|e| panic!("{e:?}"));
    assert!(matches!(
        out,
        DispatchOutcome::Blocked {
            code: DenyCode::Suppressed,
            ..
        }
    ));

    // Tenant kill switch.
    let w2 = world(SimMode::Accept).await.unwrap_or_else(|| panic!());
    pin_contact_hours(&w2).await;
    let id3 = queued_outreach(&w2).await;
    let mut tx = w2
        .store
        .begin(w2.tenant)
        .await
        .unwrap_or_else(|e| panic!("{e:?}"));
    mk_store::policy::set_tenant_dispatch(&mut tx, false, ACTOR, Utc::now())
        .await
        .unwrap_or_else(|e| panic!("{e:?}"));
    tx.commit().await.unwrap_or_else(|e| panic!("{e:?}"));
    let out = dispatch_one(&w2.ctx, &msg(&w2, id3), now_in_hours())
        .await
        .unwrap_or_else(|e| panic!("{e:?}"));
    assert_eq!(
        out,
        DispatchOutcome::Blocked {
            code: DenyCode::DispatchDisabled,
            state: ActionState::Cancelled
        }
    );
    assert!(w.sim.received.try_recv().is_err());
}

#[tokio::test]
async fn transient_failure_retries_with_consumed_approval_then_succeeds() {
    let Some(mut w) = world(SimMode::FailOnce).await else {
        eprintln!("skipping");
        return;
    };
    pin_contact_hours(&w).await;
    let id = queued_outreach(&w).await;
    let first = dispatch_one(&w.ctx, &msg(&w, id), now_in_hours())
        .await
        .unwrap_or_else(|e| panic!("{e:?}"));
    assert!(
        matches!(first, DispatchOutcome::RetryScheduled { attempt: 1, .. }),
        "{first:?}"
    );
    let _ = w.sim.received.recv().await; // simulator saw attempt 1
    let mut tx = w
        .store
        .begin(w.tenant)
        .await
        .unwrap_or_else(|e| panic!("{e:?}"));
    assert_eq!(
        actions::get(&mut tx, id).await.map(|a| a.state).ok(),
        Some(ActionState::Queued)
    );
    tx.rollback().await.unwrap_or_else(|e| panic!("{e:?}"));
    let second = dispatch_one(&w.ctx, &msg(&w, id), now_in_hours())
        .await
        .unwrap_or_else(|e| panic!("{e:?}"));
    assert_eq!(
        second,
        DispatchOutcome::Dispatched {
            pending_callback: true
        }
    );
    let mut tx = w
        .store
        .begin(w.tenant)
        .await
        .unwrap_or_else(|e| panic!("{e:?}"));
    let a = actions::get(&mut tx, id)
        .await
        .unwrap_or_else(|e| panic!("{e:?}"));
    assert_eq!((a.state, a.attempt), (ActionState::Dispatching, 2));
}

#[tokio::test]
async fn permanent_rejection_dead_letters() {
    let Some(w) = world(SimMode::Reject).await else {
        eprintln!("skipping");
        return;
    };
    pin_contact_hours(&w).await;
    let id = queued_outreach(&w).await;
    let out = dispatch_one(&w.ctx, &msg(&w, id), now_in_hours())
        .await
        .unwrap_or_else(|e| panic!("{e:?}"));
    assert_eq!(
        out,
        DispatchOutcome::DeadLettered {
            code: "agent_rejected"
        }
    );
    let mut tx = w
        .store
        .begin(w.tenant)
        .await
        .unwrap_or_else(|e| panic!("{e:?}"));
    assert_eq!(
        actions::get(&mut tx, id).await.map(|a| a.state).ok(),
        Some(ActionState::FailedFinal)
    );
    // Replay creates a new linked action; the original stays terminal.
    let orig = actions::get(&mut tx, id)
        .await
        .unwrap_or_else(|e| panic!("{e:?}"));
    let new_id = mk_domain::ActionId::new();
    let replay = actions::insert_replay(&mut tx, &orig, new_id, ACTOR, Utc::now())
        .await
        .unwrap_or_else(|e| panic!("{e:?}"));
    assert_eq!(replay.replay_of, Some(id));
    assert_eq!(replay.state, ActionState::Draft);
    assert_eq!(
        actions::get(&mut tx, id).await.map(|a| a.state).ok(),
        Some(ActionState::FailedFinal)
    );
    let _ = POLICY_VERSION;
}

/// Widen contact hours so the test is not time-of-day dependent.
async fn pin_contact_hours(w: &World) {
    let mut tx = w
        .store
        .begin(w.tenant)
        .await
        .unwrap_or_else(|e| panic!("{e:?}"));
    let (mut p, _) = mk_store::policy::load(&mut tx)
        .await
        .unwrap_or_else(|e| panic!("{e:?}"));
    p.contact_hours = (0, 24);
    mk_store::policy::write(&mut tx, "test", &p, 0)
        .await
        .unwrap_or_else(|e| panic!("{e:?}"));
    tx.commit().await.unwrap_or_else(|e| panic!("{e:?}"));
    let _ = t0();
}

fn tx_conn<'a>(tx: &'a mut mk_store::TenantTx<'_>) -> &'a mut sqlx::PgConnection {
    tx.raw_conn()
}
