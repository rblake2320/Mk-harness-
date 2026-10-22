#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::missing_panics_doc,
    clippy::too_many_lines,
    clippy::unreadable_literal,
    clippy::cast_possible_truncation
)]
//! Relay + stream integration. Needs `MK_TEST_DATABASE_URL` and
//! `MK_TEST_REDIS_URL`; skipped otherwise.

use std::time::Duration;

use mk_audit::ActorType;
use mk_domain::{Channel, ContactId, TenantId, UserId};
use mk_queue::{DispatchMessage, RelayConfig, StreamClient, run_relay_once};
use mk_store::actions::{self, Actor};
use mk_store::{Store, outbox};
use mk_testkit::{sms_request, t0};

const ACTOR: Actor<'static> = Actor {
    actor_type: ActorType::System,
    actor_id: "test",
    trace_id: None,
    policy_version: "t",
};

/// The relay claims every pending outbox row, so the two relay tests must
/// not run concurrently with each other.
static SERIAL: tokio::sync::Mutex<()> = tokio::sync::Mutex::const_new(());

async fn env() -> Option<(Store, StreamClient)> {
    let db = mk_testkit::test_database_url()?;
    let rd = mk_testkit::test_redis_url()?;
    let store = Store::connect(&db, 8).await.ok()?;
    store.migrate().await.ok()?;
    let prefix = format!("mk-test-{}", uuid::Uuid::now_v7());
    let stream = StreamClient::connect(&rd, &prefix).await.ok()?;
    stream.ensure_groups().await.ok()?;
    Some((store, stream))
}

async fn queued_action(store: &Store, tenant: TenantId) -> (mk_domain::ActionId, i64) {
    let req = sms_request(tenant, UserId::new(), ContactId::new(), t0());
    let id = req.action_id.unwrap_or_default();
    let mut tx = store
        .begin(tenant)
        .await
        .unwrap_or_else(|e| panic!("{e:?}"));
    actions::insert_draft(&mut tx, &req, Some(Channel::Sms), None, ACTOR, t0())
        .await
        .unwrap_or_else(|e| panic!("{e:?}"));
    let oid = outbox::enqueue(
        &mut tx,
        id,
        "dispatch",
        chrono::Utc::now(),
        serde_json::json!({}),
    )
    .await
    .unwrap_or_else(|e| panic!("{e:?}"));
    tx.commit().await.unwrap_or_else(|e| panic!("{e:?}"));
    (id, oid)
}

#[tokio::test]
async fn relay_publishes_and_worker_reads_then_acks() {
    let _serial = SERIAL.lock().await;
    let Some((store, stream)) = env().await else {
        eprintln!("skipping");
        return;
    };
    let tenant = TenantId::new();
    let (id, oid) = queued_action(&store, tenant).await;
    let cfg = RelayConfig {
        relay_id: "relay-t1".into(),
        batch: 50,
        lease: Duration::from_secs(30),
    };
    // Other suites may hold short leases on outbox rows; poll until ours is
    // published (bounded).
    let mut published = false;
    for _ in 0..40 {
        let stats = run_relay_once(&store, &stream, &cfg)
            .await
            .unwrap_or_else(|e| panic!("{e:?}"));
        if stats.published >= 1 {
            published = true;
            break;
        }
        tokio::time::sleep(Duration::from_millis(250)).await;
    }
    assert!(published, "row never published");

    let got = stream
        .read("worker-1", 50, 200, 60_000)
        .await
        .unwrap_or_else(|e| panic!("{e:?}"));
    let d = got
        .iter()
        .find(|d| d.message.action_id == id)
        .unwrap_or_else(|| panic!("message not delivered"));
    assert_eq!(
        d.message,
        DispatchMessage {
            tenant_id: tenant,
            action_id: id,
            outbox_id: oid,
            event_kind: "dispatch".into()
        }
    );
    // Not acked yet → another consumer reclaims it after idle threshold 0.
    let reclaimed = stream
        .read("worker-2", 50, 10, 0)
        .await
        .unwrap_or_else(|e| panic!("{e:?}"));
    assert!(
        reclaimed.iter().any(|r| r.message.action_id == id),
        "unacked entry is reclaimable (worker death)"
    );
    let r = reclaimed
        .iter()
        .find(|r| r.message.action_id == id)
        .unwrap_or_else(|| panic!());
    stream
        .ack(&r.stream, &r.id)
        .await
        .unwrap_or_else(|e| panic!("{e:?}"));
    let again = stream
        .read("worker-3", 50, 10, 0)
        .await
        .unwrap_or_else(|e| panic!("{e:?}"));
    assert!(
        !again.iter().any(|r| r.message.action_id == id),
        "acked entry never redelivered"
    );
    // Outbox row is published exactly once.
    let (depth, _) = outbox::backlog(store.pool(), chrono::Utc::now())
        .await
        .unwrap_or_else(|e| panic!("{e:?}"));
    assert!(depth >= 0);
    let _ = run_relay_once(&store, &stream, &cfg)
        .await
        .unwrap_or_else(|e| panic!("{e:?}"));
    let fresh = stream
        .read("worker-4", 100, 10, 0)
        .await
        .unwrap_or_else(|e| panic!("{e:?}"));
    assert!(
        !fresh.iter().any(|r| r.message.outbox_id == oid),
        "published rows are never republished"
    );
}

#[tokio::test]
async fn crash_after_publish_before_mark_yields_duplicate_not_loss() {
    let _serial = SERIAL.lock().await;
    let Some((store, stream)) = env().await else {
        eprintln!("skipping");
        return;
    };
    let tenant = TenantId::new();
    let (id, oid) = queued_action(&store, tenant).await;
    // Simulate: relay A claims and publishes, then dies before mark_published.
    let rows = outbox::claim_batch(
        store.pool(),
        "relay-a",
        chrono::Duration::seconds(1),
        // The test database is shared with suites running in parallel (and may hold
        // backlog): claim enough that this tenant's row is always in the batch.
        100_000,
        chrono::Utc::now(),
    )
    .await
    .unwrap_or_else(|e| panic!("{e:?}"));
    let row = rows
        .iter()
        .find(|r| r.outbox_id == oid)
        .unwrap_or_else(|| panic!("row not claimed"));
    stream
        .publish(&DispatchMessage {
            tenant_id: tenant,
            action_id: id,
            outbox_id: oid,
            event_kind: row.event_kind.clone(),
        })
        .await
        .unwrap_or_else(|e| panic!("{e:?}"));
    // (relay A dies here) — lease expires, relay B runs normally.
    tokio::time::sleep(Duration::from_millis(1100)).await;
    let cfg = RelayConfig {
        relay_id: "relay-b".into(),
        batch: 50,
        lease: Duration::from_secs(30),
    };
    // Run relay B until THIS row is marked published (other suites' rows may be
    // published first), collecting deliveries of this action as we go.
    let mut republished = false;
    let mut n = 0;
    for _ in 0..80 {
        run_relay_once(&store, &stream, &cfg)
            .await
            .unwrap_or_else(|e| panic!("{e:?}"));
        let got = stream
            .read("worker-1", 1000, 50, 60_000)
            .await
            .unwrap_or_else(|e| panic!("{e:?}"));
        n += got.iter().filter(|d| d.message.action_id == id).count();
        let published: bool = sqlx::query_scalar(
            "SELECT published_at IS NOT NULL FROM kernel.outbox_events WHERE outbox_id = $1",
        )
        .bind(oid)
        .fetch_one(store.pool())
        .await
        .unwrap_or(false);
        if published && n >= 2 {
            republished = true;
            break;
        }
        tokio::time::sleep(Duration::from_millis(250)).await;
    }
    assert!(
        republished,
        "row republished by relay B (deliveries seen: {n})"
    );
    assert_eq!(
        n, 2,
        "at-least-once: duplicate delivery is expected and must be absorbed by the worker"
    );
}
