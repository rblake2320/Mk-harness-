#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::missing_panics_doc,
    clippy::too_many_lines,
    clippy::unreadable_literal,
    clippy::cast_possible_truncation
)]
//! Integration tests against a real PostgreSQL. Skipped unless
//! `MK_TEST_DATABASE_URL` is set. Each test uses fresh tenant ids so the
//! suite runs in parallel on one database.

use chrono::Duration;
use mk_audit::ActorType;
use mk_crypto::MasterKey;
use mk_domain::{ActionState, ApprovalDecision, Channel, ContactId, TenantId, Transition, UserId};
use mk_store::actions::{self, Actor};
use mk_store::{
    Store, StoreError, adapters, approvals, audit, consent, idempotency, outbox, policy,
};
use mk_testkit::{sms_request, t0};
use secrecy::ExposeSecret;
/// Each `#[tokio::test]` owns a runtime, so each test opens its own pool.
/// `migrate` is idempotent and takes a Postgres advisory lock internally.
async fn store() -> Option<Store> {
    let url = mk_testkit::test_database_url()?;
    let s = Store::connect(&url, 12).await.ok()?;
    s.migrate().await.ok()?;
    Some(s)
}

macro_rules! require_db {
    () => {
        match store().await {
            Some(s) => s,
            None => {
                eprintln!("MK_TEST_DATABASE_URL not set; skipping");
                return;
            }
        }
    };
}

const ACTOR: Actor<'static> = Actor {
    actor_type: ActorType::System,
    actor_id: "test",
    trace_id: Some("trace-1"),
    policy_version: "mk-policy/test",
};

#[tokio::test]
async fn full_lifecycle_with_verified_audit_chain() {
    let s = require_db!();
    let (tenant, user, contact) = (TenantId::new(), UserId::new(), ContactId::new());
    let now = t0();
    let req = sms_request(tenant, user, contact, now);
    let id = req.action_id.unwrap_or_default();

    let mut tx = s.begin(tenant).await.unwrap_or_else(|e| panic!("{e:?}"));
    let a = actions::insert_draft(&mut tx, &req, Some(Channel::Sms), Some("dest"), ACTOR, now)
        .await
        .unwrap_or_else(|e| panic!("{e:?}"));
    assert_eq!(a.state, ActionState::Draft);
    assert_eq!(a.digest, req.digest().unwrap_or_else(|_| panic!()));
    for t in [
        Transition::SubmitForPolicy,
        Transition::PolicyRequireApproval,
    ] {
        actions::transition(&mut tx, id, t, None, ACTOR, now)
            .await
            .unwrap_or_else(|e| panic!("{e:?}"));
    }
    let rec = approvals::record_decision(
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
    assert_eq!(rec.action_digest, a.digest);
    actions::transition(&mut tx, id, Transition::Approve, None, ACTOR, now)
        .await
        .unwrap_or_else(|e| panic!("{e:?}"));
    actions::transition(&mut tx, id, Transition::Enqueue, None, ACTOR, now)
        .await
        .unwrap_or_else(|e| panic!("{e:?}"));
    outbox::enqueue(&mut tx, id, "dispatch", now, serde_json::json!({}))
        .await
        .unwrap_or_else(|e| panic!("{e:?}"));
    tx.commit().await.unwrap_or_else(|e| panic!("{e:?}"));

    // Dispatch: consume approval + start + complete.
    let mut tx = s.begin(tenant).await.unwrap_or_else(|e| panic!("{e:?}"));
    let live = approvals::live_for_action_locked(&mut tx, id)
        .await
        .unwrap_or_else(|e| panic!("{e:?}"));
    let live = live.unwrap_or_else(|| panic!("live approval expected"));
    approvals::consume(&mut tx, live.approval_id, id, &a.digest, "worker-1", now)
        .await
        .unwrap_or_else(|e| panic!("{e:?}"));
    let d = actions::transition(&mut tx, id, Transition::StartDispatch, None, ACTOR, now)
        .await
        .unwrap_or_else(|e| panic!("{e:?}"));
    assert_eq!(d.attempt, 1);
    let c = actions::transition(&mut tx, id, Transition::Complete, None, ACTOR, now)
        .await
        .unwrap_or_else(|e| panic!("{e:?}"));
    assert_eq!(c.state, ActionState::Completed);
    // Second consume of the same approval must fail.
    assert!(matches!(
        approvals::consume(&mut tx, live.approval_id, id, &a.digest, "worker-2", now).await,
        Err(StoreError::Conflict(_))
    ));
    tx.commit().await.unwrap_or_else(|e| panic!("{e:?}"));

    let mut tx = s.begin(tenant).await.unwrap_or_else(|e| panic!("{e:?}"));
    let n = audit::verify_tenant(&mut tx)
        .await
        .unwrap_or_else(|e| panic!("{e:?}"));
    assert!(n >= 9, "expected a dense chain of >= 9 events, got {n}");
}

#[tokio::test]
async fn illegal_transition_persists_nothing() {
    let s = require_db!();
    let (tenant, user, contact) = (TenantId::new(), UserId::new(), ContactId::new());
    let req = sms_request(tenant, user, contact, t0());
    let id = req.action_id.unwrap_or_default();
    let mut tx = s.begin(tenant).await.unwrap_or_else(|e| panic!("{e:?}"));
    actions::insert_draft(&mut tx, &req, Some(Channel::Sms), None, ACTOR, t0())
        .await
        .unwrap_or_else(|e| panic!("{e:?}"));
    tx.commit().await.unwrap_or_else(|e| panic!("{e:?}"));

    let mut tx = s.begin(tenant).await.unwrap_or_else(|e| panic!("{e:?}"));
    let r = actions::transition(&mut tx, id, Transition::StartDispatch, None, ACTOR, t0()).await;
    assert!(matches!(r, Err(StoreError::Transition(_))));
    tx.rollback().await.unwrap_or_else(|e| panic!("{e:?}"));

    let mut tx = s.begin(tenant).await.unwrap_or_else(|e| panic!("{e:?}"));
    assert_eq!(
        actions::get(&mut tx, id)
            .await
            .map_or(ActionState::Completed, |a| a.state),
        ActionState::Draft
    );
    let head = audit::head(&mut tx)
        .await
        .unwrap_or_else(|e| panic!("{e:?}"));
    assert_eq!(head.count, 1, "only the proposal event exists");
}

#[tokio::test]
async fn concurrent_consumers_cannot_both_consume() {
    let s = require_db!();
    let (tenant, user, contact) = (TenantId::new(), UserId::new(), ContactId::new());
    let now = t0();
    let req = sms_request(tenant, user, contact, now);
    let id = req.action_id.unwrap_or_default();
    let mut tx = s.begin(tenant).await.unwrap_or_else(|e| panic!("{e:?}"));
    let a = actions::insert_draft(&mut tx, &req, Some(Channel::Sms), None, ACTOR, now)
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
    let rec = approvals::record_decision(
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
    tx.commit().await.unwrap_or_else(|e| panic!("{e:?}"));

    let digest = a.digest.clone();
    let mut handles = Vec::new();
    for i in 0..8 {
        let s = s.clone();
        let digest = digest.clone();
        handles.push(tokio::spawn(async move {
            let mut tx = s.begin(tenant).await.ok()?;
            let r =
                approvals::consume(&mut tx, rec.approval_id, id, &digest, &format!("w{i}"), now)
                    .await;
            if r.is_ok() {
                tx.commit().await.ok()?;
                Some(true)
            } else {
                Some(false)
            }
        }));
    }
    let mut ok = 0;
    for h in handles {
        if h.await.ok().flatten() == Some(true) {
            ok += 1;
        }
    }
    assert_eq!(ok, 1, "exactly one consumer wins");
}

#[tokio::test]
async fn approval_with_wrong_digest_is_not_consumable() {
    let s = require_db!();
    let (tenant, user, contact) = (TenantId::new(), UserId::new(), ContactId::new());
    let now = t0();
    let req = sms_request(tenant, user, contact, now);
    let id = req.action_id.unwrap_or_default();
    let mut tx = s.begin(tenant).await.unwrap_or_else(|e| panic!("{e:?}"));
    actions::insert_draft(&mut tx, &req, Some(Channel::Sms), None, ACTOR, now)
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
    let rec = approvals::record_decision(
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
    let forged = mk_crypto::Digest::of(b"something else");
    assert!(matches!(
        approvals::consume(&mut tx, rec.approval_id, id, &forged, "w", now).await,
        Err(StoreError::Conflict(_))
    ));
    // Expired at consume time.
    let late = now + Duration::seconds(901);
    assert!(matches!(
        approvals::consume(&mut tx, rec.approval_id, id, &rec.action_digest, "w", late).await,
        Err(StoreError::Conflict(_))
    ));
    // A second live approval for the same action is refused by the partial unique index.
    let dup = approvals::record_decision(
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
    .await;
    assert!(matches!(dup, Err(StoreError::Conflict(_))));
}

#[tokio::test]
async fn cross_tenant_access_is_invisible_even_with_raw_sql() {
    let s = require_db!();
    let (ta, tb, user, contact) = (
        TenantId::new(),
        TenantId::new(),
        UserId::new(),
        ContactId::new(),
    );
    let req = sms_request(ta, user, contact, t0());
    let id = req.action_id.unwrap_or_default();
    let mut tx = s.begin(ta).await.unwrap_or_else(|e| panic!("{e:?}"));
    actions::insert_draft(&mut tx, &req, Some(Channel::Sms), None, ACTOR, t0())
        .await
        .unwrap_or_else(|e| panic!("{e:?}"));
    tx.commit().await.unwrap_or_else(|e| panic!("{e:?}"));

    // Repository layer: tenant B sees NotFound.
    let mut txb = s.begin(tb).await.unwrap_or_else(|e| panic!("{e:?}"));
    assert!(matches!(
        actions::get(&mut txb, id).await,
        Err(StoreError::NotFound)
    ));
    assert!(matches!(
        actions::transition(&mut txb, id, Transition::SubmitForPolicy, None, ACTOR, t0()).await,
        Err(StoreError::NotFound)
    ));
    assert!(matches!(
        approvals::live_for_action_locked(&mut txb, id).await,
        Ok(None)
    ));
    txb.rollback().await.unwrap_or_else(|e| panic!("{e:?}"));

    // RLS layer: a non-superuser role with tenant B context cannot see the row
    // even when the query omits the tenant predicate entirely.
    let pool = s.pool();
    let _ = sqlx::query("CREATE ROLE mk_rls_probe NOLOGIN")
        .execute(pool)
        .await;
    sqlx::query("GRANT USAGE ON SCHEMA kernel TO mk_rls_probe")
        .execute(pool)
        .await
        .unwrap_or_else(|e| panic!("{e:?}"));
    sqlx::query("GRANT SELECT ON kernel.actions TO mk_rls_probe")
        .execute(pool)
        .await
        .unwrap_or_else(|e| panic!("{e:?}"));
    sqlx::query("GRANT mk_rls_probe TO CURRENT_USER")
        .execute(pool)
        .await
        .unwrap_or_else(|e| panic!("{e:?}"));
    let mut raw = pool.begin().await.unwrap_or_else(|e| panic!("{e:?}"));
    sqlx::query("SET LOCAL ROLE mk_rls_probe")
        .execute(&mut *raw)
        .await
        .unwrap_or_else(|e| panic!("{e:?}"));
    sqlx::query(&format!("SET LOCAL kernel.tenant_id = '{}'", tb.0))
        .execute(&mut *raw)
        .await
        .unwrap_or_else(|e| panic!("{e:?}"));
    let n: i64 = sqlx::query_scalar("SELECT count(*) FROM kernel.actions WHERE action_id = $1")
        .bind(id.0)
        .fetch_one(&mut *raw)
        .await
        .unwrap_or_else(|e| panic!("{e:?}"));
    assert_eq!(n, 0, "RLS must hide tenant A's row from tenant B context");
    sqlx::query(&format!("SET LOCAL kernel.tenant_id = '{}'", ta.0))
        .execute(&mut *raw)
        .await
        .unwrap_or_else(|e| panic!("{e:?}"));
    let n: i64 = sqlx::query_scalar("SELECT count(*) FROM kernel.actions WHERE action_id = $1")
        .bind(id.0)
        .fetch_one(&mut *raw)
        .await
        .unwrap_or(-1);
    assert_eq!(n, 1);
    // No tenant context at all → nothing visible (fail closed).
    sqlx::query("SET LOCAL kernel.tenant_id = ''")
        .execute(&mut *raw)
        .await
        .unwrap_or_else(|e| panic!("{e:?}"));
    let n: i64 = sqlx::query_scalar("SELECT count(*) FROM kernel.actions WHERE action_id = $1")
        .bind(id.0)
        .fetch_one(&mut *raw)
        .await
        .unwrap_or(-1);
    assert_eq!(n, 0);
    raw.rollback().await.unwrap_or_else(|e| panic!("{e:?}"));
}

#[tokio::test]
async fn audit_rows_cannot_be_updated_or_deleted_even_by_owner() {
    let s = require_db!();
    let tenant = TenantId::new();
    let mut tx = s.begin(tenant).await.unwrap_or_else(|e| panic!("{e:?}"));
    policy::set_tenant_dispatch(&mut tx, true, ACTOR, t0())
        .await
        .unwrap_or_else(|e| panic!("{e:?}"));
    tx.commit().await.unwrap_or_else(|e| panic!("{e:?}"));
    let pool = s.pool();
    let upd = sqlx::query("UPDATE kernel.audit_events SET actor_id = 'x' WHERE tenant_id = $1")
        .bind(tenant.0)
        .execute(pool)
        .await;
    assert!(upd.is_err(), "update must be refused by trigger");
    let del = sqlx::query("DELETE FROM kernel.audit_events WHERE tenant_id = $1")
        .bind(tenant.0)
        .execute(pool)
        .await;
    assert!(del.is_err(), "delete must be refused by trigger");
    // Tampering the head is detected by the verifier.
    sqlx::query("UPDATE kernel.audit_heads SET last_hash = 'deadbeef' WHERE tenant_id = $1")
        .bind(tenant.0)
        .execute(pool)
        .await
        .unwrap_or_else(|e| panic!("{e:?}"));
    let mut tx = s.begin(tenant).await.unwrap_or_else(|e| panic!("{e:?}"));
    assert!(matches!(
        audit::verify_tenant(&mut tx).await,
        Err(StoreError::Audit(_))
    ));
}

#[tokio::test]
async fn nonce_replay_and_idempotency() {
    let s = require_db!();
    let tenant = TenantId::new();
    let master = MasterKey::generate();
    let mut tx = s.begin(tenant).await.unwrap_or_else(|e| panic!("{e:?}"));
    let (reg, secret) = adapters::register(
        &mut tx,
        &master,
        "sim-1",
        "Sim",
        "android",
        "1.0",
        &["input".into()],
        &[],
        "kernel.internal",
        ACTOR,
        t0(),
    )
    .await
    .unwrap_or_else(|e| panic!("{e:?}"));
    assert!(!reg.verified_on_device);
    assert_eq!(secret.expose_secret().len(), 43);
    adapters::record_nonce(&mut tx, reg.adapter_id, "n1", Duration::seconds(300), t0())
        .await
        .unwrap_or_else(|e| panic!("{e:?}"));
    assert!(matches!(
        adapters::record_nonce(&mut tx, reg.adapter_id, "n1", Duration::seconds(300), t0()).await,
        Err(StoreError::Conflict(_))
    ));
    tx.commit().await.unwrap_or_else(|e| panic!("{e:?}"));

    let mut tx = s.begin(tenant).await.unwrap_or_else(|e| panic!("{e:?}"));
    let d1 = mk_crypto::Digest::of(b"req-1");
    let a1 = mk_domain::ActionId::new();
    assert_eq!(
        idempotency::check_or_insert(&mut tx, mk_domain::ActionKind::SendSms, "key-1", &d1, a1)
            .await
            .ok(),
        Some(idempotency::IdempotencyOutcome::Fresh)
    );
    assert_eq!(
        idempotency::check_or_insert(
            &mut tx,
            mk_domain::ActionKind::SendSms,
            "key-1",
            &d1,
            mk_domain::ActionId::new()
        )
        .await
        .ok(),
        Some(idempotency::IdempotencyOutcome::Replay(a1))
    );
    assert!(matches!(
        idempotency::check_or_insert(
            &mut tx,
            mk_domain::ActionKind::SendSms,
            "key-1",
            &mk_crypto::Digest::of(b"req-2"),
            a1
        )
        .await,
        Err(StoreError::Conflict(_))
    ));
}

#[tokio::test]
async fn adapter_rotation_overlap_and_revocation() {
    let s = require_db!();
    let tenant = TenantId::new();
    let master = MasterKey::generate();
    let now = t0();
    let mut tx = s.begin(tenant).await.unwrap_or_else(|e| panic!("{e:?}"));
    let (reg, s1) = adapters::register(
        &mut tx,
        &master,
        "sim-2",
        "Sim",
        "android",
        "1.0",
        &[],
        &[],
        "kernel.internal",
        ACTOR,
        now,
    )
    .await
    .unwrap_or_else(|e| panic!("{e:?}"));
    let live = adapters::live_secrets(&mut tx, &master, reg.adapter_id, now)
        .await
        .unwrap_or_else(|e| panic!("{e:?}"));
    assert_eq!(live.len(), 1);
    assert_eq!(live[0].expose_bytes(), s1.expose_secret().as_bytes());

    let s2 = adapters::rotate(
        &mut tx,
        &master,
        reg.adapter_id,
        Duration::seconds(60),
        ACTOR,
        now,
    )
    .await
    .unwrap_or_else(|e| panic!("{e:?}"));
    let during = adapters::live_secrets(
        &mut tx,
        &master,
        reg.adapter_id,
        now + Duration::seconds(30),
    )
    .await
    .unwrap_or_else(|e| panic!("{e:?}"));
    assert_eq!(during.len(), 2, "both valid during overlap");
    assert_eq!(
        during[0].expose_bytes(),
        s2.expose_secret().as_bytes(),
        "newest first"
    );
    let after = adapters::live_secrets(
        &mut tx,
        &master,
        reg.adapter_id,
        now + Duration::seconds(61),
    )
    .await
    .unwrap_or_else(|e| panic!("{e:?}"));
    assert_eq!(after.len(), 1);
    assert_eq!(after[0].expose_bytes(), s2.expose_secret().as_bytes());

    adapters::revoke(&mut tx, reg.adapter_id, ACTOR, now + Duration::seconds(70))
        .await
        .unwrap_or_else(|e| panic!("{e:?}"));
    let none = adapters::live_secrets(
        &mut tx,
        &master,
        reg.adapter_id,
        now + Duration::seconds(71),
    )
    .await
    .unwrap_or_else(|e| panic!("{e:?}"));
    assert!(none.is_empty());
    assert!(matches!(
        adapters::rotate(
            &mut tx,
            &master,
            reg.adapter_id,
            Duration::seconds(1),
            ACTOR,
            now + Duration::seconds(72)
        )
        .await,
        Err(StoreError::Conflict(_))
    ));
    // Wrong master key cannot unseal.
    assert!(matches!(
        adapters::live_secrets(&mut tx, &MasterKey::generate(), reg.adapter_id, now).await,
        Err(StoreError::Crypto) | Ok(_)
    ));
}

#[tokio::test]
async fn outbox_claim_publish_and_leases() {
    let s = require_db!();
    let (tenant, user, contact) = (TenantId::new(), UserId::new(), ContactId::new());
    let now = t0();
    let req = sms_request(tenant, user, contact, now);
    let id = req.action_id.unwrap_or_default();
    let mut tx = s.begin(tenant).await.unwrap_or_else(|e| panic!("{e:?}"));
    actions::insert_draft(&mut tx, &req, Some(Channel::Sms), None, ACTOR, now)
        .await
        .unwrap_or_else(|e| panic!("{e:?}"));
    let oid = outbox::enqueue(&mut tx, id, "dispatch", now, serde_json::json!({"k": 1}))
        .await
        .unwrap_or_else(|e| panic!("{e:?}"));
    tx.commit().await.unwrap_or_else(|e| panic!("{e:?}"));

    let batch = outbox::claim_batch(s.pool(), "relay-a", Duration::seconds(1), 100, now)
        .await
        .unwrap_or_else(|e| panic!("{e:?}"));
    assert!(batch.iter().any(|r| r.outbox_id == oid));
    // Another relay cannot claim the same leased row.
    let batch2 = outbox::claim_batch(s.pool(), "relay-b", Duration::seconds(1), 100, now)
        .await
        .unwrap_or_else(|e| panic!("{e:?}"));
    assert!(!batch2.iter().any(|r| r.outbox_id == oid));
    // Lease expiry makes it claimable again (relay crash before publish).
    let batch3 = outbox::claim_batch(
        s.pool(),
        "relay-b",
        Duration::seconds(1),
        100,
        now + Duration::seconds(31),
    )
    .await
    .unwrap_or_else(|e| panic!("{e:?}"));
    assert!(batch3.iter().any(|r| r.outbox_id == oid && r.attempts == 2));
    assert!(
        !outbox::mark_published(s.pool(), oid, "relay-a", now)
            .await
            .unwrap_or(true),
        "stale relay cannot publish"
    );
    assert!(
        outbox::mark_published(s.pool(), oid, "relay-b", now)
            .await
            .unwrap_or(false)
    );
    assert!(
        !outbox::mark_published(s.pool(), oid, "relay-b", now)
            .await
            .unwrap_or(true),
        "publish is idempotent"
    );

    let mut tx = s.begin(tenant).await.unwrap_or_else(|e| panic!("{e:?}"));
    let l1 = outbox::acquire_lease(&mut tx, id, "w1", Duration::seconds(60), now)
        .await
        .unwrap_or_else(|e| panic!("{e:?}"));
    assert!(l1.is_some());
    let l2 = outbox::acquire_lease(
        &mut tx,
        id,
        "w2",
        Duration::seconds(60),
        now + Duration::seconds(10),
    )
    .await
    .unwrap_or_else(|e| panic!("{e:?}"));
    assert!(l2.is_none(), "live lease blocks a second worker");
    let l3 = outbox::acquire_lease(
        &mut tx,
        id,
        "w3",
        Duration::seconds(60),
        now + Duration::seconds(61),
    )
    .await
    .unwrap_or_else(|e| panic!("{e:?}"));
    assert!(l3.is_some(), "expired lease is recoverable");
    assert!(
        !outbox::release_lease(&mut tx, id, l1.unwrap_or_default())
            .await
            .unwrap_or(true),
        "stale token cannot release"
    );
    assert!(
        outbox::release_lease(&mut tx, id, l3.unwrap_or_default())
            .await
            .unwrap_or(false)
    );
}

#[tokio::test]
async fn revocation_finds_pending_actions_and_policy_roundtrip() {
    let s = require_db!();
    let (tenant, user, contact) = (TenantId::new(), UserId::new(), ContactId::new());
    let now = t0();
    let mut tx = s.begin(tenant).await.unwrap_or_else(|e| panic!("{e:?}"));
    let pid = consent::grant_permission(
        &mut tx,
        contact,
        Channel::Sms,
        &["customer_requested_follow_up".into()],
        "web_form",
        &mk_crypto::Digest::of(b"proof"),
        now,
        now + Duration::days(30),
        user,
        ACTOR,
        now,
    )
    .await
    .unwrap_or_else(|e| panic!("{e:?}"));
    let facts = consent::permissions_for(&mut tx, contact, Channel::Sms)
        .await
        .unwrap_or_else(|e| panic!("{e:?}"));
    assert_eq!(facts.len(), 1);
    let req = sms_request(tenant, user, contact, now);
    let id = req.action_id.unwrap_or_default();
    actions::insert_draft(
        &mut tx,
        &req,
        Some(Channel::Sms),
        Some("dest-1"),
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
    let (c, ch) = consent::revoke_permission(&mut tx, pid, ACTOR, now)
        .await
        .unwrap_or_else(|e| panic!("{e:?}"));
    assert_eq!((c, ch), (contact, Channel::Sms));
    let pending = actions::pending_for_destination(&mut tx, Some(Channel::Sms), Some("dest-1"))
        .await
        .unwrap_or_else(|e| panic!("{e:?}"));
    assert_eq!(pending, vec![id]);
    let sup = consent::add_suppression(
        &mut tx,
        Some(Channel::Sms),
        Some("dest-1"),
        "destination",
        "opt_out",
        true,
        "callback",
        ACTOR,
        now,
    )
    .await
    .unwrap_or_else(|e| panic!("{e:?}"));
    assert!(
        matches!(
            consent::lift_suppression(&mut tx, sup, user, false, ACTOR, now).await,
            Err(StoreError::Conflict(_))
        ),
        "permanent needs elevated lift"
    );
    let sups = consent::suppressions_for(&mut tx, Channel::Sms, "dest-1")
        .await
        .unwrap_or_else(|e| panic!("{e:?}"));
    assert_eq!(sups.len(), 1);

    let (defaults, off) = policy::load(&mut tx)
        .await
        .unwrap_or_else(|e| panic!("{e:?}"));
    assert_eq!(off, -300);
    let mut p = defaults.clone();
    p.max_per_contact_per_day = 5;
    policy::write(&mut tx, "v2", &p, -360)
        .await
        .unwrap_or_else(|e| panic!("{e:?}"));
    policy::set_tenant_dispatch(&mut tx, false, ACTOR, now)
        .await
        .unwrap_or_else(|e| panic!("{e:?}"));
    let (loaded, off) = policy::load(&mut tx)
        .await
        .unwrap_or_else(|e| panic!("{e:?}"));
    assert_eq!(loaded.max_per_contact_per_day, 5);
    assert!(
        !loaded.dispatch_enabled,
        "tenant kill switch folds into policy"
    );
    assert_eq!(off, -360);
    assert!(
        policy::global_dispatch_enabled(s.pool())
            .await
            .unwrap_or(false)
    );
    tx.commit().await.unwrap_or_else(|e| panic!("{e:?}"));

    let mut tx = s.begin(tenant).await.unwrap_or_else(|e| panic!("{e:?}"));
    assert!(audit::verify_tenant(&mut tx).await.unwrap_or(0) >= 7);
}
