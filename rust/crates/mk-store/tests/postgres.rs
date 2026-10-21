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

/// `GRANT role TO CURRENT_USER`, tolerant of a concurrent test doing the same
/// (nextest runs tests in separate processes; two simultaneous grants of one
/// membership can race on pg_auth_members). Membership is asserted afterwards.
async fn ensure_member<'e, E>(exec: E, role: &str)
where
    E: sqlx::PgExecutor<'e> + Copy,
{
    let _ = sqlx::query(sqlx::AssertSqlSafe(format!("GRANT {role} TO CURRENT_USER")))
        .execute(exec)
        .await;
    let ok: bool = sqlx::query_scalar("SELECT pg_has_role(current_user, $1, 'MEMBER')")
        .bind(role)
        .fetch_one(exec)
        .await
        .unwrap_or(false);
    assert!(ok, "current user must be a member of {role}");
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
    let a = actions::insert_draft(
        &mut tx,
        &req,
        Some(Channel::Sms),
        Some(&mk_store::fingerprint::Fingerprints::legacy("dest")),
        ACTOR,
        now,
    )
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
        mk_store::approvals::HumanBinding::Unbound,
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
        mk_store::approvals::HumanBinding::Unbound,
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
        mk_store::approvals::HumanBinding::Unbound,
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
        mk_store::approvals::HumanBinding::Unbound,
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
    ensure_member(pool, "mk_rls_probe").await;
    let mut raw = pool.begin().await.unwrap_or_else(|e| panic!("{e:?}"));
    sqlx::query("SET LOCAL ROLE mk_rls_probe")
        .execute(&mut *raw)
        .await
        .unwrap_or_else(|e| panic!("{e:?}"));
    sqlx::query(sqlx::AssertSqlSafe(format!(
        "SET LOCAL kernel.tenant_id = '{}'",
        tb.0
    )))
    .execute(&mut *raw)
    .await
    .unwrap_or_else(|e| panic!("{e:?}"));
    let n: i64 = sqlx::query_scalar("SELECT count(*) FROM kernel.actions WHERE action_id = $1")
        .bind(id.0)
        .fetch_one(&mut *raw)
        .await
        .unwrap_or_else(|e| panic!("{e:?}"));
    assert_eq!(n, 0, "RLS must hide tenant A's row from tenant B context");
    sqlx::query(sqlx::AssertSqlSafe(format!(
        "SET LOCAL kernel.tenant_id = '{}'",
        ta.0
    )))
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
    let master = mk_crypto::Keyring::legacy(&MasterKey::generate());
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
    let master = mk_crypto::Keyring::legacy(&MasterKey::generate());
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
        adapters::live_secrets(
            &mut tx,
            &mk_crypto::Keyring::legacy(&MasterKey::generate()),
            reg.adapter_id,
            now
        )
        .await,
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
        &mk_store::fingerprint::Fingerprints::legacy("dest"),
        None,
        ACTOR,
        now,
    )
    .await
    .unwrap_or_else(|e| panic!("{e:?}"));
    let facts = consent::permissions_for(&mut tx, contact, Channel::Sms, None)
        .await
        .unwrap_or_else(|e| panic!("{e:?}"));
    assert_eq!(facts.len(), 1);
    let req = sms_request(tenant, user, contact, now);
    let id = req.action_id.unwrap_or_default();
    actions::insert_draft(
        &mut tx,
        &req,
        Some(Channel::Sms),
        Some(&mk_store::fingerprint::Fingerprints::legacy("dest-1")),
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
    let pending = actions::pending_for_destination(
        &mut tx,
        Some(Channel::Sms),
        Some(&mk_store::fingerprint::Fingerprints::legacy("dest-1")),
    )
    .await
    .unwrap_or_else(|e| panic!("{e:?}"));
    assert_eq!(pending, vec![id]);
    let sup = consent::add_suppression(
        &mut tx,
        Some(Channel::Sms),
        Some(&mk_store::fingerprint::Fingerprints::legacy("dest-1")),
        None,
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
    let sups = consent::suppressions_for(
        &mut tx,
        Channel::Sms,
        &mk_store::fingerprint::Fingerprints::legacy("dest-1"),
    )
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

/// Every statement the API's callback handler runs must be permitted for the
/// API role; the e2e suites run as superuser and would not notice a missing
/// grant.
#[tokio::test]
async fn api_role_can_run_every_callback_statement() {
    let s = require_db!();
    let needed = [
        ("kernel.actions", "UPDATE"),
        ("kernel.action_attempts", "UPDATE"),
        ("kernel.execution_leases", "DELETE"),
        ("kernel.dead_letters", "INSERT"),
        ("kernel.adapter_nonces", "INSERT"),
        ("kernel.adapter_callbacks", "INSERT"),
        ("kernel.audit_events", "INSERT"),
        ("kernel.audit_heads", "UPDATE"),
        ("kernel.adapter_registrations", "UPDATE"),
    ];
    for (table, privilege) in needed {
        let ok: bool = sqlx::query_scalar("SELECT has_table_privilege('mk_kernel_api', $1, $2)")
            .bind(table)
            .bind(privilege)
            .fetch_one(s.pool())
            .await
            .unwrap_or(false);
        assert!(ok, "mk_kernel_api lacks {privilege} on {table}");
    }
    // And the runtime roles can never rewrite audit history.
    for role in [
        "mk_kernel_api",
        "mk_kernel_worker",
        "mk_kernel_relay",
        "mk_kernel_readonly",
    ] {
        for privilege in ["UPDATE", "DELETE", "TRUNCATE"] {
            let ok: bool =
                sqlx::query_scalar("SELECT has_table_privilege($1, 'kernel.audit_events', $2)")
                    .bind(role)
                    .bind(privilege)
                    .fetch_one(s.pool())
                    .await
                    .unwrap_or(true);
            assert!(!ok, "{role} must not have {privilege} on audit_events");
        }
    }
}

#[tokio::test]
async fn assertion_jti_is_single_use_across_pools_and_purgeable() {
    use mk_store::assertions::{JtiOutcome, consume_jti, purge_jtis};
    let s = require_db!();
    // A second, independent pool stands in for a second API replica.
    let s2 = store().await.unwrap_or_else(|| panic!("db"));
    let (jti, tenant, sub) = (
        uuid::Uuid::now_v7(),
        uuid::Uuid::now_v7(),
        uuid::Uuid::now_v7(),
    );
    let exp = chrono::Utc::now() + Duration::seconds(65);
    assert_eq!(
        consume_jti(s.pool(), jti, tenant, sub, exp).await.unwrap(),
        JtiOutcome::Fresh
    );
    // Replica B sees replica A's consumption.
    assert_eq!(
        consume_jti(s2.pool(), jti, tenant, sub, exp).await.unwrap(),
        JtiOutcome::Replayed
    );
    // Even a different tenant cannot reuse the same jti.
    assert_eq!(
        consume_jti(s2.pool(), jti, uuid::Uuid::now_v7(), sub, exp)
            .await
            .unwrap(),
        JtiOutcome::Replayed
    );
    // Concurrent first use from both pools: exactly one wins.
    let j2 = uuid::Uuid::now_v7();
    let (a, b) = tokio::join!(
        consume_jti(s.pool(), j2, tenant, sub, exp),
        consume_jti(s2.pool(), j2, tenant, sub, exp)
    );
    let outcomes = [a.unwrap(), b.unwrap()];
    assert_eq!(
        outcomes.iter().filter(|o| **o == JtiOutcome::Fresh).count(),
        1
    );
    // Purge removes only expired rows; the live one stays single-use.
    let stale = uuid::Uuid::now_v7();
    consume_jti(
        s.pool(),
        stale,
        tenant,
        sub,
        chrono::Utc::now() - Duration::seconds(1),
    )
    .await
    .unwrap();
    assert!(purge_jtis(s.pool(), chrono::Utc::now()).await.unwrap() >= 1);
    assert_eq!(
        consume_jti(s.pool(), jti, tenant, sub, exp).await.unwrap(),
        JtiOutcome::Replayed
    );
    assert_eq!(
        consume_jti(s.pool(), stale, tenant, sub, exp)
            .await
            .unwrap(),
        JtiOutcome::Fresh,
        "purged jti row is gone (its assertion is already unverifiable)"
    );
}

#[tokio::test]
async fn api_role_cannot_delete_or_update_jti_rows() {
    use mk_store::assertions::consume_jti;
    let s = require_db!();
    let (jti, tenant, sub) = (
        uuid::Uuid::now_v7(),
        uuid::Uuid::now_v7(),
        uuid::Uuid::now_v7(),
    );
    consume_jti(
        s.pool(),
        jti,
        tenant,
        sub,
        chrono::Utc::now() + Duration::seconds(60),
    )
    .await
    .unwrap();
    ensure_member(s.pool(), "mk_kernel_api").await;
    let mut conn = s.pool().acquire().await.unwrap();
    sqlx::query("BEGIN").execute(&mut *conn).await.unwrap();
    sqlx::query("SET LOCAL ROLE mk_kernel_api")
        .execute(&mut *conn)
        .await
        .unwrap();
    let del = sqlx::query("DELETE FROM kernel.assertion_jtis WHERE jti = $1")
        .bind(jti)
        .execute(&mut *conn)
        .await;
    assert!(del.is_err(), "api role must not delete jti evidence");
    sqlx::query("ROLLBACK").execute(&mut *conn).await.unwrap();
    sqlx::query("BEGIN").execute(&mut *conn).await.unwrap();
    sqlx::query("SET LOCAL ROLE mk_kernel_api")
        .execute(&mut *conn)
        .await
        .unwrap();
    let upd = sqlx::query("UPDATE kernel.assertion_jtis SET expires_at = now() WHERE jti = $1")
        .bind(jti)
        .execute(&mut *conn)
        .await;
    assert!(upd.is_err(), "api role must not edit jti evidence");
    sqlx::query("ROLLBACK").execute(&mut *conn).await.unwrap();
}

#[tokio::test]
async fn tenant_kill_switch_applies_without_policy_row() {
    // Found by the live smoke: a tenant on default policy (no
    // policy_versions row) had its kill switch silently ignored.
    let s = require_db!();
    let tenant = TenantId::new();
    let mut tx = s.begin(tenant).await.unwrap();
    let (p, _) = policy::load(&mut tx).await.unwrap();
    assert!(p.dispatch_enabled, "defaults start enabled");
    policy::set_tenant_dispatch(&mut tx, false, ACTOR, t0())
        .await
        .unwrap();
    let (p, _) = policy::load(&mut tx).await.unwrap();
    assert!(
        !p.dispatch_enabled,
        "kill switch must apply with no policy row"
    );
    policy::set_tenant_dispatch(&mut tx, true, ACTOR, t0())
        .await
        .unwrap();
    let (p, _) = policy::load(&mut tx).await.unwrap();
    assert!(p.dispatch_enabled);
    tx.commit().await.unwrap();
}

/// A pool whose every connection runs as the given NOLOGIN privilege role,
/// so the production functions are exercised under the production identity
/// (RLS enforced), not as the test superuser.
async fn role_pool(url: &str, role: &'static str) -> sqlx::PgPool {
    let admin = sqlx::PgPool::connect(url).await.unwrap();
    ensure_member(&admin, role).await;
    sqlx::postgres::PgPoolOptions::new()
        .max_connections(4)
        .after_connect(move |conn, _| {
            Box::pin(async move {
                sqlx::query(sqlx::AssertSqlSafe(format!("SET ROLE {role}")))
                    .execute(conn)
                    .await?;
                Ok(())
            })
        })
        .connect(url)
        .await
        .unwrap()
}

#[tokio::test]
async fn worker_role_can_discover_tenants_and_purge_nonces_across_tenants() {
    // Codex finding on PR #31: under mk_kernel_worker, tenant discovery and
    // the nonce purge saw zero rows. Exercise the real functions as that role.
    let s = require_db!();
    let url = mk_testkit::test_database_url().unwrap();
    let master = mk_crypto::Keyring::legacy(&MasterKey::generate());
    let tenants = [TenantId::new(), TenantId::new()];
    let now = t0();
    for t in tenants {
        let mut tx = s.begin(t).await.unwrap();
        // Any audited write creates the tenant's audit head.
        policy::set_tenant_dispatch(&mut tx, true, ACTOR, now)
            .await
            .unwrap();
        let (reg, _) = adapters::register(
            &mut tx,
            &master,
            "agent-x",
            "X",
            "android",
            "1",
            &["open".into()],
            &[],
            "kernel.internal",
            ACTOR,
            now,
        )
        .await
        .unwrap();
        // retain = window after `now` the nonce stays unusable; an expired
        // one is recorded as seen an hour ago with a 1 s window.
        adapters::record_nonce(
            &mut tx,
            reg.adapter_id,
            "expired-nonce",
            Duration::seconds(1),
            now - Duration::hours(1),
        )
        .await
        .unwrap();
        adapters::record_nonce(
            &mut tx,
            reg.adapter_id,
            "live-nonce",
            Duration::hours(1),
            now,
        )
        .await
        .unwrap();
        tx.commit().await.unwrap();
    }
    let worker = role_pool(&url, "mk_kernel_worker").await;
    let seen = audit::all_tenants(&worker).await.unwrap();
    for t in tenants {
        assert!(seen.contains(&t), "worker must discover every tenant");
    }
    let purged = adapters::purge_nonces(&worker, now).await.unwrap();
    assert!(
        purged >= 2,
        "worker must purge expired nonces in every tenant, purged={purged}"
    );
    // Live nonces untouched: a replay of the live nonce is still a conflict.
    for t in tenants {
        let mut tx = s.begin(t).await.unwrap();
        let reg = adapters::get_by_agent(&mut tx, "agent-x").await.unwrap();
        let again = adapters::record_nonce(
            &mut tx,
            reg.adapter_id,
            "live-nonce",
            Duration::hours(1),
            now,
        )
        .await;
        assert!(
            matches!(again, Err(StoreError::Conflict(_))),
            "live nonce must survive purge"
        );
        tx.rollback().await.unwrap();
    }
    // The worker can see expired leases across tenants too (existing policy).
    let _ = outbox::expired_leases(&worker, now, 10).await.unwrap();
    // But it cannot write audit heads for a tenant it is not inside.
    let bad = sqlx::query(
        "INSERT INTO kernel.audit_heads (tenant_id, last_hash, count) VALUES ($1, 'x', 0)",
    )
    .bind(uuid::Uuid::now_v7())
    .execute(&worker)
    .await;
    assert!(bad.is_err(), "discovery policy must be SELECT-only");
}

/// S6/S10 rotation drill: legacy-sealed rows → new KEK-wrapped version →
/// re-encrypt → retire refused while rows remain → retire → legacy retired.
/// Also: a keyring without a version cannot read its rows (loud, not silent),
/// and runtime logins cannot mint or retire keys.
#[tokio::test]
async fn envelope_key_rotation_drill() {
    use mk_crypto::{EnvKek, Keyring, LEGACY_VERSION};
    use mk_store::keys;
    let s = require_db!();
    // Isolated key table state: this test owns kernel.key_versions for its duration.
    sqlx::query("DELETE FROM kernel.key_versions")
        .execute(s.pool())
        .await
        .unwrap_or_else(|e| panic!("{e:?}"));
    let tenant = TenantId::new();
    let master = MasterKey::generate();
    let legacy = Keyring::legacy(&master);
    let now = t0();
    // Seal one adapter credential under the legacy key.
    let mut tx = s.begin(tenant).await.unwrap_or_else(|e| panic!("{e:?}"));
    let (reg, secret) = adapters::register(
        &mut tx,
        &legacy,
        "sim-k",
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
    tx.commit().await.unwrap_or_else(|e| panic!("{e:?}"));
    // No key rows → keyring is legacy only.
    let ring0 = keys::load_keyring(s.pool(), None, &master, true)
        .await
        .unwrap_or_else(|e| panic!("{e:?}"));
    assert_eq!(ring0.versions(), vec![LEGACY_VERSION]);

    // Rotate under a KEK: version 1 active; legacy rows still readable.
    let kek = EnvKek::new("kek-test", &[3u8; 32]).unwrap_or_else(|e| panic!("{e:?}"));
    let v1 = keys::rotate(s.pool(), &kek, "drill", "initial envelope key")
        .await
        .unwrap_or_else(|e| panic!("{e:?}"));
    assert_eq!(v1, 1);
    assert!(
        keys::load_keyring(s.pool(), None, &master, true)
            .await
            .is_err(),
        "versions exist but no KEK → refuse to start"
    );
    let wrong = EnvKek::new("kek-test", &[4u8; 32]).unwrap_or_else(|e| panic!("{e:?}"));
    assert!(
        keys::load_keyring(s.pool(), Some(&wrong), &master, true)
            .await
            .is_err(),
        "wrong KEK material → refuse"
    );
    let ring1 = keys::load_keyring(s.pool(), Some(&kek), &master, true)
        .await
        .unwrap_or_else(|e| panic!("{e:?}"));
    assert_eq!(ring1.current_version(), 1);
    assert_eq!(ring1.versions(), vec![0, 1]);
    let mut tx = s.begin(tenant).await.unwrap_or_else(|e| panic!("{e:?}"));
    let live = adapters::live_secrets(&mut tx, &ring1, reg.adapter_id, now)
        .await
        .unwrap_or_else(|e| panic!("{e:?}"));
    assert_eq!(
        live[0].expose_bytes(),
        secret.expose_secret().as_bytes(),
        "legacy row readable through the new ring"
    );
    drop(tx);
    // Stale rows reported; retiring legacy is impossible (it has no row) but retiring v... let's rotate again to exercise retire.
    // Scoped to this test's tenant: other tests seal rows under their own random keys,
    // which the operator path reports as `unreadable` rather than aborting on.
    let stale = keys::stale_counts(s.pool(), &ring1, Some(tenant))
        .await
        .unwrap_or_else(|e| panic!("{e:?}"));
    assert!(
        stale
            .iter()
            .any(|(t, n)| t.starts_with("kernel.adapter_credentials.") && *n >= 1)
    );
    let rep = keys::reencrypt(s.pool(), &ring1, Some(tenant))
        .await
        .unwrap_or_else(|e| panic!("{e:?}"));
    assert!(rep.resealed >= 1 && rep.unreadable == 0, "{rep:?}");
    let stale = keys::stale_counts(s.pool(), &ring1, Some(tenant))
        .await
        .unwrap_or_else(|e| panic!("{e:?}"));
    assert!(stale.iter().all(|(_, n)| *n == 0), "{stale:?}");
    // Across all tenants, foreign-key rows are reported, not destroyed.
    let all = keys::reencrypt(s.pool(), &ring1, None)
        .await
        .unwrap_or_else(|e| panic!("{e:?}"));
    assert_eq!(all.resealed, 0);
    // Now the legacy key can be dropped from the ring and rows still read.
    let ring1_only = keys::load_keyring(s.pool(), Some(&kek), &master, false)
        .await
        .unwrap_or_else(|e| panic!("{e:?}"));
    assert_eq!(ring1_only.versions(), vec![1]);
    let mut tx = s.begin(tenant).await.unwrap_or_else(|e| panic!("{e:?}"));
    let live = adapters::live_secrets(&mut tx, &ring1_only, reg.adapter_id, now)
        .await
        .unwrap_or_else(|e| panic!("{e:?}"));
    assert_eq!(live[0].expose_bytes(), secret.expose_secret().as_bytes());
    // A fresh credential is sealed under v1 (not legacy).
    let s2 = adapters::rotate(
        &mut tx,
        &ring1_only,
        reg.adapter_id,
        Duration::hours(1),
        ACTOR,
        now,
    )
    .await
    .unwrap_or_else(|e| panic!("{e:?}"));
    assert!(!s2.expose_secret().is_empty());
    tx.commit().await.unwrap_or_else(|e| panic!("{e:?}"));
    // Rotate to v2; retire v1 is refused while rows use it; after reencrypt it succeeds.
    let v2 = keys::rotate(s.pool(), &kek, "drill", "second rotation")
        .await
        .unwrap_or_else(|e| panic!("{e:?}"));
    assert_eq!(v2, 2);
    let ring2 = keys::load_keyring(s.pool(), Some(&kek), &master, false)
        .await
        .unwrap_or_else(|e| panic!("{e:?}"));
    assert_eq!(ring2.versions(), vec![1, 2]);
    assert!(
        matches!(
            keys::retire(s.pool(), &ring2, 1, now).await,
            Err(StoreError::Conflict(_))
        ),
        "rows still under v1"
    );
    assert!(
        matches!(
            keys::retire(s.pool(), &ring2, 2, now).await,
            Err(StoreError::Conflict(_))
        ),
        "cannot retire active"
    );
    keys::reencrypt(s.pool(), &ring2, Some(tenant))
        .await
        .unwrap_or_else(|e| panic!("{e:?}"));
    keys::retire(s.pool(), &ring2, 1, now)
        .await
        .unwrap_or_else(|e| panic!("{e:?}"));
    let ring_final = keys::load_keyring(s.pool(), Some(&kek), &master, false)
        .await
        .unwrap_or_else(|e| panic!("{e:?}"));
    assert_eq!(ring_final.versions(), vec![2]);
    let mut tx = s.begin(tenant).await.unwrap_or_else(|e| panic!("{e:?}"));
    let live = adapters::live_secrets(&mut tx, &ring_final, reg.adapter_id, now)
        .await
        .unwrap_or_else(|e| panic!("{e:?}"));
    assert_eq!(live.len(), 2);
    drop(tx);
    // Containment: a ring that lost v2 (compromised → removed) cannot read anything — rows fail closed.
    let legacy_only = Keyring::legacy(&master);
    let mut tx = s.begin(tenant).await.unwrap_or_else(|e| panic!("{e:?}"));
    assert!(
        adapters::live_secrets(&mut tx, &legacy_only, reg.adapter_id, now)
            .await
            .is_err()
    );
    drop(tx);
    // Runtime identities cannot mint or retire keys (owner-only table).
    ensure_member(s.pool(), "mk_kernel_api").await;
    let denied = sqlx::query("SET ROLE mk_kernel_api; INSERT INTO kernel.key_versions (version, kek_id, wrapped_dek, status, created_by) VALUES (99,'x','\\x00','active','x')")
        .execute(s.pool())
        .await;
    assert!(denied.is_err(), "runtime login must not mint key versions");
    sqlx::query("RESET ROLE").execute(s.pool()).await.ok();
    sqlx::query("DELETE FROM kernel.key_versions")
        .execute(s.pool())
        .await
        .unwrap_or_else(|e| panic!("{e:?}"));
}

/// S6: rotating the destination-fingerprint key must not orphan opt-outs or
/// consent. Rows written under the master-key fingerprint (`m0`) keep matching
/// after `k2` becomes current; removing `m0` before rekey orphans them (shown,
/// then fixed); after rekey a `k2`-only configuration still finds every row,
/// including a provider opt-out written without a sealed destination.
#[tokio::test]
async fn fingerprint_key_rotation_never_orphans_suppressions_or_consent() {
    use base64::Engine as _;
    use mk_store::fingerprint::{self, FingerprintKeys};
    let s = require_db!();
    let (tenant, user, contact) = (TenantId::new(), UserId::new(), ContactId::new());
    let now = t0();
    let master = MasterKey::generate();
    let ring = mk_crypto::Keyring::legacy(&master);
    let raw = "+1 (555) 555-0123";
    let k0 = FingerprintKeys::from_master(&master);
    let fp0 = k0.compute(tenant, Channel::Sms, raw);

    let mut tx = s.begin(tenant).await.unwrap_or_else(|e| panic!("{e:?}"));
    consent::grant_permission(
        &mut tx,
        contact,
        Channel::Sms,
        &["customer_requested_follow_up".into()],
        "web_form",
        &mk_crypto::Digest::of(b"proof"),
        now,
        now + Duration::days(30),
        user,
        &fp0,
        Some((&ring, raw)),
        ACTOR,
        now,
    )
    .await
    .unwrap_or_else(|e| panic!("{e:?}"));
    // Inbound STOP: sealed raw destination.
    consent::add_suppression(
        &mut tx,
        Some(Channel::Sms),
        Some(&fp0),
        Some((&ring, raw)),
        "destination",
        "sms_opt_out",
        true,
        "sms_reply",
        ACTOR,
        now,
    )
    .await
    .unwrap_or_else(|e| panic!("{e:?}"));
    // Provider opt-out: no sealed raw — recovered through the action's canonical `to`.
    let provider_sup = consent::add_suppression(
        &mut tx,
        Some(Channel::Sms),
        Some(&fp0),
        None,
        "destination",
        "provider_opt_out",
        true,
        "provider",
        ACTOR,
        now,
    )
    .await
    .unwrap_or_else(|e| panic!("{e:?}"));
    let mut req = sms_request(tenant, user, contact, now);
    req.arguments
        .insert("to".into(), serde_json::json!("+15555550123"));
    let action_id = req.action_id.unwrap_or_default();
    actions::insert_draft(&mut tx, &req, Some(Channel::Sms), Some(&fp0), ACTOR, now)
        .await
        .unwrap_or_else(|e| panic!("{e:?}"));
    actions::transition(
        &mut tx,
        action_id,
        Transition::SubmitForPolicy,
        None,
        ACTOR,
        now,
    )
    .await
    .unwrap_or_else(|e| panic!("{e:?}"));
    tx.commit().await.unwrap_or_else(|e| panic!("{e:?}"));

    // Phase 2: k2 current, m0 still configured.
    let k2b64 = base64::engine::general_purpose::STANDARD.encode([9u8; 32]);
    let k_rot = FingerprintKeys::parse(&format!("k2={k2b64},m0=master"), &master).unwrap();
    let fp_rot = k_rot.compute(tenant, Channel::Sms, "+15555550123");
    assert_ne!(fp_rot.primary, fp0.primary);
    let mut tx = s.begin(tenant).await.unwrap_or_else(|e| panic!("{e:?}"));
    let sups = consent::suppressions_for(&mut tx, Channel::Sms, &fp_rot)
        .await
        .unwrap();
    assert_eq!(sups.len(), 2, "both pre-rotation suppressions still apply");
    assert!(
        sups.iter()
            .all(|f| f.destination_hash.as_deref() == Some(fp_rot.primary.as_str()))
    );
    let perms = consent::permissions_for(&mut tx, contact, Channel::Sms, Some(&fp_rot))
        .await
        .unwrap();
    assert_eq!(
        perms[0].destination_hash.as_deref(),
        Some(fp_rot.primary.as_str()),
        "consent still binds"
    );
    let pending = actions::pending_for_destination(&mut tx, Some(Channel::Sms), Some(&fp_rot))
        .await
        .unwrap();
    assert_eq!(pending, vec![action_id]);
    drop(tx);
    let st = fingerprint::status(s.pool(), &k_rot, Some(tenant))
        .await
        .unwrap();
    assert!(
        st.iter().map(|t| t.lacking_current).sum::<u64>() >= 4,
        "{st:?}"
    );
    assert!(st.iter().all(|t| t.orphaned == 0), "{st:?}");

    // Removing m0 before rekey would orphan every row: lookups find nothing.
    let k_only = FingerprintKeys::parse(&format!("k2={k2b64}"), &master).unwrap();
    let fp_only = k_only.compute(tenant, Channel::Sms, raw);
    let mut tx = s.begin(tenant).await.unwrap_or_else(|e| panic!("{e:?}"));
    assert!(
        consent::suppressions_for(&mut tx, Channel::Sms, &fp_only)
            .await
            .unwrap()
            .is_empty()
    );
    drop(tx);
    let st = fingerprint::status(s.pool(), &k_only, Some(tenant))
        .await
        .unwrap();
    assert!(
        st.iter().map(|t| t.orphaned).sum::<u64>() >= 4,
        "status must flag orphaned rows: {st:?}"
    );

    // Rekey with both keys configured; then k2 alone matches everything.
    let rep = fingerprint::rekey(s.pool(), &ring, &k_rot, Some(tenant))
        .await
        .unwrap();
    assert_eq!(rep.unresolved, 0, "{rep:?}");
    assert_eq!(rep.updated, 4, "{rep:?}");
    let again = fingerprint::rekey(s.pool(), &ring, &k_rot, Some(tenant))
        .await
        .unwrap();
    assert_eq!(again.updated, 0, "rekey is idempotent: {again:?}");
    let st = fingerprint::status(s.pool(), &k_only, Some(tenant))
        .await
        .unwrap();
    assert!(
        st.iter().all(|t| t.lacking_current == 0 && t.orphaned == 0),
        "{st:?}"
    );
    let mut tx = s.begin(tenant).await.unwrap_or_else(|e| panic!("{e:?}"));
    let sups = consent::suppressions_for(&mut tx, Channel::Sms, &fp_only)
        .await
        .unwrap();
    assert_eq!(
        sups.len(),
        2,
        "opt-outs survive removal of the old key after rekey"
    );
    let perms = consent::permissions_for(&mut tx, contact, Channel::Sms, Some(&fp_only))
        .await
        .unwrap();
    assert_eq!(
        perms[0].destination_hash.as_deref(),
        Some(fp_only.primary.as_str())
    );
    assert_eq!(
        actions::pending_for_destination(&mut tx, Some(Channel::Sms), Some(&fp_only))
            .await
            .unwrap(),
        vec![action_id]
    );
    let _ = provider_sup;
    // A different number never matches (no false positives from overlap).
    let other = k_only.compute(tenant, Channel::Sms, "+15555550999");
    assert!(
        consent::suppressions_for(&mut tx, Channel::Sms, &other)
            .await
            .unwrap()
            .is_empty()
    );
}

/// Rekey refuses to re-point a row: a sealed destination that does not
/// reproduce any stored tag (tampered row / wrong raw) is left unresolved.
#[tokio::test]
async fn fingerprint_rekey_rejects_inconsistent_raw_destination() {
    use base64::Engine as _;
    use mk_store::fingerprint::{self, FingerprintKeys, Fingerprints};
    let s = require_db!();
    let tenant = TenantId::new();
    let now = t0();
    let master = MasterKey::generate();
    let ring = mk_crypto::Keyring::legacy(&master);
    let mut tx = s.begin(tenant).await.unwrap_or_else(|e| panic!("{e:?}"));
    // Tags claim one number; sealed raw is another.
    let claimed: Fingerprints =
        FingerprintKeys::from_master(&master).compute(tenant, Channel::Sms, "+15555550001");
    consent::add_suppression(
        &mut tx,
        Some(Channel::Sms),
        Some(&claimed),
        Some((&ring, "+15555550002")),
        "destination",
        "sms_opt_out",
        true,
        "sms_reply",
        ACTOR,
        now,
    )
    .await
    .unwrap_or_else(|e| panic!("{e:?}"));
    tx.commit().await.unwrap_or_else(|e| panic!("{e:?}"));
    let rep = fingerprint::rekey(
        s.pool(),
        &ring,
        &FingerprintKeys::from_master(&master),
        Some(tenant),
    )
    .await
    .unwrap();
    assert_eq!(
        (rep.updated, rep.unresolved),
        (0, 0),
        "already complete under m0: {rep:?}"
    );
    let k = FingerprintKeys::parse(
        &format!(
            "k3={},m0=master",
            base64::engine::general_purpose::STANDARD.encode([3u8; 32])
        ),
        &master,
    )
    .unwrap();
    let rep = fingerprint::rekey(s.pool(), &ring, &k, Some(tenant))
        .await
        .unwrap();
    assert_eq!((rep.updated, rep.unresolved), (0, 1), "{rep:?}");
    let st = fingerprint::status(s.pool(), &k, Some(tenant))
        .await
        .unwrap();
    assert_eq!(
        st.iter().map(|t| t.lacking_current).sum::<u64>(),
        1,
        "still blocks key removal"
    );
}
