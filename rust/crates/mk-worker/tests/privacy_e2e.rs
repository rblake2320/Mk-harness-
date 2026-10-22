#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::too_many_lines
)]
//! Actual PostgreSQL worker-role leases, provider HTTP, disabled credentials,
//! retries, immutable receipts, and backup obligations. No external sends.
use chrono::{Duration, Utc};
use mk_adapters::egress::EgressAllowlist;
use mk_adapters::twilio::{SenderResolver, TwilioAdapter};
use mk_adapters::twilio_sim::{ErasureSimMode, TwilioSimMode, TwilioSimulator};
use mk_adapters::{ActionAdapter, AdapterRegistry, AuthorizedAction, InternalRecordAdapter};
use mk_audit::ActorType;
use mk_crypto::{AdapterSecret, Digest, Keyring, MasterKey};
use mk_domain::{ContactId, TenantId, UserId};
use mk_policy::ToolAllowlist;
use mk_queue::RetryPolicy;
use mk_store::{Store, actions::Actor, messaging, privacy};
use mk_worker::{WorkerContext, resolver::StoreSenderResolver};
use secrecy::SecretString;
use serde_json::json;
use sqlx::Row;
use uuid::Uuid;

struct World {
    admin: Store,
    ctx: WorkerContext,
    sim: TwilioSimulator,
    tenant: TenantId,
    sender: Uuid,
    request: Uuid,
    subject: Uuid,
    user: UserId,
    keys: Keyring,
}

async fn world() -> Option<World> {
    let url = mk_testkit::test_database_url()?;
    let admin = Store::connect(&url, 1).await.unwrap();
    admin.migrate().await.unwrap();
    let runtime = Store::connect(&url, 1).await.unwrap();
    sqlx::query("SET ROLE mk_kernel_worker")
        .execute(runtime.pool())
        .await
        .unwrap();
    let tenant = TenantId::new();
    let user = UserId::new();
    let keys = Keyring::legacy(&MasterKey::generate());
    let account = format!("AC{}", Uuid::now_v7().simple());
    let number = format!("+1{:010}", Uuid::now_v7().as_u128() % 10_000_000_000);
    let sim = TwilioSimulator::start(
        &account,
        AdapterSecret::new("synthetic-privacy-token"),
        TwilioSimMode::Accept,
    )
    .await
    .unwrap();
    let mut tx = admin.begin(tenant).await.unwrap();
    let sender = messaging::register_sender(
        &mut tx,
        &keys,
        user,
        "synthetic",
        &account,
        &SecretString::from("synthetic-privacy-token"),
        Some(&number),
        None,
        user,
        Utc::now(),
    )
    .await
    .unwrap();
    tx.commit().await.unwrap();
    let adapter = TwilioAdapter::new(
        EgressAllowlist::new([sim.authority().as_str()], true),
        &sim.api_base(),
        Box::new(StoreSenderResolver {
            store: runtime.clone(),
            keyring: keys.clone(),
            public_webhook_base: "https://example.invalid".into(),
        }),
    )
    .unwrap();
    let subject = Uuid::now_v7();
    let mut req = mk_testkit::sms_request(tenant, user, ContactId::from_uuid(subject), Utc::now());
    req.arguments
        .insert("sender_identity_id".into(), json!(sender));
    req.arguments.insert("to".into(), json!("+15555550100"));
    req.arguments.insert(
        "rendered_text".into(),
        json!("synthetic private erasure canary"),
    );
    let action = AuthorizedAction {
        tenant_id: tenant,
        action_id: req.action_id.unwrap(),
        attempt: 1,
        action_digest: req.digest().unwrap(),
        request: req,
    };
    let sid = adapter
        .execute(&action)
        .await
        .unwrap()
        .external_ref
        .unwrap();
    let request = Uuid::now_v7();
    let mut tx = admin.begin(tenant).await.unwrap();
    sqlx::query("INSERT INTO kernel.privacy_erasure_requests(tenant_id,request_id,subject_kind,subject_id,requested_at) VALUES($1,$2,'contact',$3,now())")
        .bind(tenant.0).bind(request).bind(subject).execute(tx.raw_conn()).await.unwrap();
    sqlx::query("INSERT INTO kernel.privacy_provider_deletions(tenant_id,request_id,sender_identity_id,provider,provider_message_id) VALUES($1,$2,$3,'twilio',$4)")
        .bind(tenant.0).bind(request).bind(sender).bind(sid).execute(tx.raw_conn()).await.unwrap();
    // Account erasure disables sends before its cleanup worker gets the job.
    sqlx::query("UPDATE kernel.sender_identities SET status='disabled' WHERE tenant_id=$1 AND sender_identity_id=$2")
        .bind(tenant.0).bind(sender).execute(tx.raw_conn()).await.unwrap();
    tx.commit().await.unwrap();
    let ctx = WorkerContext {
        store: runtime,
        registry: AdapterRegistry {
            internal: InternalRecordAdapter,
            mobile: None,
            twilio: Some(adapter),
        },
        tools: ToolAllowlist::v1(),
        worker_id: "privacy-e2e".into(),
        lease_ttl: std::time::Duration::from_mins(1),
        retry: RetryPolicy::default(),
    };
    Some(World {
        admin,
        ctx,
        sim,
        tenant,
        sender,
        request,
        subject,
        user,
        keys,
    })
}

#[tokio::test]
async fn provider_worker_disabled_sender_cleanup_preserves_backup_obligation_and_audit() {
    let Some(w) = world().await else {
        return;
    };
    let resolver = StoreSenderResolver {
        store: w.ctx.store.clone(),
        keyring: w.keys.clone(),
        public_webhook_base: "https://example.invalid".into(),
    };
    assert!(resolver.resolve(w.tenant, w.sender).await.is_none());
    assert!(
        resolver
            .resolve_for_erasure(w.tenant, w.sender)
            .await
            .is_some()
    );
    assert!(
        resolver
            .resolve_for_erasure(TenantId::new(), w.sender)
            .await
            .is_none()
    );
    let stats = mk_worker::privacy::run_once(&w.ctx, &[w.tenant], Utc::now())
        .await
        .unwrap();
    assert_eq!(
        (stats.checked, stats.active_deleted, stats.pending),
        (1, 1, 0)
    );
    assert!(w.sim.created_messages().await.is_empty());
    assert_eq!(w.sim.calls(), 1);
    let mut tx = w.admin.begin_erasure(w.tenant).await.unwrap();
    let receipt = privacy::erase(
        &mut tx,
        w.request,
        privacy::SubjectKind::Contact,
        w.subject,
        w.user,
        Actor {
            actor_type: ActorType::System,
            actor_id: "test",
            trace_id: None,
            policy_version: "test",
        },
        Utc::now(),
    )
    .await
    .unwrap();
    assert_eq!(receipt.pending_provider_deletions, 0);
    assert_eq!(receipt.pending_provider_retention, 1);
    let row = sqlx::query("SELECT confirmed_at,backup_not_before,backup_confirmed_at,receipt_digest FROM kernel.privacy_provider_deletions WHERE tenant_id=$1 AND request_id=$2")
        .bind(w.tenant.0).bind(w.request).fetch_one(tx.raw_conn()).await.unwrap();
    let confirmed: chrono::DateTime<Utc> = row.get("confirmed_at");
    let expires: chrono::DateTime<Utc> = row.get("backup_not_before");
    assert_eq!(expires - confirmed, Duration::days(30));
    assert!(
        row.get::<Option<chrono::DateTime<Utc>>, _>("backup_confirmed_at")
            .is_none()
    );
    assert!(
        row.get::<String, _>("receipt_digest")
            .parse::<Digest>()
            .is_ok()
    );
    let audit:serde_json::Value = sqlx::query_scalar("SELECT payload_redacted FROM kernel.audit_events WHERE tenant_id=$1 AND event_type='provider_content_erased'")
        .bind(w.tenant.0).fetch_one(tx.raw_conn()).await.unwrap();
    assert_eq!(audit["backup_status"], "pending");
    assert!(!audit.to_string().contains("canary"));
    tx.commit().await.unwrap();
    let again = mk_worker::privacy::run_once(&w.ctx, &[w.tenant], Utc::now() + Duration::days(31))
        .await
        .unwrap();
    assert_eq!(
        again.checked, 0,
        "time alone cannot certify provider backup deletion"
    );
    assert_eq!(w.sim.deletes(), 1);
    for query in [
        "UPDATE kernel.privacy_provider_deletions SET backup_confirmed_at=now(),backup_receipt_digest='forged' WHERE tenant_id=$1",
        "UPDATE kernel.privacy_provider_deletions SET provider_message_id='replacement' WHERE tenant_id=$1",
        "UPDATE kernel.privacy_provider_deletions SET confirmed_at=NULL,receipt_digest=NULL,backup_not_before=NULL WHERE tenant_id=$1",
        "DELETE FROM kernel.privacy_provider_deletions WHERE tenant_id=$1",
    ] {
        let mut tx = w.ctx.store.begin(w.tenant).await.unwrap();
        assert!(
            sqlx::query(query)
                .bind(w.tenant.0)
                .execute(tx.raw_conn())
                .await
                .is_err()
        );
        tx.rollback().await.unwrap();
    }
    let mut tx = w.ctx.store.begin(TenantId::new()).await.unwrap();
    assert_eq!(
        sqlx::query_scalar::<_, i64>("SELECT count(*) FROM kernel.privacy_provider_deletions")
            .fetch_one(tx.raw_conn())
            .await
            .unwrap(),
        0
    );
}

#[tokio::test]
async fn provider_worker_lost_response_and_restart_retries_without_resend() {
    let Some(w) = world().await else {
        return;
    };
    w.sim
        .set_erasure_mode(ErasureSimMode::DeleteThenUnavailable)
        .await;
    let now = Utc::now();
    let first = mk_worker::privacy::run_once(&w.ctx, &[w.tenant], now)
        .await
        .unwrap();
    assert_eq!((first.pending, first.active_deleted), (1, 0));
    assert!(w.sim.created_messages().await.is_empty());
    assert_eq!(
        mk_worker::privacy::run_once(&w.ctx, &[w.tenant], now)
            .await
            .unwrap()
            .checked,
        0
    );
    let second = mk_worker::privacy::run_once(&w.ctx, &[w.tenant], now + Duration::minutes(5))
        .await
        .unwrap();
    assert_eq!((second.checked, second.active_deleted), (1, 1));
    assert_eq!(w.sim.deletes(), 2);
    assert_eq!(w.sim.calls(), 1);
}

#[tokio::test]
async fn provider_worker_lease_crash_expiry_cas_and_concurrent_replicas() {
    let Some(w) = world().await else {
        return;
    };
    let now = Utc::now();
    let mut tx = w.ctx.store.begin(w.tenant).await.unwrap();
    let abandoned = privacy::claim_provider_deletion(&mut tx, now)
        .await
        .unwrap()
        .unwrap();
    tx.commit().await.unwrap();
    assert_eq!(
        mk_worker::privacy::run_once(&w.ctx, &[w.tenant], now)
            .await
            .unwrap()
            .checked,
        0
    );
    let tenants = [w.tenant];
    let (a, b) = tokio::join!(
        mk_worker::privacy::run_once(&w.ctx, &tenants, now + Duration::minutes(2)),
        mk_worker::privacy::run_once(&w.ctx, &tenants, now + Duration::minutes(2))
    );
    assert_eq!(a.unwrap().active_deleted + b.unwrap().active_deleted, 1);
    assert_eq!(w.sim.deletes(), 1);
    let mut tx = w.ctx.store.begin(w.tenant).await.unwrap();
    assert!(
        !privacy::finish_provider_deletion(
            &mut tx,
            &abandoned,
            None,
            Some("late_failure"),
            now + Duration::minutes(3)
        )
        .await
        .unwrap()
    );
    tx.commit().await.unwrap();
}

#[tokio::test]
async fn provider_worker_false_success_stays_pending_then_recovers() {
    let Some(w) = world().await else {
        return;
    };
    w.sim.set_erasure_mode(ErasureSimMode::FalseSuccess).await;
    let now = Utc::now();
    let first = mk_worker::privacy::run_once(&w.ctx, &[w.tenant], now)
        .await
        .unwrap();
    assert_eq!((first.active_deleted, first.pending), (0, 1));
    assert_eq!(w.sim.created_messages().await.len(), 1);
    w.sim.set_erasure_mode(ErasureSimMode::Delete).await;
    assert_eq!(
        mk_worker::privacy::run_once(&w.ctx, &[w.tenant], now + Duration::minutes(5))
            .await
            .unwrap()
            .active_deleted,
        1
    );
}

#[tokio::test]
async fn intake_role_cannot_insert_a_forged_completed_provider_receipt() {
    let Some(w) = world().await else {
        return;
    };
    let mut tx = w.admin.begin(w.tenant).await.unwrap();
    sqlx::query("SET LOCAL ROLE mk_kernel_api")
        .execute(tx.raw_conn())
        .await
        .unwrap();
    let forged=sqlx::query("INSERT INTO kernel.privacy_provider_deletions(tenant_id,request_id,sender_identity_id,provider,provider_message_id,confirmed_at,receipt_digest,backup_not_before)
        VALUES($1,$2,$3,'twilio',$4,now(),$5,now()+interval '30 days')")
        .bind(w.tenant.0).bind(w.request).bind(w.sender).bind(format!("SM{}",Uuid::now_v7().simple()))
        .bind(Digest::of(b"forged").to_string()).execute(tx.raw_conn()).await;
    assert!(
        forged.is_err(),
        "intake must never certify provider cleanup at INSERT time"
    );
    tx.rollback().await.unwrap();
}
