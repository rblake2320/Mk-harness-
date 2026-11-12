//! S14 against real PostgreSQL: an anchor taken now still verifies after more
//! events are appended, and every way of rewriting anchored history — editing an
//! anchored event, truncating the chain, deleting the tenant's chain, rebuilding the
//! chain consistently — is reported by `verify_against`.
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use chrono::Utc;
use ed25519_dalek::SigningKey;
use mk_audit::{ActorType, EventType, NewEvent};
use mk_domain::TenantId;
use mk_store::Store;
use mk_worker::anchor::{self, Anchor};
use serde_json::json;

async fn append(store: &Store, t: TenantId, n: usize) {
    let mut tx = store.begin(t).await.unwrap();
    for i in 0..n {
        mk_store::audit::append_event(
            &mut tx,
            NewEvent {
                tenant_id: t,
                occurred_at: Utc::now(),
                actor_type: ActorType::System,
                actor_id: "anchor-test",
                action_id: None,
                event_type: EventType::KillSwitchChanged,
                payload_redacted: json!({"i": i}),
                trace_id: None,
                policy_version: mk_policy::POLICY_VERSION.0,
            },
        )
        .await
        .unwrap();
    }
    tx.commit().await.unwrap();
}

/// Superuser tamper (the threat S14 exists for): bypass the append-only trigger.
async fn tamper(store: &Store, sql: &str, t: TenantId) {
    let mut c = store.pool().acquire().await.unwrap();
    sqlx::query("SET session_replication_role = replica")
        .execute(&mut *c)
        .await
        .unwrap();
    sqlx::query(sqlx::AssertSqlSafe(sql.to_owned()))
        .bind(t.0)
        .execute(&mut *c)
        .await
        .unwrap();
    sqlx::query("SET session_replication_role = DEFAULT")
        .execute(&mut *c)
        .await
        .unwrap();
}

fn only(a: &Anchor, t: TenantId) -> Anchor {
    // Keep only this test's tenant leaf (the shared test DB holds other tenants),
    // re-signed: the check under test is the database comparison.
    let key = SigningKey::from_bytes(&[11u8; 32]);
    let leaves = a
        .leaves
        .iter()
        .filter(|l| l.tenant_ref == anchor::tenant_ref(t.0))
        .cloned()
        .collect();
    anchor::build(leaves, "t1", &key, a.anchored_at)
}

#[tokio::test]
async fn anchored_history_cannot_be_rewritten_unnoticed() {
    let Some(url) = mk_testkit::test_database_url() else {
        eprintln!("skipping");
        return;
    };
    let store = Store::connect(&url, 2).await.unwrap();
    store.migrate().await.unwrap();
    let key = SigningKey::from_bytes(&[11u8; 32]);
    let keys = vec![("t1".to_owned(), key.verifying_key())];
    let mut failures_for = Vec::new();
    for case in ["none", "edit", "truncate", "delete_chain", "rebuild"] {
        let t = TenantId::new();
        append(&store, t, 5).await;
        let leaves = anchor::heads(store.pool())
            .await
            .unwrap()
            .into_iter()
            .map(|(tn, count, last_hash)| anchor::Leaf {
                tenant_ref: anchor::tenant_ref(tn),
                count,
                last_hash,
            })
            .collect();
        let a = only(&anchor::build(leaves, "t1", &key, Utc::now()), t);
        assert_eq!(a.leaves.len(), 1);
        append(&store, t, 3).await; // the chain grows after the anchor: still consistent
        match case {
            "edit" => tamper(&store, "UPDATE kernel.audit_events SET event_hash = md5(random()::text) || md5(random()::text) WHERE tenant_id = $1 AND tenant_sequence = 5", t).await,
            "truncate" => {
                tamper(&store, "DELETE FROM kernel.audit_events WHERE tenant_id = $1 AND tenant_sequence > 2", t).await;
                tamper(&store, "UPDATE kernel.audit_heads SET count = 2 WHERE tenant_id = $1", t).await;
            }
            "delete_chain" => {
                tamper(&store, "DELETE FROM kernel.audit_events WHERE tenant_id = $1", t).await;
                tamper(&store, "DELETE FROM kernel.audit_heads WHERE tenant_id = $1", t).await;
            }
            "rebuild" => {
                // Consistent rewrite: delete the chain and re-append the same number
                // of different events. The local chain verifies; the anchor does not.
                tamper(&store, "DELETE FROM kernel.audit_events WHERE tenant_id = $1", t).await;
                tamper(&store, "DELETE FROM kernel.audit_heads WHERE tenant_id = $1", t).await;
                append(&store, t, 8).await;
                let mut tx = store.begin(t).await.unwrap();
                assert_eq!(mk_store::audit::verify_tenant(&mut tx).await.unwrap(), 8, "local chain looks fine");
                tx.commit().await.unwrap();
            }
            _ => {}
        }
        let f = anchor::verify_against(store.pool(), &[a], &keys)
            .await
            .unwrap();
        failures_for.push((case, f.len()));
    }
    assert_eq!(
        failures_for,
        vec![
            ("none", 0),
            ("edit", 1),
            ("truncate", 1),
            ("delete_chain", 1),
            ("rebuild", 1)
        ]
    );
}
