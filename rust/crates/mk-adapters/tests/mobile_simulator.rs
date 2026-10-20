#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::missing_panics_doc,
    clippy::too_many_lines,
    clippy::unreadable_literal,
    clippy::cast_possible_truncation
)]
//! Mobile adapter ↔ simulator conformance: signed delivery, replay refusal,
//! retry classification by HTTP status, and work-order contract validity.

use std::collections::HashMap;

use async_trait::async_trait;
use mk_adapters::egress::EgressAllowlist;
use mk_adapters::mobile::{AgentResolver, AgentTarget, MobileAdapter};
use mk_adapters::simulator::{SimMode, Simulator};
use mk_adapters::{ActionAdapter, AuthorizedAction};
use mk_crypto::AdapterSecret;
use mk_domain::{ContactId, TenantId, UserId};
use mk_queue::RetryClass;
use mk_testkit::{sms_request, t0};
use serde_json::json;

#[derive(Debug)]
struct MapResolver(HashMap<(TenantId, String), AgentTarget>);

#[async_trait]
impl AgentResolver for MapResolver {
    async fn resolve(&self, tenant: TenantId, agent_id: &str) -> Option<AgentTarget> {
        self.0.get(&(tenant, agent_id.to_owned())).cloned()
    }
}

async fn setup(mode: SimMode) -> (Simulator, MobileAdapter, AuthorizedAction, TenantId) {
    let tenant = TenantId::new();
    let secret = AdapterSecret::new("sim-secret-0123456789");
    let sim = Simulator::start(secret.clone(), &tenant.to_string(), "simulator-1", mode)
        .await
        .unwrap_or_else(|e| panic!("{e}"));
    let target = AgentTarget {
        adapter_id: uuid::Uuid::now_v7(),
        agent_id: "simulator-1".into(),
        intake_url: sim.intake_url(),
        secret,
        callback_authority: "kernel.internal".into(),
        capabilities: vec!["open".into(), "input".into()],
    };
    let resolver = MapResolver(HashMap::from([(
        (tenant, "simulator-1".to_string()),
        target,
    )]));
    let egress = EgressAllowlist::new([sim.authority().as_str()], true);
    let adapter = MobileAdapter::new(egress, Box::new(resolver), "phoneclaw@c59995b")
        .unwrap_or_else(|e| panic!("{e}"));
    let mut req = sms_request(tenant, UserId::new(), ContactId::new(), t0());
    req.arguments.insert("to".into(), json!("+15555550100"));
    req.arguments
        .insert("agent_id".into(), json!("simulator-1"));
    let digest = req.digest().unwrap_or_else(|_| panic!());
    let action = AuthorizedAction {
        tenant_id: tenant,
        action_id: req.action_id.unwrap_or_default(),
        attempt: 1,
        request: req,
        action_digest: digest,
    };
    (sim, adapter, action, tenant)
}

#[tokio::test]
async fn accept_mode_delivers_valid_signed_order() {
    let (mut sim, adapter, action, _) = setup(SimMode::Accept).await;
    adapter
        .validate(&action)
        .await
        .unwrap_or_else(|e| panic!("{e}"));
    let receipt = adapter
        .execute(&action)
        .await
        .unwrap_or_else(|e| panic!("{e}"));
    assert!(receipt.pending_callback);
    assert_eq!(
        receipt.external_ref.as_deref(),
        Some(action.action_id.0.simple().to_string().as_str())
    );
    let order = sim
        .received
        .recv()
        .await
        .unwrap_or_else(|| panic!("simulator received nothing"));
    assert!(!order.verified_on_device);
    assert_eq!(order.workflow, "follow_up");
    assert!(
        order
            .callback_url
            .starts_with("https://kernel.internal/adapter/v1/work-orders/")
    );
    assert_eq!(order.validate(), Ok(()));
}

#[tokio::test]
async fn retry_classification_by_status() {
    let (_sim, adapter, action, _) = setup(SimMode::FailOnce).await;
    let first = adapter
        .execute(&action)
        .await
        .err()
        .unwrap_or_else(|| panic!("expected failure"));
    assert_eq!(first.class, RetryClass::Transient);
    assert!(
        adapter.execute(&action).await.is_ok(),
        "second attempt succeeds"
    );

    let (_sim, adapter, action, _) = setup(SimMode::Reject).await;
    assert_eq!(
        adapter.execute(&action).await.err().map(|e| e.class),
        Some(RetryClass::Permanent)
    );

    let (_sim, adapter, action, _) = setup(SimMode::UnsupportedActions).await;
    assert_eq!(
        adapter.execute(&action).await.err().map(|e| e.class),
        Some(RetryClass::Permanent)
    );
}

#[tokio::test]
async fn unreachable_agent_is_transient_and_bad_inputs_are_permanent() {
    let (sim, adapter, mut action, _) = setup(SimMode::Accept).await;
    drop(sim); // port closed
    tokio::time::sleep(std::time::Duration::from_millis(50)).await;
    assert_eq!(
        adapter.execute(&action).await.err().map(|e| e.class),
        Some(RetryClass::Transient)
    );

    action
        .request
        .arguments
        .insert("to".into(), json!("555-0100"));
    assert_eq!(
        adapter.validate(&action).await.err().map(|e| e.code),
        Some("destination_not_e164")
    );
    action
        .request
        .arguments
        .insert("to".into(), json!("+15555550100"));
    action
        .request
        .arguments
        .insert("agent_id".into(), json!("ghost"));
    assert_eq!(
        adapter.validate(&action).await.err().map(|e| e.code),
        Some("agent_not_registered")
    );
}

#[tokio::test]
async fn wrong_secret_is_rejected_by_simulator() {
    let (mut sim, _adapter, action, tenant) = setup(SimMode::Accept).await;
    let bad = AgentTarget {
        adapter_id: uuid::Uuid::now_v7(),
        agent_id: "simulator-1".into(),
        intake_url: sim.intake_url(),
        secret: AdapterSecret::new("rotated-elsewhere"),
        callback_authority: "kernel.internal".into(),
        capabilities: vec!["open".into(), "input".into()],
    };
    let resolver = MapResolver(HashMap::from([((tenant, "simulator-1".to_string()), bad)]));
    let adapter = MobileAdapter::new(
        EgressAllowlist::new([sim.authority().as_str()], true),
        Box::new(resolver),
        "x",
    )
    .unwrap_or_else(|e| panic!("{e}"));
    assert_eq!(
        adapter.execute(&action).await.err().map(|e| e.code),
        Some("agent_rejected")
    );
    assert!(
        sim.received.try_recv().is_err(),
        "unsigned/forged orders never reach the device logic"
    );
}
