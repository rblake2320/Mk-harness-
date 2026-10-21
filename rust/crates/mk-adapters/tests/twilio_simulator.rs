#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::missing_panics_doc
)]
//! Twilio adapter ↔ simulator conformance (row C1): tenant-bound sender
//! resolution, outbound submission with a provider message id, conservative
//! error classification (opt-out, invalid destination, 5xx and lost response
//! are never retried blindly), rate-limit class, and reconciliation of an
//! ambiguous submission to exactly one provider message.

use async_trait::async_trait;
use mk_adapters::egress::EgressAllowlist;
use mk_adapters::twilio::{Reconciled, SenderResolver, TwilioAdapter, TwilioSender};
use mk_adapters::twilio_sim::{TwilioSimMode, TwilioSimulator};
use mk_adapters::{ActionAdapter, AuthorizedAction};
use mk_crypto::AdapterSecret;
use mk_domain::{ContactId, TenantId, UserId};
use mk_queue::RetryClass;
use mk_testkit::{sms_request, t0};
use serde_json::json;

const ACCOUNT: &str = "ACaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";

#[derive(Debug)]
struct OneSender(TenantId, TwilioSender);

#[async_trait]
impl SenderResolver for OneSender {
    async fn resolve(&self, tenant: TenantId, id: uuid::Uuid) -> Option<TwilioSender> {
        (tenant == self.0 && id == self.1.sender_identity_id).then(|| self.1.clone())
    }
}

async fn setup(
    mode: TwilioSimMode,
) -> (
    TwilioSimulator,
    TwilioAdapter,
    AuthorizedAction,
    TenantId,
    uuid::Uuid,
) {
    let tenant = TenantId::new();
    let token = AdapterSecret::new("auth-token-0123456789");
    let sim = TwilioSimulator::start(ACCOUNT, token.clone(), mode)
        .await
        .unwrap();
    let sid = uuid::Uuid::now_v7();
    let sender = TwilioSender {
        sender_identity_id: sid,
        account_sid: ACCOUNT.into(),
        auth_token: token,
        from_number: Some("+15005550006".into()),
        messaging_service_sid: None,
        status_callback_url: format!("https://kernel.example.com/webhooks/twilio/status/{sid}"),
    };
    let egress = EgressAllowlist::new([sim.authority().as_str()], true);
    let adapter =
        TwilioAdapter::new(egress, &sim.api_base(), Box::new(OneSender(tenant, sender))).unwrap();
    let mut req = sms_request(tenant, UserId::new(), ContactId::new(), t0());
    req.arguments.insert("to".into(), json!("+15555550100"));
    req.arguments
        .insert("sender_identity_id".into(), json!(sid.to_string()));
    req.arguments.insert(
        "rendered_text".into(),
        json!("Hi! Your order shipped. Reply STOP to opt out."),
    );
    let digest = req.digest().unwrap();
    let action = AuthorizedAction {
        tenant_id: tenant,
        action_id: req.action_id.unwrap_or_default(),
        attempt: 1,
        request: req,
        action_digest: digest,
    };
    (sim, adapter, action, tenant, sid)
}

#[tokio::test]
async fn accept_returns_provider_message_id_and_pending_callback() {
    let (sim, adapter, action, _, sid) = setup(TwilioSimMode::Accept).await;
    adapter.validate(&action).await.unwrap();
    let r = adapter.execute(&action).await.unwrap();
    assert!(
        r.external_ref
            .as_deref()
            .is_some_and(|s| s.starts_with("SM"))
    );
    assert!(r.pending_callback);
    assert_eq!(r.adapter_id, Some(sid));
    let created = sim.created_messages().await;
    assert_eq!(created.len(), 1);
    assert_eq!(created[0]["to"], json!("+15555550100"));
    assert_eq!(created[0]["from"], json!("+15005550006"));
}

#[tokio::test]
async fn provider_opt_out_and_invalid_destination_are_permanent_and_distinct() {
    let (_sim, adapter, action, _, _) = setup(TwilioSimMode::RecipientOptedOut).await;
    let e = adapter.execute(&action).await.unwrap_err();
    assert_eq!(
        (e.class, e.code),
        (RetryClass::Permanent, "provider_opt_out")
    );
    let (_sim, adapter, action, _, _) = setup(TwilioSimMode::InvalidDestination).await;
    let e = adapter.execute(&action).await.unwrap_err();
    assert_eq!(
        (e.class, e.code),
        (RetryClass::Permanent, "destination_invalid")
    );
}

#[tokio::test]
async fn server_error_and_lost_response_are_ambiguous_never_retried_blindly() {
    let (sim, adapter, action, _, _) = setup(TwilioSimMode::ServerErrorThenAccept(1)).await;
    let e = adapter.execute(&action).await.unwrap_err();
    assert_eq!((e.class, e.code), (RetryClass::Ambiguous, "provider_5xx"));
    assert_eq!(sim.calls(), 1, "adapter must not retry on its own");
    let (sim, adapter, action, _, _) = setup(TwilioSimMode::AcceptButDropResponse).await;
    let e = adapter.execute(&action).await.unwrap_err();
    assert_eq!(e.class, RetryClass::Ambiguous, "{e}");
    assert_eq!(
        sim.created_messages().await.len(),
        1,
        "the provider did create the message"
    );
    assert_eq!(sim.calls(), 1);
}

#[tokio::test]
async fn rate_limit_is_classified_with_backoff() {
    let (_sim, adapter, action, _, _) = setup(TwilioSimMode::RateLimited).await;
    let e = adapter.execute(&action).await.unwrap_err();
    assert!(matches!(e.class, RetryClass::RateLimited { .. }), "{e}");
}

#[tokio::test]
async fn ambiguous_submission_reconciles_to_exactly_one_provider_message() {
    let (sim, adapter, action, tenant, sid) = setup(TwilioSimMode::AcceptButDropResponse).await;
    let _ = adapter.execute(&action).await.unwrap_err();
    let today = chrono::Utc::now().date_naive();
    let r = adapter
        .reconcile_submission(
            tenant,
            sid,
            "+15555550100",
            "Hi! Your order shipped. Reply STOP to opt out.",
            today,
        )
        .await
        .unwrap();
    match r {
        Reconciled::Found {
            provider_message_id,
            ..
        } => assert!(provider_message_id.starts_with("SM")),
        other => panic!("{other:?}"),
    }
    // A different body (one byte) does not match: reconciliation never guesses.
    let r = adapter
        .reconcile_submission(
            tenant,
            sid,
            "+15555550100",
            "Hi! Your order shipped. Reply STOP to opt out!",
            today,
        )
        .await
        .unwrap();
    assert_eq!(r, Reconciled::NotFound);
    // A second identical submission would make the match ambiguous → Multiple.
    let _ = adapter.execute(&action).await;
    let r = adapter
        .reconcile_submission(
            tenant,
            sid,
            "+15555550100",
            "Hi! Your order shipped. Reply STOP to opt out.",
            today,
        )
        .await
        .unwrap();
    assert_eq!(r, Reconciled::Multiple(2));
    assert_eq!(sim.created_messages().await.len(), 2);
}

#[tokio::test]
async fn wrong_tenant_or_unknown_sender_is_refused_before_any_network_call() {
    let (sim, adapter, mut action, _, _) = setup(TwilioSimMode::Accept).await;
    action.tenant_id = TenantId::new();
    let e = adapter.execute(&action).await.unwrap_err();
    assert_eq!(e.code, "sender_not_registered");
    action
        .request
        .arguments
        .insert("sender_identity_id".into(), json!("not-a-uuid"));
    assert_eq!(
        adapter.validate(&action).await.unwrap_err().code,
        "missing_sender_identity"
    );
    assert_eq!(sim.calls(), 0);
}

#[tokio::test]
async fn egress_outside_allowlist_is_refused_at_construction() {
    let tenant = TenantId::new();
    let sender = TwilioSender {
        sender_identity_id: uuid::Uuid::nil(),
        account_sid: ACCOUNT.into(),
        auth_token: AdapterSecret::new("t"),
        from_number: Some("+15005550006".into()),
        messaging_service_sid: None,
        status_callback_url: "https://k/x".into(),
    };
    let egress = EgressAllowlist::new(["api.twilio.com"], false);
    assert!(
        TwilioAdapter::new(
            egress,
            "https://api.evil.example",
            Box::new(OneSender(tenant, sender))
        )
        .is_err()
    );
}
