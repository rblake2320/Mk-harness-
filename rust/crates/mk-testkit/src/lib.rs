//! Shared test fixtures. Not a production dependency of any binary.

use chrono::{DateTime, TimeZone, Utc};
use mk_contracts::{ActionRequest, Evidence, Origin, Resource};
use mk_crypto::Digest;
use mk_domain::{
    ActionId, ActionKind, ContactId, OriginType, ResourceType, Risk, TenantId, UserId, Workflow,
};
use serde_json::json;
use std::sync::Arc;
use std::sync::atomic::{AtomicI64, Ordering};

/// Deterministic, advanceable clock.
#[derive(Debug, Clone)]
pub struct FakeClock {
    secs: Arc<AtomicI64>,
}

impl FakeClock {
    #[must_use]
    pub fn at(t: DateTime<Utc>) -> Self {
        Self {
            secs: Arc::new(AtomicI64::new(t.timestamp())),
        }
    }

    #[must_use]
    pub fn now(&self) -> DateTime<Utc> {
        Utc.timestamp_opt(self.secs.load(Ordering::SeqCst), 0)
            .single()
            .unwrap_or_default()
    }

    pub fn advance_secs(&self, s: i64) {
        self.secs.fetch_add(s, Ordering::SeqCst);
    }
}

/// 2026-10-19T10:00:00Z — inside default contact hours in America/Chicago.
#[must_use]
pub fn t0() -> DateTime<Utc> {
    Utc.with_ymd_and_hms(2026, 10, 19, 15, 0, 0)
        .single()
        .unwrap_or_default()
}

/// A valid, approval-requiring SMS follow-up proposal, already bound.
#[must_use]
pub fn sms_request(
    tenant: TenantId,
    user: UserId,
    contact: ContactId,
    now: DateTime<Utc>,
) -> ActionRequest {
    ActionRequest {
        schema_version: "mk.action.v1".into(),
        action_id: Some(ActionId::new()),
        tenant_id: tenant,
        requested_by: user,
        origin: Origin {
            origin_type: OriginType::Agent,
            session_id: Some("sess-1".into()),
            model_call_id: Some("call-1".into()),
            mcp_server_id: None,
        },
        workflow: Workflow::CustomerFollowUp,
        action_kind: ActionKind::SendSms,
        tool_id: "mobile.sms.send.v1".into(),
        resource: Resource {
            resource_type: ResourceType::Contact,
            id: contact.to_string(),
        },
        arguments: json!({
            "contact_id": contact.to_string(),
            "template_id": "reorder_followup.v1",
            "rendered_text": "Hi! Your order shipped. Reply STOP to opt out."
        })
        .as_object()
        .cloned()
        .unwrap_or_default(),
        purpose: "customer_requested_follow_up".into(),
        risk: Risk::High,
        requested_at: now,
        expires_at: now + chrono::Duration::minutes(30),
        idempotency_key: format!("follow-up:{contact}:{}", now.timestamp()),
        evidence: vec![Evidence {
            evidence_type: "conversation".into(),
            id: "conv-1".into(),
            digest: Digest::of(b"conv-1"),
        }],
    }
}

/// Test database URL. Integration tests are skipped when unset.
#[must_use]
pub fn test_database_url() -> Option<String> {
    std::env::var("MK_TEST_DATABASE_URL").ok()
}

#[must_use]
pub fn test_redis_url() -> Option<String> {
    std::env::var("MK_TEST_REDIS_URL").ok()
}
