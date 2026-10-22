//! Tamper-evident audit chain.
//!
//! Each tenant has an independent chain. Every event carries
//! `tenant_sequence` (dense, starting at 1), `previous_event_hash`, and
//! `event_hash`, where
//!
//! ```text
//! event_hash = SHA-256( JCS({
//!     tenant_id, tenant_sequence, occurred_at, actor_type, actor_id,
//!     action_id, event_type, payload_digest, previous_event_hash, policy_version
//! }) )
//! ```
//!
//! `payload_digest` is the SHA-256 of the JCS of the *redacted* payload, so
//! the payload itself can be retention-pruned without breaking the chain.
//! The genesis `previous_event_hash` is the fixed string `genesis`.
//!
//! This crate computes and verifies; `mk-store` persists under a per-tenant
//! head lock. A local chain detects rewriting; it cannot prevent a privileged
//! writer from rewriting *everything consistently*. External anchoring of
//! periodic tenant roots is a later release ([`ChainHead::root_commitment`]
//! is the value to anchor).

use chrono::{DateTime, SecondsFormat, Utc};
use mk_crypto::{Digest, canonicalize};
use mk_domain::{ActionId, TenantId};
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use uuid::Uuid;

pub const GENESIS: &str = "genesis";

/// Who caused the event.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum ActorType {
    User,
    Agent,
    Worker,
    Adapter,
    System,
    Operator,
}

/// Closed set of event types. Metrics and queries key on these.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum EventType {
    ActionProposed,
    DraftInvalidated,
    PolicyDecision,
    ApprovalGranted,
    ApprovalRejected,
    ApprovalRevoked,
    ApprovalConsumed,
    PermissionGranted,
    PermissionRevoked,
    SuppressionAdded,
    SuppressionLifted,
    StateTransition,
    Enqueued,
    DispatchStarted,
    DispatchCompleted,
    DispatchFailed,
    RetryScheduled,
    DeadLettered,
    Replayed,
    AdapterRegistered,
    AdapterRotated,
    AdapterRevoked,
    SignatureFailure,
    ReplayRejected,
    CallbackReceived,
    ReconciliationRequired,
    AuditExport,
    KillSwitchChanged,
    ApprovalCredentialRegistered,
    ApprovalCredentialRevoked,
    PrincipalRevoked,
    SenderIdentityRegistered,
    SenderIdentityUpdated,
    InboundReceived,
    InboundOptOut,
    InboundHeld,
    DeliveryEvent,
    InboundPaused,
    InboundResumed,
    PrivacyRequested,
    ContentErased,
    ProviderContentErased,
    PrivacyRestored,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AuditEvent {
    pub event_id: Uuid,
    pub tenant_id: TenantId,
    pub tenant_sequence: i64,
    pub occurred_at: DateTime<Utc>,
    pub actor_type: ActorType,
    pub actor_id: String,
    pub action_id: Option<ActionId>,
    pub event_type: EventType,
    /// Already redacted by the producer. Never contains secrets or raw PII.
    pub payload_redacted: Value,
    pub payload_digest: Digest,
    pub previous_event_hash: String,
    pub event_hash: String,
    pub trace_id: Option<String>,
    pub policy_version: String,
}

/// The per-tenant head: last hash and count. Persisted in
/// `kernel.audit_heads` and locked during append.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ChainHead {
    pub tenant_id: TenantId,
    pub last_hash: String,
    pub count: i64,
}

impl ChainHead {
    #[must_use]
    pub fn genesis(tenant_id: TenantId) -> Self {
        Self {
            tenant_id,
            last_hash: GENESIS.to_owned(),
            count: 0,
        }
    }

    /// A single value to anchor externally. Binds tenant, count and last hash.
    #[must_use]
    pub fn root_commitment(&self) -> Digest {
        let v = json!({
            "tenant_id": self.tenant_id,
            "count": self.count,
            "last_hash": self.last_hash,
        });
        Digest::of(&canonicalize(&v).unwrap_or_default())
    }
}

/// Inputs for one append. `occurred_at` is supplied by the caller so the
/// store transaction's clock is the clock of record.
#[derive(Debug, Clone)]
pub struct NewEvent<'a> {
    pub tenant_id: TenantId,
    pub occurred_at: DateTime<Utc>,
    pub actor_type: ActorType,
    pub actor_id: &'a str,
    pub action_id: Option<ActionId>,
    pub event_type: EventType,
    pub payload_redacted: Value,
    pub trace_id: Option<&'a str>,
    pub policy_version: &'a str,
}

#[derive(Debug, thiserror::Error, Clone, PartialEq, Eq)]
pub enum AuditError {
    #[error("payload cannot be canonicalized")]
    Payload,
    #[error("payload contains a forbidden key: {0}")]
    ForbiddenPayloadKey(String),
    #[error("chain break at sequence {sequence}: {reason}")]
    ChainBreak { sequence: i64, reason: &'static str },
    #[error("head mismatch: expected count {expected_count}, found {found_count}")]
    HeadMismatch {
        expected_count: i64,
        found_count: i64,
    },
}

/// Keys that must never appear anywhere in an audit payload. Checked
/// recursively; producers redact before calling.
const FORBIDDEN_PAYLOAD_KEYS: [&str; 18] = [
    "secret",
    "token",
    "api_key",
    "password",
    "authorization",
    "rendered_text",
    "phone",
    "email",
    "destination",
    "assertion",
    "reason",
    "source_reference",
    "source_version",
    "platform",
    "capabilities",
    "callback_authority",
    "provider_status",
    "agent_id",
];

fn scan_forbidden(v: &Value) -> Result<(), AuditError> {
    match v {
        Value::Object(m) => {
            for (k, val) in m {
                let lk = k.to_ascii_lowercase();
                if FORBIDDEN_PAYLOAD_KEYS.iter().any(|f| lk == *f)
                    || FORBIDDEN_PAYLOAD_KEYS[..10]
                        .iter()
                        .any(|f| lk.ends_with(&format!("_{f}")))
                {
                    return Err(AuditError::ForbiddenPayloadKey(k.clone()));
                }
                scan_forbidden(val)?;
            }
            Ok(())
        }
        Value::Array(a) => a.iter().try_for_each(scan_forbidden),
        _ => Ok(()),
    }
}

fn ts(t: DateTime<Utc>) -> String {
    t.to_rfc3339_opts(SecondsFormat::Micros, true)
}

/// Compute the hash for a candidate event. Pure.
fn compute_hash(
    tenant_id: TenantId,
    sequence: i64,
    occurred_at: DateTime<Utc>,
    actor_type: ActorType,
    actor_id: &str,
    action_id: Option<ActionId>,
    event_type: EventType,
    payload_digest: &Digest,
    previous: &str,
    policy_version: &str,
) -> Result<String, AuditError> {
    let v = json!({
        "tenant_id": tenant_id,
        "tenant_sequence": sequence,
        "occurred_at": ts(occurred_at),
        "actor_type": actor_type,
        "actor_id": actor_id,
        "action_id": action_id,
        "event_type": event_type,
        "payload_digest": payload_digest.to_string(),
        "previous_event_hash": previous,
        "policy_version": policy_version,
    });
    let bytes = canonicalize(&v).map_err(|_| AuditError::Payload)?;
    Ok(mk_crypto::sha256_hex(&bytes))
}

/// Append to a chain. Returns the new event and the advanced head. The
/// caller persists both in one transaction while holding the head lock.
pub fn append(head: &ChainHead, new: NewEvent<'_>) -> Result<(AuditEvent, ChainHead), AuditError> {
    debug_assert_eq!(head.tenant_id, new.tenant_id);
    scan_forbidden(&new.payload_redacted)?;
    let payload_digest =
        Digest::of(&canonicalize(&new.payload_redacted).map_err(|_| AuditError::Payload)?);
    let sequence = head.count + 1;
    let event_hash = compute_hash(
        new.tenant_id,
        sequence,
        new.occurred_at,
        new.actor_type,
        new.actor_id,
        new.action_id,
        new.event_type,
        &payload_digest,
        &head.last_hash,
        new.policy_version,
    )?;
    let event = AuditEvent {
        event_id: Uuid::now_v7(),
        tenant_id: new.tenant_id,
        tenant_sequence: sequence,
        occurred_at: new.occurred_at,
        actor_type: new.actor_type,
        actor_id: new.actor_id.to_owned(),
        action_id: new.action_id,
        event_type: new.event_type,
        payload_redacted: new.payload_redacted,
        payload_digest,
        previous_event_hash: head.last_hash.clone(),
        event_hash: event_hash.clone(),
        // A caller-supplied correlation string can contain an address or body.
        // Preserve only the UUID representation minted by supported clients.
        trace_id: new
            .trace_id
            .and_then(|id| Uuid::parse_str(id).ok())
            .map(|id| id.to_string()),
        policy_version: new.policy_version.to_owned(),
    };
    let next = ChainHead {
        tenant_id: head.tenant_id,
        last_hash: event_hash,
        count: sequence,
    };
    Ok((event, next))
}

/// Verify an ordered sequence of events for one tenant against a head.
/// Checks: dense sequence from 1, link continuity, payload digest, event
/// hash, and that the head matches the final state. Returns the number of
/// verified events.
pub fn verify_chain<'a>(
    tenant_id: TenantId,
    events: impl IntoIterator<Item = &'a AuditEvent>,
    head: &ChainHead,
) -> Result<i64, AuditError> {
    let mut previous = GENESIS.to_owned();
    let mut expected = 1i64;
    for e in events {
        if e.tenant_id != tenant_id {
            return Err(AuditError::ChainBreak {
                sequence: expected,
                reason: "foreign tenant event",
            });
        }
        if e.tenant_sequence != expected {
            return Err(AuditError::ChainBreak {
                sequence: expected,
                reason: "sequence gap or reorder",
            });
        }
        if e.previous_event_hash != previous {
            return Err(AuditError::ChainBreak {
                sequence: expected,
                reason: "link mismatch",
            });
        }
        let pd = Digest::of(&canonicalize(&e.payload_redacted).map_err(|_| AuditError::Payload)?);
        if !pd.ct_eq(&e.payload_digest) {
            return Err(AuditError::ChainBreak {
                sequence: expected,
                reason: "payload digest mismatch",
            });
        }
        let h = compute_hash(
            e.tenant_id,
            e.tenant_sequence,
            e.occurred_at,
            e.actor_type,
            &e.actor_id,
            e.action_id,
            e.event_type,
            &e.payload_digest,
            &e.previous_event_hash,
            &e.policy_version,
        )?;
        if !mk_crypto::constant_time_eq(h.as_bytes(), e.event_hash.as_bytes()) {
            return Err(AuditError::ChainBreak {
                sequence: expected,
                reason: "event hash mismatch",
            });
        }
        previous.clone_from(&e.event_hash);
        expected += 1;
    }
    let count = expected - 1;
    if head.count != count || head.last_hash != previous {
        return Err(AuditError::HeadMismatch {
            expected_count: head.count,
            found_count: count,
        });
    }
    Ok(count)
}

#[cfg(test)]
#[allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::unreadable_literal,
    clippy::cast_possible_truncation,
    clippy::float_cmp
)]
mod tests {
    use super::*;
    use chrono::TimeZone;
    use proptest::prelude::*;

    fn t(s: u32) -> DateTime<Utc> {
        Utc.with_ymd_and_hms(2026, 10, 19, 10, 0, s)
            .single()
            .unwrap_or_default()
    }

    fn chain(tenant: TenantId, n: u32) -> (Vec<AuditEvent>, ChainHead) {
        let mut head = ChainHead::genesis(tenant);
        let mut events = Vec::new();
        for i in 0..n {
            let (e, h) = append(
                &head,
                NewEvent {
                    tenant_id: tenant,
                    occurred_at: t(i),
                    actor_type: ActorType::Worker,
                    actor_id: "worker-1",
                    action_id: Some(ActionId::new()),
                    event_type: EventType::StateTransition,
                    payload_redacted: json!({"from": "queued", "to": "dispatching", "i": i}),
                    trace_id: Some("trace"),
                    policy_version: "mk-policy/test",
                },
            )
            .unwrap_or_else(|_| unreachable!());
            events.push(e);
            head = h;
        }
        (events, head)
    }

    #[test]
    fn empty_chain_verifies() {
        let tn = TenantId::new();
        assert_eq!(verify_chain(tn, [].iter(), &ChainHead::genesis(tn)), Ok(0));
    }

    #[test]
    fn valid_chain_verifies_and_is_deterministic() {
        let tn = TenantId::new();
        let (events, head) = chain(tn, 5);
        assert_eq!(verify_chain(tn, &events, &head), Ok(5));
        assert_eq!(events[0].previous_event_hash, GENESIS);
        // Recompute hash from fields: must match (no hidden inputs).
        let e = &events[2];
        let h = compute_hash(
            e.tenant_id,
            e.tenant_sequence,
            e.occurred_at,
            e.actor_type,
            &e.actor_id,
            e.action_id,
            e.event_type,
            &e.payload_digest,
            &e.previous_event_hash,
            &e.policy_version,
        );
        assert_eq!(h, Ok(e.event_hash.clone()));
    }

    #[test]
    fn every_tamper_is_detected() {
        let tn = TenantId::new();
        let (events, head) = chain(tn, 6);

        let mut m = events.clone();
        m[3].payload_redacted = json!({"from": "queued", "to": "completed", "i": 3});
        assert!(matches!(
            verify_chain(tn, &m, &head),
            Err(AuditError::ChainBreak {
                sequence: 4,
                reason: "payload digest mismatch"
            })
        ));

        let mut m = events.clone();
        m[3].actor_id = "attacker".into();
        assert!(matches!(
            verify_chain(tn, &m, &head),
            Err(AuditError::ChainBreak {
                sequence: 4,
                reason: "event hash mismatch"
            })
        ));

        let mut m = events.clone();
        m.remove(2);
        assert!(matches!(
            verify_chain(tn, &m, &head),
            Err(AuditError::ChainBreak { sequence: 3, .. })
        ));

        let mut m = events.clone();
        m.swap(1, 2);
        assert!(matches!(
            verify_chain(tn, &m, &head),
            Err(AuditError::ChainBreak { sequence: 2, .. })
        ));

        let mut m = events.clone();
        m.pop();
        assert!(matches!(
            verify_chain(tn, &m, &head),
            Err(AuditError::HeadMismatch { .. })
        ));

        // Consistent rewrite of the tail without updating the head is caught.
        let (mut forged, _) = chain(tn, 6);
        forged.truncate(5);
        let (extra, _) = chain(tn, 1);
        let mut last = extra[0].clone();
        last.tenant_sequence = 6;
        last.previous_event_hash = forged[4].event_hash.clone();
        last.event_hash = compute_hash(
            tn,
            6,
            last.occurred_at,
            last.actor_type,
            &last.actor_id,
            last.action_id,
            last.event_type,
            &last.payload_digest,
            &last.previous_event_hash,
            &last.policy_version,
        )
        .unwrap_or_default();
        forged.push(last);
        assert!(matches!(
            verify_chain(tn, &forged, &head),
            Err(AuditError::HeadMismatch { .. })
        ));

        // Foreign tenant event spliced in.
        let other = TenantId::new();
        let (foreign, _) = chain(other, 1);
        let mut m = events.clone();
        m[0] = foreign[0].clone();
        assert!(matches!(
            verify_chain(tn, &m, &head),
            Err(AuditError::ChainBreak {
                sequence: 1,
                reason: "foreign tenant event"
            })
        ));
    }

    #[test]
    fn forbidden_payload_keys_rejected() {
        let tn = TenantId::new();
        let head = ChainHead::genesis(tn);
        for key in [
            "token",
            "rendered_text",
            "Phone",
            "adapter_secret",
            "AUTHORIZATION",
            "reason",
            "source_reference",
            "platform",
            "capabilities",
            "provider_status",
        ] {
            let r = append(
                &head,
                NewEvent {
                    tenant_id: tn,
                    occurred_at: t(0),
                    actor_type: ActorType::System,
                    actor_id: "s",
                    action_id: None,
                    event_type: EventType::AdapterRegistered,
                    payload_redacted: json!({"nested": [{key: "x"}]}),
                    trace_id: None,
                    policy_version: "p",
                },
            );
            assert!(
                matches!(r, Err(AuditError::ForbiddenPayloadKey(_))),
                "{key}"
            );
        }
    }

    #[test]
    fn root_commitment_binds_count_and_hash() {
        let tn = TenantId::new();
        let (_, h5) = chain(tn, 5);
        let (_, h6) = chain(tn, 6);
        assert_ne!(h5.root_commitment(), h6.root_commitment());
        assert_ne!(
            ChainHead::genesis(tn).root_commitment(),
            ChainHead::genesis(TenantId::new()).root_commitment()
        );
    }

    proptest! {
        #![proptest_config(ProptestConfig::with_cases(200))]
        #[test]
        fn random_single_field_mutation_breaks_chain(n in 1u32..8, idx_seed in 0u32..100, which in 0u8..4) {
            let tn = TenantId::new();
            let (mut events, head) = chain(tn, n);
            let idx = (idx_seed % n) as usize;
            match which {
                0 => events[idx].occurred_at += chrono::Duration::microseconds(1),
                1 => events[idx].event_type = EventType::ApprovalGranted,
                2 => events[idx].policy_version = "other".into(),
                _ => events[idx].tenant_sequence += 1,
            }
            prop_assert!(verify_chain(tn, &events, &head).is_err());
        }
    }
}
