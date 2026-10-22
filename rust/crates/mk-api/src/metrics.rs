//! Prometheus metrics. Labels are closed enums (bounded cardinality).

use prometheus_client::encoding::{EncodeLabelSet, EncodeLabelValue};
use prometheus_client::metrics::counter::Counter;
use prometheus_client::metrics::family::Family;
use prometheus_client::metrics::gauge::Gauge;
use prometheus_client::metrics::histogram::{Histogram, exponential_buckets};
use prometheus_client::registry::Registry;
use std::sync::Mutex;

#[derive(Clone, Debug, Hash, PartialEq, Eq, EncodeLabelSet)]
pub struct DecisionLabels {
    pub decision: DecisionKind,
    pub code: String,
}

#[derive(Clone, Copy, Debug, Hash, PartialEq, Eq, EncodeLabelValue)]
pub enum DecisionKind {
    Allow,
    Deny,
    RequireApproval,
    MoreInfo,
}

#[derive(Clone, Debug, Hash, PartialEq, Eq, EncodeLabelSet)]
pub struct RouteLabels {
    pub route: String,
    pub status: u16,
}

#[derive(Clone, Debug, Hash, PartialEq, Eq, EncodeLabelSet)]
pub struct AuthFailLabels {
    pub code: String,
}

#[derive(Clone, Debug, Hash, PartialEq, Eq, EncodeLabelSet)]
pub struct PathLabels {
    /// The matched route template (never the concrete path: no ids).
    pub route: String,
}

#[derive(Clone, Debug, Hash, PartialEq, Eq, EncodeLabelSet)]
pub struct DispositionLabels {
    pub disposition: String,
}

#[derive(Debug)]
pub struct Metrics {
    registry: Mutex<Registry>,
    pub requests: Family<RouteLabels, Counter>,
    pub request_duration: Family<PathLabels, Histogram>,
    pub inbound_events: Family<DispositionLabels, Counter>,
    pub decisions: Family<DecisionLabels, Counter>,
    pub assertion_failures: Family<AuthFailLabels, Counter>,
    pub hmac_failures: Family<AuthFailLabels, Counter>,
    pub approvals_pending: Gauge,
    pub callbacks_applied: Counter,
    pub callbacks_duplicate: Counter,
    /// Requests refused for capacity: `reason` = tenant_read | tenant_write | over_capacity.
    pub rejected: Family<AuthFailLabels, Counter>,
}

impl Default for Metrics {
    fn default() -> Self {
        Self::new()
    }
}

impl Metrics {
    #[must_use]
    pub fn new() -> Self {
        let mut registry = Registry::default();
        let requests = Family::<RouteLabels, Counter>::default();
        let request_duration = Family::<PathLabels, Histogram>::new_with_constructor(|| {
            Histogram::new(exponential_buckets(0.002, 2.0, 14))
        });
        let inbound_events = Family::<DispositionLabels, Counter>::default();
        let decisions = Family::<DecisionLabels, Counter>::default();
        let assertion_failures = Family::<AuthFailLabels, Counter>::default();
        let hmac_failures = Family::<AuthFailLabels, Counter>::default();
        let rejected = Family::<AuthFailLabels, Counter>::default();
        let approvals_pending = Gauge::default();
        let callbacks_applied = Counter::default();
        let callbacks_duplicate = Counter::default();
        registry.register(
            "mk_requests",
            "Requests by route and status",
            requests.clone(),
        );
        registry.register(
            "mk_request_duration_seconds",
            "Request latency by matched route template",
            request_duration.clone(),
        );
        registry.register(
            "mk_inbound_events",
            "Authenticated inbound customer messages recorded, by disposition (suppressed/held/queued_for_meaning/duplicate)",
            inbound_events.clone(),
        );
        registry.register(
            "mk_policy_decisions",
            "Policy decisions by kind and code",
            decisions.clone(),
        );
        registry.register(
            "mk_assertion_failures",
            "Actor assertion verification failures",
            assertion_failures.clone(),
        );
        registry.register(
            "mk_hmac_failures",
            "Adapter signature failures incl. replay",
            hmac_failures.clone(),
        );
        registry.register(
            "mk_approvals_pending",
            "Pending approvals (last observed)",
            approvals_pending.clone(),
        );
        registry.register(
            "mk_callbacks_applied",
            "Adapter callbacks that changed state",
            callbacks_applied.clone(),
        );
        registry.register(
            "mk_callbacks_duplicate",
            "Idempotent duplicate callbacks",
            callbacks_duplicate.clone(),
        );
        registry.register(
            "mk_requests_rejected",
            "Requests refused by per-tenant limits or replica capacity (label code = reason)",
            rejected.clone(),
        );
        Self {
            registry: Mutex::new(registry),
            requests,
            request_duration,
            inbound_events,
            decisions,
            assertion_failures,
            hmac_failures,
            approvals_pending,
            callbacks_applied,
            callbacks_duplicate,
            rejected,
        }
    }

    #[must_use]
    pub fn encode(&self) -> String {
        let mut out = String::new();
        if let Ok(r) = self.registry.lock() {
            let _ = prometheus_client::encoding::text::encode(&mut out, &r);
        }
        out
    }
}
