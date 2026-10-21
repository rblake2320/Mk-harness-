//! Worker-side Prometheus metrics (contract O6/O7).
//!
//! Two kinds:
//! * event counters/histograms updated inline by the dispatch loop and
//!   housekeeping (`mk_dispatch_outcomes`, `mk_dispatch_duration_seconds`, …);
//! * state gauges refreshed by [`sample`], which walks every tenant under the
//!   worker's own login (RLS: the worker sees a tenant's rows only inside a
//!   tenant transaction) and publishes **aggregates only** — never a per-tenant
//!   label, so cardinality is bounded regardless of tenant count.
//!
//! Exposed on `MK_METRICS_BIND` (default `127.0.0.1:9100`) as OpenMetrics text.
//! No payloads, destinations or identifiers are ever exported.

use std::sync::Mutex;
use std::time::Duration;

use chrono::{DateTime, Utc};
use mk_domain::TenantId;
use mk_store::Store;
use prometheus_client::encoding::{EncodeLabelSet, EncodeLabelValue};
use prometheus_client::metrics::counter::Counter;
use prometheus_client::metrics::family::Family;
use prometheus_client::metrics::gauge::Gauge;
use prometheus_client::metrics::histogram::{Histogram, exponential_buckets};
use prometheus_client::registry::Registry;
use sqlx::Row;

use crate::DispatchOutcome;

#[derive(Clone, Copy, Debug, Hash, PartialEq, Eq, EncodeLabelValue)]
pub enum Outcome {
    Dispatched,
    PendingCallback,
    Blocked,
    Deferred,
    RetryScheduled,
    DeadLettered,
    ReconciliationRequired,
    Skipped,
    Error,
}

impl Outcome {
    #[must_use]
    pub fn of(r: &Result<DispatchOutcome, crate::DispatchError>) -> Self {
        match r {
            Ok(DispatchOutcome::Dispatched {
                pending_callback: true,
            }) => Self::PendingCallback,
            Ok(DispatchOutcome::Dispatched {
                pending_callback: false,
            }) => Self::Dispatched,
            Ok(DispatchOutcome::Blocked { .. }) => Self::Blocked,
            Ok(DispatchOutcome::Deferred { .. }) => Self::Deferred,
            Ok(DispatchOutcome::RetryScheduled { .. }) => Self::RetryScheduled,
            Ok(DispatchOutcome::DeadLettered { .. }) => Self::DeadLettered,
            Ok(DispatchOutcome::ReconciliationRequired) => Self::ReconciliationRequired,
            Ok(DispatchOutcome::Skipped { .. }) => Self::Skipped,
            Err(_) => Self::Error,
        }
    }
}

#[derive(Clone, Debug, Hash, PartialEq, Eq, EncodeLabelSet)]
pub struct OutcomeLabels {
    pub outcome: Outcome,
}

#[derive(Clone, Debug, Hash, PartialEq, Eq, EncodeLabelSet)]
pub struct KindLabels {
    pub kind: String,
}

#[derive(Debug)]
pub struct WorkerMetrics {
    registry: Mutex<Registry>,
    pub dispatch_outcomes: Family<OutcomeLabels, Counter>,
    pub dispatch_duration: Histogram,
    pub housekeeping: Family<KindLabels, Counter>,
    pub sampler_errors: Counter,
    pub sampler_duration: Histogram,
    // state gauges (aggregates across tenants)
    pub queue_depth: Gauge,
    pub queue_oldest_eligible_age: Gauge<f64, std::sync::atomic::AtomicU64>,
    pub outbox_unpublished: Gauge,
    pub outbox_lag: Gauge<f64, std::sync::atomic::AtomicU64>,
    pub leases_active: Gauge,
    pub lease_oldest_age: Gauge<f64, std::sync::atomic::AtomicU64>,
    pub dispatching: Gauge,
    pub reconciliation_required: Gauge,
    pub deliveries_submission_unknown: Gauge,
    pub dead_letters: Gauge,
    pub approvals_pending: Gauge,
    pub approvals_expiring_1h: Gauge,
    pub inbound_pending: Gauge,
    pub inbound_oldest_pending_age: Gauge<f64, std::sync::atomic::AtomicU64>,
    pub tenants_inbound_blocked: Gauge,
    pub tenants_dispatch_disabled: Gauge,
    pub kill_switch_global_enabled: Gauge,
    pub tenants_total: Gauge,
    pub key_versions_retiring: Gauge,
    pub sealed_with_legacy_key: Gauge,
    /// Tenants whose audit head disagrees with the last stored event (O(1) tail check each sample).
    pub audit_head_mismatches: Gauge,
    /// 1 when the provider adapter points at the live provider API (not a simulator).
    pub provider_live: Gauge,
}

impl Default for WorkerMetrics {
    fn default() -> Self {
        Self::new()
    }
}

macro_rules! reg {
    ($r:expr, $name:literal, $help:literal, $m:expr) => {
        $r.register($name, $help, $m.clone())
    };
}

impl WorkerMetrics {
    #[must_use]
    pub fn new() -> Self {
        let mut r = Registry::default();
        let dispatch_outcomes = Family::<OutcomeLabels, Counter>::default();
        let dispatch_duration = Histogram::new(exponential_buckets(0.005, 2.0, 14));
        let housekeeping = Family::<KindLabels, Counter>::default();
        let sampler_errors = Counter::default();
        let sampler_duration = Histogram::new(exponential_buckets(0.01, 2.0, 12));
        let g = Gauge::default;
        let gf = Gauge::<f64, std::sync::atomic::AtomicU64>::default;
        let (queue_depth, outbox_unpublished, leases_active, dispatching, reconciliation_required) =
            (g(), g(), g(), g(), g());
        let (deliveries_submission_unknown, dead_letters, approvals_pending, approvals_expiring_1h) =
            (g(), g(), g(), g());
        let (
            inbound_pending,
            tenants_inbound_blocked,
            tenants_dispatch_disabled,
            kill_switch_global_enabled,
        ) = (g(), g(), g(), g());
        let (
            tenants_total,
            key_versions_retiring,
            sealed_with_legacy_key,
            audit_head_mismatches,
            provider_live,
        ) = (g(), g(), g(), g(), g());
        let (queue_oldest_eligible_age, outbox_lag, lease_oldest_age, inbound_oldest_pending_age) =
            (gf(), gf(), gf(), gf());
        reg!(
            r,
            "mk_dispatch_outcomes",
            "Dispatch attempts by outcome",
            dispatch_outcomes
        );
        reg!(
            r,
            "mk_dispatch_duration_seconds",
            "Wall time of dispatch_one (lease → outcome)",
            dispatch_duration
        );
        reg!(
            r,
            "mk_housekeeping",
            "Housekeeping actions by kind",
            housekeeping
        );
        reg!(
            r,
            "mk_metrics_sampler_errors",
            "Gauge sampler failures (gauges may be stale)",
            sampler_errors
        );
        reg!(
            r,
            "mk_metrics_sampler_duration_seconds",
            "Gauge sampler wall time",
            sampler_duration
        );
        reg!(
            r,
            "mk_queue_depth",
            "Actions in state queued (all tenants)",
            queue_depth
        );
        reg!(
            r,
            "mk_queue_oldest_eligible_age_seconds",
            "Age of the oldest queued action whose outbox message is available",
            queue_oldest_eligible_age
        );
        reg!(
            r,
            "mk_outbox_unpublished",
            "Outbox rows not yet published to the stream",
            outbox_unpublished
        );
        reg!(
            r,
            "mk_outbox_lag_seconds",
            "Age of the oldest unpublished, available outbox row",
            outbox_lag
        );
        reg!(
            r,
            "mk_leases_active",
            "Live execution leases",
            leases_active
        );
        reg!(
            r,
            "mk_lease_oldest_age_seconds",
            "Age of the oldest live lease",
            lease_oldest_age
        );
        reg!(
            r,
            "mk_actions_dispatching",
            "Actions in state dispatching",
            dispatching
        );
        reg!(
            r,
            "mk_actions_reconciliation_required",
            "Actions awaiting human reconciliation (uncertain submissions)",
            reconciliation_required
        );
        reg!(
            r,
            "mk_deliveries_submission_unknown",
            "Provider deliveries in submission_unknown",
            deliveries_submission_unknown
        );
        reg!(
            r,
            "mk_dead_letters",
            "Dead-lettered actions not yet replayed",
            dead_letters
        );
        reg!(
            r,
            "mk_approvals_pending",
            "Approved, unconsumed, unrevoked approvals",
            approvals_pending
        );
        reg!(
            r,
            "mk_approvals_expiring_1h",
            "Pending approvals that expire within one hour",
            approvals_expiring_1h
        );
        reg!(
            r,
            "mk_inbound_pending",
            "Inbound events not yet processed for meaning",
            inbound_pending
        );
        reg!(
            r,
            "mk_inbound_oldest_pending_age_seconds",
            "Age of the oldest unprocessed inbound event",
            inbound_oldest_pending_age
        );
        reg!(
            r,
            "mk_tenants_inbound_blocked",
            "Tenants whose dispatch is deferred by inbound health (unverified/stale/paused)",
            tenants_inbound_blocked
        );
        reg!(
            r,
            "mk_tenants_dispatch_disabled",
            "Tenants with the tenant kill switch off",
            tenants_dispatch_disabled
        );
        reg!(
            r,
            "mk_kill_switch_global_enabled",
            "1 when global dispatch is enabled",
            kill_switch_global_enabled
        );
        reg!(
            r,
            "mk_tenants_total",
            "Tenants known to the kernel",
            tenants_total
        );
        reg!(
            r,
            "mk_key_versions_retiring",
            "Key versions in retiring state (re-encryption in progress)",
            key_versions_retiring
        );
        reg!(
            r,
            "mk_sealed_with_legacy_key",
            "1 when the active key version is the legacy single master key",
            sealed_with_legacy_key
        );
        reg!(
            r,
            "mk_audit_head_mismatches",
            "Tenants whose audit head does not match the last stored event (tail integrity check)",
            audit_head_mismatches
        );
        reg!(
            r,
            "mk_provider_live",
            "1 when MK_TWILIO_API_BASE is the live provider API",
            provider_live
        );
        Self {
            registry: Mutex::new(r),
            dispatch_outcomes,
            dispatch_duration,
            housekeeping,
            sampler_errors,
            sampler_duration,
            queue_depth,
            queue_oldest_eligible_age,
            outbox_unpublished,
            outbox_lag,
            leases_active,
            lease_oldest_age,
            dispatching,
            reconciliation_required,
            deliveries_submission_unknown,
            dead_letters,
            approvals_pending,
            approvals_expiring_1h,
            inbound_pending,
            inbound_oldest_pending_age,
            tenants_inbound_blocked,
            tenants_dispatch_disabled,
            kill_switch_global_enabled,
            tenants_total,
            key_versions_retiring,
            sealed_with_legacy_key,
            audit_head_mismatches,
            provider_live,
        }
    }

    pub fn record_outcome(
        &self,
        r: &Result<DispatchOutcome, crate::DispatchError>,
        took: Duration,
    ) {
        self.dispatch_outcomes
            .get_or_create(&OutcomeLabels {
                outcome: Outcome::of(r),
            })
            .inc();
        self.dispatch_duration.observe(took.as_secs_f64());
    }

    pub fn record_housekeeping(&self, s: &crate::housekeeping::HousekeepingStats) {
        let inc = |k: &str, n: u64| {
            if n > 0 {
                self.housekeeping
                    .get_or_create(&KindLabels { kind: k.to_owned() })
                    .inc_by(n);
            }
        };
        inc("expired", u64::try_from(s.expired).unwrap_or(u64::MAX));
        inc(
            "leases_recovered",
            u64::try_from(s.leases_recovered).unwrap_or(u64::MAX),
        );
        inc("nonces_purged", s.nonces_purged);
        inc("jtis_purged", s.jtis_purged);
        inc("challenges_purged", s.challenges_purged);
        inc(
            "stranded_requeued",
            u64::try_from(s.stranded_requeued).unwrap_or(u64::MAX),
        );
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

#[derive(Debug, Default, Clone, Copy)]
struct Agg {
    queue_depth: i64,
    oldest_eligible: f64,
    outbox_unpublished: i64,
    outbox_lag: f64,
    leases: i64,
    lease_oldest: f64,
    dispatching: i64,
    reconciliation: i64,
    sub_unknown: i64,
    dead: i64,
    approvals: i64,
    approvals_1h: i64,
    inbound_pending: i64,
    inbound_oldest: f64,
    inbound_blocked: i64,
    dispatch_disabled: i64,
    head_mismatch: i64,
}

fn age(now: DateTime<Utc>, t: Option<DateTime<Utc>>) -> f64 {
    // Ages are bounded by wall-clock spans; i64→f64 precision loss above 2^53 ms is irrelevant.
    #[allow(clippy::cast_precision_loss)]
    t.map_or(0.0, |t| (now - t).num_milliseconds().max(0) as f64 / 1000.0)
}

/// Refresh every state gauge. One tenant transaction per tenant; aggregates
/// only. Errors are counted and the previous gauge values stay (alerting on
/// `mk_metrics_sampler_errors` covers the "stale gauges" case).
pub async fn sample(store: &Store, tenants: &[TenantId], m: &WorkerMetrics, now: DateTime<Utc>) {
    let started = std::time::Instant::now();
    let mut a = Agg::default();
    let mut failed = false;
    for t in tenants {
        match sample_tenant(store, *t, now).await {
            Ok(x) => {
                a.queue_depth += x.queue_depth;
                a.oldest_eligible = a.oldest_eligible.max(x.oldest_eligible);
                a.outbox_unpublished += x.outbox_unpublished;
                a.outbox_lag = a.outbox_lag.max(x.outbox_lag);
                a.leases += x.leases;
                a.lease_oldest = a.lease_oldest.max(x.lease_oldest);
                a.dispatching += x.dispatching;
                a.reconciliation += x.reconciliation;
                a.sub_unknown += x.sub_unknown;
                a.dead += x.dead;
                a.approvals += x.approvals;
                a.approvals_1h += x.approvals_1h;
                a.inbound_pending += x.inbound_pending;
                a.inbound_oldest = a.inbound_oldest.max(x.inbound_oldest);
                a.inbound_blocked += x.inbound_blocked;
                a.dispatch_disabled += x.dispatch_disabled;
                a.head_mismatch += x.head_mismatch;
            }
            Err(e) => {
                failed = true;
                tracing::warn!(error = %e, "metrics sampler: tenant skipped");
            }
        }
    }
    match mk_store::policy::global_dispatch_enabled(store.pool()).await {
        Ok(en) => {
            m.kill_switch_global_enabled.set(i64::from(en));
        }
        Err(_) => failed = true,
    }
    match key_state(store.pool()).await {
        Ok((retiring, legacy)) => {
            m.key_versions_retiring.set(retiring);
            m.sealed_with_legacy_key.set(i64::from(legacy));
        }
        Err(_) => failed = true,
    }
    if failed {
        m.sampler_errors.inc();
    }
    m.tenants_total
        .set(i64::try_from(tenants.len()).unwrap_or(i64::MAX));
    m.queue_depth.set(a.queue_depth);
    m.queue_oldest_eligible_age.set(a.oldest_eligible);
    m.outbox_unpublished.set(a.outbox_unpublished);
    m.outbox_lag.set(a.outbox_lag);
    m.leases_active.set(a.leases);
    m.lease_oldest_age.set(a.lease_oldest);
    m.dispatching.set(a.dispatching);
    m.reconciliation_required.set(a.reconciliation);
    m.deliveries_submission_unknown.set(a.sub_unknown);
    m.dead_letters.set(a.dead);
    m.approvals_pending.set(a.approvals);
    m.approvals_expiring_1h.set(a.approvals_1h);
    m.inbound_pending.set(a.inbound_pending);
    m.inbound_oldest_pending_age.set(a.inbound_oldest);
    m.tenants_inbound_blocked.set(a.inbound_blocked);
    m.tenants_dispatch_disabled.set(a.dispatch_disabled);
    m.audit_head_mismatches.set(a.head_mismatch);
    m.sampler_duration.observe(started.elapsed().as_secs_f64());
}

async fn key_state(pool: &sqlx::PgPool) -> Result<(i64, bool), mk_store::StoreError> {
    let r = sqlx::query(
        "SELECT count(*) FILTER (WHERE status = 'retiring') AS retiring,
                count(*) FILTER (WHERE status = 'active') AS active
         FROM kernel.key_versions",
    )
    .fetch_one(pool)
    .await?;
    let retiring: i64 = r.try_get("retiring")?;
    let active: i64 = r.try_get("active")?;
    Ok((retiring, active == 0))
}

async fn sample_tenant(
    store: &Store,
    t: TenantId,
    now: DateTime<Utc>,
) -> Result<Agg, mk_store::StoreError> {
    let mut tx = store.begin(t).await?;
    let c = tx.raw_conn();
    let tid = t.0;
    let mut a = Agg::default();
    let r = sqlx::query(
        "SELECT
           count(*) FILTER (WHERE state = 'queued')                  AS queued,
           count(*) FILTER (WHERE state = 'dispatching')             AS dispatching,
           count(*) FILTER (WHERE state = 'reconciliation_required') AS reconciliation
         FROM kernel.actions WHERE tenant_id = $1",
    )
    .bind(tid)
    .fetch_one(&mut *c)
    .await?;
    a.queue_depth = r.try_get("queued")?;
    a.dispatching = r.try_get("dispatching")?;
    a.reconciliation = r.try_get("reconciliation")?;
    let r = sqlx::query(
        "SELECT count(*) FILTER (WHERE published_at IS NULL) AS unpublished,
                min(available_at) FILTER (WHERE published_at IS NULL AND available_at <= $2) AS oldest_unpublished,
                min(available_at) FILTER (WHERE available_at <= $2 AND EXISTS (
                    SELECT 1 FROM kernel.actions a WHERE a.tenant_id = o.tenant_id AND a.action_id = o.action_id AND a.state = 'queued')) AS oldest_eligible
         FROM kernel.outbox_events o WHERE tenant_id = $1",
    )
    .bind(tid)
    .bind(now)
    .fetch_one(&mut *c)
    .await?;
    a.outbox_unpublished = r.try_get("unpublished")?;
    a.outbox_lag = age(now, r.try_get("oldest_unpublished")?);
    a.oldest_eligible = age(now, r.try_get("oldest_eligible")?);
    let r = sqlx::query("SELECT count(*) AS n, min(acquired_at) AS oldest FROM kernel.execution_leases WHERE tenant_id = $1 AND expires_at > $2")
        .bind(tid)
        .bind(now)
        .fetch_one(&mut *c)
        .await?;
    a.leases = r.try_get("n")?;
    a.lease_oldest = age(now, r.try_get("oldest")?);
    a.sub_unknown = sqlx::query_scalar("SELECT count(*) FROM kernel.message_deliveries WHERE tenant_id = $1 AND state = 'submission_unknown'")
        .bind(tid)
        .fetch_one(&mut *c)
        .await?;
    a.dead = sqlx::query_scalar(
        "SELECT count(*) FROM kernel.dead_letters WHERE tenant_id = $1 AND replayed_as IS NULL",
    )
    .bind(tid)
    .fetch_one(&mut *c)
    .await?;
    let r = sqlx::query(
        "SELECT count(*) AS n, count(*) FILTER (WHERE expires_at <= $2 + interval '1 hour') AS soon
         FROM kernel.approvals WHERE tenant_id = $1 AND decision = 'approved' AND consumed_at IS NULL AND revoked_at IS NULL AND expires_at > $2",
    )
    .bind(tid)
    .bind(now)
    .fetch_one(&mut *c)
    .await?;
    a.approvals = r.try_get("n")?;
    a.approvals_1h = r.try_get("soon")?;
    let r = sqlx::query("SELECT count(*) AS n, min(received_at) AS oldest FROM kernel.inbound_events WHERE tenant_id = $1 AND processed_at IS NULL")
        .bind(tid)
        .fetch_one(&mut *c)
        .await?;
    a.inbound_pending = r.try_get("n")?;
    a.inbound_oldest = age(now, r.try_get("oldest")?);
    let disabled: Option<bool> = sqlx::query_scalar("SELECT dispatch_enabled FROM kernel.kill_switches WHERE scope = 'tenant' AND tenant_id = $1")
        .bind(tid)
        .fetch_optional(&mut *c)
        .await?;
    a.dispatch_disabled = i64::from(disabled == Some(false));
    a.inbound_blocked = i64::from(
        mk_store::messaging::inbound_dispatch_block(&mut tx, now)
            .await?
            .is_some(),
    );
    a.head_mismatch = i64::from(!mk_store::audit::head_consistent(&mut tx).await?);
    tx.rollback().await?;
    Ok(a)
}

/// Serve `/metrics` (and `/health`) on `bind`. Loopback by default; the
/// orchestrator scrapes it over the private network.
pub async fn serve(bind: &str, metrics: std::sync::Arc<WorkerMetrics>) -> anyhow::Result<()> {
    use axum::{Router, routing::get};
    let app = Router::new()
        .route(
            "/metrics",
            get(move || {
                let m = metrics.clone();
                async move {
                    (
                        [(
                            axum::http::header::CONTENT_TYPE,
                            "application/openmetrics-text; version=1.0.0; charset=utf-8",
                        )],
                        m.encode(),
                    )
                }
            }),
        )
        .route("/health", get(|| async { "ok" }));
    let listener = tokio::net::TcpListener::bind(bind).await?;
    axum::serve(listener, app).await?;
    Ok(())
}
