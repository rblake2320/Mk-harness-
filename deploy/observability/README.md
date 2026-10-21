# Observability (contract O6, O7)

| Artifact | What it is | Status |
|---|---|---|
| `mk-action-api /metrics` | OpenMetrics: `mk_requests` (by matched route template + status), `mk_request_duration_seconds`, `mk_policy_decisions`, `mk_assertion_failures` (incl. `WEBHOOK_*` codes), `mk_hmac_failures`, `mk_callbacks_*`, `mk_inbound_events` by disposition | Implemented; asserted in `mk-api` e2e (`http_e2e.rs`) |
| `mk-action-worker` `MK_METRICS_BIND` (default `127.0.0.1:9100`) | inline: `mk_dispatch_outcomes`, `mk_dispatch_duration_seconds`, `mk_housekeeping`; sampled every `MK_METRICS_SAMPLE_SECS` (15 s) across tenants, aggregates only: queue depth, oldest eligible age, outbox lag, leases, dispatching, reconciliation required, submission unknown, dead letters, approvals pending/expiring, inbound pending/oldest age, tenants inbound-blocked / dispatch-disabled, global switch, key versions, audit head mismatches (O(1) tail check), `mk_provider_live` | Implemented; asserted in `mk-worker` e2e (`dispatch_e2e.rs`), including the "no identifier in exposition" check and a tampered-head detection |
| `alerts.yml` | 19 Prometheus rules covering every O7 paging condition that the exported metrics can express; each names a runbook | Implemented |
| `alerts_test.yml` | `promtool test rules` unit tests: 11 scenarios, every paging rule fires on injected series and stays silent on the healthy counterpart | Implemented; run in CI (`observability` job) |
| `dashboards/kernel.json` | Grafana dashboard (safety state, API availability/latency with O3 targets, queue/dispatch, provider/inbound, sampler health) | Implemented; not reviewed against a live Prometheus |
| OpenTelemetry traces | — | **Not demonstrated** (tracing is structured JSON logs with request ids; no OTLP exporter yet) |
| DB/Redis/resource saturation, cost anomalies | from the hosting layer (RDS/ElastiCache/ECS exporters) | **Not demonstrated** (depends on `infra/`, see D5/O1) |
| On-call rota, 15-min ack, primary + backup operator | people, not code | **Not demonstrated** |

## Scrape configuration

```yaml
scrape_configs:
  - job_name: mk-api
    static_configs: [{ targets: ["kernel-api:8090"] }]          # /metrics on the API bind
  - job_name: mk-worker
    static_configs: [{ targets: ["kernel-worker:9100"] }]       # MK_METRICS_BIND=0.0.0.0:9100 inside the task
rule_files: [ "alerts.yml" ]
```

Add an `environment` external label (`production` / `staging`); the
`MKDispatchEnabledOnStaging` rule depends on it.

## What a paging alert means

Every `severity: page` rule is either an integrity signal (unapproved send,
audit mismatch, cross-tenant 5xx, key rotation stalled) or a customer-visible
flow failure (inbound outage, opt-out backlog, eligible queue age, error rate,
component down). Acknowledge within 15 minutes, open the named runbook, and
**disable dispatch first** whenever the signal is an integrity one.

## Cardinality rules

No tenant, action, contact, user or worker identifier is ever a label. Routes
are labelled by matched template (`/internal/v1/actions/{action_id}`), never by
concrete path. Outcome / decision / disposition labels are closed enums. The
e2e tests assert this for both processes.

## Testing the rules locally

```sh
promtool check rules deploy/observability/alerts.yml
promtool test  rules deploy/observability/alerts_test.yml
```
