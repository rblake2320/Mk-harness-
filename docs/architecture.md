# Architecture (D5) — target production topology and component responsibilities

**Status:** recorded 2026-10-20 (WP02). Infrastructure as code: WP09 (`infra/`). Rows D5, O1.

## Components and authority

```
 Consultant (responsive web, mobile-first)
   │ HTTPS, session + passkey
   ▼
 FastAPI application ───────────────────────────────┐
   customers, consent/suppression records, imports,  │ proposes (Ed25519 assertion)
   commitments, brief, drafts, outcomes, UI, AI      │ relays approval (WebAuthn assertion)
   NO sending credential, NO execution authority     ▼
                                           Rust action kernel (mk-action-api / relay / worker)
                                             policy · exact-digest approval · outbox → Redis Streams
                                             dispatch-time recheck · provider adapter · audit chain
                                                │ egress allowlist                 ▲ signed webhooks
                                                ▼                                  │
                                           Twilio Programmable Messaging ──────────┘
                                             (dedicated registered number per consultant business)
```

- **Authoritative state:** PostgreSQL (Multi-AZ, PITR). Redis Streams accelerates dispatch
  and is never the only durable record of an approved action (outbox in Postgres).
- **AI layer** (bounded extraction + drafting) runs inside the application tier with no
  kernel credential; its outputs are data.
- **Audit roots** are anchored to an independently protected destination (S14).

## Hosting (AWS, US)

| Layer | Production | Staging |
|---|---|---|
| Compute | ECS/Fargate, 2 AZs; ≥2 API tasks, ≥2 worker tasks, ≥1 relay task, scheduled verifier task | same shape, smaller |
| Database | RDS PostgreSQL Multi-AZ, PITR, 35-day backups, per-process IAM/password logins | separate instance |
| Queue | ElastiCache Redis with replication | separate |
| Secrets | AWS Secrets Manager; KMS CMKs for envelope encryption (message bodies, adapter credentials, tenant material) | separate keys |
| Evidence/object storage | S3, SSE-KMS, versioning, object lock for audit-root anchors | separate bucket |
| Ingress | ALB + WAF rate limiting; TLS 1.2+; private subnets for data services | same |
| Observability | Prometheus-compatible scrape (AMP) + OpenTelemetry traces + dashboards + alert routing to on-call | same |
| Uptime | external synthetic checks of the core workflow (not only /health) | — |

## Environments and promotion

`main` → build (digest-pinned, signed provenance) → staging deploy with dispatch disabled →
pre-flight (`scripts/kernel-preflight.sh`) → controlled smoke → cohort enable. Production
follows the same gate list (O8). No deployment from a laptop build.

## Data classification (summary; full map in `docs/data-retention-and-deletion.md`)

| Class | Examples | Storage | Telemetry |
|---|---|---|---|
| Customer PII | destinations, names, message bodies | encrypted fields (KMS envelope), tenant-scoped | never |
| Consent/suppression evidence | consent records, STOP events | Postgres + separately protected ledger | ids only |
| Audit | event types, digests, actor ids | append-only chain, anchored | ids/digests only |
| Operational | metrics, traces, logs | observability stack | no PII labels |
