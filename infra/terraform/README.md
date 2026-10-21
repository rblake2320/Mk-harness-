# Infrastructure as code — AWS hosting (contract D5, O1)

**Status: Implemented, not applied.** This tree has never been applied to an
AWS account by the author or anyone else; no environment exists. The rows D5
and O1 of `docs/production-acceptance.md` stay **Not demonstrated** until a
staging apply succeeds, the smoke suite runs against it, and a second person
records that run under `evidence/releases/`. What this tree *does* establish is
that the topology the contract requires is specified as code, with the
guardrails enforced at plan time rather than in prose.

## Layout

```
infra/terraform/
  modules/kernel-platform/   one module = one environment (VPC, RDS, Redis, ECS, ALB/WAF, KMS, Secrets Manager, S3, AMP, alarms)
  envs/staging/              separate account + state; provider adapter points at the simulator
  envs/production/           separate account + state; requires the audit-root bucket of a THIRD (audit) account
```

## What it provisions (module `kernel-platform`)

| Contract item | Resource(s) | Notes |
|---|---|---|
| Separate prod / staging | one root per env, separate S3 state, `environment` variable drives guardrails | staging cannot target `https://api.twilio.com` unless `allow_live_provider_in_staging` is set for a supervised qualification run |
| ECS/Fargate across 2 AZs, ≥2 API, ≥2 worker | `aws_ecs_service.svc` for kernel_api, kernel_worker (validated ≥2), kernel_relay (2), app (2); circuit-breaker rollback | read-only rootfs, caps dropped, non-root UID 65532, no `execute-command` |
| Multi-AZ PostgreSQL with PITR | `aws_db_instance.kernel`: multi_az, KMS at rest, `rds.force_ssl`, 35-day backups in prod, deletion protection, enhanced monitoring, PI | per-process DB logins still come from `deploy/kernel/roles.sql` (run by the migrator task) |
| Replicated managed Redis | `aws_elasticache_replication_group.queue`: 2 nodes, multi-AZ failover, TLS + at-rest | snapshots deliberately **off**: Redis is never restored; the outbox republishes (drill F5) |
| Private data networking | public / private / data subnet tiers; data tier has no route out; interface endpoints for Secrets Manager, KMS, ECR, logs, STS; S3 gateway endpoint; reject-flow logs | kernel API reachable only from app tasks (/internal) and the ALB (/webhooks) by security group |
| Encrypted object storage for evidence | `aws_s3_bucket.evidence`: versioned, SSE-KMS, Object Lock (COMPLIANCE 7 y in prod), lifecycle to Glacier-IR; tasks may put but never delete | |
| Independently protected audit-root destination | cross-account replication to `audit_root_bucket_arn` encrypted with the audit account's KMS key; production **refuses to plan** without it | the audit account itself is out of scope here (one bucket, one key, deny-delete policy, no roles assumable from prod) |
| Managed secrets + KMS envelope | three CMKs (data, secrets, logs) with rotation; ten **empty** Secrets Manager secrets; task roles may read only their own | Terraform never holds a secret value; values are set out of band after apply |
| HTTPS ingress with rate limiting | ALB TLS 1.3 policy, ACM cert, WAF rate rule 2000/5 min/IP + AWS common rules; only `/webhooks/*` routes to the kernel; the kernel host answers 404 otherwise | |
| External uptime checks | Route 53 health check on the application’s `/api/health/ready` (DB + kernel readiness) + CloudWatch alarm → SNS | measures the real path, not the kernel's liveness endpoint alone |
| Observability wiring | Amazon Managed Prometheus workspace with `deploy/observability/alerts.yml` loaded as a rule namespace; Alertmanager → SNS; RDS/Redis saturation alarms | the scrape collector (ADOT) task is **not** in this tree yet |
| Versioned containers | `kernel_image` / `app_image` must be digest-pinned (`@sha256:`) — tags are rejected at plan time | |
| Automated gated deployment | **not here** — see `.github/workflows/` (CI) and the enable sequence in `deploy/kernel/README.md`; a deploy pipeline that applies this tree does not exist yet |

## Deliberate non-defaults, stated plainly

* `RUST_ACTION_KERNEL_ENABLED` is **not** set in any task definition. Enabling
  dispatch is the release owner's manual step with a passkey (kill switch).
* `MK_LEGACY_SEAL_RETIRED=1` is set: a fresh environment starts with
  `mk-keyctl rotate "initial"` under `MK_KEK` and never seals with the bare
  master key.
* Database URLs are composed inside the binaries from `MK_DB_HOST` /
  `MK_DB_USER` / `MK_DB_PASSWORD` (`mk_store::database_url_from_env`), so a
  password never appears in a task definition.
* The ECS health probe is `mk-healthcheck` (shipped in the image) because the
  distroless image has no shell or curl.

## Applying (first time, staging)

1. Create the state bucket + lock table in the staging account; replace
   `REPLACE_ACCOUNT_ID` in `envs/staging/main.tf`.
2. `terraform init && terraform plan -var kernel_image=…@sha256:… -var app_image=…@sha256:… -var alert_email=…`
3. `terraform apply`; add the ACM DNS validation records it outputs.
4. Populate the ten secrets (`aws secretsmanager put-secret-value`).
5. Run the migrator task (`MK_RUN_MIGRATIONS=1`, roles.sql, `mk-keyctl rotate initial`).
6. Deploy the ADOT collector, then follow `deploy/kernel/README.md` → bring-up.
7. Run `scripts/kernel-live-smoke.sh` against the environment and record it.

## Validation performed by the author

`tofu fmt -check` and `tofu validate` (OpenTofu 1.10, AWS provider 5.x) on the
module and both roots — syntax, references and type checks only. No `plan`
against a real account has been run.
