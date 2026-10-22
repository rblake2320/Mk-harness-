# Post-backup opt-out and principal restriction recovery

Source: `0abace63c4f960cf9a0dc346c3470ba29e1eaf5d`. Author-run, synthetic local
fixtures only. No live provider request, production change, independent release
record, or merge was performed.

## Observed outcomes

- **Failed, reproduced:** all three original cases restored an older real
  PostgreSQL backup and received restore-gate PASS while a later opt-out, session
  revocation or user revocation was absent. `restriction-restore-red.*` retains
  those failures. The first repair retest exposed a missing migration registration
  (API 500); `restriction-restore-green-v1.*` retains that failed attempt despite
  its provisional filename. Registration was corrected; no check was waived.
- **Worked:** kernel ledger v2 exports content-free restriction identities,
  validates the complete document, replays active destination/channel/tenant
  opt-outs and user/session revocations atomically, and checks enforcement.
  Session digests are tenant/user-bound and checked at authentication and dispatch.
  Version 1, malformed shapes, missing retained restrictions and identity
  conflicts are refused. Replay never enables dispatch.
- **Worked:** 29 dedicated real-API/pg_dump/pg_restore controls, including tenants
  absent from backup, targeted versus unaffected sessions/users/tenants,
  suppression policy refusal, dry-run, repeat/re-export, immutable runtime
  privileges, SQL shape rejection and mid-replay rollback. Final broader
  PostgreSQL/cross-service/billing suite: **80 passed**, one upstream Starlette
  deprecation warning. `restriction-postgres-v1.*` uses final rebuilt binaries.
- **Worked:** 238 Rust workspace tests; 14 final store unit retests after separating
  pending-content and pending-restriction report counts; Clippy all targets and
  features with warnings denied; 139 deployment/image-security controls.
- **Worked:** actual rebuilt image pg_dump/restore retained one post-backup
  opt-out and one session revocation with no raw session restored. No external
  ledger and future freshness cutoff were refused; dispatch stayed disabled.
  The provider simulator process-kill/restart drill retained one active receipt,
  with two DELETEs, zero sends and a separate backup obligation still pending.
  Audit/metric/log canaries were absent; owned fixture resources were removed.
- **Worked:** final kernel image `sha256:67f077f3c1bbc8f966001aa367e8b6a8617c33ea63cead168c39bd8aaac3552e`;
  scan: 0 critical, 0 high, 23 medium, 8 low. Full findings and SBOM are retained.
  The earlier image-build-v1 preceded the report-field refinement; v2 is final.
- Prior billing-restoration head `991ac76` completed all **11 CI
  jobs** (5 application, 6 kernel) successfully. Those CI receipts apply to that
  prior head, not this source commit.

`restriction-readiness.json` remains **NOT READY, 0/87 closed**. Remaining work
includes other authority-revocation recovery and the separately governed live
staging/production, custody, independent verification and release authorization.
This batch does not substitute local author tests for those row requirements.

`restriction-sha256.json` binds the retained batch artifacts (including failed
attempts), source commit and final image ID. It excludes its own digest.
