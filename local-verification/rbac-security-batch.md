# Scoped tenant roles — S3 engineering batch

Source `e568336c17eccba2b6a7726dfff740b8216411bc`, 2026-10-22, PR37.
Author-run local verification, not independent release qualification.

- Unknown stored roles fail closed instead of becoming consultant/agent kernel
  principals. Managers get team review/usage but no member administration;
  auditors get a narrow route allowlist and cannot obtain kernel authority.
- Admin member changes require fresh password/MFA, lock the tenant, recheck the
  acting administrator and target scope, revoke every target session, enqueue
  durable kernel revocations, and record before/after audit. Self-demotion and
  self-disable are refused. Concurrent administrators disabling each other leave
  exactly one active administrator; foreign targets return 404.
- Web member controls and auditor-only navigation reflect server permissions.
  Native auditor controls were added and TypeScript checked, not device-tested.
- Initial red tests (`rbac-initial-red.xml`) reproduced unrestricted stored-role
  access and missing scoped member management. Six targeted role scenarios now
  pass, including a sweep of more than 70 protected route operations and the
  two-administrator race (`rbac-races-v1.xml`).
- **318 Python tests passed, zero skips**, at the source pin
  (`rbac-python-e568336.xml`). Intermediate runs are retained under their own
  names. **27 web tests passed**, production build and Expo typecheck passed;
  `rbac-web-v1.json` was produced from this source content before the commit.
- Real loopback app/kernel/Postgres and native Python Playwright
  (`rbac-browser-e568336/rbac-browser.json`): UI role change requested fresh
  password/MFA; old member access and refresh returned 401; new auditor customer
  and kernel access returned 403; scoped audit export returned 200 and contained
  the role-change event. Zero page errors, viewport/document width 360/360.
  The retained mobile-width screenshot was visually inspected.
- Source-pin stack readback: 7/7 outbox revocations confirmed in the kernel,
  8 sessions / 7 revoked. Owned processes stopped and the private database was
  removed (`rbac-stack-e568336/stack-summary.json`). No shared database reset.
- CI at predecessor `026f502` failed because production preflight still used
  password-only login. The failure is retained in
  `rbac-prior-ci-smoke-failure.log`. `93a2842` adds a verified-session or explicit
  operator second-factor preflight, refuses automatic enrollment, and validates
  the live session; five targeted tests pass (`preflight-mfa-targeted.xml`).

The separate application database-runtime/migration privilege gap is the next
engineering task. No row is closed by this batch. The manifest binds these
author-run artifacts without relabelling them as staging or independent proof.
