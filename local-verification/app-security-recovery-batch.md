# Application security recovery — author-run engineering evidence

Source: `ac14c4e77b550ef89614a5e76cf1fc3659dece8c` on the draft PR37 branch.
This is not independent staging evidence or release closure. Readiness remains
**0/87 closed**; no qualifying release YAML was manufactured.

- **Failed, reproduced:** deletion-only replay after actual pg_dump/pg_restore
  reauthorized all four tested old sessions: logout, password change, demotion
  and disabled account (HTTP 200 instead of 401). Retained
  `app-security-restore-red-v2.log/.xml`. The first red run also contained three
  fixture step-up mistakes; those were repaired before the four genuine reds.
  Three synthetic bearer-token renderings in that first output were explicitly
  redacted; the small redaction receipt preserves that fact.
- **Worked:** separately encrypted X25519/HKDF/AES-GCM current-security archive,
  bound to the exact public erasure ledger, schema, recipient and independent
  digest/freshness pins. Paired export is one repeatable-read source cut. Public
  erasure exports do not gain profiles, password verifiers or MFA secrets.
- **Worked:** controlled operator-only atomic replay, current account/MFA state,
  post-backup accounts and session obligations, cleared pending enrollment and
  invalidation of all known sessions. Immutable generation/target/input receipts
  and SQL fences block reopening old sessions. Repeat replay never overwrites
  post-recovery credentials. New generations require fresh kernel receipts.
- **Worked:** 17 dedicated actual-PostgreSQL recovery cases, within **107 passing
  PostgreSQL/integration checks** (`app-security-full-postgres-v2.*`). Coverage
  includes password/logout/demotion/disable, factor and recovery-code rotation,
  consumption/lockout, refresh rotation, pending enrollment, missing-backup
  accounts/sessions, input conflicts, dry-run, SQL immutability and a deliberate
  failure after credential writes proving whole-transaction rollback. The first
  full run caught an old fixture trying to delete an immutable receipt table;
  the fixture now preserves protected tables. Targeted and full reruns passed.
- **Worked:** the actual signed HTTP app-to-Rust bridge revokes restored and
  post-backup sessions, which then receive HTTP 401. An unrelated session still
  reaches normal policy handling. Repeat delivery is idempotent; a second
  generation cannot reuse previous confirmations. Readiness fails immediately
  while recovered revocations are pending. A late HTTP success cannot confirm
  a newer generation's delivery lease.
- **Worked:** **480** app/contract/readiness/image-security tests, **46** targeted
  cryptography/session tests (a subset), **139** deployment/image gate checks,
  workflow lint and source whitespace validation. The archive rejects digest,
  recipient, nonce/ciphertext, schema, version, privacy binding, freshness,
  duplicate/unknown-field, type, ownership and bounded-size violations. Earlier
  unit fixture import/email-reuse errors and an invalid lockout-test input are
  retained alongside their repaired reruns. One upstream Starlette deprecation
  warning remains; no tests were waived.
- **Worked:** final shipped app image
  `sha256:cdaa55609924164a60857546956022977f654724b4cc4855dec75c8b666770f5`
  runs non-root, read-only and capability-dropped against distinct PostgreSQL
  roles. Actual source-container stop precedes packaged export. Packaged replay
  erases restored content and preserves post-backup billing cleanup without
  recreating the billing intent. Two session fences remain pending with no
  kernel configured; packaged `check` and runtime-only `deliver` exit 2, record
  zero deliveries and never report security readiness. All owned image-drill
  resources were removed. See `app-security-image-runtime-v2/report.json`.
- **Worked:** final image scan/SBOM: **71 components, zero vulnerabilities at all
  severities** (`app-security-image-scan-v2/`). Ciphertext, public synthetic
  ledger and digests are retained; the ephemeral synthetic private recovery key
  was not retained or printed. Earlier image v1 predates the standalone delivery
  command and is retained separately, not substituted for final v2 evidence.
- The previous authority-recovery head `b9d328f` passed all 11 CI jobs; both
  receipts are retained as `authority-{app,kernel}-ci-v1.json`. They describe
  that previous head, not this new source commit.

Remaining release work includes sender/policy recovery and the independently
operated staging/production, custody, main-branch and human qualification gates.
This batch does not merge, deploy, open ingress, enable dispatch or send traffic
to any real provider/recipient.
