# Recovery of withdrawn kernel authority

Source: `6b91a10708db6ed2c5c3ae4bdf2e7854d03f54ea`. Author-run local synthetic
fixtures; no live provider call, production mutation, independent verifier record
or merge.

## Observed outcomes

- **Failed, reproduced:** restore returned PASS while a revoked permission,
  approval credential, adapter or old rotated adapter key became usable again.
  The approval credential could request an operator step-up challenge (HTTP 200
  instead of 412). `authority-restore-red-v2.*` retains all four failures. The
  earlier `red.*` contains two genuine failures plus two adapter-fixture response
  parsing errors; the fixture was corrected before the four-case reproduction.
- **Failed, reproduced:** the first draft recovery restored its version fence
  but left the old action queued. `authority-expanded-v1.*` retains that failure
  and eight passing authority controls. Replay now invokes the existing draft
  invalidation/cancellation path and checks that no cancellable action remains.
- **Worked:** kernel ledger v3 binds withdrawals to minimal immutable-identity
  digests and original cutoff times. It preserves contact-permission, approval
  credential, adapter, adapter-key and draft withdrawals. Recovery-only fences
  retain obligations for absent objects/tenants without recreating credentials.
  SQL guards refuse reused IDs, reopened authority, relaxed or removed fences.
  Versions 1/2, malformed data, omissions and identity conflicts are refused.
- **Worked:** 90 PostgreSQL/cross-service/billing checks, including 39 kernel
  restore cases: restored/absent objects and tenants, source withdrawal APIs,
  credential eligibility, repeat/re-export, omission/conflict refusal, rollback
  after writes, role/RLS boundaries, immutable fences and stale-write refusal.
  One upstream Starlette deprecation warning remains. The extra database-timezone
  check passed without a production repair; its provisional `timezone-red.*`
  filename is not a failure classification.
- **Worked:** 239 Rust workspace tests on a fresh disposable database; 15 final
  store unit tests; Clippy all targets/features with warnings denied; 139
  deployment/image-security checks. The first Clippy run caught unit-test unwraps;
  tests now propagate setup errors, without lint waivers. The disposable database
  was removed after successful execution; cleanup receipt is retained.
- **Worked:** built kernel image actual pg_dump/restore retains three authority
  fences (permission, adapter, adapter key), plus opt-out/session restrictions and
  deletion fences. It refuses missing ledgers/future freshness pins, preserves
  revoked/expired authority and leaves dispatch disabled. Provider simulator
  kill/restart recovery still yields two DELETEs, zero sends, one active receipt
  and a separately pending backup obligation. Fixture resources were removed.
- **Worked:** image `sha256:64880679a9028b13db0be71e96b29797c363d7d1cfcf91dda9c3165b85432542`;
  migration count 21; scan 0 critical, 0 high, 23 medium, 8 low. Full scan/SBOM
  and runtime reports are retained.
- Prior restriction-recovery head `674fec2` passed all 11 CI jobs. Its two CI
  receipts are retained here; they do not describe this new source commit.

`authority-readiness.json`: **NOT READY, 0/87 closed**. Remaining recovery work
includes application sessions/security state, sender and policy state; independently
operated staging/production evidence, custody and release authorization remain
governed requirements. `authority-sha256.json` binds this batch's retained evidence
and failed attempts to the source/image, excluding its own digest.
