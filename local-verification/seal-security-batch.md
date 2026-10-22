# Application sealing-key rotation — S10 engineering batch

Application source `650b407d5d504918e07fc02a221097e4b931bf94`;
restore-verifier/runbook follow-up `94234cc8eb138e756460890996e3abc7c66b6009`.
2026-10-22, PR37. Author-run engineering, not independent release qualification.

## Implemented and measured

- `APP_SEAL_KEYS` selects versioned, tenant/user/purpose/session-bound AES-GCM
  envelopes independently of fingerprint keys. Unlisted/retired ids never fall
  back to MASTER_KEY. Six malformed-configuration cases fail closed; tampering
  with the key id fails even when two ids carry the same key material.
- All nine encrypted model columns are in an executable inventory. Rekey uses
  bounded, audited compare-and-swap batches; a newer concurrent secret is retained
  and reported as a conflict. Unreadable ciphertext remains intact and prevents
  a clean retirement verdict. Repeated successful rekey changes zero rows.
- PostgreSQL migration 0002 adds an operator-owned write policy. All nine fields
  refuse obsolete writers. Runtime cannot edit that policy. Activation waits
  for an already-writing transaction; an old writer waiting behind activation
  reads the new fence and is denied. Repeatable-read ciphertext writes cannot
  use an old policy snapshot. Startup checks the configured writer; an old live
  process's refused write is a content-free 503 with no saved change.
- **339 Python tests passed**, no skips (`seal-python-650b407.xml`). This includes
  the previous fingerprint/suppression tests, independently of sealing rotation.
- **19 real PostgreSQL tests passed**, no skips (`seal-postgres-650b407.xml`),
  including the preceding DB-role tests, all-nine-field rotation/denials and
  both actual lock races. A real CLI process was SIGKILLed after committed
  batches over **4,009 encrypted values**; a new process resumed the remainder,
  and a scan with the old key removed decrypted all 4,009 values. The dedicated
  kill run is also retained (`seal-kill-v1.xml`).
- Built image
  `sha256:e846cae2dc699b1c174ca91fd41cfbc779ca6875fe60d023dacf248ab1bba5d2`
  ran non-root/read-only with dropped capabilities. Real HTTP MFA and exports
  passed; after activation an already-running old-key server returned 503;
  the rekey CLI updated the provider key and active MFA seed; new-key-only
  runtime kept the existing session usable (200) and verified TOTP (200).
  Readback: one retained customer, 11 audit records, actual runtime identity
  `mk_app_login`. See `seal-image-restore-v2/report.json`.
- A real `pg_dump` custom-format backup taken before rotation was restored with
  `pg_restore` into a separate disposable database. New-key-only scanning found
  two unreadable old-key values as expected. Controlled recovery-key access,
  activation and rekey recovered both; the final new-key-only scan has zero
  stale/unreadable/conflicting values. Backup bytes/hash are in the report; the
  synthetic backup stayed in process memory, not a public artifact.
- All image-drill databases, containers and networks were removed. No real
  provider, AWS resource, customer data or shared database was changed.
- OpenTofu validation passed. Predecessor source `49f42ee` passed all **ten** CI
  checks, including the added real PostgreSQL job; metadata is retained as
  `seal-predecessor-*-ci.json`. Current source CI is tracked separately.

## Failures preserved and repaired

Initial tests reproduced ignored sealing-key selection and continued legacy
decryption after intended retirement (`seal-initial-red.xml`). The first SQL
function migration exposed the driver's empty-parameter-map treatment of literal
`%ROWTYPE`; migrations now execute raw SQL without interpolation
(`seal-migration-v1.xml`, repaired `seal-migration-v2.xml`). An over-broad unused
variable cleanup broke the existing environment/Ollama provider fallback; the
four regression failures in `seal-python-v2.xml` are retained, and the required
settings variable is restored in the 339-test source-pin run.

The first source-pin restore attempt was correctly refused because a new database
retained default PUBLIC TEMP privileges: pg_dump without database creation does
not copy database-wide ACL revocations. The verifier now measures TEMP=true,
reapplies operator bootstrap, measures TEMP=false, then performs the key-escrow
drill. That repaired run is separately labelled, not substituted for the earlier
failure (`seal-image-650b407/` versus `seal-image-restore-v2/`).

The runbook covers staged readers, maintenance, write fencing, escrow and guarded
restore. This local drill does not represent real KMS rotation, production
recovery, or independent incident-response sign-off. Those remain required
release work; no acceptance row is closed by this report.

`seal-security-manifest.json` binds retained artifacts to the source/verifier pins.
