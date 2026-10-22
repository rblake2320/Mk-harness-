# Application account-security recovery (S2 / O9)

The application erasure ledger alone cannot recover password changes, MFA
rotation, disabled accounts, role changes or logged-out sessions accepted after
a backup. Use the paired recovery export below. Kernel ledger v3, sender/policy
reconciliation, provider reconciliation and release-owner authorization remain
separate requirements. No command here opens ingress or enables dispatch.

## Source cut and independent custody

1. Stop source intake and **all** security, billing and cleanup writers. Identify
   the authoritative source and record a synchronized UTC cutoff before export.
   `--quiesced` is an operator acknowledgment, not an automatic stop mechanism.
2. Supply the ordinary restricted application database identity and a separately
   provisioned X25519 public recovery key in `MK_SECURITY_RECOVERY_PUBLIC_KEY`
   (32 bytes, lowercase hex). The source does not need the private recovery key.
3. Export both files in the same repeatable-read, read-only transaction:

```sh
python -m app.tools.security_restore export \
  --privacy-ledger /protected/application-privacy.json \
  --security-ledger /protected/application-security.enc --quiesced
```

The public ledger stays content-free. The second file is an AES-GCM encrypted
archive containing current account profiles, password verifiers, encrypted MFA
factors, consumed recovery-code digests and session identity bindings. Treat it
as sensitive backup material: restrictive access, independently governed
retention, and a recovery private key held separately from source/backups. The
CLI creates files without overwrite, requests Unix mode 0600, and emits only
digests/status. Windows operators must enforce an equivalent directory ACL.

Retain **both** returned SHA256 values, source identity, original cutoff and
approved recovery recipient in the independent recovery record. Public-key
encryption does not authenticate an exporter; adjacent checksum files are not
independent custody. The encrypted header binds the exact privacy ledger digest,
shipped migration set, recipient and export time. Do not re-label older formats,
invent an empty export from the backup, or weaken a freshness refusal.

## Controlled restore

Restore into a new target with public ingress and all outbound dispatch disabled.
In-place recovery that reuses the old database identity/generation is unsupported.
Run the shipped forward migrations first. Use a controlled migration/operator
URL in `MK_SECURITY_RESTORE_DATABASE_URL`; the API must never receive it. Supply
the separately held `MK_SECURITY_RECOVERY_PRIVATE_KEY` and source application
seal-key ring (`APP_SEAL_KEYS` / supported `MASTER_KEY`) through secret injection,
not command arguments or logs. Record a fresh 32-character lowercase UUID-hex
recovery generation ID **outside the restored backup**.

```sh
python -m app.tools.security_restore replay \
  --privacy-ledger /protected/application-privacy.json \
  --security-ledger /protected/application-security.enc \
  --privacy-sha256 "$PRIVACY_PIN" --security-sha256 "$SECURITY_PIN" \
  --not-before "$SOURCE_CUTOFF" --recovery-id "$RECOVERY_ID"
# Review VALIDATED_ONLY, then repeat exactly with --apply --quiesced.
```

The operator takes migration/recovery exclusion locks, verifies schema/checksums,
validates complete identities and MFA key availability, then atomically replays
erasure and current security state. SQL erasure fences stay enabled. Current
accounts created after the backup can be reconstructed; erased accounts stay
anonymized/disabled. Pending enrollments are cleared. Every restored or
source-known session is invalidated, including sessions absent from the backup.
Refresh tokens do not survive; users must authenticate again with current
password/MFA state. SQL fences block reopening recovered session IDs even through
older application code. Any failure rolls back all writes.

An immutable operator-only receipt binds input digests, target host/port/database
and database OID, generation ID, and the exact session set. Use the same endpoint
spelling for replay/check/delivery. Repeating the same generation is idempotent
and never overwrites credentials changed after recovery. A different recovery
generation resets downstream revocation proof; an older generation cannot reuse
its confirmations. Exporting a restored source retains its session fences.

## Kernel receiving proof before readiness

`applied:true` initially reports `PENDING_KERNEL_REVOCATIONS`, not restore success.
Bring up only the internal kernel endpoint with dispatch disabled. Supply the
ordinary app runtime DB credential and route-scoped kernel signing configuration
to the delivery process; it needs neither the archive private key nor operator
database privileges:

```sh
python -m app.tools.security_restore deliver \
  --privacy-sha256 "$PRIVACY_PIN" --security-sha256 "$SECURITY_PIN" \
  --recovery-id "$RECOVERY_ID"
```

One invocation attempts at most 50 due outbox entries. Exit 2 means pending;
repeat respecting the retained retry/backoff schedule, or run the ordinary
revocation worker on the isolated network. Missing kernel configuration,
timeouts, malformed responses and lost delivery leases retain pending work.
Receipt recording uses a compare-and-swap delivery lease. Application readiness
is immediately false while any recovered revocation is pending, without the
ordinary 60-second backlog grace period.

The operator can run `check` with the same pinned replay arguments (without
`--apply`). It exits 2 while pending and emits `READY_SECURITY_ONLY` only after
every expected session fence has a matching generation and receiving receipt.
This is **only the application security check**. Complete kernel recovery,
deletion/provider obligations, sender/policy reconciliation and release-owner
authorization before opening ingress or dispatch.

## Retained verification

`tools/verification/test_app_security_restore.py` uses real HTTP, separate
restricted PostgreSQL roles, actual pg_dump/pg_restore and the real Rust kernel.
It exercises password/logout/demotion/disable, MFA and recovery-code rotation,
consumption/lockout, refresh rotation, pending enrollment, post-backup accounts
and sessions, exact receiving refusal, generation binding, SQL immutability,
dry-run and atomic rollback. Cryptographic tampering tests are in
`backend/tests/test_security_recovery.py`. CI runs both suites.

The shipped-image drill adds `--security-restore` to
`tools/verification/app_database_image.py --erase`: it physically stops the
source container, runs the packaged paired export/replay/check commands,
retains ciphertext and digests, and refuses readiness without kernel delivery.
Its private recovery key exists only in the synthetic drill process and is not
retained. Author-run results are in `local-verification/`; independent staging
custody, timed recovery and verification remain release requirements.
