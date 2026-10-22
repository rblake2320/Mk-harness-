# Application sealing-key rotation and containment

`APP_SEAL_KEYS` is a bounded key ring: `kid=base64(32 bytes),kid=...`; the first
entry writes, all explicitly retained entries can read. Empty configuration is
the compatibility key `m0=master`. `mk1:<kid>:<ciphertext>` binds the key id and
the existing tenant/user/purpose/session scope in AES-GCM authenticated data.
Unversioned legacy ciphertext can be read only while `m0` is explicitly retained.
Removing it does not fall back to MASTER_KEY.

This key ring is independent of `FINGERPRINT_KEYS` / `MK_FINGERPRINT_KEYS`.
Changing sealing keys does not change destination matching, suppression hashes,
message digests, approvals or dispatch state. MASTER_KEY remains a separate
legacy/kernel/fingerprint concern. If that key is compromised, complete both
the sealing procedure here and the fingerprint/kernel procedure in
`key-compromise.md`; do not merely replace MASTER_KEY and make old data unreadable.

## Inventory and roles

The rotation inventory includes nine encrypted columns: provider credentials;
customer destinations; imported phone/email; draft text; exception detail;
outcome notes; active and pending MFA seeds. A model-column regression detects
an encrypted column missing from the inventory. Pending MFA retains its exact
session binding. Recovery-code hashes are not encryption keys and are unchanged.

`python -m app.tools.reseal status|rekey` uses the restricted runtime database
login. `activate` requires the separate `MK_APP_MIGRATION_URL`, verifies its real
identity and elevated-role restrictions, and assumes only the migration owner.
Secrets belong in the private environment/secret store, never command arguments,
terminal output or retained reports. `--actor` identifies the actual operator.

## Maintenance sequence

1. Disable dispatch and stop app writers. Verify backup and the approved image
   digest. Deploy migration 0002 and the compatible reader code before changing
   keys. Old binaries cannot read the new envelope. Record the current inventory
   and preserve the old key in restricted recovery escrow until retention and
   restore requirements permit its destruction.
2. Generate a fresh 32-byte sealing key. In the rotation process set
   `APP_SEAL_KEYS=s2=<new>,m0=master` (include every retained old sealing key if
   rotating a later version). Run `status`: it returns counts and exits 1 for
   stale/unreadable rows, missing policy, or an unfenced writer. It prints no
   ciphertext, seed, provider key, raw destination or message.
3. With the separate migration credential run
   `python -m app.tools.reseal activate --actor <operator-id>`.
   The database policy becomes `s2`, legacy writes disabled. An exclusive
   transaction lock waits for old ciphertext writes to commit; future writes
   across all nine columns must use the new key id. Runtime cannot edit this
   policy. A waiting old writer sees the new fence; repeatable-read ciphertext
   writes are refused so an old snapshot cannot bypass it.
4. Remove migration credentials from the process. Using the runtime credential
   and the retained key ring run
   `python -m app.tools.reseal rekey --batch-size 200 --actor <operator-id>`.
   Each bounded batch atomically commits compare-and-swap ciphertext changes
   with count-only audit entries. Concurrent newer values are not overwritten.
   A killed process can be rerun; already-current rows are not rewritten.
5. Require `status` exit 0: all values decrypt under the current key, no stale or
   unreadable rows, database writer matches, legacy writes disabled. Investigate
   corruption or missing old keys; never delete a row to make the report green.
   A conflict produces a non-clean report and requires a fresh scan/retry.
6. Remove retired keys from the runtime ring, run `status` again, and start app
   replicas with `APP_SEAL_KEYS=s2=<new>`. Startup refuses a mismatched writer.
   A surviving old-key process receives 503 `SEAL_WRITER_RETIRED` on attempted
   ciphertext writes; the rejected change is not saved. Verify fresh MFA,
   credential resolution, imported/customer destinations, draft/exception/outcome
   reads, unchanged suppressions, and normal preflight before enabling dispatch.

Activation/rekey change no customer permission or approval and call no provider.
Rollback uses the compatible reader with retained keys, not an old binary that
cannot understand envelopes. Do not re-enable legacy writes to silence errors.
An old backup may contain retired-key data; recovery must use controlled escrow,
reapply database bootstrap/privilege checks (a restore into a fresh database does
not copy database-level ACL revocations), repeat activation/rekey/verification
in isolation, and keep dispatch disabled
until the existing restore gate and replay checks pass.

## Executable checks

Unit checks cover nine-field round trips after removing the old key, tamper and
scope rejection, corrupt-value retention, malformed configuration, concurrent
newer-value preservation and idempotence. Real PostgreSQL checks cover all nine
write fences, operator/runtime separation, both activation races and real
SIGKILL/resume over 4,009 encrypted values. The built-image check uses
`tools/verification/app_database_image.py --rotate-seal`: activate, reject an
already-running old-key writer, reseal, remove the old key, then verify an
existing session and fresh TOTP. These author-run results do not close S10's
independent staging/incident-response qualification.
