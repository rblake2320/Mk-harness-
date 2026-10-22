# Runbook — Restore without re-sending (contract O9)

**Status vocabulary:** this runbook is *Implemented* (text + `mk-restore-gate` +
drill scenario F6 in `scripts/kernel-fault-drill.sh`). It becomes
*Independently verified* only when a timed restore drill against a real
PostgreSQL snapshot is performed by someone other than the author and recorded
under `evidence/releases/<id>/restore-drill.json`.

## Principle

A restored environment must never send a message the pre-restore environment
may already have sent. Restoration therefore starts **with dispatch disabled**
and ends with a **human** release-owner decision. No step below is automated
end-to-end on purpose; the gate binary refuses to enable anything.

## Preconditions

* The RDS/PostgreSQL snapshot or PITR target is identified; its timestamp is
  the `--restored-at` value (RFC3339, UTC).
* `MK_MASTER_KEY`, `MK_KEK`, `MK_KEK_ID` for the restored data are available
  from the secrets manager (same values the pre-restore environment used, or the
  KEK generation still able to unwrap the stored key versions).
* Redis is **empty** (never restore Redis — it is a cache of the outbox, and the
  relay republishes from PostgreSQL).
* The audit-root and deletion-ledger destinations (separately protected stores)
  are reachable. Obtain the final deletion ledger, its SHA256 and the minimum
  acceptable export time through the independent recovery record, not from the
  restored database or an adjacent untrusted checksum file. Missing evidence
  blocks recovery; do not manufacture an empty ledger from the backup.
* Source intake is quiesced before the final ledger export. The destination
  fingerprint keys and their version labels must match the source configuration.
  Keep API/worker/relay ingress stopped until the gate and operator review finish.

## Procedure

| # | Step | Command / check | Pass condition |
|---|---|---|---|
| 1 | Restore the database to a new instance; do **not** repoint any process yet | provider console / Terraform | instance reachable with the owner login |
| 2 | Confirm dispatch is disabled on the restored data | `SELECT dispatch_enabled FROM kernel.kill_switches WHERE scope='global'` | exactly one `false` row. Disable it using the controlled owner recovery login and record the action before starting any worker |
| 3 | Run migrations forward only | `MK_MIGRATE_ONLY=1 mk-action-api`, with the controlled migration identity and required configuration | exit 0; migrations/checksums verified |
| 4 | Load the independently retained deletion ledger and its independent digest/freshness pin | commands below | authenticated input accepted; report lists missing content/fences without enabling traffic |
| 5 | Reconcile the separately retained opt-out/revocation recovery records | operator evidence review | every post-backup opt-out/revocation enforced. The privacy ledger below covers erasure requests/fences, not a complete opt-out/revocation archive; its PASS alone is not authorization to skip this step |
| 6 | Gate, apply mode | command below with `--apply` | exit 0, `gate:PASS`; all checks `ok:true`; any unresolved privacy content keeps the gate failed |
| 7 | Reconcile every `reconciliation_required` action against exact provider identity using the passkey-protected exception workflow | human, per action | accepted resolution receipt with bound provider evidence. Destination/time-window searches and provider absence alone are not negative-send proof; ambiguous actions stay quarantined. Never re-propose automatically |
| 8 | Confirm sender bindings | gate `credentials_unseal` detail + provider console webhook URL = `MK_PUBLIC_WEBHOOK_BASE` | `unreadable: 0`; webhook URL matches |
| 9 | Start api / relay / worker in shadow mode (`RUST_ACTION_KERNEL_ENABLED` unset) | | `/health/ready` ok; worker log shows `envelope keyring loaded` |
| 10 | Release-owner authorization | written sign-off naming the restore point, backlog disposition, and the operator | recorded in `evidence/releases/<id>/restore-drill.json` |
| 11 | Enable through the enable sequence (`deploy/kernel/README.md`) with passkey step-up | platform operator | audit event `kill_switch_global` with the operator credential |

## What the gate guarantees and what it does not

* Guarantees: no dispatch enabled by software; in-flight actions never resume
  as sends; approvals granted before the restore point cannot authorize
  anything; unreadable credentials are surfaced, not skipped.
* Does not: decide whether a provider actually delivered an uncertain message
  (step 7 is human), or restore Redis (by design).

## Kernel deletion ledger commands

Export from the quiesced authoritative source with a read-capable operator
identity. The output contains only immutable request UUIDs/times and destination
fingerprints, not addresses, bodies, signing keys or provider credentials. It is
still sensitive pseudonymous data: retain with restricted access and immutable
external custody. The command creates a new file (0600 on Unix) and refuses to
overwrite an existing path.

```sh
mk-privacy-ledger export --ledger /protected/kernel-erasure.json
```

Retain the returned `sha256` in the independent recovery record. On the restored
database, use a controlled recovery/owner identity even for report mode, which
takes exclusion locks. Supply the independently approved values, not values
inferred from the restored backup:

```sh
mk-restore-gate --restored-at "$RESTORED_AT" \
  --privacy-ledger /protected/kernel-erasure.json \
  --privacy-sha256 "$INDEPENDENT_SHA256" \
  --privacy-not-before "$INDEPENDENT_NOT_BEFORE"
# Review the report, then repeat the exact command with --apply.
```

The standalone `mk-privacy-ledger replay --ledger <file> --sha256 <pin>
--not-before <time> [--apply]` performs only the deletion replay, not the other
restore-gate checks. It authenticates and validates the entire bounded document,
rejects missing/conflicting retained identities, locks tenants in sorted order,
replays contacts before accounts, and commits atomically. Post-backup destination
fences are restored even when the contact did not exist at the backup point.
Any SQL failure rolls back the entire replay. Repeating replay preserves fences
and identity. In-flight/unresolved sends remain quarantined, keep their necessary
resolution data, and yield a failing privacy check until safely resolved and erased.
Provider active/backup receipts are not invented by recovery.

Record the cutoff from a verified, synchronized source clock before the final
export and retain it independently with the digest. Never invent the cutoff from
the restored database. Check clock skew between the export source, operator host
and recovery runtime: a host ahead of the source can create a future cutoff that
correctly fails freshness validation. Do not weaken the gate or backdate the pin
to make a refused recovery pass. The local image drill records the original live
database's pre-export UTC cutoff and separately records the host's observed UTC;
it also confirms that an intentionally future cutoff is refused.

`--inspection-only` is only for live preflight/smoke inspection. It cannot combine
with `--apply`, emits `gate:INSPECTION_ONLY`, and never authorizes a restore.

The mandatory PostgreSQL CI test `tools/verification/test_kernel_privacy_restore.py`
uses actual API/recovery binaries, `pg_dump`/`pg_restore`, restricted API logins and
fresh UUID databases. It exercises post-backup deletion/fence replay, tampering,
freshness, identity conflicts, rollback after a mid-replay SQL fault, and uncertain
send quarantine. Local author-run results belong in `local-verification/`; staging
and independently retained restore evidence are separate release requirements.

## Timing targets

RPO ≤ 5 min (PITR) and RTO ≤ 60 min (contract O3) are *claims about the
hosting*, not about this runbook. They are measured during the drill: record
`restore_started_at`, `gate_pass_at`, `dispatch_enabled_at`.
