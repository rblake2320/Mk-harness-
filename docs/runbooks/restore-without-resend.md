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
* The audit-root destination (separately protected bucket) is reachable.

## Procedure

| # | Step | Command / check | Pass condition |
|---|---|---|---|
| 1 | Restore the database to a new instance; do **not** repoint any process yet | provider console / Terraform | instance reachable with the owner login |
| 2 | Confirm dispatch is disabled on the restored data | `psql … -c "select enabled from kernel.global_dispatch"` or step 4 output | `false`. If `true`, run `POST /internal/v1/kill-switch/global {"enabled":false}` **before** starting any worker, or set it directly with the owner login and record that in the drill log |
| 3 | Run migrations forward only (`MK_RUN_MIGRATIONS=1`) | migrator login | no error; `kernel.key_versions` present |
| 4 | Gate, report mode | `mk-restore-gate --restored-at <ts>` | every `check` line `ok:true` except possibly `in_flight_marked_unknown` / `pre_restore_approvals_invalidated` (fixed in step 6); `keyring_loads`, `audit_chain_verified`, `suppression_ledger_loaded`, `credentials_unseal` **must** be `ok:true` — if any is false, stop: the restore is not usable |
| 5 | Load the suppression / deletion recovery ledger from the separately protected destination and reconcile against `kernel.suppressions` | `tools/evidence/check.py` ledger mode (WP10) / manual diff | every ledger entry present in the restored table; any missing entry re-inserted **as a suppression** (never lifted) before step 7 |
| 6 | Gate, apply mode | `mk-restore-gate --restored-at <ts> --apply` | exit 0; `in_flight_marked_unknown` and `pre_restore_approvals_invalidated` now `ok:true`; `reconciliation_backlog` lists the actions |
| 7 | Reconcile every `reconciliation_required` action against provider records (Twilio console / Messages API by `provider_message_id`, or by `to`+time window if unknown) | human, per action | each action resolved to `completed` (provider has it) or `failed` (provider does not) via the exceptions UI; nothing is re-proposed automatically |
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

## Timing targets

RPO ≤ 5 min (PITR) and RTO ≤ 60 min (contract O3) are *claims about the
hosting*, not about this runbook. They are measured during the drill: record
`restore_started_at`, `gate_pass_at`, `dispatch_enabled_at`.
