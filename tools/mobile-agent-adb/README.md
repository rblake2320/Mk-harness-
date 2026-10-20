# mk-mobile-agent-adb

Reference **real-device** adapter for the MK action kernel: a controller-host
process that accepts HMAC-signed work orders from the kernel worker, executes
them on an Android phone over ADB, and posts HMAC-signed callbacks. Standard
library only. Windows-first (`py -3 agent.py`).

It is the kernel-side counterpart of the Moto courier pattern (receive a signed
job, execute, report a signed result). The courier can be dropped in as the
executor by implementing `Executor.run(order, evidence_dir) -> ExecResult`.

| Mode | `MK_EXECUTOR` | Result |
|---|---|---|
| ADB (stock Messages composer) | `adb` | `complete {sent:true, evidence_digest}` or `failed/<code>` |
| Dry run (no device) | `dry-run` | always `failed/dry_run_no_device` — used by `scripts/kernel-live-smoke.sh` |

Security: signature over `METHOD\nPATH\nTS\nNONCE\nSHA256(body)`; 120 s skew;
nonce replay window persisted across restarts; `task_id` idempotency (same body
→ 200 not re-executed, different body → 409); `verified_on_device` must be
`false` in every order; no phone number or message text in logs, callbacks or
the hash chain — only digests. Evidence: `<task_id>.json`, `<task_id>.png`,
`evidence-ledger.jsonl` (hash-chained, `EvidenceChain.verify`), `ledger.json`.

Tests (36, stdlib): `python -m unittest -v` in this directory. They prove the
published HMAC vectors, every intake rejection path, replay across restart,
idempotent redelivery, schema hygiene, callback shapes, PII discipline,
evidence chain tamper detection, and the ADB executor against a scripted adb
(sent-row parsing, Send-button discovery, empty-boot-id refusal).

See `docs/real-device-acceptance.md` for the human acceptance procedure.
