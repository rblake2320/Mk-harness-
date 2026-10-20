# Real-device acceptance record

Copy to `deploy/kernel/ACCEPTANCE.md` after a run that passes every gate in
`docs/real-device-acceptance.md` §4. `scripts/kernel-preflight.sh --for-enable`
reads this file; every field below must be present (exact prefixes) and
`Result:` must be `ACCEPTED` before `RUST_ACTION_KERNEL_ENABLED=1` is allowed.
Commit it: it is part of the evidence, reviewed like code.

Date: YYYY-MM-DD HH:MM America/Chicago
Device: <model, e.g. Moto G …>, serial digest sha256:<from bundle evidence.device.serial_digest>
Android: <version / build fingerprint>
Kernel commit: <git sha of main deployed>
Agent commit: <git sha of tools/mobile-agent-adb deployed>
Destination: controlled test phone (never a customer number)
Task id: <32-hex task_id>
Evidence chain head: <entry_hash from evidence-ledger.jsonl == result.evidence_digest in the completion callback>
Audit root: sha256:<root from mk-audit-verifier for the tenant>
Negative runs: revoke-before-dispatch = no send (yes/no); tenant kill switch = no send (yes/no)
Reviewer: <name> — looked at <task_id>.png and the receiving phone
Result: ACCEPTED | REJECTED (<reason>)
