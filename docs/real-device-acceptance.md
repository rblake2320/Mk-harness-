# Real-device acceptance — MK action kernel (test equipment procedure)

> **Scope note (2026-10-20):** per `docs/transport-decision.md` the Moto/ADB agent is
> **engineering test equipment**, not a production transport. This procedure
> produces evidence that the kernel's work-order/callback contract works on real
> hardware; it does not close any production-transport row (C1–C10), which are
> met only by the provider path.

`verified_on_device` is `false` everywhere in this repository and the work-order
schema pins it to `false`. Nothing in code flips it. This document is the only
path by which it becomes true: a human runs the procedure below on a real phone,
reviews the evidence, and records the result. Until then the kernel is accepted
for **simulator and dry-run evidence only**.

The procedure reuses what already exists for the Moto phones (controller host +
ADB courier). The reference agent in `tools/mobile-agent-adb/` is the kernel-side
counterpart of that courier: receive a signed work order, execute on the device,
report a signed result. If the local courier is preferred as the executor, it
replaces `AdbExecutor` and must satisfy the same evidence contract.

## 0. What is accepted today (no device)

`scripts/kernel-live-smoke.sh` proves, with real processes and a real
Postgres/Redis, through the FastAPI application path:

| Gate | Claim | Evidence |
|---|---|---|
| 1 | An approved action reaches the device agent and its HMAC-signed callback is accepted | action terminal state via callback; agent evidence bundle; audit events |
| 2 | A suppressed contact is refused at proposal (403, nothing queued) | `decision.code = suppressed` |
| 3 | A revoked approval is never dispatched | state `cancelled`, task id absent from agent log |
| 4 | Tenant kill switch blocks dispatch after approval and refuses new proposals | state `cancelled`; proposal `403 dispatch_disabled` |
| 5 | Idempotent proposals; single-use assertions across API instances | `replayed: true`; second use of a jti → 401 |
| 6 | Audit chain verifies under the read-only identity | `mk-audit-verifier` chain ok |
| 7 | Each process runs as a least-privilege DB login | API cannot claim outbox, relay cannot read approvals, readonly cannot write |

The agent runs with `MK_EXECUTOR=dry-run`, so gate 1 ends in
`failed_final / dry_run_no_device`. That is the honest state: the round trip is
proven, the send is not.

## 1. Preconditions for a device run

* Controller host (Windows is fine) with `adb` on PATH and **one** device in
  `adb devices` (serial known; set `MK_ADB_SERIAL`).
* Test SIM in the phone; the destination is a **second test phone you control**.
  Never a customer number. Consent for that contact is granted through
  `/api/agent-ops/contacts/{id}/permissions` like any other.
* Boot identity readable: `adb shell cat /proc/sys/kernel/random/boot_id`
  prints a UUID. The agent refuses to execute when it is empty (the courier
  lesson: an empty boot identity is not a device).
* Stock Messages app set as default SMS app, screen unlocked, USB debugging
  authorized.
* A staging kernel stack (`docker-compose.kernel.yml` or the smoke script's
  processes) reachable from the controller; callback authority registered for
  the agent via `/api/agent-ops/adapters` and allowlisted in `MK_EGRESS_AUTHORITIES`.

## 2. Run

```powershell
# controller host (PowerShell)
$env:MK_AGENT_ID      = "moto-1"
$env:MK_TENANT_ID     = "<tenant uuid>"
$env:MK_AGENT_SECRET  = "<enrollment secret from /api/agent-ops/adapters, shown once>"
$env:MK_EXECUTOR      = "adb"
$env:MK_ADB_SERIAL    = "<serial>"
$env:MK_CALLBACK_BASE = "https://<kernel callback authority>"
$env:MK_EVIDENCE_DIR  = "C:\mk-evidence\run-$(Get-Date -Format yyyyMMdd-HHmm)"
py -3 tools\mobile-agent-adb\agent.py
```

Then, through the application (two users: the proposer's agent and a separate
approver — outreach forbids self-approval by default):

1. `POST /api/agent-ops/actions` with `origin: "agent"`, `send_sms`, `arguments.agent_id = "moto-1"`.
2. Approver: `POST /api/agent-ops/actions/{id}/approve` with the exact `action_digest`.
3. Wait for `GET /api/agent-ops/actions/{id}` to reach `completed`.

## 3. Evidence bundle (what the reviewer checks)

Under `MK_EVIDENCE_DIR`:

| File | Must show |
|---|---|
| `<task_id>.json` | `sent: true`, `verified_on_device: false` (the agent never claims it), `evidence.device.boot_id_digest` non-empty, `sent_rows_after = sent_rows_before + 1`, `sms_row_id_digest` non-empty, `screenshot_sha256` matching `<task_id>.png` |
| `<task_id>.png` | the Messages thread with the sent text (reviewer sees it; it never leaves the bundle) |
| `evidence-ledger.jsonl` | hash chain verifies (`python -c "import agent;print(agent.EvidenceChain.verify(...))"`); the last `entry_hash` equals `result.evidence_digest` in the kernel's completion callback |
| `ledger.json` | task state `reported`, `callback_status: 200` |

On the kernel side: `mk-audit-verifier` reports `chain ok`; the action's audit
trail shows `dispatch_started → callback_received(executing) → callback_received(complete)`;
`kernel.adapter_callbacks` holds the two signed callbacks with the body digests.

On the receiving test phone: the message arrived with the opt-out text.

## 4. Acceptance gates (all required; any failure = not accepted)

Mirrors the gates adopted for the courier reboot acceptance: the tooling must
reject its own false positives.

- [ ] Completion callback accepted by the kernel **and** `sent: true` in the bundle — not one without the other.
- [ ] Non-empty device identity (`serial_digest`, `boot_id_digest`) in the bundle.
- [ ] `sms_row_id_digest` present and the sent-row count increased by exactly one.
- [ ] Screenshot digest matches the file; a human looked at the screenshot.
- [ ] Message received on the destination test phone (photo or second-device log).
- [ ] Agent evidence chain verifies; kernel audit chain verifies; the two digests agree.
- [ ] Timestamps are within the run window (no stale artifacts from a prior run); fresh `MK_EVIDENCE_DIR` per run.
- [ ] No manual intervention on the phone between approval and completion.
- [ ] Negative run in the same session: revoke an approval before dispatch → nothing sent, no new sent row.
- [ ] Negative run: tenant kill switch on → nothing sent.

## 5. Recording the result

Record in the PR / release notes: date, device model, Android version, kernel
commit, agent commit, evidence chain head, audit root commitment, and the
reviewer. Only then may product copy describe real-device execution. The
schema constant stays `false`; a future contract revision may add a
`device_verified_by` evidence reference instead of a boolean the code can set.

## 6. Known limits

* The reference executor targets the stock Messages composer and locates the
  Send button via `uiautomator`; vendor messaging apps may need `MK_SMS_SEND_TAP`.
* DMs/social posts are out of scope for the first device run.
* A phone behind NAT cannot receive pushed work orders; run the agent on the
  controller host (as with the courier) and keep the phone on USB/`adb connect`.

## 7. iPhone (no ADB) — assisted mode, not yet built

iOS exposes no SMS automation: nothing can send a text without a human tap.
The facelink pattern (phone opens a LAN HTTPS page served by the controller,
self-signed cert accepted once, page polls for commands, posts results over
HTTPS because iOS refuses WSS on self-signed certs) gives a sound transport for
an **assisted executor**:

1. Agent serves a page; the consultant's iPhone opens it on the same Wi-Fi.
2. A work order appears as a card showing the kernel's `task_id`, destination
   and text (exactly what was approved; the digest is displayed).
3. Tapping **Send** opens `sms:<to>&body=<text>`; iOS Messages prefilled; the
   human taps send in Messages and returns.
4. The page asks "Sent?" — tapping Yes posts the signed `complete` callback with
   `result.mode = "assisted"`; No posts `failed/human_declined`.

Evidence for assisted mode is weaker (human attestation + a screenshot the
consultant shares) and the bundle must say `mode: assisted`. It is a valid
execution mode for the product — the human is the last authority on iOS — but
it does not satisfy the automated acceptance gates above; it gets its own
gate list when built. The Moto/ADB path remains the automated reference.
