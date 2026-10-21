# Runbook — Inbound outage (contract C8, O7)

**Status:** *Implemented* (text; behaviour covered by `mk-api` e2e
`ambiguous_submission_becomes_submission_unknown_and_inbound_pause_defers_dispatch`
and smoke gate 10). *Independently verified* requires the game-day record.

## What the system does on its own

The kernel will not dispatch to a tenant whose inbound path is not known to be
working. `inbound_dispatch_block` (`mk-store::messaging`) returns one of:

| Reason | Trigger | Dispatch |
|---|---|---|
| `inbound_unverified` | the tenant has an active sender identity and no successful probe has ever been recorded | deferred (`DispatchOutcome::Deferred`, message stays queued, re-delivered later) |
| `inbound_stale` | last probe failure is newer than the last success **and** the last success is older than `INBOUND_STALE_SECS` = 60 s | deferred |
| `inbound_paused` | an operator (or the probe job) called `pause_inbound` | deferred until `resume_inbound` succeeds |

Every authenticated inbound webhook refreshes `last_ok_at` (`inbound_ok`), so
real customer traffic keeps the path "fresh" without a probe. Deferred actions
are **not** failed and **not** expired early; they age in the queue and the
`mk_queue_oldest_eligible_age_seconds` metric rises, which pages at 60 s for
5 min (`MKEligibleQueueAge`).

Resuming is deliberately strict: `resume_inbound` refuses while any inbound
event is still unprocessed (`pending_inbound_count > 0`) or the last success is
older than 60 s. Dispatch never resumes "because the outage is probably over".

## Operator procedure

1. **Confirm** — `GET /api/agent-ops/inbound/health` per affected tenant, the
   provider status page, and the ingress/WAF logs for `/webhooks/twilio/inbound/*`
   (expect 200s from the provider's IP ranges; 403s mean signature failures —
   see step 4).
2. **Pause explicitly** if the outage is ours (ingress, certificate, DNS,
   kernel API down): `POST /inbound/health {"ok":false}` for each tenant, or
   `pause_inbound` via the ops tool. This makes the deferral visible as
   `inbound_paused` in the exceptions view instead of looking like a stale probe.
3. **Fix the path** — ingress → `mk-action-api` → PostgreSQL. The provider
   retries inbound webhooks for a limited window only; messages missed beyond
   that window are retrieved in step 5.
4. **Signature failures** (`callbacks_auth_failures_total` / 403s): the public
   URL the provider calls must equal `MK_PUBLIC_WEBHOOK_BASE` byte-for-byte
   (scheme, host, port, path). A load balancer that rewrites the path or adds a
   port breaks the HMAC. Never "fix" this by trusting `X-Forwarded-*`.
5. **Recover missed inbound** — list provider messages received by each sender
   number during the outage (provider Messages API, direction inbound). For
   every one not present in `kernel.inbound_events` (match on `MessageSid`),
   replay it through the webhook endpoint **signed with the sender's token**
   (the `twilio_sim` replay tool does this in staging; in production use the
   provider's redeliver feature or the signed-replay script). Opt-outs received
   during the outage are therefore recorded **before** any dispatch resumes.
6. **Process the backlog** — the application's `POST /api/inbound/process`
   until `processed: 0`; every event gets a disposition (`opt_out`, `held`,
   `queued_for_meaning`), none is dropped.
7. **Resume** — `POST /inbound/health {"ok":true}` then `resume_inbound`
   (returns `false` while step 6 is incomplete). Watch
   `mk_queue_oldest_eligible_age_seconds` fall and `dispatch_outcomes_total{outcome="deferred"}`
   stop increasing.
8. **Record** — duration, number of deferred actions, number of replayed
   inbound events, number of opt-outs recovered, in the incident log. If an
   opt-out was missed **and** a message went out after it, this becomes
   `incident-unapproved-or-duplicate-send.md`.

## Do not

* Do not lift the deferral by editing `kernel.inbound_health` directly.
* Do not fail or expire deferred actions to "clear the queue"; the consultant
  sees them as waiting, and they expire on their own `expires_at`.
* Do not disable webhook signature verification, even temporarily.
