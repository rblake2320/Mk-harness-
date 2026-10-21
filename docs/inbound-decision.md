# Decision record — inbound replies

**Status:** recorded 2026-10-20 per the completion contract. Implementation: not
demonstrated (`C5`–`C8`).

## Decision

Replies are received through the **provider's authenticated inbound webhook for the same
enrolled sending identity** (see `docs/transport-decision.md`). No other inbound source
(personal phone, company account, consumer messaging app) is read.

## Processing contract (order is mandatory)

1. **Authenticate** the webhook with the provider's signature procedure against the
   configured public URL. Client-supplied forwarding headers are never used in the
   signed string.
2. **Bind** the receiving sender resource to exactly one tenant and sender identity;
   unknown resource → reject and alert.
3. **Durably deduplicate** on `(provider, provider_event_id)` before any side effect.
4. **Detect opt-out or possible opt-out** (supported keywords, provider opt-out
   signals, reasonable plain-language revocation; ambiguity → hold, never ignored).
5. **Apply suppression** (explicit) or a **temporary safety hold** (ambiguous) in the
   same serialized customer/channel control path used by dispatch authorization (C6),
   so an opt-out committed before dispatch authorization blocks that action.
6. **Acknowledge** to the provider only after steps 1–5 are durably committed.
7. **Process conversational meaning asynchronously**: date requests → draft deferrals
   with evidence; questions → brief candidates; product/skin concerns → escalation and
   suspension of ordinary sales follow-up; complaints, wrong-number, identity ambiguity
   → visible exceptions.

## Record

`contracts/inbound/v1/inbound-event.schema.json` (to be authored in WP07) carries:
`event_id, provider, provider_event_id, tenant_id, sender_identity_id,
source_destination, received_at, provider_timestamp, content_reference,
authentication_result, raw_event_digest`. The body is stored encrypted under the
content reference; it never appears in logs, metrics or audit metadata.

## Trust statement

A signed webhook authenticates the **provider integration**, not the human author of
the text. A matching phone number is never sufficient to execute instructions or expose
customer records. Model interpretation of a reply never re-enables messaging; re-consent
requires fresh, purpose-specific evidence through an explicit workflow.

## Health coupling

Inbound health is checked continuously. If it fails for 60 seconds, the affected
tenant's outbound dispatch pauses; it resumes only after recovery checks pass and the
backlog of pending events has been processed (C8). A system that cannot hear STOP must
not keep talking.

## Targets

Opt-out persistence p99 ≤ 2 s from receipt at the application; inbound persistence
p99 ≤ 2 s; inbound → inbox visible p95 ≤ 5 s (O3).


## Implementation status (WP07, 2026-10-20)

| Contract step | Implementation |
|---|---|
| Authenticate | `X-Twilio-Signature` over `MK_PUBLIC_WEBHOOK_BASE` + path (+ query), verified with the sender identity's own token; `Host`/`X-Forwarded-*` never read; unknown sender id answers like a bad signature |
| Bind sender → tenant | sender identity id in the URL path; `AccountSid` echo and `To` number checked against the identity |
| Durable dedupe | `kernel.inbound_events UNIQUE (provider, provider_event_id)`; a redelivery returns 200 and creates nothing |
| Detect opt-out / possible opt-out | `mk-adapters::twilio::detect_opt_out` (vocabulary mirrored in `backend/app/inbound.py`) |
| Suppress or hold | explicit → permanent suppression + queued outreach suppressed; possible → non-permanent hold a human must lift; both under the serialized control path |
| Acknowledge | empty TwiML after commit |
| Async meaning | `GET /internal/v1/inbound/pending` (body unsealed only for a human principal) → `POST /api/inbound/process` → `POST /internal/v1/inbound/{id}/processed` (single-shot) |
| Health → pause | `kernel.inbound_health`; worker defers provider dispatch when stale (>60 s after a failure), paused, or unverified; resume requires a fresh ok and zero pending events |

Not yet: the public-URL probe job (WP09), delivery-uncertainty exceptions in the app view
(WP08), and any real-provider run.
