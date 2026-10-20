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
