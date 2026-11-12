# Message states — support and marketing reference (contract row C3)

Support material, onboarding text and marketing copy that describe what happened to a
customer message must use these labels and quote these definitions **verbatim**. They are
the same words the API returns (`message_state`, `message_state_definitions`) and the web
and mobile apps display (`packages/sdk/src/vocabulary.ts`). The single source is
`rust/crates/mk-contracts/src/message_state.rs`; `packages/sdk/test/vocabulary.test.ts`
fails if this table drifts from it.

Rules:

- Never say a message was "sent" or "delivered" unless the state is exactly `sent` or
  `delivered`. Approved, queued and provider-accepted messages have not been sent.
- "Delivered" is a provider/carrier receipt, not proof that a person read the message,
  and never a resolved commitment or a sale.
- Unknown stays unknown. No state is upgraded because time has passed.
- Read status is separate from delivery and is "Unknown" unless a supported
  recipient-read signal exists.

## Message states

| Label | Identifier | Definition |
|---|---|---|
| Proposed | `proposed` | Proposed by the AI or the consultant; nothing has been authorized. |
| Awaiting approval | `awaiting_approval` | Waiting for an explicit human approval gesture. |
| Approved | `approved` | Approved by a human; not yet queued for execution. |
| Queued | `queued` | Queued for execution; policy will be re-evaluated before any send. |
| Dispatch authorized | `dispatch_authorized` | Dispatch authorization obtained; no provider request has been made. |
| Submission started | `submission_started` | The provider request is in flight or its outcome is not yet recorded. |
| Provider accepted | `provider_accepted` | Provider acknowledged submission. |
| Sent | `sent` | Provider reports outbound network submission. |
| Delivered | `delivered` | Supported provider/carrier receipt reports delivery. |
| Failed | `failed` | Provider reported a terminal failure. |
| Delivery unknown | `delivery_unknown` | Evidence is insufficient to say whether the message was delivered. |
| Submission unknown | `submission_unknown` | Evidence is insufficient to say whether the message was submitted; a human must resolve before any replacement. |
| Cancelled | `cancelled` | Cancelled before any provider submission. |
| Denied | `denied` | Refused by policy; nothing was sent. |
| Expired | `expired` | The authorization window elapsed before execution. |

## Read status

| Label | Identifier | Definition |
|---|---|---|
| Unknown | `unknown` | Evidence is insufficient. |
| Read | `read` | Supported recipient-read signal exists. |
