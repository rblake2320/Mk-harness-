# Decision record — production messaging transport

**Status:** recorded 2026-10-20 per `docs/production-completion-contract.md`. Subject to
provider onboarding and the legal/policy decision (M1). Not a declaration that the
provider is already approved, registered, or operational.

## Decision

Production customer messaging uses a commercially supported business-messaging API —
**Twilio Programmable Messaging** — as the default production candidate, with:

- a **dedicated, properly registered business number per consultant business** (no
  shared outbound identity that misrepresents independent businesses);
- **authenticated status callbacks** (provider acceptance, sent, delivered, failed)
  and **authenticated inbound webhooks** for the same enrolled sending identity
  (`docs/inbound-decision.md`);
- provider resources isolated per consultant business; credentials tenant-bound and
  held only by the kernel's execution adapter.

The adapter lives behind the Rust kernel's `ActionAdapter` interface. No frontend, AI
worker or Python endpoint holds a sending credential.

## What must be validated before this decision is accepted (owner: legal/privacy reviewer + engineering owner)

| Item | Why | Evidence |
|---|---|---|
| Target market and carrier terms (US, A2P 10DLC registration, brand/campaign registration) | sending unregistered traffic is blocked or filtered | registration records |
| Sender ownership and number provenance per consultant business | consent is bound to a sender; a changed sender is a new relationship | number inventory with owner |
| Consent provenance and wording | existing consent does not transfer to a new sender or purpose | consent evidence schema (F2) |
| Supported countries, delivery coverage, failover behaviour | release scope is US-only | provider documentation review |
| Provider opt-out handling vs application suppression | provider keyword handling is one input; application suppression is authoritative | C6 design |
| Price and support terms | economics (M4) | cost model |
| Data handling by the provider (message bodies at rest, retention) | privacy (S13, M1) | processor agreement |

## Rules that follow from the decision

- **No silent transport failover.** A provider rejection, outage or legal restriction
  blocks launch or pauses dispatch; an ambiguous submission is never repeated through a
  different path to improve success rates.
- **Delivery vocabulary** (C3): provider accepted ≠ sent ≠ delivered ≠ read. Provider
  `delivered` is carrier confirmation (handset confirmation where the carrier supplies
  it), never a human read receipt. Unknown stays unknown.
- **Ambiguous submission** (C4): submission intent is persisted before the provider call;
  an uncertain response sets `submission_unknown`; reconciliation uses provider message
  ids and callbacks; no blind retry; human resolution before any replacement message.

## Moto/ADB device agent — engineering test equipment only

`tools/mobile-agent-adb/` remains in the repository as **test equipment**: it exercises
the kernel's work-order/callback contract end to end on real hardware and in the CI
live smoke (dry-run). It is **not a general-release dependency** and must not be
described as a supported customer-messaging transport. It may become a separately
gated candidate only by meeting every row of the matrix that the production transport
must meet (reliability over the C10 window, security review, onboarding, operations,
permitted use). Until then `verified_on_device` stays `false` and the agent is
disabled in production configuration.

## Rejected alternatives

| Alternative | Reason |
|---|---|
| ADB-driven consumer phone as the production path | unregistered consumer sender, carrier terms, no delivery receipts, physical device operations, onboarding burden — fails C1, C3, C10 and X5 by construction |
| iPhone assisted mode (human taps send) | no automation possible on iOS; weaker evidence; remains a documented idea, not a candidate |
| Direct carrier integrations | scope and cost exceed a single provider API with no reliability benefit at this scale |
