# Decision Record

## D-001 - Use an adapter contract, not an invented PhoneClaw API

The current [PhoneClaw repository](https://github.com/rohanarun/phoneclaw)
documents JavaScript helpers such as `magicClicker` and `magicScraper`, but no
remote HTTP/webhook protocol was found. The harness therefore emits a versioned,
signed work-order envelope for an operator-controlled adapter. The envelope pins
the reviewed upstream commit and says `verified_on_device: false`.

## D-002 - Require human approval before execution

Generated text and UI instructions can be wrong even after rule checks. Every
task stops at `awaiting_approval`; an authenticated tenant user must explicitly
approve it. A conditional database update claims the task before network
delivery, preventing two approvals from sending the same work order.

## D-003 - Gate direct outreach on a recorded permission

Current FTC guidance requires do-not-call procedures and distinguishes live,
automated, informational, and marketing outreach. The FCC confirms that AI
generated voice calls fall within TCPA artificial/prerecorded voice rules. The
harness does not decide legal sufficiency. It requires a time-bounded,
revocable, operator-attested record whose keyed destination fingerprint must
match an outbound SMS/DM task.

Sources: [FTC TSR business guidance](https://www.ftc.gov/business-guidance/resources/complying-telemarketing-sales-rule),
[FCC 24-17](https://docs.fcc.gov/public/attachments/FCC-24-17A1.pdf).

## D-004 - Keep audit data tenant-scoped and transactional

A shared JSONL file would mix tenants and could diverge from task state. The
database chain commits with the state transition and has one head per tenant.
It is tamper-evident relative to the retained head. It is not signed, externally
anchored, immutable, or automatically admissible evidence.

## D-005 - Use exact authority allowlists

Adapter URLs and device-side portal URLs are SSRF boundaries. HTTPS alone is
insufficient, so registration and task intake require exact configured
authorities, reject credentials/fragments, and reject private or reserved IP
literals. Webhook query strings are rejected to keep HMAC path semantics
unambiguous.

## D-006 - Separate release truth from future plans

Implemented and tested behavior belongs in `CHANGELOG.md` and `LOG.md`.
Unimplemented integrations, stronger evidence properties, and voice calling are
kept in `PARKED.md` with objective restoration conditions. This prevents a
roadmap item from being mistaken for a product, security, patent, or compliance
claim.

## D-007 - Make the adapter boundary executable before partner integration

A prose envelope description is too ambiguous for independent implementations.
The v1 contract is therefore published as strict JSON Schemas plus a fixed HMAC
test vector, and the same schemas execute at outbound and callback trust
boundaries. A loopback-only simulator provides deterministic integration tests
without pretending to be a PhoneClaw device. Transient delivery retries use a
fresh nonce while retaining `task_id` as the adapter idempotency key. The
reviewed PhoneClaw source is pinned separately from the still-absent concrete
adapter and real-device evidence.
