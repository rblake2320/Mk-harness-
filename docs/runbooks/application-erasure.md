# Application erasure and restore replay

This runbook implements the active-application-store portion of S13. It does not
close S13 or certify legal sufficiency. The kernel/provider work queue, automatic
retention enforcement and independently anchored production ledger remain separate
acceptance gates; pending tasks must never be manually marked confirmed to make a
dashboard green.

## Request and receipt

Account deletion requires current password plus fresh MFA step-up. Customer deletion
also requires step-up. Both return HTTP 202 with an immutable request ID, the local
active-store result, the pending stages and deadlines. Account deletion revokes all
sessions and removes active/pending MFA secrets and user-owned provider credentials.
Shared business credentials survive another member's deletion, but are removed when
the last active member is erased. Removing a stored BYO key is not revocation of that
key at the external provider.

The receipt's narrow status token expires after 45 days. Keep it private; it cannot
authenticate normal API routes. Check it with POST `/api/account/erasure-status` and
JSON `{"status_token":"<private receipt token>"}`. Never put it in a URL or ticket.
The web app clears its session credentials and offers a receipt download.

Active-store erasure removes the customer dependency graph, linked import copies,
drafts, commitments, messages, outcomes and skin results. Source consent rows are
replaced with a strict allowlist of proof digests and times; no free-text evidence
reference is retained. Suppression fingerprints remain without a customer FK or
free-text reason. Inbound idempotency markers remain with their content/linkage
cleared, preventing ordinary webhook replay from reconstructing deleted records.
Audit entries contain request IDs, not content. Billing provider references remain
pending actual provider cancellation/deletion receipts; do not tell a customer their
charges have stopped based on the local response.

## Restore safety

1. Keep application traffic and kernel dispatch disabled. Restore into an isolated
   database; never serve a pre-erasure backup directly.
2. Reapply the operator bootstrap's database-level ACLs. `pg_dump` without
   `--create` does not preserve the database-wide PUBLIC CREATE/TEMP revocations.
3. Quiesce deletion intake on the authoritative source. Export its latest tombstone
   ledger to a **new** file using `python -m app.tools.privacy_ledger export --ledger
   <path>`. Retain the ledger and printed SHA256 outside the database's recovery
   domain, through the separately approved immutable storage/anchor process.
4. Obtain the expected SHA256 and minimum acceptable ledger time from that external
   incident record, not the restored database. An old backup's own tombstones omit
   requests received since that backup and cannot satisfy this gate.
5. With the restored database's restricted runtime credentials, run
   `python -m app.tools.privacy_ledger replay --ledger <path> --sha256 <trusted hash>
   --not-before <trusted UTC intake-quiesced time>` to validate the entire input.
   Repeat with `--apply` to erase in one transaction. Wrong digest, stale/future
   ledger, duplicate IDs, conflicting tombstones or ownership mismatch fail closed.
6. Verify customer/content/key/factor absence, session denial and downstream receipt
   state. Replay is repeatable. Reconcile kernel and provider deletion using their
   own evidence before resuming traffic. This command never enables either service.

The SHA256 is a corruption/pinning check, not a substitute for external authenticity
or freshness. The external trust and retention configuration must be independently
verified. The request's `backup_expires_at` is a deadline, not evidence that a backup
was deleted. Do not confirm backup expiry from the clock alone.

## Retention and holds

The completion contract supplies engineering defaults: content 12 months; ordinary
resolved work and content-free audit 24 months; minimal consent five years; backup
35 days. A privacy/legal owner must approve exceptions and restricted legal holds.
This batch does not add an unaudited admin override or silently treat every record
as being under legal hold. Automated expiry/hold enforcement and live provider qualification
are still required before production qualification.

## Kernel delivery and pending work

The application starts a durable privacy worker independently of session-revocation
delivery. It leases only `kernel_contact` and `kernel_account` tasks, validates their
identity against the immutable application tombstone, and calls the kernel's exact
`POST /internal/v1/privacy/erase` service route. A `privacy_eraser` assertion cannot
read data, propose, approve, register passkeys or invoke another operator route.
Receipt tenant/request/subject identities and all integer counts must match. A 201
alone never confirms a task: active content must be erased and every pending count
must be zero. Lost responses are retried with the same erasure request identity.

The kernel serializes erasure ahead of ordinary tenant transaction locks, cancels
cancellable actions through its state machine, revokes approvals, clears canonical
request/message bodies and free-text metadata, and preserves the original action
digest with an audit tombstone. Late inbound content is discarded at the database
write boundary; dedupe and a pending provider-deletion job remain. Late authenticated
delivery receipts remain usable without resurrecting content. UUID subject matching
handles compact, hyphenated, braced and URN spellings used by previous clients.

Unresolved/in-flight submissions report `blocked_actions`; retain their resolution
evidence and use the existing passkey resolution workflow. Nonterminal provider
delivery likewise remains pending. Account-owned sender credentials remain disabled
with `pending_sender_cleanup` until provider-resource cleanup has its own receipt.
`privacy_provider_deletions` is a durable queue, not a deletion receipt. The kernel
worker consumes it independently of Redis startup and dispatch traffic. Each item
has a 90-second lease, bounded exponential retry and lease-owner CAS completion.
It authenticates a GET of the exact message, binds the returned account/sender/id,
performs DELETE, and requires authenticated 404/code 20404 readback. False 204,
proxy 404, authentication failure, rate limit, wrong sender and lost responses do
not confirm deletion. Retry after a lost response safely handles already-absent
resources. Disabled sender credentials are usable only by the cleanup resolver;
ordinary submission still refuses them. API intake cannot insert or update outcome
fields; workers cannot rewrite targets, regress receipts or certify backups.

Successful active deletion records a digest-bound audit receipt and a separate
`pending_provider_retention` obligation. The application requires this count too;
an older receipt omitting it fails closed. The backup window begins at verified
provider absence, not at the user's earlier request. Time alone does not confirm
backup erasure. A delayed provider cleanup can therefore miss the overall 35-day
backup deadline; operations must clear active provider copies within five days or
obtain a stricter verified provider retention control. Independent vendor backup
evidence and an authorized retention verifier remain required. No live provider
was contacted by author-run verification. Twilio documents that Message DELETE returns 204, and
message bodies may remain in its backups for up to 30 days after deletion
([Twilio Message resource](https://www.twilio.com/docs/messaging/api/message-resource#delete-a-message-resource)).

Hash-only destination fences are included in fingerprint-key retirement inventory.
If their raw destination has been erased and a replacement key cannot derive a new
tag, retirement remains blocked; never omit these fences to make an inventory green.
The privacy-preserving key-transition/retention policy remains a release task.

Kernel recovery now requires its own independently retained deletion ledger and
external digest/freshness pin. `mk-privacy-ledger` exports/replays request identity
and destination fences, including post-backup contacts; `mk-restore-gate` rejects
missing input and unresolved privacy content. See
[restore without resend](restore-without-resend.md) for the commands, required
source quiescence, separate opt-out/revocation review and controlled recovery role.
This is not an external custody service and does not complete application
`restore_ledger_anchor` tasks or certify provider/backup erasure.

## Executable checks

`tools/verification/test_app_privacy.py` runs against a dedicated disposable
PostgreSQL database with actual runtime permissions and foreign keys. It covers
linked deletion, credentials, minimal retained evidence, scope isolation, immutable
tombstones, in-flight write serialization, late write/identity resurrection refusal
and restore-ledger refusal cases. The mandatory app PostgreSQL CI job includes it.

`tools/verification/app_database_image.py --erase` runs actual HTTP/MFA against the
built image, takes a real `pg_dump`, deletes, restores, and replays the ledger. With
`--browser-url` it drives the real production web UI through a transparent loopback
proxy to that image, including logout, receipt download and a 360px viewport.

`tools/verification/test_privacy_bridge.py` uses two fresh PostgreSQL databases, the
restricted application runtime and a distinct restricted kernel login, a real Rust
API process, and the actual Python assertion/client/delivery code. Set
`MK_PRIVACY_KERNEL_BINARY` to the built API and `MK_APP_TEST_ADMIN_URL` to the explicit
disposable cluster. It removes only its own UUID databases/login/process. The app
PostgreSQL CI job runs this bridge for all four accepted UUID spellings. Rust HTTP
tests additionally cover forced RLS, service authority, in-flight DB lock waits,
queued dispatch refusal, uncertain submissions and late inbound/delivery webhooks.

`rust/crates/mk-worker/tests/privacy_e2e.rs` exercises the actual worker database
role, concurrent replicas, abandoned leases, false provider success, disabled
sender authentication, immutable receipts and backup pending state.
`tools/verification/test_privacy_process.py` launches the actual API and worker
binaries against a fresh database with separate restricted logins and a loopback
provider. It holds Redis unavailable, kills the worker after provider deletion but
before the response, expires the recorded lease, and restarts the process. Cleanup
must recover exactly one audit receipt without a send or a false backup completion.
This process drill runs in the mandatory app PostgreSQL CI job.

## Billing state after account erasure

Late authenticated Stripe checkout, subscription and payment webhooks are
acknowledged without changing an erased account's billing mirror. They cannot
reactivate a subscription, replace provider identifiers or record a new first
payment after the tombstone. A later referred customer's payment also cannot
create a Stripe customer or award credit for an erased/inactive referrer.

Migration `0004_billing_erasure_fence.sql` enforces this at the restricted
PostgreSQL write boundary, including writers already waiting when erasure
commits. New/rebound billing rows, active states and new business fields are
refused. Terminal cleanup may retain or clear the existing provider identifiers
and use `deletion_pending`/`canceled`; that local update never confirms an erasure
task or certifies an external cancellation. The migration is additive; old
migration files are unchanged, and a newer image refuses an older ledger until
the separate migrator upgrades it.

Verification includes seven application regressions, direct runtime SQL,
concurrent-write and existing-data upgrade tests. The actual shipped-image drill
supports `--erase --billing-privacy`: it reproduces late-event resurrection in
the old image, checks all six signed webhook variants in the repaired image,
then restores the pre-deletion backup, replays the separately pinned erasure
ledger and confirms the restored billing row cannot be reactivated. The drill
uses a synthetic incoming-webhook secret, supplies no Stripe API key and makes
no external billing call.

## Billing creation and provider cleanup

Migration `0005_billing_provisions.sql` adds an immutable customer-creation
identity. The account lock serializes intent creation with erasure; the intent
commits before HTTP. It retains tenant/user/intent IDs, creation time and a
once-bound customer ID, not email, names or payment data. Both checkout and
referral customer creation use it. Account deletion queues `billing_provision`
even when the provider has accepted creation but its response was lost.

Creation uses the same metadata-only request and idempotency key on retries.
Checkout collects the billing email directly. After 23 hours the application
never repeats a creation POST: it searches by intent, requires exactly one
ownership match and verifies the exact customer with GET. A missing, ambiguous,
deleted or mismatched result stays unresolved. This is intentionally not an
absence certificate: Stripe search is eventually consistent, and idempotency
keys may expire after 24 hours. See the primary [idempotency contract](https://docs.stripe.com/api/idempotent_requests),
[customer search](https://docs.stripe.com/api/customers/search), and
[Checkout customer/email behavior](https://docs.stripe.com/api/checkout/sessions/create).

The privacy worker drains billing tasks separately from kernel work when billing
is configured. A 120-second CAS lease protects each delivery; transactions end
before network I/O. Cleanup binds the task to the account tombstone and immutable
provision, verifies the provider's ownership metadata, persists the customer ID
before DELETE, and requires an exact authenticated `deleted: true` readback.
After a crash, the persisted ID permits a deleted-object readback without another
DELETE. HTTP 404, redirects, wrong IDs, wrong ownership, malformed bodies and
delete acceptance without readback never confirm a task. Provider response/error
content is not stored in receipts or returned to callers.

Stripe [customer deletion](https://docs.stripe.com/api/customers/delete) cancels
active subscriptions. A separate `billing_subscription` task requires GET of its
exact customer-bound subscription showing `canceled`; it does not introduce
additional invoice, proration or refund operations. This confirms the API state,
not a billing-correction decision or legal/provider-backup retention completion.

Legacy customer references without a matching immutable creation binding are
`blocked` with `BILLING_OWNERSHIP_BINDING_REQUIRED`; the worker makes no provider
call for them. Do not invent metadata or reset an old creation timestamp/key to
make cleanup proceed. Legacy binding migration requires operator/provider
evidence before introducing any destructive automation.

Tests cover in-flight erasure, lost creation/deletion responses, expired keys,
crossed ownership, stale worker writes, ambiguous readbacks and exact subscription
state. `test_app_billing_privacy.py` additionally kills an actual delivery process
after the loopback provider deletes the customer, checks the durable pending
lease in PostgreSQL, and restarts it: one DELETE, two GETs, no creates, one
confirmed task. This simulator is isolated; no real customer was deleted or
charged. Live qualification, legacy ownership evidence and provider/legal
retention remain separate release requirements.

## Restoring post-backup billing obligations

The application erasure ledger now exports `mk-erasure-ledger-v2`, including the
immutable billing intent and any accepted customer ID for each account request.
The prior tombstone-only v1 format is refused: produce a new externally retained
v2 ledger from the current source instead of labelling an older ledger complete.
Quiesce intake, billing creation and provider-cleanup workers before the final
export; the final cut must include every accepted external effect. Pin its hash
and minimum freshness outside the database being restored.

Migration `0006_billing_restore_bindings.sql` provides cleanup-only bindings for
identities that postdate the backup. Replay validates every binding against its
account tombstone and any surviving creation record before changing data.
Conflicting owners, timestamps, IDs or provider bindings are refused. A binding
cannot be rebound or removed and can learn a previously unknown customer ID only
once. Its presence never permits billing, account sign-in or business intake.

Replay retains these obligations even if the tenant and user did not exist at
the backup point. It does not recreate their business rows. The recovered task
uses the same exact ownership/readback checks as normal cleanup; a previously
deleted customer can be confirmed with authenticated GET without another create
or delete. Repeat replay is idempotent. The generic backup/anchor/legal-retention
obligations remain pending until their own evidence is supplied.

The actual-image acceptance helper's `--erase --billing-privacy --billing-restore`
case takes pg_dump first, records a synthetic accepted billing identity afterward,
deletes the account and exports its pinned ledger, then performs pg_restore and
replay. It requires the exact cleanup binding plus one pending task to survive,
with no recreated business intent. No real billing API key or provider call is
used in that drill.
