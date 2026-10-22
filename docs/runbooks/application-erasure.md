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
as being under legal hold. Automated expiry/hold enforcement and provider erasure
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
`privacy_provider_deletions` is a durable queue, not a deletion receipt. Its consumer
and provider-backup evidence are still required; no live provider was contacted by
this author-run verification. Twilio documents that Message DELETE returns 204, and
message bodies may remain in its backups for up to 30 days after deletion
([Twilio Message resource](https://www.twilio.com/docs/messaging/api/message-resource#delete-a-message-resource)).

Hash-only destination fences are included in fingerprint-key retirement inventory.
If their raw destination has been erased and a replacement key cannot derive a new
tag, retirement remains blocked; never omit these fences to make an inventory green.
The privacy-preserving key-transition/retention policy remains a release task.

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
