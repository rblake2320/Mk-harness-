# Data retention and deletion (S12, S13) — engineering defaults pending legal review

**Status:** recorded 2026-10-20 (WP02). These are proposed product rules, not assertions
of legal sufficiency; the legal/privacy reviewer's written decision (M1) confirms or
changes them. Implementation and the deletion lifecycle test: WP03/WP09.

## Data map

The [implemented field and telemetry inventory](data-map.md) distinguishes
field-sealed columns from private business columns relying on storage encryption.
The table below records proposed retention targets, not completed automation.

| Data | Store | Protection | Default retention | Deletable on request |
|---|---|---|---|---|
| Customer records, normalized destinations, preferences | Postgres (app) | tenant scope, destination field-encrypted | life of relationship | yes (anonymize) |
| Message bodies and attachments (outbound drafts/sent, inbound) | Postgres (app) + S3 attachments | KMS envelope field encryption | 12 months | yes |
| Commitments, brief items, outcomes | Postgres (app) | tenant scope | 24 months after resolution | yes |
| Consent evidence (minimal: who, what purpose, when, source digest) | Postgres (app) + separately protected ledger | append-only | 5 years after last reliance | no (legal record) |
| Suppression identifier (hashed destination + channel) | kernel `suppressions` + separately protected ledger | append-only; hash is **not** anonymization — access-controlled | while the business relationship/account is active, minimum fields | no (prevents unwanted contact) |
| Kernel audit events (content-free: types, digests, actor ids) | kernel `audit_events` | append-only chain, anchored | 24 months | tombstone only (content-free; chain intact) |
| Diagnostic application logs | log store | no PII by rule (S12) | 30 days | n/a |
| Redacted security investigation logs | restricted log store | redacted | 90 days | n/a |
| Temporary exports | S3 | SSE-KMS, expiring URLs | 24 hours | auto |
| Test screenshots (test equipment only) | controller host | local | 7 days | auto |
| Database backups | RDS | encrypted | 35 days | age out |

**Permitted encrypted business storage vs prohibited telemetry.** Message bodies and
destinations *may* live in encrypted application records (that is the product). They
*must not* appear in logs, metrics labels, traces, audit payloads, callbacks, evidence
digests' plaintext, or public audit roots. S7/S12 are read this way.

## Deletion lifecycle (request → ≤30 days; backups age out ≤35 days)

1. Verify requester identity (consultant for their customer; step-up auth).
2. Anonymize customer record (destination replaced by irreversible tombstone id); delete
   message bodies/attachments; delete commitments/outcomes content; keep aggregate counts.
3. Purge search/retrieval indexes and caches for the subject.
4. Delete temporary exports.
5. Address provider-held copies via supported provider controls; record the request id.
6. Preserve: minimal consent evidence (hashed destination + purpose + time), suppression
   identifier, content-free audit tombstones. The audit chain must verify after deletion.
7. Restore-safety: deletion requests are written to the separately protected
   suppression/deletion ledger; the restore procedure (O9) replays this ledger before
   dispatch is enabled so deleted content cannot reappear.
8. Legal holds: explicit, restricted, logged, disclosed where required.

Acceptance (S13): deletion test covering primary storage, indexes, caches, object storage,
exports and a backup restore, with chain verification before and after.
