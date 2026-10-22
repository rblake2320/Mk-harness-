# S13 application erasure: author-run evidence

Source: `54dedb55374524e8c6d1ff0b695e5c7e340b53f7` on draft PR37.
Shipped image: `sha256:7c0292687d2be8c579ee7d7ef67a087d8293164549d9e75b7ec09ccfddd18527`.
Synthetic fixtures, owned disposable PostgreSQL/container resources, no provider
requests or paid infrastructure. This is active-application-store engineering
evidence, not independent staging qualification or S13 closure.

## Observed failures and repairs

- **Failed before repair:** deleting a linked customer raised PostgreSQL
  `customer_destinations_customer_id_fkey`; account deletion returned success but
  retained its owned provider credential. Both failures are retained in
  `privacy-postgres-red.xml`.
- **Worked after repair:** the linked graph is removed transactionally with real
  foreign keys enabled. Credentials and MFA secrets are removed; only allowlisted
  consent proof and unlinked minimal suppression identifiers remain. Other tenants,
  other members and their shared business keys survive.
- **Worked:** actual blocked-lock inspection confirms erasure waits for an in-flight
  write, then removes that write. Late writes, account reactivation and a new shared
  credential after last-member deletion are rejected by PostgreSQL. Runtime cannot
  rewrite/delete request tombstones or retained minimal proof.
- **Worked:** receipt-only status remains readable after logout, but its token cannot
  authenticate ordinary app routes. A normal access token, tampering and invalid
  receipt are refused. API responses are `no-store`.
- A regression assertion initially expected the sealing guard's repeatable-read
  refusal, but the newly earlier privacy guard refused the same transaction first.
  `privacy-postgres-v3.xml` retains that failure; the test now accepts either exact
  independent guard code while still requiring a database CheckViolation.

## Fixed-source verification

| Scenario | Observed result | Artifact |
|---|---|---|
| Backend + contracts + readiness | 340 passed, zero skips/failures | `privacy-python-54dedb5.xml` |
| Real PostgreSQL boundary/rotation/erasure | 27 passed, zero skips/failures | `privacy-postgres-54dedb5.xml` |
| Production web build | Exit 0 | `privacy-web-build-54dedb5.log` |
| Browser regressions and accessibility | 29 passed | `privacy-web-results-54dedb5.json` |
| Native source typecheck | Exit 0 (not a device run) | `privacy-mobile-typecheck-54dedb5.log` |
| Built image + real web UI + actual PostgreSQL | Worked | `privacy-image-54dedb5/report.json` |

The real UI uses a transparent loopback proxy to the pinned image, not canned API
responses. Deletion returned 202/pending, revoked old access (401), cleared browser
auth storage, downloaded a private receipt, showed no page errors and had no 360px
overflow. Desktop and 360px screenshots are retained; the final 360px render was
visually inspected. No receipt token or backup contents are retained in this bundle.

## Actual backup/restore

The image drill took a 142,679-byte custom-format `pg_dump` before deletion (digest
in the report). A fresh `pg_restore` recovered one customer, destination, provider
key and MFA factor. After explicit database-ACL bootstrap, the separately pinned
819-byte, two-request erasure ledger was replayed with the restricted runtime login.
All four restored content/secret counts became zero; two immutable request rows
remained. Repeating replay succeeded. Wrong hash, stale ledger, duplicates
and identity/scope mismatch are refused in the PostgreSQL acceptance suite.

Each image drill removed exactly its own recorded API container, network and two
temporary databases; the shared task-owned disposable test cluster remains running.

## Qualification boundaries and next work

S13 remains open. The durable queue explicitly records kernel contact/account
erasure, provider/billing tasks, protected restore-ledger anchoring and backup expiry
instead of declaring those effects complete. Downstream workers, automatic retention
and restricted legal holds are the next implementation work. Live external storage,
provider controls, reviewed legal decisions, independent staging verification and
actual deadline/backup-expiry evidence are still required. The local SHA256 pin is
not an independent trust anchor. No acceptance evidence YAML was fabricated.

Predecessor `667bcd7` passed all ten CI checks (retained JSON snapshots). Fixed-source
`54dedb5` CI was dispatched separately; its result is not inferred from its predecessor.
