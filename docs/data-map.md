# S12 data and telemetry map

Engineering inventory, 2026-10-22. This is not legal approval or a staging
qualification. The separate retention targets are in
[data-retention-and-deletion.md](data-retention-and-deletion.md).

| Surface | Actual retained data and boundary | Privacy treatment |
|---|---|---|
| Application PostgreSQL business records | Tenant/user customer book, chat, commitments, claims and source provenance; application authorization and runtime database role | Some columns are plaintext business content, not individually encrypted: e.g. customer names/notes and commitment text. Disk/backup encryption must be verified in the deployed environment. Do not describe all application columns as field-encrypted. |
| Sealed application columns | Destination values, imported phone/email values, draft text, exception details, outcome notes, provider credentials and MFA seeds | Versioned authenticated encryption with tenant/purpose binding; key fence, rotation/reseal and backup recovery tests. Plaintext exists in memory for authorized use. |
| Kernel business records | Canonical action requests, recipient/permission/suppression state, provider metadata and recovery state | Canonical requests can contain plaintext message/destination data inside the private database. Inbound content and sender/adapter secrets are sealed. Account/contact erasure removes active content and fences reintake; uncertain submissions remain quarantined for resolution. |
| Application audit | Event names, server record IDs, closed categories, counts, booleans and digests | Member email, provenance text, claim identifiers, free-form reasons and generator text are excluded by producers. The shared audit helper rejects nested known raw/secret fields. Older direct producers use closed values or validated record IDs; this is not a database-wide free-text detector. |
| Kernel audit | Hash-chained events, UUID principals/registered adapter IDs, closed categories, counts and digests | Free-form adapter descriptions, permission scopes, suppression reasons, rejected tool names and provider status are not copied. Device errors become a fixed failure category; provider error codes must be bounded digits. Correlation IDs are canonical UUIDs only. Hashes and IDs remain restricted pseudonymous data, not anonymous public material. |
| Application HTTP logs | Closed method, route **template**, status, elapsed time; exception class only | Default Uvicorn raw-target/peer access logging is disabled by middleware. Unknown routes use `unmatched`, custom methods use `OTHER`. Unhandled failures return generic errors; stream failures rethrow only a sanitized exception, without the original chain. No query, body, credentials, peer IP or expanded path is logged here. |
| Kernel logs and metrics | Operational categories, matched route templates, counts and timing | Canary tests inspect actual API logs, stored audit events and image metrics. Database exception details are not logged. Credentials and raw bodies are forbidden. Worker identities are operator configuration, not customer input. |
| Provider/device boundaries | Approved content is sent to the selected transport; receipts authenticated before application | Provider business payloads are not trusted as telemetry. Signed status and device callbacks cannot insert arbitrary error/identity text into the audit chain. Provider deletion/readback and backup obligations have separate receipts. |
| Exports, evidence and roots | Authorized exports can contain personal data; local verification uses synthetic fixtures | No raw dump, private restore ledger or credential is included in verification artifacts. Public/externally anchored roots must carry only content-free commitments; an external anchoring deployment is still required. |

## Executable checks

- `backend/tests/test_audit_privacy.py`: member email, source provenance, claim
  identifiers, consent/suppression reasons, commitment provenance, nested raw keys.
- `backend/tests/test_telemetry_privacy.py`: query/path/peer canaries, unmatched
  route, custom method, ordinary failure and failure after response streaming starts.
- `tools/verification/test_kernel_audit_privacy.py`: signed internal HTTP,
  authenticated provider and device callbacks, UUID correlation preservation,
  database fault canary, audit actor/payload scans. The device test seeds a synthetic
  dispatch state; it does not claim a physical device execution.
- `tools/verification/app_database_image.py --audit-privacy`: actual container
  URL/query canaries and presence of content-free replacement request events.
- `tools/verification/kernel_privacy_image.py`: actual restricted image audit,
  log and metric canaries, together with dump/restore and provider crash recovery.

## Deployment and historical-data handling

These changes prevent the reproduced writes; they do **not** rewrite existing
immutable audit chains. A historical scan and explicit retention/tombstone handling
must precede release of an existing database. Do not delete evidence or silently
replace old chain roots. External audit custody, proxy/load-balancer log settings,
trace exporter payloads, log retention/access controls and staging canary scans
must be qualified against the deployed configuration. They cannot be inferred
from a localhost test or an unapplied Terraform plan.
