# S12: audit, callback and application HTTP privacy

Runtime source: `f39cd6788b511b5d48c6deb0ef1004e52d48b1db`, draft PR37.
Author-run synthetic fixtures only. No production requests, external messages,
paid deployment, historical audit rewrite or independent row closure.

## Reproductions and repairs

- `audit-privacy-app-red-v2.xml`: member email, provenance and nested raw fields
  entered audit records. The first red fixture used an invalid test email domain;
  it is retained but is not the leak reproduction. Producers now use internal
  IDs/counts/booleans and the shared helper recursively rejects raw/secret keys.
- `audit-privacy-kernel-red-v1.xml`: permission scope and suppression reason
  canaries entered the immutable chain. Both producers now retain counts/presence.
- `audit-privacy-kernel-v2.xml`: arbitrary correlation text entered `trace_id`.
  The canonical UUID path remains usable; non-UUID input is omitted.
- `audit-privacy-identifier-red-v1.xml`: rejected tool names, device actor text
  and free-form device errors entered permanent audit. Only registered tool names
  and adapter UUIDs are now used. Device errors use a fixed category with a digest
  in restricted dead-letter metadata. The device case seeds synthetic dispatch
  state; it does not represent physical execution.
- Callback regression `audit-privacy-workspace-v1.log` and
  `audit-privacy-callback-red-v1.xml`: the new guard correctly rejected three old
  raw-status producers but caused HTTP 500. These producers now use folded/closed
  state and digests. The first erased-callback fixture had an unresolved delivery;
  correcting it to terminal delivery exercises the intended content-erased path.
- `audit-privacy-app-image-red-v1/report.json`: the prior image recorded raw URL
  and query canaries. The replacement middleware disables default Uvicorn access
  logging and emits method/route-template/status/timing only. Exceptions expose
  their class, not private messages; streamed failures suppress the original chain.

Application v2's five failures were one missed raw consent-revocation reason; v3
also corrected a test-only source enum. Clippy v3 caught a redundant closure.
All are retained along with the subsequent successful retests.

## Observed results

| Scenario | Outcome | Retained evidence |
|---|---|---|
| Rust workspace, PostgreSQL/Redis, pool one | Worked: 236 passed | `audit-privacy-workspace-v3.log` |
| All-target/all-feature Clippy | Worked | `audit-privacy-clippy-v4.log` |
| Application, contracts and readiness suite | Worked: 385 passed | `audit-privacy-app-v5.xml` |
| PostgreSQL runtime, erasure, recovery and new kernel canaries | Worked: 60 passed | `audit-privacy-postgres-v1.xml` |
| Exception and streaming sanitization | Worked: four cases, also in 385 above | `audit-privacy-telemetry-v1.xml` |
| Source secret scan | Worked: no leaks | `audit-privacy-source-secret-scan.json` |

Application image `sha256:dc06f016bb751dd233ba88c91e663ba74dd2690203dd4aacc3fdc99ed12955e9`:
`audit-privacy-app-image-v1/report.json` verifies raw URL/query absence and actual
replacement HTTP events, MFA/step-up, restart, active erasure and real dump/restore
ledger replay. Runtime UID 65532, read-only root and dropped capabilities retained.

Kernel image `sha256:215efe3164b60995b6f08d5e19f4f41173a7070b30f12e1154f039acebb5c1f7`:
`audit-privacy-kernel-image-v1/report.json` scans eight new audit events, actual
logs and metrics, including a signed provider callback. It also repeats actual
dump/restore and provider deletion crash recovery: Redis unavailable, SIGKILL 137,
restart, two DELETE attempts, zero sends, one receipt, provider backup still pending.
Owned probe containers, networks, databases and logins were removed.

The final count remains 0/87 checker-closed rows (`audit-privacy-readiness.json`).
These are implemented repairs with author evidence, not independent staging
qualification. Historical audit handling and the remaining deployed telemetry
surfaces stay in the engineering/qualification queue.

All ten source-pinned GitHub jobs passed: application workflow `39753507305`
and kernel workflow `39753507314`, including actual PostgreSQL, live smoke and
image builds. Full job records are in `audit-privacy-app-ci.json` and
`audit-privacy-kernel-ci.json`, both bound to the runtime source above.
