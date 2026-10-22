# S13 provider cleanup: retained author-run evidence

Runtime source: `e08a51d3486f7f2d10be9d29264d8b788e4315ef`, draft PR37.
Synthetic messages, loopback provider simulator, disposable PostgreSQL and owned
containers only. No real Twilio deletion, outbound customer send or paid deployment.

## Failures, repairs and targeted retests

- **Failed:** no provider-erasure adapter existed (`privacy-provider-red.log`).
  The implemented adapter authenticates and binds the existing resource, performs
  DELETE and requires canonical absent readback. Thirteen adapter scenarios pass,
  including false success, proxy 404, cross-tenant/sender, path injection, inbound
  identity, lost response, authentication failure and rate limiting.
- **Failed:** the first worker test found the new migration was not registered in
  the embedded migrator (`privacy-provider-worker-v1.log`). Registered migration
  0018; later migration 0019 preserves its already-applied bytes.
- **Failed:** the actual worker exited on Redis connection failure before privacy
  work started (`privacy-provider-process-red.xml`). Redis connection/reconnection
  now belongs to the dispatch loop; PostgreSQL maintenance starts independently.
- **Failed:** the intake database role could INSERT a fabricated completed provider
  receipt (`privacy-provider-forged-insert-red.log`). Column-scoped INSERT grants
  now permit only target fields. The targeted SQL negative test passes.
- Intermediate process tests also corrected the fixture's webhook egress authority
  and its use of the deleted user's identity as a service principal. The final
  fixture uses a separate privacy principal and only explicit loopback authorities.
- The first concurrent kernel-image attempt could not allocate a Docker network.
  The application image drill was using the remaining default subnet. After its
  own normal cleanup, the serialized kernel drill succeeded. No unrelated network
  or container was removed. The partial first report is retained, not called passed.

## Final checks

| Scenario | Result | Artifact |
|---|---|---|
| Full Rust workspace, real PostgreSQL/Redis | 233 passed | `privacy-provider-workspace-v2.log` |
| All-target/all-feature clippy | Clean | `privacy-provider-clippy-v5.log` |
| Backend/contracts/readiness | 353 passed | `privacy-provider-app-v1.xml` |
| App DB/erasure/bridge and actual worker process | 32 passed | `privacy-provider-postgres-v1.xml` |
| Final migration-0019 bridge/process retest | Five passed | `privacy-provider-bridge-process-v3.xml` |
| Actual restricted worker SQL privileges and leases | Five passed | `privacy-provider-worker-v3.log` |
| Staged source secret scan | No leaks | `privacy-provider-source-secret-scan.json` |

The real-process test kills the worker after the simulator removes the resource,
before the response is delivered. PostgreSQL retains the unconfirmed leased job.
A fresh process, still without Redis, recovers an expired lease and commits exactly
one digest-bound audit receipt. Two DELETE attempts, zero sends, zero authentication
failures. The expired lease is advanced explicitly by the fixture, not by waiting
90 seconds; the process death/restart and external deletion are real.

## Built-image drills

Kernel image:
`sha256:6be6b56caade9abec3b12af0f7358b0d803f80618506cf00c1aaf03acfff13cd`.
Application image:
`sha256:9fb550e6ded6e454c05bc4f8dded30211eac906d24cd273c49ddc4541fea3f2d`.

`privacy-provider-kernel-image-e08a51d-v3/report.json` repeats the process drill
inside the actual optimized worker image: UID 65532, read-only root, all capabilities
dropped, separate worker-only login, Redis absent and SIGKILL exit 137. It verifies
19 migrations, API erasure/re-intake refusal, one active-provider receipt and the
still-pending backup obligation. The fixture server shares the worker's isolated
network namespace; no production HTTP egress rule was weakened.

`privacy-provider-app-image-e08a51d/report.json` verifies actual MFA/customer/export,
restart, HTTP deletion, session revocation and receipt status. A real pre-erasure
pg_dump restores customer, destination, provider key and MFA data; replay of the
separately pinned ledger removes all four again. This run is an API/restore drill;
the unchanged UI's visual checks remain in the prior source bundle.

Each drill removes exactly its recorded temporary containers, networks, databases
and roles. No provider credentials, signing keys, private receipt tokens or database
backup bodies are included in the evidence bundle.

## Remaining acceptance work

Active provider absence is not a backup receipt. A distinct retention obligation
starts at verified absence, cannot be certified by the worker, and is not cleared
by time alone. Sender-resource cancellation, billing cleanup, kernel restore-ledger
replay, automatic retention/holds, privacy-compatible fingerprint retirement and
protected external anchors remain in the work queue. Live vendor/legal evidence,
independent staging and production qualification require their own retained proof.
The readiness checker remains **0/87 closed; NOT READY**. No release YAML was created.
