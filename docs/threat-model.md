# Threat model — MK Harness (WP02)

**Status:** v1, 2026-10-20. Closes the *authoring* part of S1; S1 is **Implemented**
until the security reviewer (independent) reviews it, and **Independently verified**
only when every listed mitigation maps to a retained test record.
**Scope:** the integrated product within the release scope: FastAPI application, Rust
action kernel, provider messaging adapter (D1), inbound webhooks (D2), approval path
(D4), AWS deployment (D5), recovery (O9). Out of scope: the Moto/ADB test equipment in
production (D3).

Legend for *Control status*: **V** = independently verified today; **I** = implemented;
**N** = not demonstrated. Test refs are to existing suites or the work package that must
add them.

## 1. Assets and trust boundaries

| Asset | Why it matters |
|---|---|
| Customer destinations, message bodies, consent evidence | PII; unwanted contact is the primary harm |
| Suppression records | authoritative "never contact"; loss = unlawful/unwanted messages |
| Approvals (exact-digest, single-consume) | the only authority to send |
| Assertion private key (FastAPI), adapter/provider credentials, DB credentials, master/KMS keys | forgery of identity or sends |
| Audit chain + evidence bundles | accountability; tamper → undetectable misuse |
| Provider sender identities (registered numbers) | carrier standing; misuse = brand and legal harm |

Boundaries: browser ↔ FastAPI; FastAPI ↔ kernel (assertion); kernel ↔ Postgres (RLS + per-process logins); kernel worker ↔ provider (adapter, egress allowlist); provider ↔ kernel (signed webhooks/callbacks); operators ↔ production (break-glass).

## 2. Attackers, attacks, controls, gaps

### T1 Malicious tenant user (authenticated consultant)
| Attack | Control | Status | Test / WP |
|---|---|---|---|
| Send to a number without permission | deny-by-default consent at proposal and at dispatch; suppression > permission | V | `mk-policy` consent tests; live smoke gate 2 |
| Forge permission by editing a profile or importing a CSV with a "consented" column | permission requires evidence source + purpose; import never sets consent; profile edit cannot touch suppression | N | WP03 F2/F3/F8 tests |
| Exceed frequency / contact hours | dispatch-time recheck with per-contact advisory lock | V | `dispatch_e2e` frequency cap |
| Approve own proposal when tenant policy forbids | `check_approver`; `allow_self_approval` per tenant | V (forbid) / N (permit flow) | WP06 H8 |
| Smuggle secrets or callback URLs into action arguments | schema forbids `callback_url/password/api_key/token/secret`; proxy rejects before forwarding | V | `test_agent_ops` |
| Abuse rate (burst proposals) | per-user limiter | I | WP09 S5 per-tenant limits |

### T2 Cross-tenant attacker
| Attack | Control | Status | Test / WP |
|---|---|---|---|
| Read/modify another tenant's actions, approvals, consent via API | tenant bound from app JWT; kernel binds from assertion; RLS on every tenant table forced for runtime logins | V | `postgres.rs` cross-tenant; `test_agent_ops` cross-tenant 404; pre-flight §4 |
| Replay a captured assertion | ≤30 s life, single-use jti durable across replicas | V | `http_e2e` second-instance replay |
| Guess/enumerate action ids | UUIDv7 ids; RLS makes other tenants' rows invisible (404) | V | — |
| Cross-tenant via exports/search (future features) | must inherit tenant scoping | N | WP03/WP08 F7 |

### T3 Compromised browser / session
| Attack | Control | Status | Test / WP |
|---|---|---|---|
| Session token theft → approve sends | approvals require explicit gesture; 15-min TTL; **planned**: step-up WebAuthn bound to the action digest | I (TTL) / N (WebAuthn) | WP06 H4, H6 |
| Long-lived sessions | JWT 30-min access + `pv` password fingerprint invalidation | I | WP06 H9 revocation list |
| CSRF on approval | bearer-token API (no cookie auth) | I | WP08 verify |

### T4 Compromised FastAPI proposal service (holds the assertion private key)
| Attack | Control | Status | Test / WP |
|---|---|---|---|
| Mint an assertion for any user/tenant and **approve** | **Gap:** today the same key signs proposal and approval principals | **N** | WP06 H6: separate approval authority — approval requests carry a WebAuthn assertion whose challenge = action digest, verified by the kernel against the user's registered credential; FastAPI cannot produce it |
| Mint `platform_operator` and flip the global switch | role minted only for ids in `KERNEL_PLATFORM_OPERATORS` — but a compromised FastAPI controls that env | N | WP06: global switch requires WebAuthn step-up by an operator credential registered in the kernel |
| Propose unlimited actions | policy still applies; approvals still required; frequency caps | V | — |
| Exfiltrate PII | FastAPI holds customer data by design; mitigations are detection (S12 logging rules), least data in kernel responses | I | WP09 |

### T5 Compromised messaging adapter / provider credentials
| Attack | Control | Status | Test / WP |
|---|---|---|---|
| Send arbitrary messages with the provider credential | credential tenant-bound and held only by the kernel worker; egress allowlist; every send must be preceded by `dispatch_authorized` for an approved action — adapter receives only authorized actions | I (ADB) / N (provider) | WP07 C1, C9 |
| Replay or forge callbacks/webhooks | HMAC with per-adapter secret + nonce window (test equipment); **provider**: signature validation against configured public URL; durable dedupe | V (test equipment) / N (provider) | WP07 C2, C5 |
| Report false `delivered` | state derived from authenticated events only; never upgraded by time; `delivered` labelled as carrier report | N | WP07 C3 |

### T6 Compromised device / test agent (Moto/ADB)
Not a production component (D3). Controls exist (HMAC, nonce ledger, PII discipline, boot-identity gate) and are tested in `tools/mobile-agent-adb/test_agent.py`. Production config disables the adapter kind.

### T7 Insider database access (DBA / cloud operator)
| Attack | Control | Status | Test / WP |
|---|---|---|---|
| Edit or delete audit rows | append-only triggers; runtime roles lack UPDATE/DELETE; hash chain detects tampering | V (chain) | `audit_rows_cannot_be_updated_or_deleted` |
| Rewrite history with owner privileges and recompute the chain | **residual trust**: a schema-owner can rewrite; mitigation = external anchoring of `root_commitment` to an independently protected destination | **N** | WP09 S14 |
| Read message bodies | field-level encryption with KMS envelope keys; bodies never in audit | N | WP09 S6 |
| Resurrect suppressed contacts via restore of an old backup | restore procedure loads the separately protected suppression/deletion ledger before dispatch is enabled | N | WP09 O9 |

### T8 Forged or replayed callbacks (network attacker)
Covered under T5; plus: duplicate Authorization headers refused; nonce reuse refused for 2×tolerance+60 s; timestamp skew 120 s. Status V for the kernel endpoint; provider webhook path N (WP07).

### T9 Prompt injection via customer messages, notes, documents
| Attack | Control | Status | Test / WP |
|---|---|---|---|
| Inbound text instructs the assistant to change recipient / text / clear suppression / approve | model has **no** kernel credential; approval binds exact digest; suppression only cleared by explicit re-consent workflow; model outputs are data (W/P rows) | V (kernel authority) / N (pipeline) | A5 500 adversarial cases |
| Injected text alters an already-approved message | digest binding → approval invalid | V | `http_e2e` digest mismatch |

### T10 Dependency / supply-chain compromise
cargo deny + audit, Trivy image scan, SBOM, all GitHub Actions digest-pinned (I); secret scanning and signed build provenance (N, WP09 S8); distroless non-root image (I).

### T11 Stolen backups
Encrypted backups (N, WP09); message bodies field-encrypted so a backup alone is not plaintext (N, WP09 S6); backup retention 35 days (S13).

### T12 Privileged support misuse / impersonation
Break-glass with approval, expiry, audit; no impersonation without explicit authorization and traceability (N, WP09 S9).

### T13 Account recovery abuse
MFA/passkeys; recovery flows with step-up and audit (N, WP06/WP09 S2).

### T14 Uncertain external sends (not an attacker — a failure mode the contract names)
Crash after provider submission before durable confirmation. Control: persist `submission_started` before the call, stable provider id, `submission_unknown` on uncertain response, reconciliation by provider ids/callbacks, no blind retry, human resolution before replacement (N, WP07 C4; fault tests O5).

## 3. Decisions taken by this model

1. **Separate approval authority (H6).** Approval of consequential actions requires a WebAuthn/passkey assertion from the human's registered credential whose challenge is the action digest; the kernel verifies it. FastAPI's assertion key establishes *who is asking*; it can no longer establish *human approval*. Until implemented, the matrix carries H6 as Not demonstrated and the release is blocked.
2. **Global kill switch** moves to the same step-up path for operator credentials registered in the kernel.
3. **External audit anchoring** is required (S14); the local chain alone is not accepted as protection against privileged rewrite.
4. **Restore starts with dispatch disabled** and loads the suppression/deletion ledger from a separately protected store before anything is enabled (O9).

## 4. Residual risks accepted only with named owner sign-off

| Risk | Owner |
|---|---|
| Provider-side data handling of message bodies | legal/privacy reviewer |
| Carrier filtering/false `failed` on legitimate traffic | operations owner |
| Model-level errors within evaluated thresholds (A1–A6) | release owner |

## 5. Review

| Role | Name | Date | Result |
|---|---|---|---|
| Security reviewer (independent) | unassigned | — | pending |
