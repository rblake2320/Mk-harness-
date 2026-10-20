# MK Harness — Production Acceptance Specification and Evidence Matrix

**Standard:** production-grade, market-leading consultant follow-through product. Not an MVP.
**Status of this document:** v1, 2026-10-20. It defines what must be true before a general
production release and what counts as evidence. It is not a claim that any row is met.

## 0. Vocabulary (used in every status report from here on)

| State | Meaning | What it is NOT |
|---|---|---|
| **Implemented** | Code exists on `main` with tests that exercise it | proof it works in production |
| **Independently verified** | Someone/something other than the author exercised it against the stated requirement (external review, red-team, live gate, device run) and the record is kept | proof it holds under production load/time |
| **Production-proven** | Observed meeting its target in the production (or production-identical) environment over the stated window, with monitoring data | permanent; it is re-earned after material change |
| **Not demonstrated** | No evidence at the required level. Includes "unknown" | a defect; it is a blocker for sign-off |

Rules of evidence:
- Green CI is evidence that the tests in CI pass. Nothing more.
- A signed device callback is evidence the device agent *reported* an outcome. "Sent" means a sent-row appeared on the device. Delivered and read require carrier/recipient evidence and are reported as **unknown** until a source exists.
- One device run establishes *feasibility*. Reliability requires the run counts in §2.
- Rust, RLS, HMAC, Ed25519 are mechanisms. Each requirement is proven by a test of the requirement, never by naming the mechanism.
- Any manual step inside a workflow that the product describes as automated is a release blocker until it is either automated or disclosed in the product's own words.
- An **unknown** critical control blocks sign-off; it does not imply the control is defective.

Sign-off: every row marked **Gate = Release** must be at least *Independently verified*, and every row marked **Gate = Release (proven)** must be *Production-proven*, before "production-ready" is used. Until then the wording is **"progress toward production"**.

---

## 1. Complete customer workflow

| ID | Requirement | Verification | Evidence artifact | Status (2026-10-20) | Gate |
|---|---|---|---|---|---|
| W1 | Commitments: a promise made in conversation becomes a reviewable record (who, what, due, evidence pointer, permission snapshot); never auto-committed | Unit + e2e: conversation → draft commitment → consultant confirms → record | `backend/tests/test_commitments.py`; fixture conversations | **Not demonstrated** (no commitments domain exists) | Release |
| W2 | Daily priorities: rule-based candidates (promise due, explicit ask, unanswered question, customer-supplied date) with the rule named on each item; no inferred "running out" without a labeled estimate | Golden-set test: known records → expected brief, each item carries its rule and evidence | brief fixtures + assertions | **Not demonstrated** | Release |
| W3 | Draft: personalized message with approved-claim language only; conversational text separated from controlled claims | AI-quality eval (§5) + schema that marks claim spans | eval report | **Not demonstrated** | Release |
| W4 | Approval: consultant sees recipient, exact text, permission state, reason; approves the exact digest | kernel exact-digest approval; UI shows digest-bound content | `http_e2e.rs` approval binding; UI test | Kernel side **Independently verified** (Codex review + live smoke); UI **Not demonstrated** | Release |
| W5 | Execution: kernel rechecks permission/suppression/kill switch/frequency/hours at dispatch | `dispatch_e2e.rs`, live smoke gates 2–4 | CI `live-smoke` artifacts | **Independently verified** | Release |
| W6 | Inbound replies: STOP cancels pending outreach; date → deferred task; concern → human escalation; all through an authenticated channel | Inbound contract + tests; live run with a real reply | contract `mk.inbound.v1`; device-run record | **Not demonstrated** (no inbound channel) | Release |
| W7 | Exceptions: ambiguous reply, missing permission, product concern stop automation and surface to the consultant with context | e2e: each exception class → task state + consultant-visible item | tests + screenshots | **Not demonstrated** | Release |
| W8 | Outcomes: resolved / deferred / opted-out / consultant-confirmed order recorded per action; no causal lift claims | schema + report test; wording review | report fixture | **Not demonstrated** | Release |
| W9 | No hidden manual repair anywhere in W1–W8 | Workflow walk-through with every manual step listed and either automated or disclosed | walk-through record | **Not demonstrated** | Release |

## 2. Dependable communications

| ID | Requirement | Verification | Evidence artifact | Status | Gate |
|---|---|---|---|---|---|
| C1 | Supported transport: the device/carrier path is permitted by the carrier, the OS, and the consultant agreement; no account automation of third-party systems | Written policy check against primary sources; transport decision record | `docs/transport-decision.md` | **Not demonstrated** (ADB path is a candidate, not accepted) | Release |
| C2 | Restart recovery: agent, worker, relay, API each crash at every step; no lost or duplicated send | Chaos suite: kill -9 at each phase, assert outbox/lease/idempotency invariants | `rust/crates/*/tests/chaos_*.rs`; agent restart tests | Store/queue crash cases **Implemented** (`redis_postgres.rs`); agent restart **Implemented** (ledger tests); full-chain chaos **Not demonstrated** | Release |
| C3 | Duplicate prevention: at-least-once delivery absorbed; exactly one customer message per approved action | e2e with forced duplicate stream entries and double callbacks; device sent-row count = 1 | `dispatch_e2e.rs` duplicate test; device run log | Kernel side **Implemented**; device side **Not demonstrated** | Release |
| C4 | Opt-out: STOP honored before the next dispatch tick; suppression wins over permission everywhere | policy tests + inbound live run + timing measurement | tests; run record with timestamps | Policy **Independently verified**; inbound **Not demonstrated** | Release |
| C5 | Honest state vocabulary: attempted / sent (device row) / delivered (carrier receipt) / read (recipient signal) distinguished in data, UI and reports; unknown shown as unknown | schema review; UI strings review | state enum + UI | Kernel `sent` only; delivered/read **Not demonstrated** (no source) | Release |
| C6 | Reliability target over a soak of N ≥ 200 approved actions on controlled phones across ≥ 5 days: (a) ≥ 99% reach a terminal state within T minutes, (b) ≥ 98% of those not denied by policy end in `sent` (device sent-row confirmed; failure budget ≤ 2%), (c) 0 unapproved sends, (d) 0 duplicate customer messages, (e) every `sent` corroborated on the receiving test phone. A run that terminates in `failed_final` does not count toward (b) | Soak run on controlled devices with receiving-phone reconciliation | soak report with per-action audit ids and receive log | **Not demonstrated** | Release (proven) |
| C7 | Device agent fitness: the Moto/ADB agent meets C1–C6 or is replaced | Decision after C1 and C6 | decision record | **Not demonstrated** | Release |

## 3. Security and privacy

| ID | Requirement | Verification | Evidence artifact | Status | Gate |
|---|---|---|---|---|---|
| S1 | Tenant isolation: no cross-tenant read/write via API, SQL, queue or callback | RLS tests under real runtime identities; cross-tenant 404 tests; raw-SQL probe | `postgres.rs` cross-tenant tests; `test_agent_ops.py`; pre-flight §4 | **Independently verified** (Codex + live smoke under per-process logins) | Release |
| S2 | Least privilege: each process holds exactly its privilege role; API cannot claim outbox, relay cannot read approvals, nobody can edit audit | pre-flight §4 + store tests | pre-flight report | **Independently verified** | Release |
| S3 | Credential lifecycle: adapter secret rotation with overlap, assertion kid rotation, DB password rotation, MASTER_KEY re-encrypt migration | tests for each path incl. MASTER_KEY | rotation runbook + tests | Adapter/assertion **Implemented**; MASTER_KEY re-encrypt **Not demonstrated** (no migration exists) | Release |
| S4 | Retention and deletion: customer data, audit payloads, evidence bundles, agent screenshots have retention periods and a tested deletion path that preserves audit integrity | retention policy doc; deletion test with chain verification | policy + tests | **Not demonstrated** | Release |
| S5 | Threat model: documented attackers (malicious consultant, compromised device agent, compromised FastAPI, insider DBA, replayed messages) with mitigations mapped to tests | threat model review | `docs/threat-model.md` | **Not demonstrated** | Release |
| S6 | Independent security review of kernel + proxy + agent | external reviewer report with findings closed | report | **Not demonstrated** (automated Codex review ≠ security review) | Release |
| S7 | PII discipline: no destination/message text in logs, metrics, audit payloads, callbacks | forbidden-key scan + log grep in live smoke | smoke gate | **Independently verified** | Release |
| S8 | Secrets handling: generated with CSPRNG, stored outside git, private assertion key never reaches kernel containers | pre-flight §7; secrets script tests | pre-flight report | **Implemented**; ps1 untested in CI | Release |

## 4. Operational reliability

| ID | Requirement | Verification | Evidence artifact | Status | Gate |
|---|---|---|---|---|---|
| O1 | Availability and latency targets defined (API p95, proposal→queue, approval→dispatch) | SLO document | `docs/slo.md` | **Not demonstrated** | Release |
| O2 | Load/soak: sustained N proposals/min for H hours with targets met, no leaks | k6/locust run + Rust metrics | load report | **Not demonstrated** | Release (proven) |
| O3 | Dependency failure: Postgres down, Redis down, device agent down, FastAPI down — each fails closed, recovers, no duplicate sends | fault-injection suite | report | Fail-closed on DB **Implemented**; others **Not demonstrated** | Release |
| O4 | Monitoring: metrics exported (decisions, auth failures, approvals pending, callbacks applied/duplicate, queue depth, lease age, callback latency, dispatch outcomes), dashboards, OTLP traces | exporter + dashboard review against this list | `/metrics` output; dashboard | Exported today (`mk-api/src/metrics.rs`): requests, decisions, assertion/HMAC failures, approvals_pending, callbacks applied/duplicate — **Implemented**. Queue depth, lease age, callback latency, worker dispatch outcomes, OTLP, dashboards — **Not demonstrated** | Release |
| O5 | Alerts: actionable alerts for kill-switch flips, audit chain break, dispatch stall, callback failures, assertion failures | alert rules tested by injection | rules + test log | **Not demonstrated** | Release |
| O6 | Backup and tested restoration: Postgres restore drill with audit chain verifying after restore | drill record | drill log | **Not demonstrated** | Release |
| O7 | Rollback and incident procedures exercised, not just written | game day | record | Runbook **Implemented**; exercised **Not demonstrated** | Release |
| O8 | Change management: migrations additive or with a tested down-path; pre-flight runs on every deploy and blocks on failure | deploy pipeline definition + deploy logs showing pre-flight per deploy | pipeline config; deploy log | Pre-flight tooling **Implemented** (`scripts/kernel-preflight.sh`; exercised by the live smoke, which PR #32 adds to CI — CI is not a deploy). No deploy pipeline exists, so every-deploy enforcement is **Not demonstrated** | Release |

## 5. AI quality

| ID | Requirement | Verification | Evidence artifact | Status | Gate |
|---|---|---|---|---|---|
| A1 | Factual accuracy: product statements come only from an authorized, versioned source; eval shows 0 invented benefits on the golden set | retrieval + claim-span eval | eval report | **Not demonstrated** | Release |
| A2 | Appropriate uncertainty: the brief distinguishes confirmed facts from estimates in every item | eval over brief outputs | report | **Not demonstrated** | Release |
| A3 | Correct customer context: drafts reference the right customer, promise, product; cross-customer leakage = 0 on adversarial set | eval | report | **Not demonstrated** | Release |
| A4 | Resistance to malicious input: prompt injection via customer messages/notes cannot change recipient, text after approval, permissions, or produce forbidden claims | red-team suite; kernel digest binding makes post-approval change impossible | suite + kernel tests | Kernel binding **Independently verified**; model-level red team **Not demonstrated** | Release |
| A5 | Safe escalation: medical/skin concerns, complaints, ambiguous replies route to the human; `SKIN_FORBIDDEN_TERMS` path preserved | eval + existing skin compliance tests | tests | Skin path **Implemented**; outreach escalation **Not demonstrated** | Release |

## 6. Consultant experience

| ID | Requirement | Verification | Evidence artifact | Status | Gate |
|---|---|---|---|---|---|
| X1 | Onboarding: consultant enrolls, grants permissions, pairs device, sends first approved message in ≤ 15 minutes without engineer help | timed sessions with ≥ 5 consultants | session records | **Not demonstrated** | Release |
| X2 | Everyday workflow: time per resolved follow-up measured against the consultant's current tools; must be lower | comparative study (§7) | study | **Not demonstrated** | Release |
| X3 | Error states are understandable (why an action was denied, what to do) | usability review of every deny code's UI text | review | **Not demonstrated** | Release |
| X4 | Accessibility and mobile fit of approve/edit/skip | audit | report | **Not demonstrated** | Release |

## 7. Competitive advantage

| ID | Requirement | Verification | Evidence artifact | Status | Gate |
|---|---|---|---|---|---|
| K1 | Hands-on comparison against the consultant's current official tools and ≥ 2 independent tools on the same tasks (promise follow-through, opt-out handling, approval control, outcome visibility) | side-by-side protocol, scored | comparison report | **Not demonstrated** (desk research only) | Release |
| K2 | Claims register: every marketing claim maps to a K1 result or is removed | review | register | **Not demonstrated** | Release |

## 8. Commercial readiness

| ID | Requirement | Verification | Evidence artifact | Status | Gate |
|---|---|---|---|---|---|
| M1 | Authorized integrations only: no scraping or automation of company-controlled accounts; data sources are consultant-owned or explicitly permitted | legal/policy review against the binding agreement read in the logged-in source | review memo | **Not demonstrated** | Release |
| M2 | Promotion constraints understood (consultant social pages, marks, AI imagery) | policy review | memo | **Not demonstrated** | Release |
| M3 | Support ownership: who answers a consultant at 7 pm when a send fails; SLA | support plan | plan | **Not demonstrated** | Release |
| M4 | Unit economics: messaging + hosting + model cost per resolved task vs price | cost model with measured inputs | model | **Not demonstrated** | Release |
| M5 | Accurate product claims: UI and marketing use the C5 vocabulary; nothing says "delivered" without a receipt | copy review | review | **Not demonstrated** | Release |

---

## 9. Current position, honestly

**Independently verified today:** tenant isolation, least-privilege identities, dispatch-time policy recheck (consent, suppression, kill switches, frequency, hours), exact-digest approval, single-use assertions across replicas, PII discipline — all through the live smoke under production-faithful identities, plus external review cycles.

**Implemented, not independently verified:** crash semantics of store/queue, agent nonce/idempotency ledgers, the exported subset of Prometheus metrics, pre-flight tooling (not enforced per deploy), runbook, secrets generation.

**Not demonstrated:** the entire consultant-facing workflow (commitments, brief, drafts UI, inbound, exceptions, outcomes), transport acceptance, reliability over a soak, threat model and external security review, retention/deletion, SLOs, load/fault injection, alerting, restore drill, all AI-quality evals, all consultant-experience and competitive evidence, all commercial items.

**Therefore:** progress toward production. No general release. No comparative claims.

## 10. Order of work (dependencies, not a feature wish-list)

1. Transport decision (C1) and inbound channel decision (W6) — everything in §1–2 depends on them.
2. Threat model (S5) before more surface is added.
3. Commitments + brief + outcomes data model (W1, W2, W8) with golden sets.
4. Inbound contract and exceptions (W6, W7) with the chosen channel.
5. Controlled-device feasibility run (existing `docs/real-device-acceptance.md`), then soak (C6).
6. Fault injection + SLOs + alerts (O1–O5), restore drill (O6).
7. AI evals (A1–A5) on the real brief/draft pipeline.
8. Consultant sessions (X1–X3) and side-by-side comparison (K1).
9. Security review (S6), retention (S4), legal/policy (M1–M2), support + economics (M3–M4).

Each step closes rows in this matrix; a status report lists rows moved and the artifact that moved them.
