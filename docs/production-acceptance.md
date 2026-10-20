# MK Harness — Production Acceptance Matrix (v2)

**Governing document:** `docs/production-completion-contract.md`. This matrix implements
it; where they disagree the contract wins and this file is corrected.
**Standard:** production-grade, market-leading customer follow-through assistant within the
defined release scope (US, English, adults, two-way business SMS, responsive web). Not an MVP.
**Status of this document:** v2, 2026-10-20. Every status below is a classification of
retained evidence, not an assertion of readiness. **Current verdict: NOT READY.**

## 0. Vocabulary and rules of evidence

| State | Meaning |
|---|---|
| **Not demonstrated** | Required evidence absent or insufficient. Includes "unknown". Blocks sign-off. |
| **Implemented** | Code and applicable automated tests exist on `main`. |
| **Independently verified** | Another qualified person (or recorded independent CI with identity, configuration and artifacts) reproduced the stated requirement against a named commit and retained the record. Author-run tests and review comments do not qualify. |
| **Production-proven** | Held in the approved production or production-identical environment over the specified observation window, with retained monitoring data. Pre-release acceptance uses production-identical; actual production history is labelled separately. |

Precedence: Not demonstrated < Implemented < Independently verified < Production-proven.
A parent requirement takes the lowest state of any required child.

Rules:
- No row is closed by a PR description, a passing unrelated test, a named technology, or an assertion.
- Green CI proves the tests in CI passed. A signed callback proves the reporting integration reported. A device sent-row proves a row appeared. Provider `delivered` is carrier confirmation, not a human read. Unknown stays unknown; outcomes are never upgraded because time elapsed.
- A manual step inside a workflow described as automated blocks release until automated or disclosed in product wording.
- A finite zero-defect test result is evidence about that test, not a universal guarantee; wording must say so.
- Material change (model, prompt, retrieval, claims registry, policy, provider config, schema, infra) invalidates affected rows; they are re-earned.

**Evidence governance.** Every closed row has a record in `evidence/releases/<release-id>/<ID>.yaml` with the fields in `evidence/releases/README.md`: requirement ID, exact acceptance condition, owner, source commit, deployed image digest, environment/configuration, test procedure and version, expected result, actual result, evidence location and checksum, verifier identity and independence, verification date, status, invalidation triggers. A planned filename is not evidence.

**Roles (must be named before implementation sign-off):** engineering owner; verification owner (independent of author); security reviewer (independent); legal/privacy reviewer; release owner; operations owner + backup. Current assignment: **Not demonstrated** (all roles unassigned).

**Gates.** `Release` = at least Independently verified. `Release (proven)` = Production-proven over the stated window. `Commercial` = required before accepting paying customers.

---

## 1. Release decisions (fixed by the contract; records required)

| ID | Decision | Record | Status |
|---|---|---|---|
| D1 | Production messaging: Twilio Programmable Messaging, subject to provider onboarding and legal/policy acceptance; dedicated registered business number per consultant business; no silent provider/transport failover | `docs/transport-decision.md` | Record **Implemented**; onboarding/validation **Not demonstrated** |
| D2 | Inbound: provider webhooks for the same enrolled sending identity, authenticated, durably recorded before acknowledgement | `docs/inbound-decision.md` | Record **Implemented**; implementation **Not demonstrated** |
| D3 | Moto/ADB: engineering test equipment only; not a general-release dependency | `docs/transport-decision.md` §ADB | **Implemented** (documented) |
| D4 | Human approval: consultant self-approval of agent-origin proposals allowed within tenant-authorized workflow scope; agent/MCP credentials cannot approve; independent second-person approval remains configurable; separate approval authority with transaction-bound WebAuthn/passkey confirmation bound to the action digest | `docs/identity-and-approval.md` | **Not demonstrated** |
| D5 | Hosting: AWS US, production and staging separated; managed secrets + KMS envelope encryption; versioned containers + IaC; automated gated deployment | `docs/architecture.md`, `infra/` | **Not demonstrated** |
| D6 | Threat model covering all contract-listed attackers, including compromised FastAPI proposal service and uncertain external sends | `docs/threat-model.md` | **Not demonstrated** |
| D7 | Legal/privacy/provider/consultant-agreement review started before architecture lock; decisions from primary sources only | `docs/legal-review.md` (written decision) | **Not demonstrated** |

---

## 2. Customer and permission foundation (F)

| ID | Acceptance condition | Verification | Gate | Status |
|---|---|---|---|---|
| F1 | Tenant-scoped records exist for customers, normalized destinations, preferences + timezone, consent events + evidence, suppression events, sender identities, conversations/messages, commitments, brief items, draft versions, action links, exceptions, outcomes, authorized knowledge sources; each carries opaque tenant id, version, created_at, audit reference | schema tests | Release | **Implemented** (`backend/app/models.py` WP03 section; 27 tables); conversations/messages reuse existing chat tables pending WP04 |
| F2 | Permission scoped to customer, destination, consultant business, channel, purpose, evidence source, effective time, revocation status; an imported number is not permission; an inbound message is not blanket marketing permission | policy tests at proposal and dispatch | Release | Kernel scope check **Independently verified**; application `ConsentEvent` carries destination/business/evidence-source and grants the kernel permission atomically (fails closed) — **Implemented** (`test_foundation.py`); inbound-message rule **Not demonstrated** (WP07) |
| F3 | Editing a customer profile cannot erase suppression; suppression wins over permission everywhere | tests incl. profile-edit path | Release | Kernel precedence **Independently verified**; profile-edit path (suppression keyed by destination fingerprint; suppressed destination refuses consent) **Implemented** |
| F4 | Displayed permission is historical; current permission and suppression are re-checked at execution | dispatch recheck tests | Release | **Independently verified** (live smoke gates 2–4) |
| F5 | CSV import: preview, field mapping, duplicate detection, row errors, provenance, import-job idempotency, tenant isolation, no consent assumed, formula escaping on export, rollback of unreferenced records | import test suite | Release | **Implemented** (`routes/foundation.py`, `test_foundation.py`: preview/commit/rollback, in-file + existing duplicates, row errors, source digest, idempotent key, masked + formula-escaped export, rollback keeps referenced) |
| F6 | No InTouch scraping or automated login exists anywhere in the codebase | code search + review | Release | **Implemented** (none exists) — verifier to confirm |
| F7 | Cross-tenant reads/writes fail via API, SQL, background jobs, exports, search, callbacks | isolation suite under runtime identities | Release | Kernel API/SQL/callbacks/jobs **Independently verified**; new foundation routes incl. import jobs and export **Implemented** (404 + 401 on every route); search **Not demonstrated** (feature absent) |
| F8 | Duplicate imports create no duplicate contacts or work; revoked consent cannot be restored by import | tests | Release | **Implemented** (fingerprint-keyed dedupe; mapping targets for consent/suppression refused; re-import of a revoked contact leaves it revoked) |
| F9 | Unknown destination timezone prevents automated dispatch until corrected | policy test | Release | **Implemented** at proposal (`/api/agent-ops/actions` → 422 `TIMEZONE_UNKNOWN` for outreach kinds; IANA validation); kernel still evaluates contact hours in tenant tz — passing the contact tz to the kernel is WP07 |

## 3. Commitments and daily brief (W)

| ID | Acceptance condition | Verification | Gate | Status |
|---|---|---|---|---|
| W1 | Commitment record per contract schema; statuses draft/confirmed/deferred/resolved/cancelled; AI creates drafts only; consultant confirms customer, meaning and date; "next month" stays a window until a date is chosen | contract `contracts/commitments/v1`; lifecycle tests | Release | **Not demonstrated** |
| W2 | Brief candidates only from: confirmed commitment due, explicit request, unanswered question, confirmed customer-supplied date, unresolved exception; each item shows customer, reason, source, due, state, permission state + check time, next step, draft where allowed, approve/edit/defer/resolve/skip | golden fixture set → exact candidates and ordering | Release | **Not demonstrated** |
| W3 | Deterministic ranking: safety/opt-out attention → overdue confirmed → due today → unanswered → future; within category by due time then oldest | golden set | Release | **Not demonstrated** |
| W4 | No depletion inference from purchase age presented as fact; estimates labelled and never sole justification | golden set + wording review | Release | **Not demonstrated** |
| W5 | An edit cannot leave an old digest approved | kernel digest binding + UI test | Release | Kernel **Independently verified**; UI **Not demonstrated** |
| W6 | Repeated brief generation creates no duplicate commitments or actions | idempotency tests | Release | **Not demonstrated** |
| W7 | Resolved/cancelled/suppressed/deferred items behave consistently; every item has source evidence | tests | Release | **Not demonstrated** |

## 4. Drafting and product knowledge (P)

| ID | Acceptance condition | Verification | Gate | Status |
|---|---|---|---|---|
| P1 | Relationship language separated from controlled product claims; approved-claims registry per contract schema; model may select, never invent or strengthen; source versions stored per draft | registry tests; draft provenance tests | Release | **Not demonstrated** |
| P2 | Missing/expired/unauthorized/contradictory source → no recommendation, explained limitation, neutral acknowledgment or review task | tests | Release | **Not demonstrated** |
| P3 | Customer text, documents, notes are data not instructions; no model output can change tenant/customer, grant consent, clear suppression, select unapproved destination, approve, alter approved content, or execute a tool | architecture: model has no kernel credential; adversarial eval | Release | Kernel authority boundary **Independently verified** (agent-only principal cannot approve); model pipeline **Not demonstrated** |

### AI evaluation thresholds (versioned datasets; held-out set not used for tuning; two-reviewer adjudication; re-run on any model/prompt/retrieval/registry/safety change)

| ID | Evaluation | Minimum set | Required result | Status |
|---|---|---|---|---|
| A1 | Commitment extraction | 500 conversations | ≥99% precision, ≥95% recall on the annotation scheme | **Not demonstrated** |
| A2 | Customer-context correctness | 500 drafts | 0 wrong-customer references or cross-customer disclosures | **Not demonstrated** |
| A3 | Product claims | 500 cases | 0 unsupported claims accepted by the pipeline (including paraphrased invented claims) | **Not demonstrated** |
| A4 | Opt-out and escalation | 500 cases | 0 missed explicit opt-outs; every safety-critical case blocks ordinary sales follow-up | **Not demonstrated** |
| A5 | Prompt injection | 500 adversarial cases | 0 unauthorized action/permission/recipient/approval/controlled-claim changes | **Not demonstrated** |
| A6 | Date/timezone interpretation and abstention | included in A1 set | reported precision/recall and abstention rate; no silently invented dates | **Not demonstrated** |

## 5. Approval and identity (H)

| ID | Acceptance condition | Verification | Gate | Status |
|---|---|---|---|---|
| H1 | Approval screen shows destination, customer, sending business + number, exact text, purpose, supporting commitment/request, permission state, scheduled time, approval expiry | UI test | Release | **Not demonstrated** |
| H2 | Approval bound to exact action version and digest; editing one byte invalidates | kernel + UI tests | Release | Kernel **Independently verified**; UI **Not demonstrated** |
| H3 | Approval lifetime 15 min; actions beyond window need fresh approval near execution; expired approval cannot dispatch | kernel tests | Release | **Independently verified** (`approval_ttl_secs` 900 default; expiry enforced at dispatch) |
| H4 | Explicit gesture per message; no default-selected approval; no standing approval for future AI messages | UI test | Release | **Not demonstrated** |
| H5 | Agent/MCP credentials cannot approve; approval single-consume; policy re-evaluated before execution | kernel tests | Release | **Independently verified** |
| H6 | Proposal authority separated from human-approval authority: a compromised proposal service (FastAPI) cannot mint a valid approval; approval path uses authenticated human session + transaction-bound WebAuthn/passkey confirmation bound to the action digest | architecture + forgery tests | Release | **Not demonstrated** — today FastAPI mints both proposal and approval assertions (documented trust gap) |
| H7 | Assertion replay across two API replicas succeeds at most once | `http_e2e.rs` cross-instance test; live smoke gate 5 | Release | **Independently verified** |
| H8 | Same consultant may approve via human flow when tenant policy permits; tenant policy forbidding self-approval is enforced | policy tests | Release | Forbid path **Independently verified**; permit path via tenant setting **Implemented**, UI/flow **Not demonstrated** |
| H9 | Session or user revocation blocks new approval and dispatch | tests | Release | **Not demonstrated** |

## 6. Production SMS and inbound (C) — transport per D1/D2

| ID | Acceptance condition | Verification | Gate | Status |
|---|---|---|---|---|
| C1 | Versioned provider adapter behind the kernel execution interface: registered sender identity, outbound submission, provider message id, authenticated inbound webhook, authenticated status callbacks, error classification, reconciliation, provider opt-out handling, tenant-bound credentials/routing; isolated provider resources per consultant business | provider-contract tests with simulator; staging run against provider sandbox | Release | **Not demonstrated** (only the ADB test adapter exists) |
| C2 | Webhook signatures validated with the provider's procedure against the configured public URL, never client-supplied forwarding headers | tests incl. forged header | Release | **Not demonstrated** |
| C3 | State model exactly: proposed, awaiting_approval, approved, queued, dispatch_authorized, submission_started, provider_accepted, sent, delivered, failed, delivery_unknown, submission_unknown, cancelled, denied, expired; read status separate and unknown unless supplied; definitions identical in API, UI, support, marketing; never upgraded by elapsed time; callbacks late/duplicate/out-of-order preserved, monotonic derivation | state tests; wording review | Release | Kernel has a narrower set (no submission_started/provider_accepted/submission_unknown/delivery_unknown) — **Not demonstrated** |
| C4 | Ambiguous submission: persist attempt + stable identity → dispatch authorization → record submission starting → provider request; on uncertain failure set submission_unknown, no blind retry, reconcile by provider ids/records/callbacks, else surface exception; human resolution before any replacement message | fault tests: crash before submission, during uncertain response, after acceptance, before result persistence, after callback persistence before ack | Release | Partial: kernel `ReconciliationRequired` on lease expiry **Implemented**; explicit submission_unknown + reconciliation **Not demonstrated** |
| C5 | Inbound event record per contract; body stored encrypted, never in logs/audit metadata; processing order authenticate → bind tenant/sender → durable dedupe → detect opt-out/possible opt-out → suppress or hold → acknowledge → async meaning; duplicate delivery creates no duplicate tasks | `contracts/inbound/v1`; webhook fault tests; replay/out-of-order tests | Release | **Not demonstrated** |
| C6 | One serialized customer/channel control path for suppression and dispatch authorization: an opt-out durably recorded before dispatch authorization commits blocks that action; in-flight provider submissions documented as non-retractable, cancelled where supported; p99 opt-out persistence ≤2 s; queued unauthorized outreach cancelled; ambiguous opt-out → hold; no automatic re-enable; re-consent needs fresh purpose-specific evidence | concurrent transaction tests (STOP vs dispatch), delayed/duplicated inbound, consultant-recorded revocation, clock skew | Release | Kernel serializes dispatch per contact+channel via advisory lock and rechecks suppression **Independently verified**; inbound path, timing target, hold state **Not demonstrated** |
| C7 | Date requests → draft deferrals with evidence; explicit opt-outs suppress immediately; product/skin concerns stop sales follow-up and escalate; complaints, wrong-number, identity ambiguity, delivery uncertainty → visible exceptions | tests | Release | **Not demonstrated** |
| C8 | Inbound health failing for 60 s pauses the tenant's outbound dispatch; resume only after recovery checks pass and pending events processed | fault test | Release | **Not demonstrated** |
| C9 | No frontend, AI worker or legacy Python endpoint holds a customer-message sending credential | code review + secret scanning | Release | **Implemented** (no Python send path exists; `/api/agent-ops` proxies only) — verifier to confirm |

### Real communications qualification (C10)

| ID | Acceptance condition | Status |
|---|---|---|
| C10 | 1,000 approved controlled messages over 30 consecutive days, ≥6 receiving test numbers across 3 mobile networks, all permitted traffic to controlled recipients. Results: 0 unapproved; 0 duplicate customer messages; ≥99% of eligible messages corroborated on the receiving device within 5 min; ≥99.5% reach provider acceptance or explicit visible failure within 60 s; every ambiguous submission surfaced and reconciled or explicitly unknown; opt-out, wrong-number, failure and recovery scenarios included; no unresolved Sev-1/Sev-2 during window. Failed actions never count as success for reaching a terminal state. Provider receipts and device corroboration retained as distinct evidence. Gate: Release (proven) | **Not demonstrated** |

## 7. Outcomes and consultant interface (X)

| ID | Acceptance condition | Verification | Gate | Status |
|---|---|---|---|---|
| X1 | Outcomes recorded: resolved, deferred, opted_out, no_response, customer_reported_order, consultant_confirmed_order, exception_open, cancelled; business outcomes separate from transport states; delivered ≠ resolved; consultant-confirmed order ≠ verified revenue | `contracts/outcomes/v1`; tests | Release | **Not demonstrated** |
| X2 | Interface provides customer timeline, commitment list, daily brief, draft editor, approval screen, conversation inbox, exception queue, outcome recording, permission/suppression view, settings + sender status, audit/evidence export, data export + deletion requests, plain-language errors with recovery | end-to-end tests | Release | **Not demonstrated** |
| X3 | Every automated workflow discloses where human action remains necessary | copy review | Release | **Not demonstrated** |
| X4 | WCAG 2.2 AA conformance via automated checks and manual keyboard/screen-reader assessment; mobile layouts at 360 CSS px keep essential controls | accessibility report | Release | **Not demonstrated** |
| X5 | Usability with 12 representative consultants: ≥11/12 complete onboarding and first approved test message in ≤15 min without engineer help; ≥95% core tasks correct; 0 unnoticed wrong-recipient/wrong-message approvals; every denial/exception class has reviewed wording | study record | Release | **Not demonstrated** |

## 8. Security and privacy (S)

| ID | Acceptance condition | Verification | Gate | Status |
|---|---|---|---|---|
| S1 | Threat model completed before expanding exposed execution surface; covers malicious tenant user, cross-tenant attacker, compromised browser/session, compromised FastAPI proposal service, compromised messaging adapter, compromised device/test agent, insider DB access, forged/replayed callbacks, prompt injection, dependency compromise, stolen backups, privileged support misuse, account recovery abuse | reviewed `docs/threat-model.md` with mitigations mapped to tests | Release | **Not demonstrated** |
| S2 | MFA/passkeys for consultant and privileged access; revocable sessions; step-up auth for sender, permission, export, security changes | tests | Release | **Not demonstrated** (password + JWT only) |
| S3 | Tenant-scoped RBAC; separate runtime DB identities; no application owner/superuser connections at runtime | pre-flight §4; RLS tests under runtime logins | Release | DB identities **Independently verified**; RBAC beyond admin/consultant **Not demonstrated** |
| S4 | Shared durable replay protection (assertions, callbacks, webhooks) | tests | Release | Assertions + adapter callbacks **Independently verified**; webhooks **Not demonstrated** |
| S5 | Rate limits and abuse controls incl. per-tenant limits preventing noisy-tenant exhaustion | load test | Release | Per-user limiter **Implemented**; per-tenant **Not demonstrated** |
| S6 | Encryption in transit and at rest; field-level protection for message bodies and sensitive evidence; KMS-backed versioned envelope encryption replacing the single permanent master key; re-encryption and recovery proven | key tests; rotation drill | Release | AES-GCM under one master key **Implemented**; KMS/envelope/re-encrypt **Not demonstrated** |
| S7 | Restricted outbound network destinations for every service | egress tests | Release | Worker egress allowlist **Implemented**; cluster-level egress **Not demonstrated** |
| S8 | Secret scanning, dependency scanning, container scanning, SBOM, signed build provenance | CI artifacts | Release | cargo audit/deny, Trivy, SBOM **Implemented**; secret scanning, signed provenance **Not demonstrated** |
| S9 | Break-glass access with approval, expiry, audit; no support impersonation without explicit authorization and traceability | procedure + test | Release | **Not demonstrated** |
| S10 | Credential lifecycle tested: provider credentials, assertion keys, DB credentials, webhook secrets, application encryption keys, tenant encryption material; lost/compromised-key containment exercised | rotation tests + drill | Release | Assertion kid rotation, adapter secret rotation, DB password rotation **Implemented**; others **Not demonstrated** |
| S11 | Tenant isolation independently verified across API, SQL, jobs, exports, search, callbacks | isolation suite | Release | see F7 |
| S12 | PII discipline: no raw destinations, messages, names or reversible identifiers in public audit roots, metrics labels or general logs; pseudonymous identifiers access-controlled; permitted encrypted business storage documented separately from prohibited telemetry | data map; log/metric scans | Release | Telemetry/audit/callback prohibition **Independently verified** (live smoke); data map **Not demonstrated** |
| S13 | Retention defaults per contract table adopted and legally reviewed; deletion removes/anonymizes content, caches, exports, provider copies via supported controls; preserves minimal suppression/legal records; content-free audit tombstones keep verification; deleted content does not reappear after restore; requests completed ≤30 days, backups age out ≤35 days; legal holds explicit | `docs/data-retention-and-deletion.md`; deletion lifecycle test incl. restore | Release | **Not demonstrated** |
| S14 | Audit integrity: external anchoring of audit roots to an independently protected destination, or explicit documented residual privileged-operator trust | anchoring job + verification | Release | Local hash chain **Independently verified**; anchoring **Not demonstrated** |
| S15 | Independent external security review of integrated app, kernel, approval flow, messaging adapter, deployment, recovery: 0 unresolved critical, 0 unresolved high, no unresolved medium enabling unauthorized dispatch/cross-tenant disclosure/approval forgery/suppression bypass; lower findings owned with deadlines; fixes retested by reviewer | reviewer report | Release | **Not demonstrated** (coding-agent review does not qualify) |

## 9. Infrastructure, SLOs and operations (O)

| ID | Acceptance condition | Verification | Gate | Status |
|---|---|---|---|---|
| O1 | Topology: separate AWS prod/staging; ECS/Fargate across 2 AZs; ≥2 API, ≥2 worker instances; Multi-AZ managed PostgreSQL with PITR; replicated managed Redis; private data networking; encrypted object storage for evidence; managed secrets + KMS; HTTPS ingress with rate limiting; external uptime checks; independently protected audit-root destination | `infra/` + review | Release | **Not demonstrated** (compose only) |
| O2 | Capacity envelope: 1,000 businesses, ≤10 users each, 1,000,000 customer records, 100 read rps, 20 write/proposal rps, 10 dispatch/s subject to provider limits; per-tenant limits; graceful rejection above capacity; limits published internally | load tests | Release (proven) | **Not demonstrated** |
| O3 | SLOs: monthly availability 99.9% (core workflow, not health endpoint); non-AI API p95 ≤500 ms / p99 ≤1.5 s; brief retrieval p95 ≤2 s; draft generation p95 ≤15 s with progress + cancel; approved eligible action → dispatch start p95 ≤10 s / p99 ≤60 s; inbound persistence p99 ≤2 s; inbound → inbox visible p95 ≤5 s; opt-out recorded → new dispatch blocked immediately at the authorization boundary; RPO ≤5 min; RTO ≤60 min. Scheduled future actions and valid denials reported separately, never dropped | `docs/slo.md`; measurements | Release (proven) | **Not demonstrated** |
| O4 | Load: 8 h at envelope; 30 min at 2×; 24 h at ½ for leaks; provider simulator for volume; SLOs met at envelope; no unauthorized/duplicate execution; no unbounded queue growth; no unexplained resource growth; graceful limiting above capacity; recovery ≤10 min after overload | load report | Release (proven) | **Not demonstrated** |
| O5 | Fault injection: API crash; worker crash before and after external submission; relay crash; PostgreSQL interruption; Redis interruption and data loss; provider timeout/delay; duplicate/out-of-order callbacks; webhook auth failure; stale inbound; secret rotation during operation; deployment rollback; backup restoration. Each: no unauthorized execution, no blind resend, no lost approved action without visible terminal/exception state, recovery + audit consistency | `tests/faults/` reports | Release | Store/queue crash cases **Implemented**; remainder **Not demonstrated** |
| O6 | Observability: Prometheus metrics, OpenTelemetry traces, dashboards for API availability/latency, queue depth + oldest eligible age, outbox lag, lease age, dispatch outcomes, provider states, unknown submissions, callback latency + auth failures, pending approvals + expiry, opt-out latency, inbound health, kill-switch state, audit verification failures, DB/Redis/resource saturation, cost anomalies | dashboards + exporter review | Release | Exported today: requests, decisions, assertion/HMAC failures, approvals_pending, callbacks applied/duplicate — **Implemented**; all else **Not demonstrated** |
| O7 | Paging alerts: suspected unapproved/duplicate send; cross-tenant exposure; audit integrity failure; opt-out processing failure; inbound outage >60 s; eligible queue age >60 s for 5 min; error rate >5% for 5 min; restoration/key-management failure. Critical ack 15 min 24/7; primary + backup operator | alert rules tested by injection; on-call record | Release | **Not demonstrated** |
| O8 | Deployment gates: approved commit, image digest + provenance, CI + contract tests, applicable AI evals, security scans, config + runtime privilege validation, migration compatibility, backup/recovery readiness, pre-flight against target, deploy with dispatch disabled, controlled smoke, cohort enable after checks; no laptop builds; failed gate blocks; rollback never replays uncertain actions | pipeline definition + deploy logs | Release | Pre-flight tooling **Implemented**; pipeline **Not demonstrated** |
| O9 | Restoration without re-sending: every restored environment starts with dispatch disabled; before enabling: verify audit chain, load suppression/deletion ledger, reconcile actions vs provider records, mark uncertain unknown, invalidate pre-restore pending approvals, confirm credentials/sender bindings, release-owner authorization; restore never auto-replays the outbound queue; suppression/deletion recovery ledger kept in separately protected durable destination | timed restore drill meeting RPO/RTO | Release | **Not demonstrated** |
| O10 | Incident game day and restore drill exercised before release; runbooks under `docs/runbooks/` | drill records | Release | Runbook text **Implemented**; exercised **Not demonstrated** |

## 10. Commercial and competitive (M, K)

| ID | Acceptance condition | Gate | Status |
|---|---|---|---|
| M1 | Written legal/privacy decision covering messaging + privacy requirements, consent wording/evidence, sender registration + number provenance, opt-out/re-consent, privacy notice + processor agreements, retention/deletion, permitted consultant use, authorized product data, branding/affiliation, social promotion limits, AI wording + prohibited claims, hosting/model-provider data handling, incident/breach obligations — from current primary sources and binding agreements available to the account holder | Commercial | **Not demonstrated** |
| M2 | If authorization denied: remove integration/source/claim/route, re-test remaining workflow; no relabelling | Commercial | n/a until M1 |
| M3 | Support: published hours + escalation, named ownership, documentation (onboarding, recovery, privacy, export, deletion, opt-out), cancellation + billing correction | Commercial | **Not demonstrated** |
| M4 | Economics: measured provider/hosting/model/observability/storage/support cost; tenant spending + abuse limits; message charges disclosed before approval where they affect the bill; ≥70% gross margin on measured recurring cost at approved pricing incl. support labour; pricing approved by business owner before billing activates | Commercial | **Not demonstrated** |
| K1 | Competitive study: participants' current official-tool workflow + 2 independent alternatives selected by the verification owner via documented feature/access checks; 12 consultants, randomized crossover, 20 matched scenarios each (promise capture, prioritization, preparation, approval, reply deferral, opt-out, product concern, uncertain delivery, outcome recording, reason lookup). Pass: ≥30% lower median active handling time vs best alternative on the follow-through set; ≥95% correct completion; no degradation in opt-out/approval/privacy behaviour; ≥10/12 prefer MK; methods, exclusions, results retained; fail → improve and repeat | Required for any superiority claim (separate from Release) | **Not demonstrated** |
| K2 | Claims register linking every marketing statement to evidence; superiority wording only for tested claims | Commercial | **Not demonstrated** |

---

## 11. Current position (2026-10-20)

**Independently verified (kernel foundation):** tenant isolation at API/SQL/callback/job layers under runtime identities; least-privilege DB identities; dispatch-time recheck of permission scope/expiry/revocation, suppression precedence, kill switches, frequency and contact hours; exact-digest single-consume approval with 15-min TTL; agent-only principals cannot approve; cross-replica single-use assertions; telemetry/audit/callback PII prohibition; local audit hash chain.

**Implemented only:** store/queue crash semantics; adapter nonce/idempotency ledgers; partial metrics; pre-flight tooling; runbook text; secrets generation; current rotation paths; `ReconciliationRequired` on lease expiry; no Python send path; no scraping; decision records D1–D3.

**Not demonstrated:** every consultant-facing capability (F1, F5, F8, F9, W1–W7, P1–P3, H1, H4, H6, H9, X1–X5); production transport and inbound (C1–C5, C7, C8, C10); state model and ambiguous-submission handling (C3, C4); suppression timing/hold (C6 parts); all AI evaluations (A1–A6); identity and approval trust separation (D4, H6); hosting/IaC (D5, O1); SLOs, load, faults, observability, alerts, deployment pipeline, restore (O2–O10); threat model, MFA, KMS, retention/deletion, anchoring, external security review (S1, S2, S6, S9, S13–S15 and parts of S3–S12); every commercial and competitive item (M1–M4, K1–K2); role assignments.

**Verdict: NOT READY.** Failed/absent requirement IDs: all rows above marked Not demonstrated. Corrective work: `docs/production-completion-contract.md` work packages 01–12 in order. Owners: unassigned (blocking). Evidence needed: per-row records under `evidence/releases/<release-id>/`.

## 12. Work packages (from the contract) and the rows they close

| WP | Output | Closes |
|---|---|---|
| 01 Baseline | commit-pinned baseline; current contracts reconciled; current test results captured as *Implemented* only | evidence governance bootstrap |
| 02 Decisions + threat model | D1–D7 records, legal/provider feasibility started | D1–D7, S1 |
| 03 Customer foundation | preferences, consent, suppression, imports, timeline | F1–F9 (Implemented in PR wp03; verification pending), S13 (design) |
| 04 Commitments + brief | lifecycle, deterministic brief, outcome model | W1–W7, X1 |
| 05 Product drafting | authorized sources, claims registry, bounded generation | P1–P3, A1–A6 |
| 06 Approval security | human-bound approval, separated signing authority, exact preview | D4, H1–H9 |
| 07 Messaging + inbound | production adapter, webhooks, reconciliation, opt-out serialization | C1–C9 |
| 08 Complete interface | inbox, brief, editor, approval, exceptions, outcomes, settings | X2–X5 |
| 09 Operations | infra, dashboards, alerts, deployment gates, backup/restore | O1, O5–O10, S6–S8, S10 |
| 10 Independent review | security assessment + fix verification | S15 |
| 11 Qualification | 30-day communications soak; competitive study | C10, O2–O4, K1 |
| 12 Release | evidence package, legal/provider approval, support + economics | M1–M4, K2, sign-off |
