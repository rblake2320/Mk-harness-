# MK Production Completion Contract

**Authority:** issued by the product owner 2026-10-20. This file is the binding
release contract. `docs/production-acceptance.md` is the evidence matrix that
implements it; where they disagree, this contract wins and the matrix is
corrected. The text below is the directive as issued (verbatim, reflowed into
Markdown headings only).

---

Below is the final build-and-release directive. It specifies the product to finish, the engineering decisions, the acceptance thresholds, the evidence required, and the conditions for release. It is not permission to call the current implementation production-ready.

All numerical thresholds below are prescribed acceptance requirements—not claims about measured performance. This specification replaces the earlier pilot/MVP recommendations and strengthens the supplied acceptance matrix. Existing requirements remain unless explicitly replaced here.

No specification can guarantee that implementation will reveal no new defects. New defects must be corrected against this contract; they are not a reason to lower the standard or send avoidable engineering decisions back to you.


## MK production completion directive


## Product and release scope

Build a production-grade customer follow-through assistant for independent beauty consultants.

The completed product must let a consultant:

Bring in customer information through authorized, transparent methods.

Record preferences, permissions, conversations, and commitments.

Review a daily list of justified next actions.

Review and edit customer-specific message drafts.

Explicitly approve consequential actions.

Send through a supported business-messaging channel.

Receive and manage replies.

Automatically stop inappropriate follow-up.

Resolve commitments and record outcomes.

Understand what happened, why it happened, and what requires attention.

The Rust kernel remains the authority for consequential execution. The documented kernel implementation is the foundation to preserve, not a replacement for the consultant-facing product.

The initial general-release scope is:

Dimension	Release specification
Market	United States
Language	English
Customers	Adults only
Primary communication	Two-way business SMS
Main interface	Responsive web application, fully usable on mobile
Human approval	Required for every outbound customer message
Customer knowledge	Authorized imports, consultant-entered information, and authenticated messages from the enrolled channel
Product knowledge	Authorized, versioned, reviewed source material
Unsupported at release	Autonomous calls, unsolicited prospecting, automated social DMs, company-account scraping, medical diagnosis, financing, and guaranteed earnings claims
A supported scope is not an MVP concession. Everything inside that scope must meet the full production standard. Unsupported functionality must be absent or clearly unavailable—not advertised as “coming soon” functionality that already works.


## Fixed architecture decisions

Area	Required decision
Application	Keep FastAPI and the existing frontend; do not perform a wholesale rewrite
Governed execution	Rust kernel
Authoritative state	PostgreSQL
Queue acceleration	Redis Streams; never the only durable record of an approved action
Production messaging	Twilio Programmable Messaging, subject to completed provider onboarding and legal/policy acceptance
Sender model	A dedicated, properly registered business number for each consultant business
Inbound	Provider webhooks, authenticated and durably recorded
Moto/ADB	Engineering test equipment only; not a general-release dependency
AI	Bounded extraction and drafting; no authority to grant permissions, approve, dispatch, or clear suppression
Production hosting	AWS US region, with production and staging separated
Secrets	Managed secret storage and KMS-backed encryption
Observability	Prometheus-compatible metrics, OpenTelemetry traces, dashboards, and actionable alerts
Deployment	Versioned containers and infrastructure as code; automated gated deployment
Approval mode	Human approval by the consultant is allowed; independent second-person approval remains configurable
Do not switch providers or transport silently if onboarding fails. A provider rejection or legal restriction blocks launch until an explicitly reviewed replacement satisfies the same contract.

The consultant must understand that the business number is separate from a personal number. Do not imply that the system automatically reads personal messages, existing phone conversations, or company-controlled accounts.


## Accountability and evidence

Assign named people to these roles before implementation sign-off:

Engineering owner: implementation and integration.

Verification owner: reproduces acceptance tests independently of the implementation author.

Security reviewer: independent security assessment.

Legal/privacy reviewer: permissions, agreements, messaging, privacy, and promotion.

Release owner: checks the complete evidence package and authorizes deployment.

Operations owner and backup: incidents, restoration, monitoring, and customer support.

One person may hold multiple operational roles. The implementation author cannot be the sole verifier or sole security reviewer.

Every requirement must have:

text
Requirement ID
Exact acceptance condition
Responsible owner
Source commit and deployed image digest
Environment and configuration
Test procedure
Expected result
Actual result
Evidence location and checksum
Verifier identity
Verification date
Status
Material changes that invalidate the result
Use these states:

Implemented: code and applicable automated tests exist.

Independently verified: another qualified person reproduced the stated requirement and retained the record.

Production-proven: the requirement held in the approved environment over its specified observation window.

Not demonstrated: required evidence is absent or insufficient.

No row is closed by a PR description, a passing unrelated test, a named technology, or an unsupported assertion.


## Required implementation


### Customer and permission foundation

Implement tenant-scoped records for:

Customers and normalized contact destinations.

Contact preferences and timezone.

Consent events and supporting evidence.

Suppression events.

Sender identities.

Conversations and messages.

Commitments.

Brief items.

Draft versions.

Action links.

Exceptions.

Outcomes.

Authorized knowledge sources.

Every customer-facing record must carry an opaque tenant identifier, version, creation time, and appropriate audit reference.


### Permission rules

Permission must be scoped to:

text
Customer
Destination
Consultant business
Channel
Purpose
Evidence source
Effective time
Revocation status
An imported phone number is not permission.

An inbound message is not blanket marketing permission.

A consultant editing a customer profile cannot erase suppression.

Permissions displayed in the interface are historical observations. Current permission and suppression must be checked again at execution.


### Import requirements

Provide CSV import with:

Preview before commit.

Field mapping.

Duplicate detection.

Row-level errors.

Source/provenance recording.

Import-job idempotency.

Tenant isolation.

No default assumption that imported customers consented.

Spreadsheet-formula escaping on export.

Rollback of the import’s unreferenced records without corrupting subsequent activity.

Do not build InTouch scraping or automated login.


### Acceptance

Cross-tenant reads and writes fail through API, SQL, background jobs, exports, search, and callbacks.

Duplicate imports do not create duplicate contacts or duplicate work.

Revoked consent cannot be restored through import.

All permission changes retain attribution and evidence.

Unknown destination timezone prevents automated dispatch until corrected.


### Commitments and daily priorities


### Commitment record

Implement:

text
id
tenant_id
customer_id
owner_user_id
source_type
source_reference
source_version
source_evidence_reference
commitment_text
due_at or due_window
timezone
status
created_by
confirmed_by
confirmed_at
version
resolution_reference
Allowed statuses:

text
draft
confirmed
deferred
resolved
cancelled
AI extraction creates drafts only.

A consultant must confirm the customer, meaning, and date before a draft becomes actionable.

“Next month” must remain an explicit date window until the consultant chooses a date. The system must not silently invent one.


### Daily brief

Generate candidates from:

Confirmed commitment due.

Explicit customer request.

Unanswered customer question.

Confirmed customer-supplied follow-up date.

Unresolved exception.

Each item must show:

Customer.

Reason it appears.

Supporting source.

Due date or date window.

Current workflow state.

Permission state and check timestamp.

Suggested next step.

Draft, where allowed.

Approve, edit, defer, resolve, and skip controls.

Use deterministic ranking:

Safety concerns and opt-outs requiring attention.

Overdue confirmed commitments.

Due-today commitments.

Unanswered requests.

Future scheduled work.

Within a category, sort by due time, then oldest unresolved item.

Do not infer product depletion from purchase age and present it as fact. Any optional estimate must be clearly labeled and must not independently justify outreach.


### Acceptance

A golden fixture set produces exactly the expected brief candidates and ordering.

An edit cannot leave an old digest approved.

Repeated brief generation does not create duplicate commitments or actions.

Resolved, cancelled, suppressed, and deferred items behave consistently.

Every brief item has source evidence; no unexplained recommendation is allowed.


### Drafting and product knowledge

Separate two kinds of content:

Relationship language: greetings, acknowledgment, and references to confirmed customer context.

Controlled product claims: only reviewed statements from authorized, versioned material.

Implement an approved-claims registry containing:

text
claim_id
product_id
approved_text
source_reference
source_version
market
effective_at
expires_at
reviewer
review_status
The model may choose an approved claim. It may not invent or strengthen one.

Store the source versions used for every generated draft.

If the source is missing, expired, unauthorized, or contradictory:

Do not produce a product recommendation.

Explain the limitation to the consultant.

Offer a neutral acknowledgment or create a review task.

Customer text, retrieved documents, and notes are data—not instructions.

No model output can:

Change the tenant or customer.

Grant consent.

Clear suppression.

Select an unapproved destination.

Approve an action.

Alter approved content.

Execute a tool directly.


### Acceptance

Use versioned datasets with a held-out set not used for prompt tuning:

Evaluation	Minimum test set	Required result
Commitment extraction	500 conversations	At least 99% precision and 95% recall on the defined annotation scheme
Customer-context correctness	500 drafts	Zero wrong-customer references or cross-customer disclosures
Product claims	500 cases	Zero unsupported claims accepted by the pipeline
Opt-out and escalation	500 cases	Zero missed explicit opt-outs; every safety-critical case blocks ordinary sales follow-up
Prompt injection	500 adversarial cases	Zero unauthorized action, permission, recipient, approval, or controlled-claim changes
Two reviewers must adjudicate disagreements in the evaluation labels.

A zero-error test result is evidence on that dataset, not a claim that all future model errors are impossible.

Run the applicable evaluation suite whenever the model, prompt, retrieval, claims registry, or safety logic changes.


### Approval and identity

For solo consultants, enable tenant-scoped human self-approval for permitted workflows.

Human self-approval means the person approves an agent-generated proposal. It does not mean the agent approves itself.

The approval screen must show:

Actual destination.

Customer identity.

Sending business and number.

Exact outgoing text.

Purpose.

Supporting commitment or request.

Permission state.

Scheduled time.

Approval expiry.

Bind approval to the exact action version and digest.


### Required controls

Approval lifetime: 15 minutes.

Actions scheduled beyond that window require fresh approval near execution.

Content, destination, purpose, sender, or scheduling changes invalidate approval.

Explicit approval gesture required for each message.

No default-selected approval.

No standing approval for future AI-generated messages.

Agent/MCP credentials cannot invoke approval.

Approval is single-consume.

Current policy is re-evaluated before execution.

Separate proposal authority from human-approval authority.

A compromised proposal service must not be able to mint a valid human approval. Use a separately protected approval path with an authenticated human session and transaction-bound WebAuthn/passkey confirmation. The approval verification must bind the challenge to the action digest.


### Acceptance

Demonstrate that:

A proposal-service credential cannot approve.

Replaying an assertion across two API replicas succeeds at most once.

Editing one approved byte invalidates approval.

An expired approval cannot dispatch.

The same consultant can approve through the human flow when tenant policy permits it.

Tenant policy forbidding self-approval is enforced.

Session or user revocation blocks new approval and dispatch where applicable.


### Production SMS and inbound


### Provider integration

Implement a versioned provider adapter behind the Rust execution interface.

It must support:

Registered sender identity.

Outbound submission.

Provider message identifier.

Authenticated inbound webhook.

Authenticated status callbacks.

Error classification.

Reconciliation.

Provider-side opt-out handling.

Tenant-bound credentials and routing.

Configure isolated provider resources per consultant business. Avoid a shared outbound identity that misrepresents independent businesses.

Validate webhook signatures using the provider’s supported procedure, with the configured public URL—not arbitrary client-supplied forwarding headers.


### State model

Use distinct states:

text
proposed
awaiting_approval
approved
queued
dispatch_authorized
submission_started
provider_accepted
sent
delivered
failed
delivery_unknown
submission_unknown
cancelled
denied
expired
Store read status separately and leave it unknown unless a supported source actually supplies it.

Definitions must appear consistently in API responses, UI, support material, and marketing:

Provider accepted: provider acknowledged submission.

Sent: provider reports outbound network submission.

Delivered: supported provider/carrier receipt reports delivery.

Read: supported recipient-read signal exists.

Unknown: evidence is insufficient.

An outcome must never be upgraded because time elapsed.

Callbacks can arrive late, duplicated, or out of order. Preserve their original events; derive state with monotonic rules so an older event cannot overwrite stronger evidence incorrectly.


### Ambiguous submission

Before external submission:

Persist an execution attempt and stable action identity.

Obtain the dispatch authorization.

Record that submission is starting.

Make the provider request.

If the connection fails after submission may have occurred:

Set submission_unknown.

Do not blindly retry.

Reconcile using available provider identifiers, request records, and callbacks.

If reconciliation cannot establish the result, surface an exception.

Require explicit human resolution before any replacement message is proposed.

Do not advertise universal exactly-once delivery. The required behavior is duplicate prevention within controlled execution, conservative treatment of uncertainty, and honest reporting.


### Inbound processing

Inbound events must contain:

text
event_id
provider
provider_event_id
tenant_id
sender_identity_id
source_destination
received_at
provider_timestamp
content_reference
authentication_result
raw_event_digest
The message body must be stored encrypted, not placed in logs or audit metadata.

Processing order:

Authenticate.

Bind sender resources to the correct tenant.

Durably deduplicate.

Detect opt-out or possible opt-out.

Apply suppression or a temporary safety hold.

Acknowledge receipt.

Process conversational meaning asynchronously.

Duplicate delivery must not create duplicate tasks.


### Opt-out and concurrent dispatch

Use one serialized customer/channel control path for suppression and dispatch authorization.

Required rule:

If an authenticated opt-out has been durably recorded before dispatch authorization commits, that action must not be authorized.

An action already submitted to a provider may not be retractable. Record that boundary honestly and cancel where supported.

Opt-out persistence: p99 within 2 seconds of receipt at the application.

No new dispatch authorization after recorded suppression.

Cancel queued, not-yet-authorized outreach.

Apply a hold for ambiguous possible opt-outs.

Do not clear suppression automatically from an ordinary reply.

Re-consent requires fresh, purpose-specific evidence through an explicit workflow.

Test this with concurrent transactions, not only sequential unit tests.


### Dates and concerns

Date requests create draft deferrals with source evidence.

Explicit opt-outs suppress immediately.

Product/skin concerns stop ordinary sales follow-up and create human escalation.

Complaints, wrong-number reports, identity ambiguity, and delivery uncertainty create visible exceptions.

A stale or failing inbound path pauses outbound dispatch.

Pause the affected tenant’s outbound dispatch when inbound health checks fail for 60 seconds. Resume only after recovery checks pass and pending events have been processed.


### Outcomes and consultant interface

Record:

text
resolved
deferred
opted_out
no_response
customer_reported_order
consultant_confirmed_order
exception_open
cancelled
Keep business outcomes separate from transport states.

A delivered SMS is not a resolved commitment.

A consultant-confirmed order is not independently verified revenue.

Provide:

Customer timeline.

Commitment list.

Daily brief.

Draft editor.

Approval screen.

Conversation inbox.

Exception queue.

Outcome recording.

Permission and suppression view.

Settings and sender status.

Audit/evidence export.

Data export and deletion requests.

Plain-language errors and recovery instructions.

Every automated workflow must disclose where human action remains necessary.

Conform the supported web interface to WCAG 2.2 AA through automated checks and manual keyboard/screen-reader assessment.


### Usability acceptance

With 12 representative consultants:

At least 11 of 12 complete onboarding and first approved test message within 15 minutes, without engineer assistance.

At least 95% of assigned core tasks are completed correctly.

Zero unnoticed wrong-recipient or wrong-message approvals in the test protocol.

Every denial and exception class has reviewed, understandable UI wording.

Mobile layouts work at 360 CSS pixels without losing essential controls.


## Security and privacy completion


### Required security controls

Complete a threat model before expanding the exposed execution surface.

Cover:

Malicious tenant user.

Cross-tenant attacker.

Compromised browser/session.

Compromised FastAPI proposal service.

Compromised messaging adapter.

Compromised device/test agent.

Insider database access.

Forged/replayed callbacks.

Prompt injection.

Dependency compromise.

Stolen backups.

Privileged support misuse.

Account recovery abuse.

Implement:

MFA/passkeys for consultant and privileged access.

Revocable sessions.

Step-up authentication for sender, permission, export, and security changes.

Tenant-scoped RBAC.

Separate runtime database identities.

No application owner/superuser database connections.

Shared durable replay protection.

Rate limits and abuse controls.

Encryption in transit and at rest.

Field-level protection for message bodies and sensitive evidence.

Restricted outbound network destinations.

Secret scanning, dependency scanning, container scanning, SBOMs, and signed build provenance.

Break-glass access with approval, expiry, and audit.

No support impersonation without explicit authorization and traceability.


### Credential lifecycle

Test rotation and revocation for:

Provider credentials.

Actor assertion keys.

Database credentials.

Webhook verification secrets where applicable.

Application encryption keys.

Tenant encryption material.

Replace a single permanent application master-key dependency with KMS-backed key management and versioned envelope encryption.

Prove re-encryption and recovery without losing access to valid records.

A lost or compromised key must have a documented, exercised containment procedure.


### Retention and deletion

Adopt these engineering defaults, subject to the legal review described below:

Data	Default retention
Application message bodies and attachments	12 months
Resolved commitments and ordinary outcome details	24 months
Content-free security/audit events	24 months
Diagnostic application logs	30 days
Redacted security investigation logs	90 days
Temporary exports	24 hours
Test screenshots	7 days
Database backups	35 days
Minimal consent evidence	5 years after the last reliance on that consent
Suppression identifier	While the business relationship/account remains active, with the minimum information necessary to prevent unwanted contact
These are proposed product retention rules, not assertions of legal sufficiency.

Do not put raw destinations, messages, names, or reversible customer identifiers into public audit roots, metrics labels, or general logs. Pseudonymous identifiers remain access-controlled.

Deletion must:

Remove or anonymize active customer content.

Remove search/retrieval copies and caches.

Delete temporary exports.

Address provider-held copies through supported controls.

Preserve only approved minimal suppression/legal records.

Leave content-free audit tombstones without breaking verification.

Prevent deleted content from reappearing after backup restoration.

Complete normal deletion requests within 30 days, with backups aging out within 35 days. Legal holds must be explicit, restricted, and disclosed where required.


### Independent security acceptance

Commission a qualified external review of the integrated application, Rust kernel, approval flow, messaging adapter, deployment, and recovery procedures.

Release requires:

Zero unresolved critical findings.

Zero unresolved high findings.

No unresolved medium finding capable of unauthorized dispatch, cross-tenant disclosure, approval forgery, or suppression bypass.

Remaining lower-risk findings documented with owners and deadlines.

Fixes retested by the reviewer.

A coding-agent review alone does not satisfy this requirement.


## Infrastructure and reliability


### Deployment topology

Use:

Separate AWS production and staging environments.

ECS/Fargate services across two availability zones.

At least two API instances.

At least two worker instances.

Managed PostgreSQL with Multi-AZ availability and point-in-time recovery.

Managed Redis with replication.

Private networking for data services.

Object storage for encrypted evidence.

Managed secrets and KMS.

HTTPS ingress with rate limiting.

External uptime checks.

An independently protected audit-root destination.

Keep provider submission isolated behind the kernel’s execution adapter.

No frontend, AI worker, or legacy Python endpoint may hold a direct customer-message sending credential.


### Supported capacity

The release must support:

Dimension	Required envelope
Consultant businesses	1,000
Users per business	Up to 10
Total customer records	1,000,000
Sustained interactive reads	100 requests/second
Sustained writes/proposals	20 requests/second
Internal dispatch capacity	10 actions/second, subject to sender/provider limits
Per-tenant rate limits must prevent a noisy tenant from exhausting other tenants’ service.

These are qualification limits, not a claim of unlimited scale. Publish supported limits internally and reject excessive work gracefully.


### SLOs

Measurement	Required target
Core application monthly availability	99.9%
Normal non-AI API latency	p95 ≤500 ms; p99 ≤1.5 s
Daily brief retrieval	p95 ≤2 s
Draft generation	p95 ≤15 s, with visible progress and cancellation
Approved eligible action → dispatch start	p95 ≤10 s; p99 ≤60 s
Authenticated inbound persistence	p99 ≤2 s
Inbound received → inbox visible	p95 ≤5 s
Explicit opt-out recorded → new dispatch blocked	Immediate at the defined authorization boundary
Recovery point objective	≤5 minutes
Recovery time objective	≤60 minutes
Availability includes the integrated service’s ability to perform its advertised core workflow. Do not conceal a provider outage by measuring only the health endpoint.

Scheduled future actions and valid policy denials are not latency failures. They must be reported separately, not removed silently.


### Qualification tests


### Load

Run:

8 hours at the sustained envelope.

30 minutes at twice the envelope.

24 hours at half the envelope for leak detection.

Use a provider simulator for high-volume traffic. Do not generate bulk real messages to manufacture a load result.

Acceptance:

SLOs met at the sustained envelope.

No unauthorized or duplicate execution.

No unbounded queue growth.

No unexplained continuous resource growth.

Graceful rate limiting above capacity.

Normal service restored within 10 minutes after overload ends.


### Fault injection

Exercise at least:

API crash.

Worker crash before and after external submission.

Relay crash.

PostgreSQL interruption.

Redis interruption and data loss.

Provider timeout and delayed response.

Duplicate/out-of-order callbacks.

Webhook authentication failure.

Stale inbound path.

Secret rotation during operation.

Deployment rollback.

Backup restoration.

For every case demonstrate:

No unauthorized execution.

No blind resend of uncertain submissions.

No lost approved action without a visible terminal or exception state.

Recovery and audit consistency.


### Real communications qualification

Run 1,000 approved controlled messages over 30 consecutive days using at least six receiving test numbers across three mobile networks.

All test traffic must be permitted and sent to controlled recipients.

Acceptance:

Zero unapproved messages.

Zero duplicate customer messages.

At least 99% of eligible test messages corroborated on the receiving device within 5 minutes.

At least 99.5% reach provider acceptance or an explicit visible failure within 60 seconds.

Every ambiguous submission is surfaced and reconciled or explicitly left unknown.

Opt-out, wrong-number, failure, and recovery scenarios are included.

No unresolved severity-1 or severity-2 incident during the qualifying window.

Failed actions do not count as successful merely because they reached a terminal state.

Provider receipts and receiving-device corroboration must be retained as distinct evidence.


### Monitoring and incident response

Dashboard requirements:

API availability and latency.

Queue depth and oldest eligible action age.

Outbox lag.

Worker lease age.

Dispatch attempts and outcomes.

Provider acceptance and delivery states.

Unknown submissions.

Callback latency and authentication failures.

Pending approvals and expiry.

Opt-out processing latency.

Inbound health.

Tenant/global kill-switch state.

Audit verification failures.

Database, Redis, and resource saturation.

Cost and usage anomalies.

Page the operator for:

Any suspected unapproved or duplicate send.

Cross-tenant exposure.

Audit integrity failure.

Opt-out processing failure.

Inbound outage exceeding 60 seconds.

Eligible queue age exceeding 60 seconds for 5 minutes.

Error rate above 5% for 5 minutes.

Restoration or key-management failure.

Critical incident acknowledgment: 15 minutes, 24/7.

Maintain a primary and backup operator.

Exercise an incident game day and restore drill before release.


### Restoration without re-sending

Every restored environment starts with external dispatch disabled.

Before enabling:

Verify the audit chain.

Load the latest suppression/deletion ledger.

Reconcile actions against provider records.

Mark uncertain submissions unknown.

Invalidate pre-restore pending approvals.

Confirm credentials and sender bindings.

Obtain release-owner authorization.

Database restoration must never automatically replay an old outbound queue.

Preserve the suppression/deletion recovery ledger in a separately protected, durable destination so restoration cannot silently resurrect invalid permissions or erased content.


## Commercial and competitive completion


### Legal and provider gates

The legal/privacy reviewer must provide a written decision covering:

Applicable messaging and privacy requirements.

Consent wording and evidence.

Sender registration and number provenance.

Opt-out and re-consent.

Privacy notice and processor agreements.

Retention and deletion.

Permitted consultant use.

Authorized product data.

Branding and affiliation statements.

Social promotion restrictions.

AI-generated wording and prohibited claims.

Hosting/model-provider data handling.

Incident and breach response obligations.

Use current primary sources and binding agreements available to the account holder.

Do not infer permission from a third-party PDF or public marketing page.

If authorization is denied:

Remove the affected integration, data source, claim, or promotion route.

Re-test the remaining supported workflow.

Do not proceed by disguising the integration or changing the label.

No legal approval, provider account, registration, or carrier permission is assumed to exist.


### Competitive verification

Evaluate against:

The participating consultants’ current official-tool workflow.

Two independently available alternatives with the strongest verified overlap in follow-up, reminders, customer messaging, and task management.

The verification owner selects those alternatives through documented current feature/access checks—not convenience. This selection is execution work, not a question that must return to the user.

Use 12 consultants in a randomized crossover study with 20 matched task scenarios per consultant, including:

Promise capture.

Daily prioritization.

Follow-up preparation.

Approval.

Reply deferral.

Opt-out.

Product concern.

Uncertain delivery.

Outcome recording.

Finding the reason behind an action.

Competitive acceptance:

At least 30% lower median active handling time on the predefined follow-through task set than the best tested alternative.

At least 95% correct task completion.

No degradation in opt-out, approval, or privacy behavior.

At least 10 of 12 participants prefer MK for the tested follow-through workflow.

All study methods, exclusions, and results retained.

If these targets fail, improve the product and repeat the study.

Production readiness and market leadership are separate conclusions. A technically ready product must not be marketed as best-in-market without the comparative result. Even a successful comparison supports only the tested claim—not “better than everything in every respect.”

Maintain a claims register linking each marketing statement to evidence.


### Support and economics

Before accepting paying customers:

Publish support hours and escalation instructions.

Assign named support ownership.

Provide onboarding, failure recovery, privacy, export, deletion, and opt-out documentation.

Provide cancellation and billing correction.

Measure provider, hosting, model, observability, storage, and support cost.

Run tenant spending limits and abuse limits.

Disclose message-related charges before approval where they affect the customer’s bill.

Require a 70% gross-margin target using measured recurring operating costs and actual proposed pricing. Include support labor; disclose separately any excluded product-development expenditure.

Pricing must be approved by the business owner before billing is activated. That is a commercial authorization—not an unresolved engineering design decision. If pricing is not approved, billing remains disabled and general paid release remains blocked.


## Work order and repository deliverables

Execute in this order. Parallel work is allowed where dependencies permit.

Work package	Required output	Acceptance evidence
01 — Baseline	Identify merged source, reconcile current contracts, capture current test results	Commit-pinned baseline; no inherited unverified “passed” claims
02 — Decisions and threat model	Architecture, provider, sender, inbound, identity, privacy, and threat-model records	Reviewed records and early legal/provider feasibility
03 — Customer foundation	Preferences, consent, suppression, imports, customer timeline	Isolation, import, permission, and deletion tests
04 — Commitments and brief	Draft/confirm lifecycle, deterministic brief, outcome model	Golden-set and workflow tests
05 — Product drafting	Authorized sources, claims registry, bounded generation	Claim/context/extraction evaluations
06 — Approval security	Human-bound approval, separated signing authority, exact preview	Forgery/replay/edit/expiry and self-approval tests
07 — Messaging and inbound	Production adapter, webhooks, reconciliation, opt-out serialization	Provider-contract, race, duplicate, and uncertainty tests
08 — Complete interface	Inbox, brief, editor, approval, exceptions, outcomes, settings	End-to-end, mobile, accessibility, and usability results
09 — Operations	Infrastructure, dashboards, alerts, deployment gates, backup/restore	Load, fault, game-day, and restoration artifacts
10 — Independent review	Security assessment and fix verification	Findings closed under the stated rules
11 — Qualification	Real-message soak and comparative consultant study	30-day communications report and competitive report
12 — Release	Final evidence package, legal/provider approval, support and economics	Signed release record
Create and maintain:

text
docs/production-completion-contract.md
docs/production-acceptance.md
docs/architecture.md
docs/transport-decision.md
docs/inbound-decision.md
docs/identity-and-approval.md
docs/threat-model.md
docs/data-retention-and-deletion.md
docs/slo.md
docs/runbooks/
docs/competitive-protocol.md
docs/claims-register.md
docs/support-and-economics.md

contracts/inbound/v1/
contracts/commitments/v1/
contracts/outcomes/v1/

tests/acceptance/
tests/security/
tests/faults/
tests/evaluations/

infra/
evidence/releases/<release-id>/
These are required deliverables, not assertions that the paths already exist.

Preserve existing contract compatibility. A deliberate breaking change requires a new version and migration test.

Keep CLAUDE.md aligned with this contract, including the prohibition on unsupported readiness claims.


## Deployment and release decision


### Automated deployment gates

Every production deployment must:

Verify the approved source commit.

Verify image digest and build provenance.

Run required CI and contract tests.

Run applicable AI evaluations.

Check security scan results.

Validate configuration and runtime privileges.

Check migration compatibility.

Perform encrypted backup/recovery readiness checks.

Run pre-flight against the deployment target.

Deploy with dispatch initially disabled.

Perform a controlled smoke test.

Enable the authorized traffic cohort only after checks succeed.

No deployment from an unreviewed laptop build.

A failed gate blocks deployment. A rollback restores service but must not replay uncertain actions.


### Production qualification and rollout

Before general availability:

Complete the 30-day authorized qualification window.

Satisfy all release gates.

Resolve critical/high security findings and safety-impacting defects.

Obtain independent verification and business/legal approvals.

Publish honest support and service descriptions.

After approval, expand traffic in stages:

10% for 24 hours.

25% for 48 hours.

100% only if SLOs and safety checks remain satisfied.

Any unapproved send, confirmed duplicate, suppression bypass, or cross-tenant exposure triggers immediate dispatch shutdown and incident response.

Staged rollout is deployment risk control. It is not an excuse to release missing required functionality.


## Final sign-off checklist

The release owner must be able to answer yes to every item:

Is the full advertised consultant workflow complete?

Are all approvals genuinely human-authorized and digest-bound?

Can no legacy path bypass the kernel?

Is the production transport registered, permitted, and operational?

Does inbound handling reliably stop unwanted follow-up?

Are ambiguous external actions handled without blind retries?

Are status labels accurate?

Are tenant isolation, identity, and least privilege independently verified?

Are credential rotation and data deletion exercised?

Are restore and rollback safe from accidental re-sending?

Are SLO, load, fault, and communications targets met?

Are monitoring, support, and incident responsibilities staffed?

Have AI safety and factuality evaluations passed?

Has the interface passed usability and accessibility acceptance?

Are legal, privacy, provider, and branding permissions documented?

Are economics viable at the approved price?

Are all product claims supported?

Is every acceptance result linked to retained, commit-specific evidence?

If any required answer is no or unknown, general release is blocked.

The final report must state one of:

NOT READY — followed by the exact failed requirement IDs, required corrective work, owners, and evidence needed.

or:

READY FOR GENERAL RELEASE WITHIN THE DEFINED SCOPE — followed by the release commit, deployed artifact digests, qualification window, evidence index, and named sign-offs.

Market-superiority wording requires the separate competitive evidence.

This is the engineering handoff: complete the specified system, prove the specified behavior, obtain the named external authorizations, and release only when every applicable gate passes. No MVP substitution, no silent assumptions, and no readiness claim based merely on progress.
