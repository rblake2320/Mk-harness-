# Parked Work And Claims

Parked means preserved but not represented as implemented. Each item names the
reason, current replacement, and evidence required before restoration.

## P-001 - Direct PhoneClaw webhook integration

- **Parked because:** no upstream HTTP/webhook contract was found.
- **Current replacement:** signed `consultant-studio.phoneclaw-work-order.v1`
  envelope delivered to an operator-controlled adapter.
- **Restore when:** PhoneClaw publishes a versioned remote contract or the
  partner supplies a reviewed adapter specification, and real-device contract
  tests pass for a pinned build.
- **Links:** [D-001](WHY.md#d-001---use-an-adapter-contract-not-an-invented-phoneclaw-api),
  [implementation](backend/app/call_center/claw_bridge.py).

## P-002 - Autonomous dispatch without human approval

- **Parked because:** generated customer communication and UI actions can cause
  financial, privacy, platform, or consumer harm.
- **Current replacement:** mandatory authenticated approval and atomic dispatch
  claim.
- **Restore when:** a workflow-specific risk assessment, bounded action policy,
  rollback design, and adversarial test suite justify a named low-risk workflow.
- **Links:** [D-002](WHY.md#d-002---require-human-approval-before-execution),
  [dispatcher](backend/app/call_center/dispatcher.py).

## P-003 - Voice calling and AI call handling

- **Parked because:** v1.7.0 implements work orders for messaging, posting, and
  portal navigation, not telephony, speech recognition, AI voice, caller ID,
  recording consent, opt-out handling, or emergency escalation.
- **Current replacement:** none; do not describe this release as an AI voice
  call center.
- **Restore when:** telephony and consent providers are selected, federal/state
  requirements are assessed by qualified counsel, opt-out and suppression are
  enforced, and end-to-end call evidence is tested.
- **Links:** [FCC 24-17](https://docs.fcc.gov/public/attachments/FCC-24-17A1.pdf),
  [FTC TSR guidance](https://www.ftc.gov/business-guidance/resources/complying-telemarketing-sales-rule).

## P-004 - Legal-proof or compliance-ready audit claims

- **Parked because:** the current database chain is not digitally signed,
  externally anchored, WORM-backed, independently assessed, or tied to a
  documented evidence-retention control.
- **Current replacement:** narrowly described tamper detection relative to the
  retained tenant head.
- **Restore when:** signed entries, protected identity keys, off-system head
  anchoring, deletion/truncation monitoring, retention controls, and independent
  assessment are complete.
- **Links:** [D-004](WHY.md#d-004---keep-audit-data-tenant-scoped-and-transactional),
  [audit implementation](backend/app/call_center/audit.py).

## P-005 - National Do Not Call and jurisdiction automation

- **Parked because:** contact permissions are operator attestations; the harness
  does not query the National Do Not Call Registry, determine exemptions, apply
  state-specific rules, or verify evidence authenticity.
- **Current replacement:** matching, expiring, revocable permission records and
  mandatory approval.
- **Restore when:** counsel-approved policy mappings, registry access, campaign
  ownership, suppression synchronization, and periodic quality-control tests are
  implemented.
- **Links:** [D-003](WHY.md#d-003---gate-direct-outreach-on-a-recorded-permission),
  [permission API](backend/app/routes/claw.py).

## P-006 - Native execution of adapter-required actions

- **Parked because:** PhoneClaw's documented helper surface does not directly
  cover every input and URL-opening operation used by these workflows.
- **Current replacement:** those steps remain explicit declarative adapter
  actions and are never labeled verified on device.
- **Restore when:** the adapter maps each action to a pinned PhoneClaw build and
  device tests prove input, navigation, result capture, failure, and retry paths.
- **Links:** [bridge](backend/app/call_center/claw_bridge.py),
  [workflows](backend/app/call_center/workflows/).
