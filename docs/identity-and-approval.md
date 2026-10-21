# Decision record — identity and approval authority (D4)

**Status:** recorded 2026-10-20 (WP02). Implementation: WP06. Rows: D4, H1–H9.

## Decision

1. **Proposal authority** = FastAPI, via short-lived Ed25519 actor assertions (exists).
   It establishes *which authenticated user is asking* and *which tenant*.
2. **Human-approval authority** = the consultant's own registered **WebAuthn/passkey
   credential**, verified by the kernel. An approval request carries:
   - the kernel-issued approval challenge for the action (derived from the action digest,
     approval id, tenant, approver id, expiry);
   - a WebAuthn assertion over that challenge from a credential registered to the approver
     in the kernel's `kernel.approver_credentials` (registration itself requires an
     authenticated session plus a one-time registration ceremony).
   The kernel verifies signature, origin/RP id, counter, challenge binding and expiry,
   then records the approval bound to the exact action digest. **FastAPI cannot
   produce this assertion**; a compromised FastAPI can therefore propose, but not approve.
3. **Self-approval**: a consultant may approve an agent-origin proposal within the
   tenant-authorized workflow scope (`allow_self_approval`, per tenant, per workflow
   class). This is human approval, not independent second-person review; the audit
   record carries `origin=agent`, `approver=<user>`, `approval_method=webauthn`.
   Independent second-person approval stays configurable per tenant and is the default
   for `RecruitOutreach`.
4. **Agent/MCP credentials cannot approve** (exists; principals with only the `agent`
   role are refused).
5. **Platform operator actions** (global kill switch) use the same step-up path with
   operator credentials registered in the kernel; the `KERNEL_PLATFORM_OPERATORS` list in
   FastAPI becomes a UI hint only.

## Approval controls (H3–H5, unchanged or tightened)

| Control | Value |
|---|---|
| Approval lifetime | 15 minutes from approval; actions scheduled beyond that need fresh approval near execution |
| Invalidation | any change to content, destination, purpose, sender, scheduling → new digest → approval invalid |
| Gesture | explicit per message; no default selection; no standing approval |
| Consumption | single-consume under row lock (exists) |
| Re-evaluation | full policy recheck at dispatch (exists) |
| Replay | assertion jti single-use across replicas (exists); WebAuthn counter monotonic (new) |

## Sessions and revocation (H9)

Revocable sessions: a server-side session registry keyed by jti/session id; logout,
password change, admin revocation and credential loss invalidate pending approvals and
block dispatch of actions approved under the revoked session where the approval has not
yet been consumed. MFA/passkey required for consultant and privileged access (S2);
step-up for sender, permission, export and security changes.

## What this does not claim

Until WP06 lands with forgery, replay, edit, expiry and self-approval tests under an
independent verifier, H6 is **Not demonstrated** and the trust gap in `threat-model.md`
T4 stands.
