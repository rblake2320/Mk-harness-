# Decision record — identity and approval authority (D4)

**Status:** recorded 2026-10-20 (WP02); **implemented 2026-10-20 (WP06)** — see "Implementation" below. Rows: D4, H1–H9.

## Decision

1. **Proposal authority** = FastAPI, via short-lived Ed25519 actor assertions (exists).
   It establishes *which authenticated user is asking* and *which tenant*.
2. **Human-approval authority** = the consultant's own registered **WebAuthn/passkey
   credential**, verified by the kernel. An approval request carries:
   - the kernel-issued approval challenge for the action (derived from the action digest,
     approval id, tenant, approver id, expiry);
   - a WebAuthn assertion over that challenge from a credential registered to the approver
     in the kernel's `kernel.approval_credentials` (registration itself requires an
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

## Implementation (WP06)

| Piece | Where |
|---|---|
| Pure-Rust WebAuthn verifier (ES256 / EdDSA / RS256; attestation `none` and packed self-attestation; rpIdHash, origin allowlist, UP+UV flags, monotonic counter) | `rust/crates/mk-crypto/src/webauthn.rs` |
| Challenge derivation `SHA-256("mk-approval-challenge-v1" ‖ tenant ‖ user ‖ action ‖ digest ‖ nonce)` | same, `approval_challenge` |
| Tables `approval_credentials`, `approval_challenges` (single-use, 2-min TTL for approvals), `revocations`; `approvals.human_binding`, `approvals.approval_credential_row_id` | `migrations/kernel/0003_human_approval_authority.sql` |
| Routes: `/approval-credentials/register/{begin,finish}`, `/approval-credentials`, `/approval-credentials/{row}/revoke`, `/actions/{id}/approval-challenge`, `/revocations`; `approve` body takes `webauthn` | `rust/crates/mk-api/src/routes/human_approval.rs`, `approvals.rs` |
| Fail-closed configuration: `MK_APPROVAL_RP_ID` + `MK_APPROVAL_ORIGINS` required; `MK_ALLOW_UNBOUND_APPROVAL=1` is development-only and recorded on every approval row | `rust/crates/mk-api/src/state.rs` |
| Challenge burn is committed in its own transaction before verification, so a failed or transplanted attempt never leaves a live challenge | `human_approval.rs::verify_for_approval` |
| Revocation (H9): checked at authentication for every request (`PRINCIPAL_REVOKED` 401), cascades to live approvals (revoked + queued action cancelled), and is re-checked by the worker at dispatch (`approval_revoked`) | `mk-api/src/auth.rs`, `mk-store/src/human_approval.rs`, `mk-worker/src/dispatch.rs` |
| FastAPI is a relay only: it forwards the base64url bytes and never holds a passkey | `backend/app/routes/agent_ops.py` |
| Software authenticator (test equipment) | `mk-crypto::webauthn::softauthn`, `mk-softauthn` binary |

### Evidence (author-run)

- `mk-crypto` unit tests (8): registration/assertion for ES256 and Ed25519; wrong challenge, origin, rp id, type, missing UV, tampered byte, wrong key, counter regression, unsupported attestation/alg, oversized/truncated inputs.
- `mk-api/tests/http_e2e.rs::human_approval_authority_resists_forgery_replay_transplant_and_revocation` (12 steps): agent cannot register or get a challenge; no-credential precondition; attacker's own passkey under a forged manager assertion → `WEBAUTHN_CREDENTIAL_MISMATCH` and the challenge is burned; transplant A→B → 409 and burned; edited-digest challenge → 409; tampered signature → `WEBAUTHN_BAD_SIGNATURE`; legitimate path → `human_binding=webauthn`; replay → 409; session revocation → approval revoked, action cancelled, next request 401; dispatch-time user revocation → `approval_revoked`; self-approval permitted by tenant policy.
- Live smoke gates 8 and 9 (`scripts/kernel-live-smoke.sh`) run the same forgery/replay/transplant and revocation checks through FastAPI against real binaries under per-process DB logins.

## What this does not claim

H6 and H9 are **Implemented** (author-run evidence only). They become *Independently
verified* when a reviewer who did not write this code reproduces the forgery, replay,
transplant, edit, expiry and revocation results, and *Production-proven* only after real
passkeys on real devices have been used in the qualification period (WP11). The threat
model's T4 is narrowed, not closed: a compromised FastAPI can still *propose* and can
still *relay* a captured assertion once within its 2-minute challenge window if it also
controls the approver's browser session — that is the residual the UI (WP08) and the
independent review (WP10) must address.
