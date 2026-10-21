# Runbook — Key or credential compromise (contract S10)

**Status:** *Implemented* (text; rotation mechanics covered by
`envelope_key_rotation_drill`, smoke gate 11, assertion-kid and adapter-secret
rotation tests). *Independently verified* requires each containment below to be
exercised in staging by a second person with a timed record.

Containment order is always: **stop → rotate → re-seal/replace → verify →
resume**. Dispatch stays disabled until verification passes.

| Key / credential | Where it lives | Blast radius if leaked | Containment |
|---|---|---|---|
| **Provider auth token** (Twilio) | `kernel.sender_identities.auth_token_sealed` (sealed), provider console | attacker can send as the business and forge webhooks to us | 1. global kill switch off. 2. Rotate the token in the provider console (secondary token → promote). 3. `POST /api/agent-ops/senders/{id}` with the new token (re-sealed under the current key version). 4. Review `delivery_events` / provider logs for messages not originating from the kernel (SIDs with no `message_deliveries` row) → incident runbook. 5. Resume via enable sequence |
| **Webhook signing** | same token (Twilio signs with the auth token) | forged status/inbound callbacks | covered by the row above; additionally compare `callbacks_auth_failures_total` before/after |
| **Assertion private key** (FastAPI → kernel, Ed25519) | FastAPI env `KERNEL_ASSERTION_PRIVATE_KEY` | attacker can mint principals and act as any role **except** approve (approval needs a passkey) and except global enable (needs operator passkey) | 1. kill switch off. 2. `mk-devkeys gen` → new kid; add the public key to `MK_ASSERTION_KEYS` **alongside** the old one; deploy FastAPI with the new private key/kid; remove the old kid; restart api. 3. `kernel.assertion_jtis` audit: any jti minted after the suspected leak that FastAPI did not log → incident. 4. Revoke sessions issued in the window (`POST /revocations`) |
| **Approver passkey** (a user's device) | user's authenticator; public key in `kernel.approval_credentials` | approvals on that user's behalf | `POST /approval-credentials/{id}/revoke`; live approvals bound to that credential are cancelled by the kernel; user re-registers |
| **DB credentials** (per-process logins) | secrets manager | read (readonly), write within RLS (api/worker/relay) — never cross-tenant without the owner login | `ALTER ROLE … PASSWORD` for the affected login; rolling restart of that process type only; owner login password rotated the same way; check `pg_stat_activity` for unknown clients |
| **`MK_MASTER_KEY`** / **`MK_FINGERPRINT_KEYS`** | secrets manager | unseal legacy (version 0) ciphertext; `m0` destination-fingerprint key unless `MK_FINGERPRINT_KEYS` lists others | 1. kill switch off. 2. Ensure every row is under a KEK-wrapped version: `mk-keyctl reencrypt`, `retire 0`, `MK_LEGACY_SEAL_RETIRED=1`. 3. Generate a new fingerprint key and deploy API + keyctl with `MK_FINGERPRINT_KEYS=k2=<new>,m0=master` (first entry = current; old key still listed). 4. `mk-keyctl fingerprint-rekey` (owner login) — adds the `k2` tag to every suppression, permission and inbound row from its sealed destination and to every action from its canonical `to`; unsealed provider opt-outs are recovered through the action that shares their fingerprint. 5. `mk-keyctl fingerprint-status` must exit 0 (`lacking_current=0 orphaned=0` for all four tables); any `unresolved` row keeps it non-zero — resolve before step 6. 6. Only once `python -m app.tools.refingerprint status` (application) is also clean: remove `m0` from `MK_FINGERPRINT_KEYS` and the application's `FINGERPRINT_KEYS`, redeploy, then `mk-keyctl fingerprint-prune m0` to strip the compromised HMACs and rewrite hash columns. 7. Generate a new `MK_MASTER_KEY` only after steps 2 and 6 (`MK_FINGERPRINT_KEYS` must then name `m0` by explicit base64, never `master`, if it is still listed). 8. Resume only after `kernel.suppressions` count unchanged and a spot check of opted-out numbers is still refused at proposal. In step 3 give the application the same `FINGERPRINT_KEYS` value and in step 4 also run `python -m app.tools.refingerprint rekey`; the application matches inbound senders through the kernel's `destination_fingerprints` tags, so customer matching holds throughout. |
| **`MK_KEK`** (KMS data key / env KEK) | KMS or secrets manager | unwrap every DEK version → all sealed data | 1. kill switch off. 2. New KEK (`MK_KEK`/`MK_KEK_ID`), `mk-keyctl rotate` (new version wrapped by the new KEK), `reencrypt`, `retire` each version wrapped by the old KEK, destroy the old KEK. 3. `mk-restore-gate` report mode → `credentials_unseal.unreadable == 0`. (Versions wrapped by an old KEK cannot be loaded once the KEK id changes: `load_keyring` refuses a mixed ring, so the rotation must complete in one maintenance window) |
| **JWT secret** (FastAPI) | env | application sessions | rotate; all sessions invalidated; kernel unaffected (it trusts assertions, not JWTs) |
| **Tenant encryption material** | per-row AAD + key versions (no per-tenant key today) | n/a | covered by KEK/master rows; per-tenant keys are **Not demonstrated** |

## Verification after any rotation

* `mk-keyctl status` → one `active`, zero `rows_not_under_current`, no
  `legacy_version_0_loaded=true` in production.
* `mk-restore-gate --restored-at <now>` report mode → `keyring_loads`,
  `credentials_unseal` (`unreadable: 0`), `audit_chain_verified` all true.
* One signed provider callback accepted, one opted-out proposal refused.
* Enable sequence with passkey step-up; record who/when in the incident log.

## Known gaps (tracked, not hidden)

Kernel destination-fingerprint rotation is **Implemented** (migration 0008,
`mk_store::fingerprint`, `mk-keyctl fingerprint-status|fingerprint-rekey|fingerprint-prune`;
author-run tests `fingerprint_key_rotation_never_orphans_suppressions_or_consent`,
`fingerprint_rekey_rejects_inconsistent_raw_destination`,
`test_customer_match_survives_kernel_fingerprint_rotation`). It is not
*Independently verified* until a second person runs the drill on staging and
records it under `evidence/releases/`.

Application-side fingerprint rotation is **Implemented** (author-run):
`FINGERPRINT_KEYS` (same value as the kernel's `MK_FINGERPRINT_KEYS`, first =
current; unset = master key as `m0`) and `python -m app.tools.refingerprint
status|rekey` — re-fingerprints every `CustomerDestination` from its sealed value
and moves each `SuppressionEvent`/`ImportRow` with it; `status` exits 1 while any
row is not under the current key or any suppression maps to no destination
(test `test_app_fingerprint_key_rotation_never_orphans_suppressions`). Run the
app `rekey` together with the kernel's `fingerprint-rekey` (step 4) and remove the
old kid from **both** lists only when both `status` commands are clean.
Not demonstrated: rotation of the application's *sealing* key (`MASTER_KEY` for
`seal()`), which needs its own decrypt/re-encrypt job. This blocks S10 from *Independently verified*.
