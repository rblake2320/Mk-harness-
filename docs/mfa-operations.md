# Mandatory sign-in MFA and fresh sensitive-action checks

Password sign-in and signup create a limited ten-minute session. It cannot read
customer data, call models, act through the kernel or change settings. There is
no environment-variable MFA bypass. Complete enrollment or verification in the
web or Expo client to receive a new verified session. The old limited session is
revoked locally and queued for durable kernel revocation.

## Enrollment and recovery

Use a time-based authenticator, add a Consultant Studio entry with the setup key,
then enter its six-digit code. Seeds are encrypted with the application master
key and tenant/user-bound associated data; pending seeds are additionally bound
to the enrolling session. Setup is returned only to that authenticated session
and is never sent to an external QR service. Auth responses are `no-store`.

Save the eight one-use recovery codes in a password manager before continuing.
The service stores only their hashes. Login accepts an authenticator code or one
recovery code, after the password. Each TOTP time counter can be used once, with
one adjacent 30-second window of clock tolerance. A just-used code cannot be
reused for a sensitive-action check; wait for the next code or use a recovery
code. Five bad second-factor/password step-up attempts lock the factor for 15
minutes across sessions/processes. Keep server time synchronized.

Settings supports replacement of recovery codes and the authenticator after a
fresh check. Beginning replacement leaves the existing factor active. Confirming
replacement revokes every old session and recovery code; save the new codes.
Account deletion removes active/pending factor ciphertext and recovery hashes.
If all factors and recovery codes are lost, there is no password-only reset or
support backdoor in this implementation. A separately authorized recovery policy
must be defined and tested before introducing such a route.

## Step-up policy

A verified session must submit its current password plus a fresh second factor
before member creation, password changes, API-key/security changes, sender and
permission changes, exports, data/account deletion, billing checkout/portal,
suppression removal, inbound resume or enabling tenant dispatch. The grant is
limited to five minutes and the current session. The exact route-template list
is in `backend/app/security.py`; tests require every entry to be registered and
refused before validation/side effects without a grant. Enabling tenant dispatch
is checked in its handler; stopping dispatch remains immediate. Global dispatch
enable and message approvals retain their separate kernel-verified WebAuthn
ceremonies. Revoking sessions and emergency stops remain available without a
fresh step-up so security controls cannot be held behind a missing factor.

The SDK prompts only on explicit `STEP_UP_REQUIRED`, coalesces concurrent
prompts, and retries only after successful verification in the same session.
Cancelled checks, network failures and other errors never replay writes.
CSV/JSONL exports use the same checked response path: an error is not a download.

## Rollout and verification

Deploy the application and matching SDK/web/mobile build together. The app's
existing metadata bootstrap creates the new `auth_factors` and
`auth_recovery_codes` tables; no existing migration is rewritten. Existing
sessions without MFA verification are limited by the server; sign in again to
enroll. This is not a flag-controlled gradual bypass. Backups must preserve the
factor counters, consumed-code records and lockouts along with session state;
restoring historical authentication state must revoke sessions before traffic.
Application master-key custody/rotation is a separate S10 control.

`backend/tests/test_mfa_security.py` exercises the mandatory policy directly;
unrelated feature-unit tests explicitly isolate it with a test-only monkeypatch.
Real entrypoints, native browser checks and CI smoke perform actual synthetic
TOTP enrollment and step-up, never the monkeypatch. `tools/verification/mfa_fixture.py`
is a loopback-only fixture for fresh synthetic accounts and prints a verified
access token only for shell capture. Do not run it with shell tracing or live accounts.

TOTP is not phishing-resistant. Kernel approval passkeys are separate from login
MFA. Author-run checks are engineering evidence, not independent staging
qualification or full native/mobile parity. The release checker remains authoritative.
