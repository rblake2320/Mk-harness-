# Mandatory MFA and sensitive-action authentication — S2 engineering batch

Source `026f502497eec7206f1af55ba663c188e59f7b50`, PR37 branch, 2026-10-22.
Author-run development verification. No independent staging or production
qualification is claimed; no release row is closed by this report.

## Changes and observed repairs

- Password-only signup/login now create a limited ten-minute session. Mandatory
  TOTP enrollment/verification rotates the SID and revokes the old bearer; there
  is no runtime configuration bypass. Secrets use AES-GCM with tenant/user
  binding and pending-session binding. Eight 128-bit recovery codes are shown
  once and stored as hashes. Replay counters and five-failure/15-minute lockout
  state survive sessions/processes in the database.
- Sensitive actions require password plus a fresh second factor, scoped to one
  session for five minutes. Exact registered route-template tests caught two
  incorrectly named skin-data paths; both were corrected. Tenant dispatch enable
  is gated while emergency stop remains immediate. Kernel WebAuthn approval and
  global-enable checks remain separate.
- A controlled concurrency test reproduced recovery verification clearing a
  lockout committed by another request (`mfa-races-red.xml`). Conditional factor
  locking now serializes recovery/TOTP against the live factor and lockout;
  simultaneous TOTP and recovery-code consumption allow exactly one request.
- Erasure testing found the new MFA rows surviving account deletion
  (`mfa-erasure-red.xml`); deletion now removes pending/active ciphertext and
  backup-code hashes in the same transaction. Factor replacement leaves the old
  authenticator active until confirmed, then revokes all old sessions/backups.
- SDK step-up is single-flight, only retries explicit pre-action refusals and
  checks the SID before retry. CSV/JSONL exports now reject error responses.
  Web and Expo have MFA/backup-code flows; web Settings supports replacement.
  Web session changes clear prior customer/navigation state. The web identity
  request cannot repopulate identity after its component/session is replaced.
- The earlier S2 CI smoke failed because it expected a kernel error code after
  the app itself correctly returned 401. The assertion now verifies app refusal;
  the test freezes its worker before approval to remove a dispatch-before-revoke
  fixture race (`mfa-predecessor-ci-failure.log`). Smoke/fault fixtures now perform
  real synthetic TOTP enrollment and fresh authentication, without policy bypass.
- One unrelated full-suite run encountered a six-hex-character synthetic email
  collision. The affected helper now uses the full UUID; the original failing
  run is retained (`mfa-python-v2.xml`). Redis-restart acceptance now completes
  real MFA and passes while its owned Redis process is killed and restarted.

## Checks at the source pin

- **307 Python tests passed**, no skips (`mfa-python-026f502.xml`), including 13
  mandatory-policy MFA scenarios. Other feature tests explicitly isolate MFA by
  a test-only monkeypatch; actual deployments, browser checks and CI smoke do not.
- **25 web tests passed**, including MFA enrollment/recovery acknowledgement,
  360px layout, automated WCAG checks, keyboard-modal cancel/confirm, SDK
  single-flight/changed-session checks and all previous approval/session tests
  (`mfa-web-026f502.json`). Production build passed (`mfa-build-026f502.log`).
- Expo TypeScript passed (`mfa-mobile-026f502.log`). This is typechecking, not a
  native-device interaction result; X2 native parity remains queued.
- Native Python Playwright, real app/kernel/Postgres (`mfa-browser-026f502/`):
  password-only customer access 403; retired pre-MFA bearer 401; verified access
  200; export before fresh check 403 and after 200; downloaded account JSON
  validated and contains no seed/recovery code; reused backup 401; new session's
  export 403; old session after authenticator replacement 401. Zero page errors,
  width 360/360; masked screenshots visually inspected.
- Native session regression (`mfa-sessions-026f502/`): single refresh persisted
  across reload; revoke-other access/refresh 401, current session 200; logout
  access/refresh 401; new MFA login works; zero page errors, width 360/360.
- Native customer regression (`mfa-search-026f502/`): 52 scoped synthetic
  customers, foreign tenant excluded, pagination 50+2, exact/empty/clear search,
  zero browser errors and usable 360px controls, no provider calls.
- Owned-stack readback (`mfa-stack-026f502/stack-summary.json`): 13 revocations,
  all 13 delivered and represented in the kernel; 15 sessions (the two search
  fixtures remain active until disposable database removal). Runtime kernel
  identity `mk_kernel_api`. Owned processes stopped and private app/kernel
  databases removed. No shared database or unrelated service was reset.

Auth-success and error responses are non-cacheable. Seeds/backups stay in memory
in verification. Two failing pytest XML reports have synthetic JWT text redacted;
originals are in ignored `.local-tools/s2-raw/`. Early screenshot masks left a
wrapped-code fragment visible; those eight images were moved to the same private
ignored folder. The repaired capture hides secret glyphs as well as mask boxes;
only the later checked recovery captures are published. Intermediate reports
remain labelled by their run, not relabelled as successful source-pin evidence.

`mfa-security-manifest.json` records artifact SHA-256 values. CI results are
tracked separately; a green CI run is not independent release qualification.
