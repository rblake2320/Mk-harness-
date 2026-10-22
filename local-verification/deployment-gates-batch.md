# Deployment source, provenance and exact-plan gates

Author-run engineering evidence, 2026-10-22. No row is independently closed and
no cloud deployment, human approval, provider send or repository-settings change
was performed. Source commits: `f232ccda00e83d668f901d6acb8e680dc27b047c`
(source/image gates) and `b313897304a50629a27c65a390573e288f48c44e`
(exact-plan review and environment gates).

## Worked

- Source/image gate tests: final `deployment-source-green-v2` has **91 passed**.
  Final combined plan/source/image suite `deployment-plan-green-v4` has **138
  passed**. It covers hostile inputs, workflow/checkout mismatch, main ancestry,
  current independent approval, strict trusted CI, failed newer reruns, missing
  and skipped jobs, clock bounds, both-image verification, missing/weak/wildcard
  environments, self-review, cryptographic tampering, cross-run/attempt/image/
  provider-lock substitution, plan expiry and wrapper-output privacy.
- Source `f232ccd` passed **all 11 CI jobs**: application run **39761688886** and
  kernel run **39761688817**. Exact source and complete job receipts are retained
  in `deployment-source-{app,kernel}-ci-v1.json`. The later plan source has local
  evidence below; its subsequent CI is recorded separately when completed.
- Live read-only GitHub preflight **refused** main `80e08d0` because its required
  rules/independent approval and full current application job set were missing.
  It refused feature `d40e7ff` and a different requested/workflow commit. The
  production check observed zero configured environments and refused them too.
  Reports: `deployment-source-live-main-v3.json`, `...-pr-v2.json` and
  `...-production-v1.json`. These refusals are expected safety outcomes, not
  claims that the successful feature-branch CI failed.
- Actual cosign **v3.1.4** release binary: published SHA-256
  `cbe953787074611f1334cbf37dc1cf953995bb8c45398eb4fc7bb781d29c1f2a` matched.
  Its real publisher signature verified, and the MK workflow-identity claim
  failed with a SAN mismatch. Logs and hashes are in `deployment-cosign-*`.
  This is a real cryptographic identity control, not an MK release image.
- Actual Windows OpenTofu **1.10.6**: `deployment-plan-control-v2` retained
  **16 successful checks** using a disposable builtin `terraform_data` resource
  only. The CLI sealed the real plan, public artifacts excluded the private
  canary, six substituted-context/key/artifact cases produced no plaintext file,
  the exact original bytes decrypted and applied, resulting state matched the
  fixture, and a second stale apply was refused. The fixture's temporary state
  was cleaned up. No AWS provider or shared state was used. The earlier v1
  control also passed and is retained.
- Hash-locked encryption dependencies installed in a separate Linux virtualenv:
  cryptography 50.0.2, cffi 2.1.1 and pycparser 3.11; `pip check` passed.
- Workflow lint and evidence secret scan passed. Current readiness is still
  **0/87**, retained in `deployment-gates-readiness.json`.

## Retained failures and repairs

- `deployment-source-red` reproduced all four original missing deployment
  guardrails. `deployment-plan-red` reproduced the missing plan-before-approval
  job and artifact binding. `deployment-plan-green-v1` is **not green**: one
  static test searched only `tofu plan`, missing the valid `tofu -chdir=... plan`
  command. The assertion was corrected to parse that form; v2/v3/v4 passed.
- `deployment-source-live-main.json` records a Windows codepage decoding error
  while reading Unicode GitHub review JSON. The CLI now explicitly uses UTF-8;
  the retained v2/v3 calls completed and refused the actual policy gaps.
- The first Linux dependency-install wrapper lost its temporary-directory shell
  variable while crossing PowerShell/WSL. It created a virtualenv in this task's
  checkout and then hit PEP 668 instead of using that env. Readback of
  `pyvenv.cfg`, timestamps, contents and `git ls-files` established that only
  newly generated environment items were involved. Those exact five items were
  moved recoverably into `.local-tools/recovered-venv-wrapper-20261022`; no
  source or pre-existing tool environment was removed. The explicit-path
  virtualenv retry installed the locked dependencies and passed `pip check`.
  The failed log, successful retry and recovery receipt are retained.

## S8 CI completion follow-up

The earlier S8 report remains unchanged. Its corrected pushed source
`d40e7ff22ff7a4df8f0f15504f2ec5f271ce2ebf` passed **all 11 jobs** in application
run **39759444987** and kernel run **39759445027**. Complete receipts are
`image-security-{app,kernel}-ci-v2.json`; actual downloaded scanner artifacts
are `image-security-ci-v2/{app,kernel,web}`.

Application: **71 components, zero findings**. Web: **22 components, zero
findings**. Kernel: **15 components, 0 critical / 0 high / 23 medium / 8 low /
0 unknown**. No CVEs were suppressed. The prior kernel run **39758455706** is
now retained at completion: only its scanner job failed with the same Linux
cache-permission issue already repaired; live smoke and the other jobs passed.

## Concrete live qualification prerequisites

The source/provenance/plan gates are engineering, not release acceptance. The
remote smoke still intentionally refuses promotion. Authorized separate cloud
accounts, spending ceiling, domains, main-only protected environments, scoped
OIDC roles, release-owner plan-key custody and independent main/staging
qualification are required before live execution. The developer work queue still
includes target-scoped smoke and migration/recovery readiness. No placeholder
release YAML, self-approval, environment creation, key enrollment, merge or paid
resource was used to evade those requirements.
