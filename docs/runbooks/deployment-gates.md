# Deployment source and image gates (O8)

Status: implemented and author-tested; no deployment or independent release
qualification is claimed. Do not dispatch this workflow until the authorized
accounts, spending ceiling, domains, roles and protected environments exist.

## Source preflight, before a cloud token

`tools/release/deployment_source.py` reads GitHub directly. It has no option to
trust a caller-authored approval snapshot. It requires all of the following:

- Dispatch from `main`, a full lowercase commit SHA, and a closed staging or
  production target. The checkout SHA must equal the workflow execution SHA:
  GitHub's provenance identity describes that execution commit.
- The commit is on protected main. Active rules require a fresh independent PR
  approval, dismissal after changes, last-push approval, no deletion/force-push,
  and strict status checks bound to the GitHub Actions application (15368).
- A merged PR for exactly that commit has an approval from a human other than
  its author, on its final head commit, without an outstanding changes request.
- Both active CI workflows have completed successfully for that exact main
  push within 24 hours. Every required job must pass in the selected attempt;
  missing, skipped, duplicate or substituted jobs fail. A newer failed run
  cannot be hidden by selecting an older green run.
- The required deployment environments already exist, with exactly one custom
  deployment policy selecting the `main` branch (not a tag or wildcard).
  Production requires an environment reviewer and prevents self-review. An
  absent environment cannot silently become an unprotected first-use default.

The required checks are `backend-tests (3.12)`, `backend-tests (3.13)`,
`web-build`, `docker-build`, `app-postgres-boundary`, `kernel`, `contracts`,
`observability`, `secret-scan`, `kernel-image`, and `live-smoke`. Kernel CI now
runs for every main commit and PR; path filtering cannot omit a release check.
The workflow installs no cloud credentials in the source-preflight job.

This implementation expects active repository rulesets, not merely a verbal
approval or an unverified screenshot. Repository rules, environment reviewers,
and IAM trust restrictions remain independently administered controls. The
code does not create or weaken them. Restrict the build role's OIDC trust to
this repository's main branch and environment roles to their protected
environments; do not grant repository-wide wildcard trust.
Disable administrator bypass of environment protections and independently
verify that setting; the documented REST environment response does not expose
that setting to this preflight.

## Build and consumption checks

The GitHub-hosted builder builds each image once. It pulls and scans each
published digest before signing: HIGH and CRITICAL findings, including unfixed
findings, block. Full vulnerability reports and CycloneDX inventories are
retained. Both application and kernel images receive their own keyless image
signature and GitHub SLSA provenance attestation.

`tools/release/image_provenance.py` verifies both images again before staging
or production apply. References must be digest-pinned, expected image names in
the same private ECR registry. Cosign must verify the exact main deployment
workflow identity and GitHub OIDC issuer. GitHub's verifier additionally binds
source ref, source commit, signer commit and GitHub-hosted runner. There is no
identity-regex, insecure, unsigned or offline fallback. All four verification
results must succeed and their public structured evidence is retained by hash.
CLI stderr is not copied to artifacts because credential helpers may print
private material there. Missing verifiers and empty/malformed responses fail.

The registry emitted by the build job is propagated to both consumers. Set
`ARTIFACT_ACCOUNT_ID` to that registry's authorized AWS account, with explicit
cross-account read permission for the staging and production roles. Production
does not silently select a different registry through an environment secret.
The workflow pins cosign-installer v4.1.2 by commit and cosign v3.1.4; the
installer verifies the selected release using its pinned bootstrap verifier.

An older-image rollback must use previously qualified immutable digests and a
separately authorized recovery procedure. Do not rebuild an old checkout under
a newer workflow commit and claim the new workflow attests the old source.

## Plan before production approval

`production-plan` uses a separate planning role. Its IAM policy must allow only
the reads and backend lock operations needed to plan, never resource mutation
or production state writes. It has the public review-encryption key, never the
private key. It creates an OpenTofu 1.10.6 saved plan using the committed provider
lock (`init -lockfile=readonly`), then `tools/release/production_plan.py` renders
that exact binary itself and seals it using X25519, HKDF-SHA256 and AES-256-GCM.
Plan bytes are checked before and after rendering. Hash-locked dependencies are
in `tools/release/requirements.txt`.

The public GitHub artifact contains encrypted plan bytes and counts grouped by
resource type/action. It contains no resource addresses, names, variable values,
before/after values, outputs or configuration. Counts alone are **not** the
private plan review. The release owner must download the `production-plan`
artifact and inspect the decrypted plan on an authorized private machine before
approving the protected `production` environment. Keep the private review key
under that owner's custody and in the **production-environment secret only**;
never place it in repository-wide secrets or in the planning environment.

Required configuration:

- `PRODUCTION_PLAN_PUBLIC_KEY`: the dedicated X25519 public key, 32 bytes encoded
  as 64 lowercase hexadecimal characters, in a repository variable.
- `PRODUCTION_PLAN_PRIVATE_KEY`: corresponding private key in the protected
  production environment. Do not reuse application, KMS, signing or provider keys.
- `AWS_PRODUCTION_PLAN_ROLE_ARN`: separately scoped read-only planning role in
  the `production-plan` environment; existing production apply role stays in
  `production`. Both environments allow only the main branch.

Use `production_plan.py open --help` for the private review command. Its inputs
must match the artifact's repository, SHA, run ID/attempt, image digests and
committed provider-lock file; set `PLAN_PRIVATE_KEY` and the producer job's
`PLAN_ENVELOPE_SHA256` in the private process environment, not command arguments.
The output directory must be new. `tofu show` of the resulting `plan.bin` is a
private review surface and must not be copied into public logs or artifacts.
No command in this tool performs an apply.

The apply job depends on completed planning and staging, so production approval
occurs only after that artifact exists. It downloads the exact artifact ID from
the producer job, rechecks source/CI after approval, verifies both images, then
decrypts immediately before apply. Repository, source, run **and attempt**,
environment, images, tool version, provider lock, recipient and artifact hash
are bound. The plan expires after two hours; a new attempt requires a new plan
and approval. Apply consumes the exact saved bytes without replanning. OpenTofu
also refuses a stale state plan. The workflow disables the OpenTofu stdout
wrapper so private plan values cannot become action outputs. Detailed plan/apply
stdout remains only on the ephemeral runner, not in public artifacts.

## Observed checks and remaining deployment work

Author-run tests exercise unreviewed refs, path/shell inputs, wrong execution
commits, weak/missing rules, self/bot/stale/dismissed reviews, substituted CI,
failed reruns, skipped jobs, stale timestamps, registry/image substitution,
verifier failure/timeout, malformed evidence and both-image enforcement.

The live read-only preflight against main `80e08d0` refused it: main was
unprotected, the required rules and independent approval were absent, and
that historical commit lacked the current full application check set. The
feature-branch commit was also refused. These are expected safety outcomes,
not failed CI claims. Repository settings were not modified.
The later production preflight also observed **zero** configured deployment
environments and refused promotion on those missing controls.

A real cosign v3.1.4 release signature passed using its actual publisher
identity, then failed under the MK deployment identity. This is a cryptographic
identity control, not a signed MK deployment image. A full positive MK image
verification requires the authorized GitHub main build and ECR registry.

`tools/verification/production_plan_control.py` exercises the real CLI and
OpenTofu using only a disposable builtin `terraform_data` resource. The retained
control applies the exact decrypted bytes, checks the resulting private fixture
state, and rejects stale reapply plus substituted run, attempt, image, lock,
recipient and artifact. Encrypted artifact scans exclude the private canary.
The same control runs in CI. This is not an AWS apply or human approval receipt.

The remote smoke gate still deliberately refuses promotion: the local smoke
script may destroy its disposable test stack and must never be pointed at a
shared deployed environment. A dedicated target-scoped remote smoke, migration
and recovery readiness, authorized environment/IAM/key configuration, and
independent staging execution are still work items.
Dispatch remains disabled; no source or signature check enables it.
