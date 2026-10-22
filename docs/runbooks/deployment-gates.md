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

A real cosign v3.1.4 release signature passed using its actual publisher
identity, then failed under the MK deployment identity. This is a cryptographic
identity control, not a signed MK deployment image. A full positive MK image
verification requires the authorized GitHub main build and ECR registry.

The remote smoke gate still deliberately refuses promotion: the local smoke
script may destroy its disposable test stack and must never be pointed at a
shared deployed environment. A dedicated target-scoped remote smoke, migration
and recovery readiness, plan-before-production-approval workflow, environment
configuration, and independent staging execution are still work items. The
current production job's environment approval is before its plan, not approval
of that plan. Do not describe its plan artifact as reviewed authorization.
Dispatch remains disabled; no source or signature check enables it.
