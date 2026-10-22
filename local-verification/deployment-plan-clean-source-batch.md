# Provider-lock packaging correction

Correction source: `da65913c1e7d19dfc508e5d870c8469924861b7a`.

The first pushed plan-review source (`228e97b`, including `b313897`) failed the
Python 3.12 CI job at its real plan-sealing control. The local-only provider lock
was excluded by `infra/terraform/.gitignore`. Therefore the earlier local plan
passes did not establish that a clean checkout could run the gate. The failed
job log and downloaded control report are retained in
`deployment-plan-ci-first-failure.log` and `deployment-plan-ci-control-v1`.

The ignore rule is removed and the exact provider versions/checksums are now
tracked. A regression checks the Git index as well as file presence. Its first
WSL run (`deployment-plan-green-v5`, despite that filename) failed because Linux
Git cannot resolve this Windows-managed worktree's absolute Windows `gitdir`.
The same complete gate suite run on the owning Windows host passed **139 tests**
(`deployment-plan-green-v6`). No production gate was relaxed for that host issue.

A selective `git archive` of the correction commit was extracted to a new
ignored directory, containing only the release tools, disposable fixture,
control helper and now-tracked provider lock. Running the real plan control from
that clean export passed **all 16 checks**, including encrypted packaging,
private-canary exclusion, six identity/substitution refusals, exact-byte apply
and stale-plan refusal. Evidence: `deployment-plan-clean-source-control-v1`.
The fixture uses only builtin `terraform_data`; no cloud provider, shared state,
business resource or production approval was exercised.

The control helper now retains the bounded CLI error type on failure so future
missing-input defects are diagnosable without exposing plaintext plans or keys.
CI for the correction is tracked separately; this note makes no green-CI or
independent release-closure claim for it.
