# Evidence records

One YAML record per acceptance-matrix row per release candidate, at
`evidence/releases/<release-id>/<REQUIREMENT_ID>.yaml`. A row in
`docs/production-acceptance.md` is closed only by a record here whose `status`
is at the required level and whose artifact checksum verifies. A planned
filename is not evidence. Directories whose name starts with `_` (such as
`_example`) hold templates: schema-checked, checksums not verified, never
counted by `tools/evidence/readiness.py`. `tools/evidence/check.py` validates every record
against `schema.yaml` and recomputes checksums; it runs in CI.

Required fields (all mandatory; `null` is not permitted for a closed row):

```yaml
requirement_id: C6
acceptance_condition: "<exact text from the matrix row>"
owner: "<name, role>"
source_commit: "<40-hex sha on main>"
image_digests:
  mk-action-kernel: "sha256:<64-hex>"
  api: "sha256:<64-hex>"
environment: "<staging-us-east-1 | production-identical | ...>"
configuration: "<path or digest of the config used>"
test_procedure: "<path to the test/plan>"
test_version: "<commit or version of the test>"
expected_result: "<text>"
actual_result: "<text>"
evidence:
  - location: "<URL or path>"
    sha256: "<64-hex>"
verifier: "<name>"
verifier_independent_of_author: true
verification_date: "2026-10-20T00:00:00Z"
status: not_demonstrated | implemented | independently_verified | production_proven
observation_window: "<required for production_proven, e.g. 2026-11-01..2026-11-30>"
invalidation_triggers:
  - "<material change that re-opens this row>"
remaining_findings: []
```
