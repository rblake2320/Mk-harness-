# Dependency and image security (S8)

The application, web and kernel Dockerfiles pin their base images by digest.
The application runtime is Python 3.13 on Alpine, UID 65532, with the same
interpreter/musl ABI used to install its binary wheels. The runtime excludes pip,
pytest and respx; migration, health-check and recovery commands remain
`python -m app.*`. Read-only filesystems and dropped capabilities are deployment
requirements, not properties supplied by the Dockerfile alone.

## Updating dependencies

Edit `backend/requirements-runtime.in`, then regenerate the full transitive,
hash-locked runtime manifest. Development dependencies live in
`requirements-dev.in` and are constrained by that same runtime lock:

```sh
uv pip compile --python-version 3.12 --generate-hashes backend/requirements-runtime.in -o backend/requirements-runtime.lock
uv pip compile --python-version 3.12 --generate-hashes backend/requirements-dev.in -o backend/requirements.txt
python -m pip install --require-hashes -r backend/requirements.txt
```

CI tests Python 3.12 and 3.13. The application image installs the runtime lock
with `--require-hashes --only-binary=:all:`. A missing compatible wheel fails the
build. The web image and CI use `npm ci`, followed by `npm audit` (moderate or
higher blocks) and the full browser regression suite.

Framework updates must exercise real MFA and the exhaustive auditor route
allowlist. FastAPI's lazy router inclusion retains an unprefixed route object;
`app/route_policy.py` resolves the exact registered context and refuses a missing
or ambiguous match. Caller-controlled paths never become policy keys. Tests cover
nested/reused routers, deployment root paths and sensitive operations before
request-body validation.

## Scanning the actual image

```sh
python tools/verification/image_security.py --image <local-built-image> --cache <private-scanner-cache> --output <new-evidence-directory>
```

The scanner is digest-pinned, runs with a read-only root and no capabilities,
and receives only an exported image archive, writable cache and evidence folder.
It does not receive the Docker socket. The report's filesystem layers must match
the exact inspected image. Missing inventory, malformed results, scanner failure,
or any HIGH/CRITICAL finding fails the gate, including findings without fixes.
No CVE is suppressed. All lower-severity/unknown records remain in the full JSON;
the gate is not a risk-acceptance decision or a zero-vulnerability assertion.

CI retains full findings, CycloneDX inventories, scanner diagnostics, image/config
digests and artifact SHA256s for all three runtime images. The Rust source SBOM,
cargo audit/deny and full-history secret scanning remain separate gates.

After a base/runtime update, run the restricted application and kernel image
acceptance drills and web proxy canaries. Tests must include database migrations,
MFA, restart, deletion/restore and provider-recovery behavior, not just startup.
Keep failed candidate reports as well as the accepted image's reports.

Signed publication/provenance and independent staging qualification still require
the authorized release environment. Local/PR artifacts never close a release row.
