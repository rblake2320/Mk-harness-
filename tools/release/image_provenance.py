"""Verify both deployment image digests against exact main-workflow identity.

This is read-only. Registry login is supplied by the caller, never by a flag or
embedded credential. No unsigned, offline, insecure or identity-regex fallback.
Both cosign's image signature and GitHub's SLSA provenance must verify.
"""
import argparse
import hashlib
import json
from pathlib import Path
import re
import subprocess


def valid_inputs(repo, sha, kernel_image, app_image):
    if (not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9-]*/[A-Za-z0-9_.-]+", repo)
        or repo.split("/")[1] in {".", ".."} or not re.fullmatch(r"[0-9a-f]{40}", sha)):
        return False
    registry = r"[0-9]{12}\.dkr\.ecr\.[a-z]{2}-[a-z]+-[0-9]+\.amazonaws\.com"
    for ref, image in ((kernel_image, "mk-action-kernel"), (app_image, "mk-app")):
        if not re.fullmatch(registry + "/" + image + r"@sha256:[0-9a-f]{64}", ref):
            return False
    return kernel_image.split("/")[0] == app_image.split("/")[0]


def commands(repo, sha, ref):
    identity = f"https://github.com/{repo}/.github/workflows/deploy.yml@refs/heads/main"
    issuer = "https://token.actions.githubusercontent.com"
    return {
        "signature": ["cosign", "verify", ref, "--certificate-identity", identity,
            "--certificate-oidc-issuer", issuer],
        "provenance": ["gh", "attestation", "verify", "oci://" + ref, "--repo", repo,
            "--cert-identity", identity, "--cert-oidc-issuer", issuer,
            "--source-ref", "refs/heads/main", "--source-digest", sha,
            "--signer-digest", sha, "--deny-self-hosted-runners", "--format", "json"],
    }


def verify(repo, sha, kernel_image, app_image, output):
    output.mkdir(parents=True, exist_ok=False)
    report = {"scope": "signature and source provenance preflight; not deployment or release qualification",
        "source_sha": sha, "repository": repo, "verdict": "REFUSED", "checks": []}
    if not valid_inputs(repo, sha, kernel_image, app_image):
        report["error"] = "Expected same-registry ECR image digests, repository and full source SHA"
    else:
        for name, ref in (("kernel", kernel_image), ("app", app_image)):
            for kind, command in commands(repo, sha, ref).items():
                check = {"image": ref, "check": kind, "ok": False}
                try:
                    result = subprocess.run(command, capture_output=True, text=True, encoding="utf-8", timeout=120)
                    # stdout is structured public verification evidence. Do not
                    # retain CLI stderr, which may contain credential-helper data.
                    if result.returncode:
                        raise ValueError(f"Verifier returned exit {result.returncode}")
                    parsed = json.loads(result.stdout)
                    if not isinstance(parsed, list) or not parsed or not all(isinstance(row, dict) and row for row in parsed):
                        raise ValueError("Verifier returned no structured verified statements")
                    payload = (json.dumps(parsed, indent=2) + "\n").encode("utf-8")
                    filename = f"{name}-{kind}.json"
                    (output / filename).write_bytes(payload)
                    check.update(ok=True, evidence=filename, sha256=hashlib.sha256(payload).hexdigest())
                except (ValueError, OSError, subprocess.TimeoutExpired) as exc:
                    check["error"] = str(exc)
                report["checks"].append(check)
        if len(report["checks"]) == 4 and all(check["ok"] for check in report["checks"]):
            report["verdict"] = "PASS"
    (output / "summary.json").write_text(json.dumps(report, indent=2) + "\n", encoding="utf-8")
    return report


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--repo", required=True)
    parser.add_argument("--sha", required=True)
    parser.add_argument("--kernel-image", required=True)
    parser.add_argument("--app-image", required=True)
    parser.add_argument("--output", required=True, type=Path)
    args = parser.parse_args()
    report = verify(args.repo, args.sha, args.kernel_image, args.app_image, args.output)
    print(json.dumps(report))
    return 0 if report["verdict"] == "PASS" else 1


if __name__ == "__main__":
    raise SystemExit(main())
