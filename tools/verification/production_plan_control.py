"""Actual OpenTofu plan/seal/open/apply control on a disposable local fixture.

The only resource is builtin terraform_data. No cloud provider, user-selected
project, shared state, backend, credential or deployment target is accepted.
"""
import argparse
import hashlib
import json
import os
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile

from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey

ROOT = Path(__file__).resolve().parents[2]
CANARY = b"MK_PLAN_PRIVATE_CANARY_20261022"


def execute(command, cwd, environment=None):
    return subprocess.run([str(part) for part in command], cwd=cwd, env=environment,
        capture_output=True, text=True, encoding="utf-8", timeout=120)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--tofu", required=True, type=Path)
    parser.add_argument("--output", required=True, type=Path)
    args = parser.parse_args()
    tofu, output = args.tofu.resolve(), args.output.resolve()
    output.mkdir(parents=True, exist_ok=False)
    checks = []

    def check(name, condition, **measurement):
        checks.append({"check": name, "outcome": "Worked" if condition else "Failed", **measurement})
        if not condition:
            raise RuntimeError(name)

    try:
        with tempfile.TemporaryDirectory(prefix="mk-production-plan-control-") as temporary:
            fixture = Path(temporary)
            shutil.copyfile(ROOT / "tools/verification/fixtures/deployment-plan/main.tf", fixture / "main.tf")
            initialized = execute([tofu, "init", "-backend=false", "-input=false", "-no-color"], fixture)
            check("disposable_builtin_fixture_initialized", initialized.returncode == 0, exit=initialized.returncode)
            planned = execute([tofu, "plan", "-input=false", "-out=plan.bin", "-no-color"], fixture)
            check("actual_local_plan_created", planned.returncode == 0, exit=planned.returncode)
            rendered = execute([tofu, "show", "-json", "plan.bin"], fixture)
            plan_json = json.loads(rendered.stdout)
            check("only_owned_builtin_resource_can_be_applied", rendered.returncode == 0
                and len(plan_json["resource_changes"]) == 1
                and plan_json["resource_changes"][0]["type"] == "terraform_data")
            private = X25519PrivateKey.generate()
            environment = {**os.environ, "PATH": str(tofu.parent) + os.pathsep + os.environ.get("PATH", ""),
                "PLAN_PUBLIC_KEY": private.public_key().public_bytes_raw().hex()}
            # Never allow a local test to append outputs to a surrounding CI job.
            environment.pop("GITHUB_OUTPUT", None)
            source = execute(["git", "rev-parse", "HEAD"], ROOT).stdout.strip()
            registry = "123456789012.dkr.ecr.us-east-1.amazonaws.com"
            common = ["--repo", "example/local-control", "--sha", source, "--run-id", "12345", "--attempt", "1",
                "--kernel-image", registry + "/mk-action-kernel@sha256:" + "b" * 64,
                "--app-image", registry + "/mk-app@sha256:" + "c" * 64,
                "--lock-file", ROOT / "infra/terraform/modules/kernel-platform/.terraform.lock.hcl"]
            tool = [sys.executable, ROOT / "tools/release/production_plan.py"]
            package = output / "encrypted-package"
            sealed = execute(tool + ["seal", *common, "--plan", fixture / "plan.bin", "--output", package], fixture, environment)
            try:
                seal_diagnostic = json.loads(sealed.stdout)
                seal_error = seal_diagnostic.get("error_type")
            except (ValueError, AttributeError):
                seal_error = "NoStructuredCliDiagnostic"
            check("real_cli_seals_actual_binary", sealed.returncode == 0, exit=sealed.returncode, error_type=seal_error)
            seal_report = json.loads(sealed.stdout)
            check("public_artifact_excludes_private_canary", all(CANARY not in file.read_bytes() for file in package.iterdir()))
            environment.update(PLAN_PRIVATE_KEY=private.private_bytes_raw().hex(),
                PLAN_ENVELOPE_SHA256=seal_report["envelope_sha256"])
            for fault in ("different_run", "different_attempt", "different_image", "different_lock", "wrong_key", "different_artifact"):
                arguments, changed_env = list(common), dict(environment)
                if fault == "different_run": arguments[arguments.index("--run-id") + 1] = "99999"
                if fault == "different_attempt": arguments[arguments.index("--attempt") + 1] = "2"
                if fault == "different_image": arguments[arguments.index("--app-image") + 1] = registry + "/mk-app@sha256:" + "e" * 64
                if fault == "different_lock":
                    lock = fixture / "changed.lock.hcl"; lock.write_text("changed fixture lock", encoding="utf-8")
                    arguments[arguments.index("--lock-file") + 1] = lock
                if fault == "wrong_key": changed_env["PLAN_PRIVATE_KEY"] = X25519PrivateKey.generate().private_bytes_raw().hex()
                if fault == "different_artifact": changed_env["PLAN_ENVELOPE_SHA256"] = "0" * 64
                destination = fixture / fault
                refused = execute(tool + ["open", *arguments, "--package", package, "--output", destination], fixture, changed_env)
                check(fault + "_refused_without_plan_file", refused.returncode != 0 and not destination.exists(), exit=refused.returncode)
            opened = fixture / "opened"
            accepted = execute(tool + ["open", *common, "--package", package, "--output", opened], fixture, environment)
            check("exact_same_run_plan_opened", accepted.returncode == 0, exit=accepted.returncode)
            original, consumed = (fixture / "plan.bin").read_bytes(), (opened / "plan.bin").read_bytes()
            check("apply_consumes_exact_reviewed_bytes", consumed == original,
                plan_sha256=hashlib.sha256(original).hexdigest())
            applied = execute([tofu, "apply", "-input=false", "-no-color", opened / "plan.bin"], fixture)
            check("actual_local_saved_plan_apply", applied.returncode == 0, exit=applied.returncode)
            state = execute([tofu, "show", "-json"], fixture)
            resource = json.loads(state.stdout)["values"]["root_module"]["resources"][0]
            check("actual_state_matches_private_fixture", resource["values"]["input"]["message"] == CANARY.decode())
            repeated = execute([tofu, "apply", "-input=false", "-no-color", opened / "plan.bin"], fixture)
            check("stale_saved_plan_cannot_be_reapplied", repeated.returncode != 0 and "stale" in (repeated.stderr + repeated.stdout).lower(),
                exit=repeated.returncode)
            (output / "seal-report.json").write_text(json.dumps(seal_report, indent=2) + "\n", encoding="utf-8")
    except Exception as exc:
        checks.append({"check": "control_completed", "outcome": "Failed", "error_type": type(exc).__name__})
    report = {"scope": "author-run local builtin Terraform resource only; not cloud deployment or human approval",
        "outcome": "Worked" if checks and all(check["outcome"] == "Worked" for check in checks) else "Failed", "checks": checks}
    (output / "summary.json").write_text(json.dumps(report, indent=2) + "\n", encoding="utf-8")
    print(json.dumps(report))
    return 0 if report["outcome"] == "Worked" else 1


if __name__ == "__main__":
    raise SystemExit(main())
