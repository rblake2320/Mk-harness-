"""The deploy workflow must enforce source gates before requesting cloud tokens."""
from pathlib import Path
import re
import subprocess

import yaml

ROOT = Path(__file__).resolve().parents[2]


def workflow():
    return yaml.safe_load((ROOT / ".github/workflows/deploy.yml").read_text())


def test_source_gate_precedes_cloud_build():
    jobs = workflow()["jobs"]
    assert "validate-source" in jobs
    assert "validate-source" in jobs["build-sign"]["needs"]
    gate = jobs["validate-source"]
    assert gate["permissions"] == {"contents": "read", "actions": "read"}
    assert any("tools/release/deployment_source.py" in step.get("run", "") for step in gate["steps"])
    step = next(step for step in gate["steps"] if "tools/release/deployment_source.py" in step.get("run", ""))
    assert step["env"]["WORKFLOW_SHA"] == "${{ github.sha }}"
    assert '--workflow-sha "$WORKFLOW_SHA"' in step["run"]


def test_untrusted_dispatch_input_never_becomes_shell_source():
    for job in workflow()["jobs"].values():
        for step in job["steps"]:
            assert "${{ inputs." not in step.get("run", "")


def test_cloud_tokens_are_not_granted_to_every_job():
    config = workflow()
    assert config["permissions"] == {"contents": "read"}
    assert config["concurrency"]["cancel-in-progress"] is False
    assert config["jobs"]["build-sign"]["if"] == "github.ref == 'refs/heads/main'"


def test_dispatch_target_is_closed_and_kernel_checks_run_on_every_main_commit():
    config = workflow()
    # PyYAML's YAML 1.1 loader represents the GitHub `on` key as True.
    trigger = config.get("on", config.get(True))
    assert trigger["workflow_dispatch"]["inputs"]["target"]["options"] == ["staging", "production"]
    kernel = yaml.safe_load((ROOT / ".github/workflows/kernel-ci.yml").read_text())
    trigger = kernel.get("on", kernel.get(True))
    assert "paths" not in trigger["push"]


def test_both_release_images_are_scanned_before_signing_and_both_are_attested():
    steps = workflow()["jobs"]["build-sign"]["steps"]
    sign = next(i for i, step in enumerate(steps) if "cosign sign" in step.get("run", ""))
    scans = [(i, step) for i, step in enumerate(steps) if "tools/verification/image_security.py" in step.get("run", "")]
    assert len(scans) == 2
    assert all(i < sign and 'docker pull "$IMAGE"' in step["run"] and "@${{ steps." in step["env"]["IMAGE"] for i, step in scans)
    attestations = [step for step in steps if step.get("uses", "").startswith("actions/attest-build-provenance@")]
    assert {step["with"]["subject-digest"] for step in attestations} == {
        "${{ steps.kernel.outputs.digest }}", "${{ steps.app.outputs.digest }}"}


def test_staging_and_production_verify_both_images_before_any_apply():
    for name in ("staging", "production"):
        job = workflow()["jobs"][name]
        assert job["permissions"]["attestations"] == "read"
        verify = next(i for i, step in enumerate(job["steps"]) if "tools/release/image_provenance.py" in step.get("run", ""))
        apply = next(i for i, step in enumerate(job["steps"]) if "tofu apply" in step.get("run", ""))
        assert verify < apply
        step = job["steps"][verify]
        assert '--kernel-image "$KERNEL_IMAGE" --app-image "$APP_IMAGE"' in step["run"]
        assert all("needs.build-sign.outputs.registry" in step["env"][name] for name in ("KERNEL_IMAGE", "APP_IMAGE"))


def test_production_approval_follows_a_completed_encrypted_plan_job():
    jobs = workflow()["jobs"]
    assert "production-plan" in jobs
    plan, apply = jobs["production-plan"], jobs["production"]
    assert plan["environment"] == "production-plan"
    assert apply["environment"] == "production"
    assert "production-plan" in apply["needs"]
    plan_command = r"tofu(?:\s+-chdir=\S+)?\s+plan\b"
    assert any(re.search(plan_command, step.get("run", "")) for step in plan["steps"])
    assert not any("tofu apply" in step.get("run", "") for step in plan["steps"])
    assert not any(re.search(plan_command, step.get("run", "")) for step in apply["steps"])
    assert any("AWS_PRODUCTION_PLAN_ROLE_ARN" in str(step.get("with", {})) for step in plan["steps"])
    assert not any("PLAN_PRIVATE_KEY" in str(step) for step in plan["steps"])


def test_only_sealed_plan_is_uploaded_and_exact_same_run_artifact_is_consumed():
    jobs = workflow()["jobs"]
    plan_steps = jobs["production-plan"]["steps"]
    upload = next(step for step in plan_steps if step.get("with", {}).get("name") == "production-plan")
    assert upload["with"]["path"] == "production-plan-package"
    assert any("production_plan.py seal" in step.get("run", "") for step in plan_steps)
    steps = jobs["production"]["steps"]
    download = next(step for step in steps if step.get("uses", "").startswith("actions/download-artifact@"))
    assert download["with"]["artifact-ids"] == "${{ needs.production-plan.outputs.artifact_id }}"
    unseal = next(i for i, step in enumerate(steps) if "production_plan.py open" in step.get("run", ""))
    apply = next(i for i, step in enumerate(steps) if "tofu apply" in step.get("run", ""))
    assert unseal < apply
    assert steps[unseal]["env"]["PLAN_ENVELOPE_SHA256"] == "${{ needs.production-plan.outputs.envelope_sha256 }}"
    assert unseal + 1 == apply  # no long-running job between freshness check and consumption


def test_tofu_wrappers_cannot_export_private_plan_stdout_as_action_outputs():
    for job in workflow()["jobs"].values():
        for step in job["steps"]:
            if step.get("uses", "").startswith("opentofu/setup-opentofu@"):
                assert step["with"]["tofu_wrapper"] is False


def test_provider_lock_is_a_tracked_release_input_not_a_local_cache():
    path = "infra/terraform/modules/kernel-platform/.terraform.lock.hcl"
    tracked = subprocess.check_output(["git", "ls-files", "--", path], cwd=ROOT, text=True, encoding="utf-8").strip()
    assert tracked == path
    assert (ROOT / path).is_file()
