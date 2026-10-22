"""The deploy workflow must enforce source gates before requesting cloud tokens."""
from pathlib import Path

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
