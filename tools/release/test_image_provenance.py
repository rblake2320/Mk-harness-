import json
from types import SimpleNamespace

import pytest

from tools.release import image_provenance as gate

REPO, SHA = "example/project", "a" * 40
REGISTRY = "123456789012.dkr.ecr.us-east-1.amazonaws.com"
KERNEL = REGISTRY + "/mk-action-kernel@sha256:" + "b" * 64
APP = REGISTRY + "/mk-app@sha256:" + "c" * 64


@pytest.mark.parametrize("change", ["tag", "shell", "other_registry", "other_image", "uppercase", "credentials", "http"])
def test_unbounded_or_mutable_registry_references_refused(change):
    app = APP
    if change == "tag": app = REGISTRY + "/mk-app:latest"
    if change == "shell": app += "; touch /tmp/no"
    if change == "other_registry": app = app.replace("123456789012", "999999999999")
    if change == "other_image": app = app.replace("mk-app", "mk-evil")
    if change == "uppercase": app = app[:-64] + "A" * 64
    if change == "credentials": app = "password@" + app
    if change == "http": app = "http://" + app
    assert not gate.valid_inputs(REPO, SHA, KERNEL, app)


def test_invalid_input_never_runs_verifiers(monkeypatch, tmp_path):
    monkeypatch.setattr(gate.subprocess, "run", lambda *_a, **_kw: pytest.fail("unsafe input reached CLI"))
    assert gate.verify(REPO, SHA, KERNEL, "latest", tmp_path / "result")["verdict"] == "REFUSED"


def test_exact_identity_source_and_runner_constraints_are_mandatory():
    commands = gate.commands(REPO, SHA, APP)
    expected = f"https://github.com/{REPO}/.github/workflows/deploy.yml@refs/heads/main"
    assert commands["signature"][commands["signature"].index("--certificate-identity") + 1] == expected
    provenance = commands["provenance"]
    for flag, value in (("--cert-identity", expected), ("--source-ref", "refs/heads/main"),
        ("--source-digest", SHA), ("--signer-digest", SHA), ("--repo", REPO)):
        assert provenance[provenance.index(flag) + 1] == value
    assert "--deny-self-hosted-runners" in provenance
    assert not any("insecure" in item or "regex" in item or "offline" in item for command in commands.values() for item in command)


@pytest.mark.parametrize("failed_index", [0, 1, 2, 3])
@pytest.mark.parametrize("fault", ["nonzero", "malformed", "empty", "timeout", "missing"])
def test_either_image_or_verifier_failure_blocks(monkeypatch, tmp_path, failed_index, fault):
    calls = []

    def execute(command, **kwargs):
        calls.append(command)
        assert kwargs["encoding"] == "utf-8" and kwargs["timeout"] == 120
        assert not kwargs.get("shell")
        if len(calls) - 1 == failed_index:
            if fault == "timeout": raise gate.subprocess.TimeoutExpired(command, 120)
            if fault == "missing": raise FileNotFoundError("verifier not installed")
            return SimpleNamespace(returncode=1 if fault == "nonzero" else 0,
                stdout="[]" if fault == "empty" else "not JSON", stderr="credential must not be retained")
        return SimpleNamespace(returncode=0, stdout='[{"verified":"synthetic test only"}]')

    monkeypatch.setattr(gate.subprocess, "run", execute)
    output = tmp_path / "result"
    report = gate.verify(REPO, SHA, KERNEL, APP, output)
    assert report["verdict"] == "REFUSED" and len(calls) == 4
    assert sum(check["ok"] for check in report["checks"]) == 3
    assert "credential must not" not in (output / "summary.json").read_text()


def test_both_images_need_both_verifiers_and_retained_outputs(monkeypatch, tmp_path):
    calls = []

    def execute(command, **_kwargs):
        calls.append(command)
        return SimpleNamespace(returncode=0, stdout='[{"verified":"synthetic test only"}]')

    monkeypatch.setattr(gate.subprocess, "run", execute)
    output = tmp_path / "result"
    report = gate.verify(REPO, SHA, KERNEL, APP, output)
    assert report["verdict"] == "PASS" and len(calls) == 4
    assert {check["image"] for check in report["checks"]} == {APP, KERNEL}
    for check in report["checks"]:
        payload = (output / check["evidence"]).read_bytes()
        assert gate.hashlib.sha256(payload).hexdigest() == check["sha256"]
        assert json.loads(payload)


def test_previous_evidence_cannot_be_overwritten(tmp_path):
    with pytest.raises(FileExistsError):
        gate.verify(REPO, SHA, KERNEL, APP, tmp_path)
