from datetime import datetime, timedelta, timezone
import json

import pytest

from tools.release import production_plan as gate

NOW = datetime(2026, 10, 22, 12, tzinfo=timezone.utc)
PRIVATE_CANARY = "NEVER_PUBLISH_PRIVATE_PLAN_INPUT_20261022"
REGISTRY = "123456789012.dkr.ecr.us-east-1.amazonaws.com"


def expected():
    return gate.context("example/project", "a" * 40, "12345", "2",
        REGISTRY + "/mk-action-kernel@sha256:" + "b" * 64,
        REGISTRY + "/mk-app@sha256:" + "c" * 64, "d" * 64)


def plan_json():
    return {"format_version": "1.2", "terraform_version": "1.10.6", "errored": False,
        "variables": {"unmarked_private": PRIVATE_CANARY}, "planned_values": PRIVATE_CANARY,
        "resource_changes": [{"type": "aws_ecs_service", "name": PRIVATE_CANARY,
            "address": 'module.private["' + PRIVATE_CANARY + '"].aws_ecs_service.app',
            "change": {"actions": ["update"], "before": PRIVATE_CANARY, "after": PRIVATE_CANARY}}]}


def fixture(tmp_path):
    private = gate.X25519PrivateKey.generate()
    public = private.public_key().public_bytes_raw().hex()
    package = tmp_path / "package"
    plan = b"synthetic-plan-bytes:" + PRIVATE_CANARY.encode()
    sealed = gate.seal(plan, plan_json(), expected(), public, package, NOW)
    return private.private_bytes_raw().hex(), package, plan, sealed


def test_exact_plan_survives_sealing_but_private_values_never_enter_artifact(tmp_path):
    private, package, plan, sealed = fixture(tmp_path)
    for file in package.iterdir():
        assert PRIVATE_CANARY.encode() not in file.read_bytes()
    assert sealed["review"]["resource_changes"] == [{"type": "aws_ecs_service", "actions": ["update"], "count": 1}]
    result = gate.open_plan(package, expected(), private, sealed["envelope_sha256"], tmp_path / "opened", NOW)
    assert result["verdict"] == "OPENED"
    assert (tmp_path / "opened/plan.bin").read_bytes() == plan


@pytest.mark.parametrize("key", list(expected()))
def test_any_different_source_run_attempt_images_environment_or_toolchain_blocks(tmp_path, key):
    private, package, _plan, sealed = fixture(tmp_path)
    changed = expected(); changed[key] += "different"
    with pytest.raises(ValueError, match="context changed"):
        gate.open_plan(package, changed, private, sealed["envelope_sha256"], tmp_path / "opened", NOW)
    assert not (tmp_path / "opened").exists()


@pytest.mark.parametrize("offset", [timedelta(seconds=-1), timedelta(hours=2, seconds=1)])
def test_future_or_expired_plan_is_refused(tmp_path, offset):
    private, package, _plan, sealed = fixture(tmp_path)
    with pytest.raises(ValueError, match="window"):
        gate.open_plan(package, expected(), private, sealed["envelope_sha256"], tmp_path / "opened", NOW + offset)


@pytest.mark.parametrize("mutation", ["ciphertext", "nonce", "ephemeral_public_key", "metadata", "extra"])
def test_tampered_envelope_refused_even_if_attacker_rehashes_file(tmp_path, mutation):
    private, package, _plan, _sealed = fixture(tmp_path)
    envelope = json.loads((package / "plan.enc.json").read_bytes())
    if mutation == "ciphertext": envelope[mutation] = "A" * len(envelope[mutation])
    if mutation == "nonce": envelope[mutation] = "0" * 24
    if mutation == "ephemeral_public_key": envelope[mutation] = gate.X25519PrivateKey.generate().public_key().public_bytes_raw().hex()
    if mutation == "metadata": envelope[mutation]["plan_sha256"] = "0" * 64
    if mutation == "extra": envelope["ignored_field"] = "attack"
    raw = gate.canonical(envelope); (package / "plan.enc.json").write_bytes(raw)
    with pytest.raises(Exception):
        gate.open_plan(package, expected(), private, gate.sha256(raw), tmp_path / "opened", NOW)
    assert not (tmp_path / "opened").exists()


def test_replaced_artifact_or_review_or_wrong_recipient_blocks(tmp_path):
    private, package, _plan, sealed = fixture(tmp_path)
    with pytest.raises(ValueError, match="producer"):
        gate.open_plan(package, expected(), private, "0" * 64, tmp_path / "opened", NOW)
    wrong = gate.X25519PrivateKey.generate().private_bytes_raw().hex()
    with pytest.raises(ValueError, match="recipient"):
        gate.open_plan(package, expected(), wrong, sealed["envelope_sha256"], tmp_path / "opened", NOW)
    (package / "review.json").write_bytes(b"{}")
    with pytest.raises(ValueError, match="summary"):
        gate.open_plan(package, expected(), private, sealed["envelope_sha256"], tmp_path / "opened", NOW)


@pytest.mark.parametrize("change", ["errored", "version", "format", "type", "action"])
def test_unknown_or_errored_plan_cannot_be_sealed(tmp_path, change):
    plan = plan_json()
    if change == "errored": plan["errored"] = True
    if change == "version": plan["terraform_version"] = "0.1"
    if change == "format": plan["format_version"] = "2.0"
    if change == "type": plan["resource_changes"][0]["type"] = PRIVATE_CANARY
    if change == "action": plan["resource_changes"][0]["change"]["actions"] = [PRIVATE_CANARY]
    key = gate.X25519PrivateKey.generate().public_key().public_bytes_raw().hex()
    with pytest.raises(ValueError):
        gate.seal(b"plan", plan, expected(), key, tmp_path / "package", NOW)


def test_existing_output_is_not_overwritten(tmp_path):
    private, package, _plan, sealed = fixture(tmp_path)
    with pytest.raises(FileExistsError):
        gate.open_plan(package, expected(), private, sealed["envelope_sha256"], tmp_path, NOW)
