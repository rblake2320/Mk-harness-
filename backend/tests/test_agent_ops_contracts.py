"""Wire-contract and local simulator conformance tests."""

from __future__ import annotations

import json
import time
from pathlib import Path

import httpx
import pytest

from app.agent_ops import (
    COMPLETION_SCHEMA,
    EXECUTION_SCHEMA,
    WORK_ORDER_SCHEMA,
)
from app.agent_ops.contracts import (
    CONTRACT_DIR,
    ContractValidationError,
    validate_contract,
)
from app.agent_ops.security import body_digest, sign_request, verify_request
from app.agent_ops.simulator import SimulatorConfig, create_simulator_app

AGENT_ID = "simulator-1"
TENANT_ID = "00000000000040008000000000000001"
TASK_ID = "00000000000040008000000000000002"
DEVICE_TOKEN = "simulator-device-token-not-for-production"
CONTROL_TOKEN = "simulator-control-token-not-for-production"


def _work_order(*, required_actions: list[str] | None = None) -> dict:
    return {
        "schema": WORK_ORDER_SCHEMA,
        "adapter": "mobile-adapter-v1",
        "upstream_contract": (
            "PhoneClaw ClawScript helper surface at commit "
            "c59995b726a127da16275d2d8e0760408b988542"
        ),
        "verified_on_device": False,
        "workflow": "follow_up",
        "steps": [
            {"action": "open", "target": "sms"},
            {"action": "input", "field": "recipient", "value": "+13125550123"},
        ],
        "clawscript_source": 'speakText("contract test");\n',
        "adapter_actions_required": required_actions or [],
        "result_fields": [],
        "task_id": TASK_ID,
        "agent_id": AGENT_ID,
        "callback_url": f"https://harness.example/api/agent-ops/tasks/{TASK_ID}/result",
        "callback_auth": "hmac-sha256-v1",
    }


def _request(value: dict, *, timestamp: str | None = None, nonce: str | None = None):
    body = json.dumps(value, sort_keys=True, separators=(",", ":")).encode()
    headers = {
        "Content-Type": "application/json",
        "X-Mobile-Agent": AGENT_ID,
        "X-Mobile-Tenant": TENANT_ID,
        **sign_request(
            DEVICE_TOKEN,
            "POST",
            "/work",
            body,
            timestamp=timestamp,
            nonce=nonce,
        ),
    }
    return body, headers


def _app(mode="accept"):
    return create_simulator_app(
        SimulatorConfig(
            agent_id=AGENT_ID,
            tenant_id=TENANT_ID,
            device_token=DEVICE_TOKEN,
            control_token=CONTROL_TOKEN,
            mode=mode,
        )
    )


def test_all_published_schemas_accept_their_named_contracts():
    validate_contract("work_order", _work_order())
    validate_contract(
        "executing",
        {
            "schema": EXECUTION_SCHEMA,
            "status": "executing",
            "result": {},
            "error_code": "",
        },
    )
    validate_contract(
        "complete",
        {
            "schema": COMPLETION_SCHEMA,
            "status": "complete",
            "result": {"message_id": "test-1"},
            "error_code": "",
        },
    )
    with pytest.raises(ContractValidationError):
        validate_contract("work_order", {**_work_order(), "verified_on_device": True})


def test_public_hmac_vector_matches_implementation():
    vector_file = Path(CONTRACT_DIR) / "hmac-test-vectors.json"
    vector = json.loads(vector_file.read_text(encoding="utf-8"))["vectors"][0]
    body = vector["body_utf8"].encode()
    assert body_digest(body) == vector["body_sha256"]
    headers = sign_request(
        vector["secret"],
        vector["method"],
        vector["path"],
        body,
        timestamp=vector["timestamp"],
        nonce=vector["nonce"],
    )
    assert headers["X-Mobile-Signature"] == vector["signature_hex"]
    assert verify_request(
        vector["secret"],
        vector["method"],
        vector["path"],
        body,
        timestamp=vector["timestamp"],
        nonce=vector["nonce"],
        signature=vector["signature_hex"],
        now_seconds=int(vector["timestamp"]),
    )


@pytest.mark.asyncio
async def test_simulator_accepts_valid_work_order_and_rejects_replay():
    app = _app()
    body, headers = _request(_work_order(), nonce="fixed-replay-nonce")
    async with httpx.AsyncClient(
        transport=httpx.ASGITransport(app=app), base_url="http://simulator"
    ) as client:
        accepted = await client.post("/work", content=body, headers=headers)
        replayed = await client.post("/work", content=body, headers=headers)
    assert accepted.status_code == 202
    assert accepted.json() == {"accepted": True, "task_id": TASK_ID}
    assert replayed.status_code == 409


@pytest.mark.asyncio
async def test_simulator_rejects_expired_signature_and_invalid_schema():
    app = _app()
    expired_body, expired_headers = _request(
        _work_order(), timestamp=str(int(time.time()) - 301)
    )
    invalid_body, invalid_headers = _request(
        {**_work_order(), "verified_on_device": True}
    )
    async with httpx.AsyncClient(
        transport=httpx.ASGITransport(app=app), base_url="http://simulator"
    ) as client:
        expired = await client.post(
            "/work", content=expired_body, headers=expired_headers
        )
        invalid = await client.post(
            "/work", content=invalid_body, headers=invalid_headers
        )
    assert expired.status_code == 401
    assert invalid.status_code == 422


@pytest.mark.asyncio
async def test_simulator_failure_modes_are_deterministic():
    body, headers = _request(_work_order(), nonce="failure-mode-one")
    fail_once = _app("fail_once")
    async with httpx.AsyncClient(
        transport=httpx.ASGITransport(app=fail_once), base_url="http://simulator"
    ) as client:
        first = await client.post("/work", content=body, headers=headers)
        second_body, second_headers = _request(_work_order(), nonce="failure-mode-two")
        second = await client.post("/work", content=second_body, headers=second_headers)
    assert first.status_code == 503
    assert second.status_code == 202

    action_gap = _app("unsupported_actions")
    gap_body, gap_headers = _request(
        _work_order(required_actions=["input"]), nonce="action-gap"
    )
    async with httpx.AsyncClient(
        transport=httpx.ASGITransport(app=action_gap), base_url="http://simulator"
    ) as client:
        rejected = await client.post("/work", content=gap_body, headers=gap_headers)
    assert rejected.status_code == 422
    assert "not implemented" in rejected.text


@pytest.mark.asyncio
async def test_simulator_sends_schema_valid_signed_callback():
    app = _app()
    body, headers = _request(_work_order(), nonce="callback-setup")
    async with httpx.AsyncClient(
        transport=httpx.ASGITransport(app=app), base_url="http://simulator"
    ) as client:
        assert (
            await client.post("/work", content=body, headers=headers)
        ).status_code == 202

    async def callback_handler(request: httpx.Request) -> httpx.Response:
        value = json.loads(request.content)
        validate_contract("complete", value)
        assert verify_request(
            DEVICE_TOKEN,
            "POST",
            request.url.path,
            request.content,
            timestamp=request.headers["X-Mobile-Timestamp"],
            nonce=request.headers["X-Mobile-Nonce"],
            signature=request.headers["X-Mobile-Signature"],
        )
        return httpx.Response(200, json={"ok": True})

    state = app.state.simulator
    async with httpx.AsyncClient(
        transport=httpx.MockTransport(callback_handler)
    ) as callback_client:
        response = await state.send_callback(
            TASK_ID,
            "complete",
            result={"message_id": "simulated-1"},
            client=callback_client,
        )
    assert response.status_code == 200
