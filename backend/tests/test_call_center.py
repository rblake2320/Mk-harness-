"""Call-center trust-boundary, tenant-isolation, and lifecycle tests."""

import json
import uuid
from datetime import UTC, datetime, timedelta

import httpx
import respx

from app import db as dbmod
from app.call_center.security import sign_request
from app.models import CallCenterAuditEntry
from tests.conftest import auth_headers, signup


def _email() -> str:
    return f"cc-{uuid.uuid4().hex[:12]}@example.com"


def _user(client):
    tokens = signup(client, org=f"Org {uuid.uuid4().hex[:6]}", email=_email())
    headers = auth_headers(tokens)
    response = client.put(
        "/api/keys/mine",
        headers=headers,
        json={"provider": "anthropic", "api_key": "sk-ant-test"},
    )
    assert response.status_code == 200
    return tokens, headers


def _register(client, headers, agent_id=None):
    agent_id = agent_id or f"phone-{uuid.uuid4().hex[:8]}"
    response = client.post(
        "/api/claw/agents",
        headers=headers,
        json={
            "agent_id": agent_id,
            "webhook_url": "https://phone.example/work",
            "platform_specialty": "multi",
            "capabilities": {"clawscript": True},
        },
    )
    assert response.status_code == 201, response.text
    return response.json()


def _signed_headers(agent, path, body, **overrides):
    headers = {
        "Content-Type": "application/json",
        "X-Claw-Agent": agent["agent_id"],
        "X-Claw-Tenant": agent["tenant_id"],
        **sign_request(agent["device_token"], "POST", path, body),
    }
    headers.update(overrides)
    return headers


def _ping(client, agent):
    path = f"/api/claw/agents/{agent['agent_id']}/ping"
    body = b'{"status":"online"}'
    response = client.post(
        path, content=body, headers=_signed_headers(agent, path, body)
    )
    assert response.status_code == 200, response.text


def _anthropic_response(text="Hi Jane, I wanted to check in with you."):
    return httpx.Response(
        200,
        json={
            "content": [{"type": "text", "text": text}],
            "usage": {"input_tokens": 20, "output_tokens": 8},
            "model": "claude-sonnet-4-6",
        },
    )


def _permission(client, headers, destination="+13125550123"):
    now = datetime.now(UTC)
    response = client.post(
        "/api/claw/permissions",
        headers=headers,
        json={
            "channel": "sms",
            "destination": destination,
            "purpose": "marketing",
            "asserted_basis": "express_written_consent",
            "source_reference": "crm://consents/test-record",
            "evidence_sha256": "a" * 64,
            "granted_at": (now - timedelta(days=1)).isoformat(),
            "expires_at": (now + timedelta(days=30)).isoformat(),
            "operator_attestation": True,
        },
    )
    assert response.status_code == 201, response.text
    assert response.json()["legal_sufficiency_verified"] is False
    return response.json()


def _queue_follow_up(client, headers, agent_id, permission_id=""):
    return client.post(
        "/api/claw/tasks",
        headers=headers,
        json={
            "workflow": "follow_up",
            "agent_id": agent_id,
            "payload": {
                "customer_name": "Jane",
                "phone": "+13125550123",
                "last_purchase": "TimeWise set",
                "permission_id": permission_id,
            },
        },
    )


def test_agent_registration_auth_ssrf_and_secret_handling(client):
    _, headers = _user(client)
    assert client.post("/api/claw/agents", json={}).status_code == 401

    blocked = client.post(
        "/api/claw/agents",
        headers=headers,
        json={
            "agent_id": "private-target",
            "webhook_url": "http://127.0.0.1:8080/work",
        },
    )
    assert blocked.status_code == 422
    unlisted = client.post(
        "/api/claw/agents",
        headers=headers,
        json={
            "agent_id": "unlisted-target",
            "webhook_url": "https://example.com/work",
        },
    )
    assert unlisted.status_code == 422
    ambiguous = client.post(
        "/api/claw/agents",
        headers=headers,
        json={
            "agent_id": "query-target",
            "webhook_url": "https://phone.example/work?mode=admin",
        },
    )
    assert ambiguous.status_code == 422

    agent = _register(client, headers)
    assert len(agent["device_token"]) >= 40
    listed = client.get("/api/claw/agents", headers=headers).json()
    assert listed[0]["agent_id"] == agent["agent_id"]
    assert "device_token" not in listed[0]
    duplicate = client.post(
        "/api/claw/agents",
        headers=headers,
        json={
            "agent_id": agent["agent_id"],
            "webhook_url": "https://phone.example/work",
        },
    )
    assert duplicate.status_code == 409


def test_device_ping_rejects_tampering_and_replay(client):
    _, headers = _user(client)
    agent = _register(client, headers)
    path = f"/api/claw/agents/{agent['agent_id']}/ping"
    body = b'{"status":"online"}'
    signed = _signed_headers(agent, path, body)

    bad = dict(signed)
    bad["X-Claw-Signature"] = "0" * 64
    assert client.post(path, content=body, headers=bad).status_code == 401
    assert client.post(path, content=body, headers=signed).status_code == 200
    assert client.post(path, content=body, headers=signed).status_code == 409


@respx.mock
def test_full_task_dispatch_callback_and_audit(client):
    _, headers = _user(client)
    agent = _register(client, headers)
    _ping(client, agent)
    permission = _permission(client, headers)
    respx.post("https://api.anthropic.com/v1/messages").mock(
        return_value=_anthropic_response()
    )

    queued = _queue_follow_up(client, headers, agent["agent_id"], permission["id"])
    assert queued.status_code == 202, queued.text
    task_id = queued.json()["id"]
    task = client.get(f"/api/claw/tasks/{task_id}", headers=headers).json()
    assert task["status"] == "awaiting_approval"
    assert task["compliance_checked"] is True
    assert task["work_order"]["verified_on_device"] is False
    assert "Independent Beauty Consultant" in task["work_order"]["clawscript_source"]

    delivered = respx.post("https://phone.example/work").mock(
        return_value=httpx.Response(202)
    )
    approved = client.post(
        f"/api/claw/tasks/{task_id}/approve",
        headers=headers,
        json={"approved": True},
    )
    assert approved.status_code == 200, approved.text
    assert approved.json()["status"] == "dispatched"
    sent = delivered.calls[0].request
    assert sent.headers["X-Claw-Agent"] == agent["agent_id"]
    assert sent.headers["X-Claw-Tenant"] == agent["tenant_id"]
    assert json.loads(sent.content)["callback_url"].endswith(f"/{task_id}/result")

    path = f"/api/claw/tasks/{task_id}/result"
    result_body = json.dumps(
        {"status": "complete", "result": {"message_id": "sms-123"}},
        separators=(",", ":"),
    ).encode()
    result_headers = _signed_headers(agent, path, result_body)
    completed = client.post(path, content=result_body, headers=result_headers)
    assert completed.status_code == 200, completed.text
    assert completed.json()["status"] == "complete"
    assert (
        client.post(path, content=result_body, headers=result_headers).status_code
        == 409
    )

    task = client.get(f"/api/claw/tasks/{task_id}", headers=headers).json()
    assert task["result"] == {"message_id": "sms-123"}
    verified = client.get("/api/claw/audit/verify", headers=headers)
    assert verified.status_code == 200
    assert verified.json()["valid"] is True
    assert verified.json()["entries_checked"] >= 6


@respx.mock
def test_compliance_block_and_approval_state(client):
    _, headers = _user(client)
    agent = _register(client, headers)
    _ping(client, agent)
    permission = _permission(client, headers)
    respx.post("https://api.anthropic.com/v1/messages").mock(
        return_value=_anthropic_response("Join now for guaranteed passive income")
    )
    queued = _queue_follow_up(client, headers, agent["agent_id"], permission["id"])
    task_id = queued.json()["id"]
    task = client.get(f"/api/claw/tasks/{task_id}", headers=headers).json()
    assert task["status"] == "compliance_blocked"
    assert task["error_code"] == "income_claim"
    denied = client.post(
        f"/api/claw/tasks/{task_id}/approve",
        headers=headers,
        json={"approved": True},
    )
    assert denied.status_code == 409


def test_contact_permission_is_required_matchable_and_revocable(client):
    _, headers = _user(client)
    agent = _register(client, headers)
    missing = _queue_follow_up(client, headers, agent["agent_id"])
    assert missing.status_code == 422
    assert "active matching contact permission" in missing.text

    permission = _permission(client, headers)
    wrong_destination = client.post(
        "/api/claw/tasks",
        headers=headers,
        json={
            "workflow": "follow_up",
            "agent_id": agent["agent_id"],
            "payload": {
                "customer_name": "Other",
                "phone": "+13125550999",
                "permission_id": permission["id"],
            },
        },
    )
    assert wrong_destination.status_code == 422
    revoked = client.post(
        f"/api/claw/permissions/{permission['id']}/revoke", headers=headers
    )
    assert revoked.status_code == 200
    assert (
        _queue_follow_up(
            client, headers, agent["agent_id"], permission["id"]
        ).status_code
        == 422
    )


def test_cross_tenant_isolation_and_static_workflow(client):
    _, headers_a = _user(client)
    _, headers_b = _user(client)
    agent_a = _register(client, headers_a)
    agent_b = _register(client, headers_b)

    wrong_agent = client.post(
        "/api/claw/tasks",
        headers=headers_b,
        json={
            "workflow": "order_status",
            "agent_id": agent_a["agent_id"],
            "payload": {"portal_url": "https://carrier.example", "order_id": "A1"},
        },
    )
    assert wrong_agent.status_code == 404

    device_ssrf = client.post(
        "/api/claw/tasks",
        headers=headers_a,
        json={
            "workflow": "order_status",
            "agent_id": agent_a["agent_id"],
            "payload": {"portal_url": "https://127.0.0.1/admin", "order_id": "A1"},
        },
    )
    assert device_ssrf.status_code == 422

    queued = client.post(
        "/api/claw/tasks",
        headers=headers_a,
        json={
            "workflow": "order_status",
            "agent_id": agent_a["agent_id"],
            "payload": {"portal_url": "https://carrier.example", "order_id": "A1"},
        },
    )
    assert queued.status_code == 202, queued.text
    task_id = queued.json()["id"]
    assert (
        client.get(f"/api/claw/tasks/{task_id}", headers=headers_b).status_code == 404
    )
    assert (
        client.get(f"/api/claw/tasks/{task_id}", headers=headers_a).json()["status"]
        == "awaiting_approval"
    )
    assert agent_b["agent_id"] != agent_a["agent_id"]


def test_audit_tampering_is_detected(client):
    _, headers = _user(client)
    agent = _register(client, headers)
    assert client.get("/api/claw/audit/verify", headers=headers).json()["valid"] is True

    db = dbmod._SessionLocal()
    try:
        entry = (
            db.query(CallCenterAuditEntry)
            .filter(CallCenterAuditEntry.tenant_id == agent["tenant_id"])
            .order_by(CallCenterAuditEntry.sequence.desc())
            .first()
        )
        entry.event = "TAMPERED"
        db.commit()
    finally:
        db.close()
    result = client.get("/api/claw/audit/verify", headers=headers).json()
    assert result["valid"] is False
    assert result["reason"] == "entry_hash_mismatch"
