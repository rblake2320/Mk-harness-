"""C7 live uncertainty is visible, owner-scoped, and never silently dismissed."""
import uuid

import httpx
import respx

from app import db as dbmod
from app.models import ActionLink, Customer, User
from .test_agent_ops import KERNEL, verify_assertion
from .test_foundation import _customer, kernel_env  # noqa: F401
from .test_outreach import _user


def test_live_delivery_exceptions_keep_unknown_and_filter_customer_owner(client, kernel_env):
    h, uid = _user(client)
    other, _ = _user(client)
    cid, _, _ = _customer(client, h, phone="+15555558201")
    foreign_cid, _, _ = _customer(client, other, phone="+15555558202")
    aid, foreign_aid, cursor = [str(uuid.uuid4()) for _ in range(3)]
    with dbmod._SessionLocal() as db:
        tenant = db.get(Customer, cid).tenant_id
        # Deliberately corrupt app link points into another owner/tenant. No leak.
        for action, customer in [(aid, cid), (foreign_aid, foreign_cid)]:
            db.add(ActionLink(tenant_id=tenant, customer_id=customer, kernel_action_id=action,
                              action_digest="sha256:" + "a" * 64, last_known_state="reconciliation_required"))
        db.commit()
    base = {"delivery_id": str(uuid.uuid4()), "action_state": "reconciliation_required",
            "delivery_state": "submission_unknown", "provider_message_id": None, "read_status": "unknown",
            "created_at": "2026-10-21T12:00:00Z", "reconciled_at": None}
    with respx.mock() as m:
        route = m.get(f"{KERNEL}/internal/v1/deliveries/exceptions?limit=50").mock(return_value=httpx.Response(200,
            json={"items": [{**base, "action_id": aid}, {**base, "action_id": foreign_aid}], "next_cursor": cursor}))
        response = client.get("/api/delivery-exceptions", headers=h)
        assert response.status_code == 200, response.text
        data = response.json()
        assert len(data["items"]) == 1 and data["next_cursor"] == cursor
        assert data["items"][0]["customer_id"] == cid
        assert data["items"][0]["message_state"] == "submission_unknown"
        assert data["items"][0]["replacement_allowed"] is False
        assert uuid.UUID(verify_assertion(route.calls[0].request)["sub"]) == uuid.UUID(uid)
        route.mock(return_value=httpx.Response(503, json={"code": "STORE_UNAVAILABLE"}))
        assert client.get("/api/delivery-exceptions", headers=h).status_code == 503
        assert all(call.request.method == "GET" for call in m.calls)
    assert client.get("/api/delivery-exceptions").status_code == 401
    for query in ("limit=0", "limit=101", "after=wrong"):
        assert client.get(f"/api/delivery-exceptions?{query}", headers=h).status_code == 422


def test_delivery_exception_cursor_and_provider_evidence_never_clear_human_review(client, kernel_env):
    h, _ = _user(client)
    cursor = str(uuid.uuid4())
    item = {"delivery_id": str(uuid.uuid4()), "action_id": str(uuid.uuid4()),
            "action_state": "reconciliation_required", "delivery_state": "delivered",
            "provider_message_id": "SM" + "a" * 32, "read_status": "unknown"}
    with respx.mock() as m:
        m.get(f"{KERNEL}/internal/v1/deliveries/exceptions?limit=1&after={cursor}").mock(
            return_value=httpx.Response(200, json={"items": [item], "next_cursor": None}))
        response = client.get(f"/api/delivery-exceptions?limit=1&after={cursor}", headers=h)
        assert response.status_code == 200, response.text
        result = response.json()["items"][0]
        assert result["delivery_state"] == "delivered"  # receipt is separately visible
        assert result["message_state"] == "submission_unknown"  # still awaiting operator resolution
        assert result["replacement_allowed"] is False


def test_resolution_proxy_requires_admin_passkey_and_forwards_exact_binding(client, kernel_env):
    import json
    h, uid = _user(client)
    aid = str(uuid.uuid4())
    path = f"/api/agent-ops/actions/{aid}"
    choice = {"decision": "replacement_permitted"}
    payload = {**choice, "operation_digest": "sha256:" + "b" * 64,
               "webauthn": {k: "YWJj" for k in ("credential_id", "client_data_json", "authenticator_data", "signature")}}
    with respx.mock() as m:
        challenge = m.post(f"{KERNEL}/internal/v1/actions/{aid}/resolution-challenge").mock(
            return_value=httpx.Response(200, json={"challenge": "kernel-issued", **choice}))
        finish = m.post(f"{KERNEL}/internal/v1/actions/{aid}/resolve-submission").mock(
            return_value=httpx.Response(409, json={"code": "RESOLUTION_CHANGED"}))
        assert client.post(path + "/resolution-challenge", headers=h, json=choice).status_code == 200
        assert json.loads(challenge.calls[0].request.content) == choice
        claims = verify_assertion(challenge.calls[0].request)
        assert "tenant_admin" in claims["roles"] and "agent" not in claims["roles"]
        response = client.post(path + "/resolve-submission", headers=h, json=payload)
        assert response.status_code == 409
        assert json.loads(finish.calls[0].request.content) == payload
        for bad in (choice, {**payload, "decision": "mark_delivered"}, {**payload, "tenant_id": str(uuid.uuid4())},
                    {**payload, "webauthn": {**payload["webauthn"], "approved": True}}):
            assert client.post(path + "/resolve-submission", headers=h, json=bad).status_code == 422
        assert finish.call_count == 1
        assert client.post(path + "/resolve-submission", json=payload).status_code == 401
        with dbmod._SessionLocal() as db:
            db.get(User, uid).role = "consultant"
            db.commit()
        assert client.post(path + "/resolve-submission", headers=h, json=payload).status_code == 403
        assert client.post(path + "/resolution-challenge", headers=h, json=choice).status_code == 403
        assert finish.call_count == 1 and challenge.call_count == 1


def test_tenant_admin_sees_other_owner_resolution_without_cross_tenant_leak(client, kernel_env):
    h, uid = _user(client)
    other, other_uid = _user(client)
    cid, _, _ = _customer(client, other, phone="+15555558222")
    aid = str(uuid.uuid4())
    with dbmod._SessionLocal() as db:
        tenant = db.get(User, uid).tenant_id
        customer = db.get(Customer, cid)
        customer.tenant_id = tenant  # same tenant, different owner
        db.add(ActionLink(tenant_id=tenant, customer_id=cid, kernel_action_id=aid,
                          action_digest="sha256:" + "a" * 64, last_known_state="reconciliation_required"))
        db.commit()
    item = {"delivery_id": str(uuid.uuid4()), "action_id": aid, "action_state": "reconciliation_required",
            "delivery_state": "failed", "provider_message_id": "SM" + "a" * 32,
            "resolution_options": ["replacement_permitted"]}
    with respx.mock() as m:
        m.get(f"{KERNEL}/internal/v1/deliveries/exceptions?limit=50").mock(
            return_value=httpx.Response(200, json={"items": [item], "next_cursor": None}))
        result = client.get("/api/delivery-exceptions", headers=h).json()["items"]
        assert len(result) == 1 and result[0]["customer_id"] == cid
        assert result[0]["resolution_options"] == ["replacement_permitted"]
        with dbmod._SessionLocal() as db:
            db.get(User, uid).role = "consultant"
            db.commit()
        assert client.get("/api/delivery-exceptions", headers=h).json()["items"] == []
