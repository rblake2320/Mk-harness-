"""WP08 glue — draft → kernel proposal → approval screen data (rows H1, W5, C9).

Proves:
  - proposing a draft sends the kernel a contract-valid action whose rendered_text is the
    exact draft text, bound to the business's registered sender, the customer's primary SMS
    destination and timezone, with draft + commitment evidence; an ActionLink is recorded
  - the proposal is agent-origin when the draft was AI-generated (so kernel approval rules
    apply) and nothing is sent by the application (C9: no Python send path)
  - the approval screen payload carries every H1 field
  - action status exposes the contract message_state and verbatim definitions
  - a draft edit produces a new digest, so a pending approval of the old text cannot cover it (W5)
  - admin-only JSONL audit export; 401 without auth
"""
import json
import uuid

import httpx
import jsonschema
import respx
from pathlib import Path

from .conftest import auth_headers, signup
from .test_agent_ops import KERNEL, verify_assertion
from .test_commitments_brief import _anthropic_json, _commit
from .test_drafting import _model, _registry
from .test_foundation import _customer, kernel_env  # noqa: F401

SCHEMA = json.loads((Path(__file__).resolve().parents[2] / "contracts/action/v1/action-request.schema.json").read_text())


def _user(client):
    tag = uuid.uuid4().hex[:6]
    tok = signup(client, org=f"Org {tag}", email=f"u-{tag}@example.com")
    h = auth_headers(tok)
    client.put("/api/keys/mine", headers=h, json={"provider": "anthropic", "api_key": "sk-ant-test"})
    me = client.get("/api/auth/me", headers=h).json()["id"]
    return h, me


@respx.mock
def test_draft_to_proposal_to_approval_screen(client, kernel_env):
    h, me = _user(client)
    _registry(client, h)
    cid, _, _ = _customer(client, h, phone="+15555558001")
    assert client.put(f"/api/customers/{cid}/preferences", json={"timezone": "America/Chicago"}, headers=h).status_code == 200
    cm = _commit(client, h, cid, "Check how the day cream is working", absolute_date="2026-10-20")
    respx.post("https://api.anthropic.com/v1/messages").mock(return_value=_model(
        "Hi Angela! You asked me to check on the day cream. {claim:daycream.vitc.v1} Reply STOP to opt out.", ["daycream.vitc.v1"]))
    d = client.post("/api/drafts", json={"customer_id": cid, "commitment_id": cm["id"], "product_ids": ["daycream"], "provider": "anthropic"},
                    headers=h).json()["draft"]
    sender_id = str(uuid.uuid4()); seen = {}
    aid = str(uuid.uuid4())

    def propose(request):
        seen["claims"] = verify_assertion(request); seen["req"] = json.loads(request.content)
        return httpx.Response(202, json={"result": {"action_id": aid, "state": "approval_required", "message_state": "awaiting_approval",
                                                    "action_digest": "sha256:" + "a" * 64}, "decision": {"code": "require_approval"}})

    senders = [{"sender_identity_id": sender_id, "owner_user_id": str(uuid.UUID(me)), "status": "active", "provider": "twilio",
                "display_name": "Angela's Business", "from_number": "+15005550006", "registration_status": "registered"}]
    respx.get(f"{KERNEL}/internal/v1/senders").mock(return_value=httpx.Response(200, json=senders))
    respx.post(f"{KERNEL}/internal/v1/actions").mock(side_effect=propose)
    r = client.post(f"/api/drafts/{d['id']}/propose", json={}, headers=h)
    assert r.status_code == 202, r.text
    assert r.json()["action_id"] == aid and r.json()["human_steps"]
    req = seen["req"]
    jsonschema.Draft202012Validator(SCHEMA).validate(req)
    assert req["arguments"]["rendered_text"] == d["text"], "the proposal carries the exact draft text"
    assert req["arguments"]["to"] == "+15555558001" and req["arguments"]["sender_identity_id"] == sender_id
    assert req["arguments"]["contact_tz"] == "America/Chicago" and req["tool_id"] == "sms.provider.send.v1"
    assert req["origin"]["type"] == "agent" and "agent" in seen["claims"]["roles"], "AI-generated → agent origin"
    assert {e["type"] for e in req["evidence"]} == {"document", "conversation"}
    assert any(e["digest"] == d["text_digest"] for e in req["evidence"])

    # Approval screen: every H1 field present.
    wrong_sender = {**senders[0], "sender_identity_id": str(uuid.uuid4()),
                    "display_name": "Another sending identity", "from_number": "+15005550007"}
    respx.get(f"{KERNEL}/internal/v1/senders").mock(return_value=httpx.Response(200, json=[wrong_sender, *senders]))
    pending = [{"result": {"action_id": aid, "state": "approval_required", "message_state": "awaiting_approval", "action_digest": "sha256:" + "a" * 64},
                "display": {"rendered_text": d["text"], "destination_redacted": "********8001", "channel": "sms", "workflow": "customer_follow_up",
                            "purpose": "customer_requested_follow_up", "risk": "high", "evidence_count": 2, "expires_at": "2026-10-21T00:00:00Z",
                            "sender_identity_id": sender_id, "scheduled_for": "2026-10-20T22:00:00Z",
                            "can_approve": False, "approval_denial": "self_approval_forbidden", "self_approval": True,
                            "approval_ttl_seconds": 300,
                            "action_digest": "sha256:" + "a" * 64}}]
    respx.get(f"{KERNEL}/internal/v1/approvals/pending").mock(return_value=httpx.Response(200, json=pending))
    r = client.get("/api/approvals/pending", headers=h)
    assert r.status_code == 200, r.text
    item = r.json()[0]
    for k in ("exact_text", "destination_masked", "customer", "sending_business", "purpose", "supporting", "permission",
              "scheduled_for", "approval_expires_at", "action_digest", "approval_lifetime_minutes", "human_steps"):
        assert k in item, k
    assert item["customer"]["id"] == cid and item["sending_business"]["from_number"] == "+15005550006"
    assert item["sending_business"]["sender_identity_id"] == sender_id
    assert item["scheduled_for"] == "2026-10-20T22:00:00Z"
    assert item["can_approve"] is False and item["approval_denial"] == "self_approval_forbidden"
    assert item["self_approval"] is True and item["approval_lifetime_minutes"] == 5
    assert item["permission"]["state"] == "none", "permission is observed even without a brief link"
    assert item["supporting"]["commitment"]["id"] == cm["id"] and item["supporting"]["draft_version_id"] == d["id"]
    assert item["exact_text"] == d["text"] and item["destination_masked"].endswith("8001")
    # Losing the selected identity must not substitute another owned number.
    respx.get(f"{KERNEL}/internal/v1/senders").mock(return_value=httpx.Response(200, json=[wrong_sender]))
    missing = client.get("/api/approvals/pending", headers=h).json()[0]
    assert missing["sending_business"] is None

    # Status view: contract vocabulary + verbatim definitions.
    respx.get(f"{KERNEL}/internal/v1/actions/{aid}").mock(return_value=httpx.Response(200, json={"action_id": aid, "state": "queued", "message_state": "queued"}))
    r = client.get(f"/api/actions/{aid}", headers=h)
    assert r.status_code == 200 and r.json()["link"]["draft_version_id"] == d["id"]
    assert r.json()["message_state_definitions"]["sent"] == "Provider reports outbound network submission."
    assert len(r.json()["message_state_definitions"]) == 15

    # H2/W5: old version withdrawal must be confirmed before committing an edit.
    withdrawal = respx.post(f"{KERNEL}/internal/v1/drafts/{d['id']}/invalidate").mock(
        return_value=httpx.Response(200, json={"draft_id": str(uuid.UUID(d["id"])), "edit_permitted": True}))
    e = client.post(f"/api/drafts/{d['id']}/edit", json={"text": d["text"].replace("Hi Angela!", "Hi Angela —")}, headers=h).json()
    assert e["text_digest"] != d["text_digest"] and e["version"] == 2
    assert withdrawal.call_count == 1
    assert item["action_digest"] != e["text_digest"]

    # Cross-tenant: another tenant cannot propose this draft or see this action.
    h2, _ = _user(client)
    assert client.post(f"/api/drafts/{d['id']}/propose", json={}, headers=h2).status_code == 404
    assert client.get(f"/api/drafts/{d['id']}/propose").status_code in (401, 405)


@respx.mock
def test_edit_requires_confirmed_kernel_withdrawal_even_without_local_action_link(client, kernel_env):
    from sqlalchemy import func, select
    from sqlalchemy.orm import Session
    from app.models import DraftVersion, ActionLink
    from .conftest import engine
    h, me = _user(client)
    cid, _, _ = _customer(client, h, phone="+15555558012")
    respx.post("https://api.anthropic.com/v1/messages").mock(return_value=_model("Hi Angela! Reply STOP to opt out.", []))
    draft = client.post("/api/drafts", json={"customer_id": cid, "provider": "anthropic"}, headers=h).json()["draft"]
    path = f"/api/drafts/{draft['id']}/edit"
    route = respx.post(f"{KERNEL}/internal/v1/drafts/{draft['id']}/invalidate")
    text = "Hi Angela! How is your week? Reply STOP to opt out."
    with Session(engine) as db:
        assert db.scalar(select(func.count()).select_from(ActionLink).where(ActionLink.draft_version_id == draft["id"])) == 0
    for response, expected in [
        (httpx.Response(503, json={"code": "OVER_CAPACITY"}), 503),
        (httpx.Response(403, json={"code": "FORBIDDEN"}), 403),
        (httpx.Response(200, json={"draft_id": str(uuid.UUID(draft["id"])), "edit_permitted": False, "blocked_actions": ["in-flight"]}), 409),
        (httpx.Response(200, json={"draft_id": str(uuid.uuid4()), "edit_permitted": True}), 502),
        (httpx.Response(200, json={"draft_id": str(uuid.UUID(draft["id"])), "edit_permitted": "true"}), 502),
        (httpx.Response(200, json={}), 502),
    ]:
        route.mock(return_value=response)
        result = client.post(path, json={"text": text}, headers=h)
        assert result.status_code == expected, result.text
        with Session(engine) as db:
            assert db.scalar(select(func.count()).select_from(DraftVersion).where(DraftVersion.customer_id == cid)) == 1
        assert client.get(f"/api/drafts/{draft['id']}", headers=h).json()["text_digest"] == draft["text_digest"]
    route.mock(side_effect=httpx.ReadTimeout("synthetic lost withdrawal response"))
    assert client.post(path, json={"text": text}, headers=h).status_code == 503
    assert route.call_count == 7, "writes are not retried after an ambiguous response"
    other, _ = _user(client)
    assert client.post(path, json={"text": text}, headers=other).status_code == 404
    assert route.call_count == 7, "tenant ownership is checked before invalidation"
    def acknowledge(request):
        claims = verify_assertion(request)
        assert claims["sub"].replace("-", "") == me
        assert "tenant_admin" in claims["roles"]
        return httpx.Response(200, json={"draft_id": str(uuid.UUID(draft["id"])), "edit_permitted": True})
    route.mock(side_effect=acknowledge)
    result = client.post(path, json={"text": text}, headers=h)
    assert result.status_code == 201, result.text
    assert result.json()["id"] != draft["id"] and result.json()["version"] == 2
    with Session(engine) as db:
        assert db.scalar(select(func.count()).select_from(DraftVersion).where(DraftVersion.customer_id == cid)) == 2


def test_propose_requires_timezone_destination_and_sender(client, kernel_env):
    h, _ = _user(client)
    _registry(client, h)
    # No destination and no timezone.
    r = client.post("/api/customers", json={"name": "No Phone"}, headers=h)
    cid = r.json()["id"]
    with respx.mock:
        respx.post("https://api.anthropic.com/v1/messages").mock(return_value=_model("Hi No! Reply STOP to opt out.", []))
        d = client.post("/api/drafts", json={"customer_id": cid, "provider": "anthropic"}, headers=h).json()["draft"]
    r = client.post(f"/api/drafts/{d['id']}/propose", json={}, headers=h)
    assert r.status_code == 422 and r.json()["detail"]["code"] == "TIMEZONE_UNKNOWN"
    client.put(f"/api/customers/{cid}/preferences", json={"timezone": "America/Chicago"}, headers=h)
    r = client.post(f"/api/drafts/{d['id']}/propose", json={}, headers=h)
    assert r.status_code == 422 and r.json()["detail"]["code"] == "NO_SMS_DESTINATION"
    client.post(f"/api/customers/{cid}/destinations", json={"channel": "sms", "value": "+15555558002"}, headers=h)
    with respx.mock(assert_all_called=False) as m:
        m.get(f"{KERNEL}/internal/v1/senders").mock(return_value=httpx.Response(200, json=[]))
        m.post(f"{KERNEL}/internal/v1/actions").mock(return_value=httpx.Response(202, json={}))
        r = client.post(f"/api/drafts/{d['id']}/propose", json={}, headers=h)
        assert r.status_code == 422 and r.json()["detail"]["code"] == "NO_SENDER_IDENTITY"
        assert not [c for c in m.calls if c.request.url.path.endswith("/actions")], "nothing reaches the kernel without a sender"


def test_audit_export_is_admin_only_jsonl(client):
    tag = uuid.uuid4().hex[:6]
    admin = auth_headers(signup(client, org=f"Org {tag}", email=f"a-{tag}@example.com"))
    client.post("/api/auth/members", json={"email": f"c-{tag}@example.com", "password": "superSecret123!", "role": "consultant"}, headers=admin)
    cons = auth_headers(client.post("/api/auth/login", json={"email": f"c-{tag}@example.com", "password": "superSecret123!"}).json())
    assert client.get("/api/audit/export.jsonl", headers=cons).status_code == 403
    assert client.get("/api/audit/export.jsonl").status_code == 401
    r = client.get("/api/audit/export.jsonl", headers=admin)
    assert r.status_code == 200
    lines = [json.loads(l) for l in r.text.splitlines() if l]
    assert lines and all({"id", "at", "action", "detail"} <= set(l) for l in lines)
    assert any(l["action"] == "audit.export" for l in client.get("/api/audit/export.jsonl", headers=admin).text.splitlines() and
               [json.loads(x) for x in client.get("/api/audit/export.jsonl", headers=admin).text.splitlines()])
