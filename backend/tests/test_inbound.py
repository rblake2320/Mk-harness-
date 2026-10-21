"""WP07 — inbound meaning processing and provider-sender proposal binding.

Proves:
  C7   classifier: explicit opt-out / possible opt-out / wrong number / product concern /
       complaint / date request / ordinary, with safety classes winning over business ones
  C7   processing creates the contract objects: product concern → exception + kernel hold +
       sales follow-up stopped; wrong number → exception + hold; complaint → exception;
       date request → DRAFT customer_date commitment (never confirmed) + deferred outcome;
       explicit opt-out → opted_out outcome; unknown/multiple sender → identity_ambiguity
  C5   each kernel event is marked processed exactly once; bodies never reach audit metadata
  C1   provider SMS proposals are bound to the business's registered sender chosen from the
       kernel registry (never from the model); contact timezone travels to the kernel
  A4   the evaluation harness has an evaluator for the classifier
"""
import json
import uuid

import httpx
import respx

from app.inbound import classify_inbound

from .conftest import auth_headers
from .test_agent_ops import KERNEL, _signup, verify_assertion
from .test_foundation import _customer, kernel_env  # noqa: F401  (fixture)


def test_classifier_priorities_and_vocabulary():
    cases = {
        "STOP": "opt_out", "Unsubscribe": "opt_out", "stop please": "opt_out",
        "please stop texting me": "opt_out", "remove me from your list": "opt_out", "I'm not interested": "ambiguous_opt_out",
        "leave me alone": "ambiguous_opt_out",
        "who is this? wrong number": "wrong_number", "this gave me a rash and my face is burning": "product_concern",
        "my order never arrived, very disappointed": "complaint", "can you check back after the holidays?": "date_request",
        "next week works better": "date_request", "Stop by anytime, I'd love a sample!": "ordinary",
        "yes! Thursday works": "ordinary", "Thanks so much 😊": "ordinary", "": "ordinary",
        # safety over business: a concern plus a date is a concern
        "I broke out from the cream, maybe try again next month": "product_concern",
        # wrong number over a possible opt-out phrase
        "wrong number, please stop texting": "wrong_number",
    }
    for text, expected in cases.items():
        assert classify_inbound(text).label == expected, (text, classify_inbound(text))
    assert classify_inbound("this gave me a rash").evidence == "rash"


def _pending(events):
    return httpx.Response(200, json=events)


def _event(fp, body, sid=None, signal="none", disposition="queued_for_meaning"):
    return {"event_id": str(uuid.uuid4()), "provider_event_id": sid or f"SM{uuid.uuid4().hex}", "sender_identity_id": str(uuid.uuid4()),
            "source_destination_hash": fp, "received_at": "2026-10-20T15:00:00Z", "provider_timestamp": None,
            "opt_out_signal": signal, "disposition": disposition, "body": body}


def test_processing_creates_contract_objects_and_marks_each_event_once(client, kernel_env):
    tok = _signup(client, uuid.uuid4().hex[:6])
    h = auth_headers(tok)
    cid, _, fp = _customer(client, h, phone="+15555557001")
    cid2, _, fp2 = _customer(client, h, name="Bea", phone="+15555557002")
    unknown_fp = "f" * 64
    events = [
        _event(fp, "this gave me a rash and my face is burning", sid="SMconcern"),
        _event(fp, "my order never arrived", sid="SMcomplaint"),
        _event(fp, "can you reach out after the holidays?", sid="SMdate"),
        _event(fp2, "STOP", sid="SMstop", signal="explicit", disposition="suppressed"),
        _event(unknown_fp, "hello?", sid="SMunknown"),
        _event(fp, "who is this? wrong number", sid="SMwrong"),
        _event(fp, "I'm not interested", sid="SMpossible", signal="possible", disposition="held"),
    ]
    processed, holds = [], []

    def mark(request, event_id):
        verify_assertion(request); processed.append(event_id)
        return httpx.Response(204)

    def hold(request):
        verify_assertion(request); holds.append(json.loads(request.content))
        return httpx.Response(201, json={"suppression_id": str(uuid.uuid4()), "suppressed_actions": 0})

    with respx.mock() as m:
        m.get(f"{KERNEL}/internal/v1/inbound/pending?limit=50").mock(return_value=_pending(events))
        m.post(f"{KERNEL}/internal/v1/suppressions").mock(side_effect=hold)
        m.post(url__regex=rf"{KERNEL}/internal/v1/inbound/(?P<eid>[0-9a-f-]+)/processed$").mock(
            side_effect=lambda req, eid: mark(req, eid))
        r = client.post("/api/inbound/process", json={"limit": 50}, headers=h)
    assert r.status_code == 200, r.text
    out = {e["class"]: e for e in r.json()["events"]}
    assert r.json()["processed"] == 7 and len(processed) == 7 and len(set(processed)) == 7
    assert out["product_concern"]["customer_id"] == cid and any(c.startswith("exception:") for c in out["product_concern"]["created"])
    assert out["complaint"]["customer_id"] == cid and out["complaint"]["hold"] is None, "complaints do not stop follow-up by themselves"
    assert any(c.startswith("commitment_draft:") for c in out["date_request"]["created"])
    assert out["opt_out"]["customer_id"] == cid2 and "outcome:opted_out" in out["opt_out"]["created"]
    assert out["ordinary"]["matches"] == 0 and any(c.startswith("exception:") for c in out["ordinary"]["created"]), "unknown sender → identity_ambiguity"
    assert out["wrong_number"]["hold"] == 201 and out["product_concern"]["hold"] == 201
    assert out["ambiguous_opt_out"]["hold"] is None, "kernel already holds possible opt-outs"
    assert {h_["reason"] for h_ in holds} == {"hold:product_concern", "hold:wrong_number"}
    assert all(h_["destination_hash"] == fp and h_["permanent"] is False and h_["channel"] == "sms" for h_ in holds)
    # Date request produced a DRAFT, never a confirmed commitment or an invented date.
    cms = client.get(f"/api/commitments?customer_id={cid}", headers=h).json()
    drafts = [c for c in cms if c["kind"] == "customer_date"]
    assert drafts and all(c["status"] in ("draft", "deferred") and c["confirmed_by"] is None and c["due_at"] is None for c in drafts), cms
    # Exceptions are visible with the right kinds; bodies are sealed, not in audit.
    ex = client.get("/api/exceptions", headers=h).json()
    kinds = sorted(e["kind"] for e in ex)
    assert kinds == sorted(["product_concern", "complaint", "identity_ambiguity", "wrong_number", "ambiguous_opt_out"]), kinds
    from app.db import get_db  # noqa: PLC0415
    from app.models import AuditLog  # noqa: PLC0415
    from sqlalchemy import select  # noqa: PLC0415
    db = next(get_db())
    rows = db.scalars(select(AuditLog)).all()
    assert not any("rash" in (a.detail or "") or "never arrived" in (a.detail or "") for a in rows)
    # Agent principals cannot run processing (they must never see customer messages).
    r = client.post("/api/inbound/process", json={}, headers={})
    assert r.status_code == 401


def test_provider_sms_proposal_binds_registered_sender_and_contact_timezone(client, kernel_env):
    tok = _signup(client, uuid.uuid4().hex[:6])
    h = auth_headers(tok)
    cid, _, _ = _customer(client, h, phone="+15555557003")
    assert client.put(f"/api/customers/{cid}/preferences", json={"timezone": "America/Los_Angeles"}, headers=h).status_code == 200
    me = json.loads(client.get("/api/auth/me", headers=h).text)["id"]
    sender_id = str(uuid.uuid4())
    seen = {}

    def propose(request):
        seen["claims"] = verify_assertion(request); seen["body"] = json.loads(request.content)
        return httpx.Response(202, json={"result": {"action_id": str(uuid.uuid4()), "state": "approval_required", "message_state": "awaiting_approval"}, "decision": {}})

    senders = [{"sender_identity_id": sender_id, "owner_user_id": str(uuid.UUID(me)), "status": "active", "provider": "twilio"}]
    body = {"origin": "agent", "request": {"workflow": "customer_follow_up", "action_kind": "send_sms", "tool_id": "sms.provider.send.v1",
            "resource": {"type": "contact", "id": str(uuid.UUID(cid))},
            "arguments": {"contact_id": str(uuid.UUID(cid)), "template_id": "t.v1", "rendered_text": "Hi! Reply STOP to opt out.", "to": "+15555557003",
                          "sender_identity_id": str(uuid.uuid4())},  # model-supplied id: ignored unless it is the tenant's
            "purpose": "customer_requested_follow_up", "risk": "high", "requested_at": "2026-10-20T15:00:00Z",
            "expires_at": "2026-10-20T15:30:00Z", "idempotency_key": "k-" + uuid.uuid4().hex, "evidence": []}}
    with respx.mock() as m:
        m.get(f"{KERNEL}/internal/v1/senders").mock(return_value=httpx.Response(200, json=senders))
        m.post(f"{KERNEL}/internal/v1/actions").mock(side_effect=propose)
        r = client.post("/api/agent-ops/actions", json=body, headers=h)
        assert r.status_code == 422 and r.json()["detail"]["code"] == "SENDER_NOT_FOUND", r.text
        del body["request"]["arguments"]["sender_identity_id"]
        r = client.post("/api/agent-ops/actions", json=body, headers=h)
    assert r.status_code == 202, r.text
    args = seen["body"]["arguments"]
    assert args["sender_identity_id"] == sender_id and args["contact_tz"] == "America/Los_Angeles"
    # No sender registered → cannot propose provider SMS at all.
    with respx.mock(assert_all_called=False) as m:
        m.get(f"{KERNEL}/internal/v1/senders").mock(return_value=httpx.Response(200, json=[]))
        m.post(f"{KERNEL}/internal/v1/actions").mock(return_value=httpx.Response(202, json={}))
        body["request"]["idempotency_key"] = "k-" + uuid.uuid4().hex
        r = client.post("/api/agent-ops/actions", json=body, headers=h)
        assert r.status_code == 422 and r.json()["detail"]["code"] == "NO_SENDER_IDENTITY"
        assert not [c for c in m.calls if c.request.url.path.endswith("/actions")]


def test_evaluation_harness_scores_a4_with_the_classifier():
    from tests.evaluations import run as ev  # noqa: PLC0415
    r = ev.eval_a4()
    assert r.available and r.cases >= 6 and r.passed(), (r.metrics, r.failures)


def test_failed_processed_mark_never_duplicates_application_records(client, kernel_env):
    """Codex finding on #35: if the kernel 'processed' mark fails after the application
    commit, the event stays pending and the next run must not create the exception,
    outcome or draft again. The ledger row makes the retry a mark-only replay."""
    tok = _signup(client, uuid.uuid4().hex[:6])
    h = auth_headers(tok)
    cid, _, fp = _customer(client, h, phone="+15555557101")
    events = [_event(fp, "this gave me a rash", sid="SMretry1"), _event(fp, "can you text me after the holidays?", sid="SMretry2")]
    marks: list[str] = []

    def mark_fails(request, eid):
        marks.append(eid)
        return httpx.Response(500, json={"code": "INTERNAL"})

    def mark_ok(request, eid):
        marks.append(eid)
        return httpx.Response(204)

    def hold(request):
        return httpx.Response(201, json={"suppression_id": str(uuid.uuid4()), "suppressed_actions": 0})

    for side in (mark_fails, mark_ok):
        with respx.mock(assert_all_called=False) as m:
            m.get(f"{KERNEL}/internal/v1/inbound/pending?limit=50").mock(return_value=_pending(events))
            hold_route = m.post(f"{KERNEL}/internal/v1/suppressions").mock(side_effect=hold)
            m.post(url__regex=rf"{KERNEL}/internal/v1/inbound/(?P<eid>[0-9a-f-]+)/processed$").mock(side_effect=side)
            r = client.post("/api/inbound/process", json={"limit": 50}, headers=h)
            assert r.status_code == 200, r.text
            if side is mark_ok:
                assert all(e.get("replayed") for e in r.json()["events"]), r.json()
                assert all(e["marked_processed"] == 204 for e in r.json()["events"])
                assert not hold_route.called, "the hold is not requested twice"
    assert len(marks) == 4
    ex = [e for e in client.get("/api/exceptions", headers=h).json() if e["customer_id"] == cid]
    assert len(ex) == 1 and ex[0]["kind"] == "product_concern", ex
    drafts = [c for c in client.get(f"/api/commitments?customer_id={cid}", headers=h).json() if c["kind"] == "customer_date"]
    assert len(drafts) == 1, drafts


def test_customer_match_survives_kernel_fingerprint_rotation(client, kernel_env):
    """After the kernel rotates its fingerprint key, `source_destination_hash` is the
    new key's value; the application's stored fingerprint is the old (`m0`) one and
    must still match through the event's `destination_fingerprints` tags. A tag for
    an unrelated number must not match."""
    tok = _signup(client, uuid.uuid4().hex[:6])
    h = auth_headers(tok)
    cid, _, fp = _customer(client, h, phone="+15555557101")
    rotated = "a" * 64
    ev = _event(rotated, "my order never arrived", sid="SMrot")
    ev["destination_fingerprints"] = [f"k2:{rotated}", f"m0:{fp}"]
    stray = _event("b" * 64, "my order never arrived", sid="SMstray")
    stray["destination_fingerprints"] = ["k2:" + "b" * 64, "m0:" + "c" * 64]
    with respx.mock(assert_all_called=False) as m:
        m.get(f"{KERNEL}/internal/v1/inbound/pending?limit=50").mock(return_value=_pending([ev, stray]))
        m.post(f"{KERNEL}/internal/v1/suppressions").mock(return_value=httpx.Response(201, json={"suppression_id": str(uuid.uuid4()), "suppressed_actions": 0}))
        m.post(url__regex=rf"{KERNEL}/internal/v1/inbound/[0-9a-f-]+/processed$").mock(return_value=httpx.Response(204))
        r = client.post("/api/inbound/process", json={"limit": 50}, headers=h)
    assert r.status_code == 200, r.text
    by_sid = {e["event_id"]: e for e in r.json()["events"]}
    assert by_sid[ev["event_id"]]["customer_id"] == cid
    assert by_sid[stray["event_id"]]["customer_id"] is None
