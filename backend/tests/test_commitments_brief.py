"""WP04 — commitments, daily brief, outcomes (rows W1–W7, X1).

Proves:
  W1  AI extraction creates DRAFTS only; verbatim-quote evidence required; invented absolute
      dates are dropped (window kept); "next month" stays a window until a date is chosen;
      confirm requires date or window; confirming sets confirmed_by/at
  W2  golden fixture → exactly the expected candidates, each with rule + source + permission state
  W3  deterministic ranking: exception → overdue → due today → unanswered → future; within
      category by due time then oldest
  W4  no purchase-age/depletion candidates exist in the brief
  W6  repeated generation creates no duplicate items; re-running after resolve adds nothing
  W7  resolved/cancelled/deferred/suppressed items behave consistently; every item has a source
  X1  outcomes recorded separately from transport; resolve → commitment resolved; cancel; defer
  F7  cross-tenant 404 / 401 on every route
"""
import json
import uuid
from datetime import date, datetime, timedelta, timezone

import httpx
import pytest
import respx

from app.commitments import date_text_present, parse_extractor_output, window_for

from .conftest import auth_headers, signup
from .test_foundation import CONSENT, _customer, _user, kernel_env, kernel_ok  # noqa: F401


@pytest.fixture(autouse=True)
def fixed_commitment_clock(monkeypatch):
    """Golden dates and relative windows share an explicit business clock.

    Do not freeze authentication/session time: only the commitment domain clock
    is fixed, so the API still authenticates requests using the real wall clock.
    """
    monkeypatch.setattr("app.commitments.utcnow", lambda: datetime(2026, 10, 20, 17, tzinfo=timezone.utc))


def _anthropic_json(obj) -> httpx.Response:
    return httpx.Response(200, json={"content": [{"type": "text", "text": json.dumps(obj)}],
                                     "usage": {"input_tokens": 10, "output_tokens": 10}, "model": "claude-x"})


def _user_with_key(client):
    tag = uuid.uuid4().hex[:6]
    tok = signup(client, org=f"Org {tag}", email=f"u-{tag}@example.com")
    h = auth_headers(tok)
    client.put("/api/keys/mine", headers=h, json={"provider": "anthropic", "api_key": "sk-ant-test"})
    return h


# --------------------------------------------------------------------------- #
# Unit: windows, date presence, extractor validation
# --------------------------------------------------------------------------- #
def test_windows_are_explicit_and_never_invented():
    import zoneinfo
    tz = zoneinfo.ZoneInfo("America/Chicago")
    now = datetime(2026, 10, 20, 12, 0, tzinfo=tz)   # a Tuesday
    ws, we = window_for("next_month", now)
    assert (ws.date().isoformat(), we.date().isoformat()) == ("2026-11-01", "2026-11-30")
    ws, we = window_for("next_week", now)
    assert (ws.date().isoformat(), we.date().isoformat()) == ("2026-10-26", "2026-11-01")
    assert window_for("unspecified", now) == (None, None)
    dec = datetime(2026, 12, 15, tzinfo=tz)
    assert window_for("next_month", dec)[0].date().isoformat() == "2027-01-01"


def test_date_text_presence():
    src = "Sure, I'll check on the sample Oct 24 and call you 11/02."
    assert date_text_present(src, "2026-10-24")
    assert date_text_present(src, "2026-11-02")
    assert not date_text_present(src, "2026-10-25")
    assert not date_text_present(src, "garbage")


def test_extractor_output_is_validated_not_repaired():
    src = "Customer: can you check if the sample worked next month? Me: yes, I'll check next month."
    raw = json.dumps({"commitments": [
        {"kind": "promise", "text": "Check whether the sample worked", "relative_window": "next_month",
         "absolute_date": "2026-11-15", "evidence_quote": "I'll check next month"},          # invented date → dropped
        {"kind": "promise", "text": "Made up", "relative_window": "today", "evidence_quote": "not in source"},  # bad quote → dropped
        {"kind": "bogus", "text": "x", "evidence_quote": "yes"},                              # bad kind → dropped
        {"kind": "customer_request", "text": "Wants to know if sample worked", "relative_window": "sometime",
         "evidence_quote": "can you check if the sample worked"},                             # bad window → unspecified
    ]})
    out = parse_extractor_output(raw, src)
    assert len(out) == 2
    assert out[0].absolute_date is None and out[0].relative_window == "next_month"
    assert out[1].relative_window == "unspecified"
    with pytest.raises(Exception):
        parse_extractor_output("not json", src)
    with pytest.raises(Exception):
        parse_extractor_output(json.dumps({"nope": []}), src)


# --------------------------------------------------------------------------- #
# W1 lifecycle via API
# --------------------------------------------------------------------------- #
@respx.mock
def test_extraction_creates_drafts_only_and_confirmation_is_explicit(client):
    h = _user_with_key(client)
    cid, _, _ = _customer(client, h, phone="+15555551001")
    client.put(f"/api/customers/{cid}/preferences", json={"timezone": "America/Chicago"}, headers=h)
    src = "Angela: Could you check next month whether the serum sample helped? Me: Absolutely, I'll check next month."
    respx.post("https://api.anthropic.com/v1/messages").mock(return_value=_anthropic_json({"commitments": [
        {"kind": "promise", "text": "Check whether the serum sample helped", "relative_window": "next_month",
         "absolute_date": "2026-11-20", "evidence_quote": "I'll check next month"}]}))
    r = client.post("/api/commitments/extract", json={"customer_id": cid, "conversation_text": src,
                                                      "provider": "anthropic"}, headers=h)
    assert r.status_code == 201, r.text
    d = r.json()["drafts"][0]
    assert d["status"] == "draft" and d["created_by"] == "ai" and d["confirmed_by"] is None
    assert d["due_at"] is None and d["due_window"][0].startswith("2026-11-01") and d["due_window"][1].startswith("2026-11-30")
    # Draft never appears in the brief
    b = client.get("/api/brief?date=2026-11-03", headers=h).json()
    assert b["items"] == []
    # Confirm keeps the window (consultant chose not to pick a day yet)
    c = client.post(f"/api/commitments/{d['id']}/confirm", json={}, headers=h)
    assert c.status_code == 200 and c.json()["status"] == "confirmed" and c.json()["confirmed_by"]
    # A draft with no timing cannot be confirmed without choosing
    r2 = client.post("/api/commitments", json={"customer_id": cid, "text": "Call back", "evidence_text": "call me back"}, headers=h).json()
    assert client.post(f"/api/commitments/{r2['id']}/confirm", json={}, headers=h).status_code == 422
    assert client.post(f"/api/commitments/{r2['id']}/confirm", json={"relative_window": "unspecified"}, headers=h).status_code == 422
    ok = client.post(f"/api/commitments/{r2['id']}/confirm", json={"relative_window": "tomorrow"}, headers=h)
    assert ok.status_code == 200 and ok.json()["due_window"][0]


@respx.mock
def test_extractor_failure_paths(client):
    h = _user_with_key(client)
    cid, _, _ = _customer(client, h, phone="+15555551002")
    respx.post("https://api.anthropic.com/v1/messages").mock(return_value=_anthropic_json({"commitments": []}))
    r = client.post("/api/commitments/extract", json={"customer_id": cid, "conversation_text": "Hello there, thanks!",
                                                      "provider": "anthropic"}, headers=h)
    assert r.status_code == 201 and r.json()["drafts"] == []
    respx.post("https://api.anthropic.com/v1/messages").mock(
        return_value=httpx.Response(200, json={"content": [{"type": "text", "text": "I think she promised stuff"}],
                                               "usage": {"input_tokens": 1, "output_tokens": 1}, "model": "m"}))
    r = client.post("/api/commitments/extract", json={"customer_id": cid, "conversation_text": "Hello there, thanks!",
                                                      "provider": "anthropic"}, headers=h)
    assert r.status_code == 502


# --------------------------------------------------------------------------- #
# W2/W3/W6/W7 golden brief
# --------------------------------------------------------------------------- #
def _commit(client, h, cid, text, **kw):
    body = {"customer_id": cid, "text": text, "evidence_text": text, "confirm_now": True, **kw}
    r = client.post("/api/commitments", json=body, headers=h)
    assert r.status_code == 201, r.text
    return r.json()


@pytest.mark.parametrize("create_before_suppression", [False, True])
def test_suppressed_brief_keeps_evidence_and_refreshes_permission(client, kernel_env, create_before_suppression):
    h = _user(client)
    cid, did, _ = _customer(client, h, phone="+15555557501")
    commitment = _commit(client, h, cid, "Requested check-in", absolute_date="2026-10-20")
    with kernel_ok():
        assert client.post(f"/api/customers/{cid}/consent", json={**CONSENT, "destination_id": did}, headers=h).status_code == 201
        if create_before_suppression:
            old = client.get("/api/brief?date=2026-10-20", headers=h).json()["items"]
            assert old[0]["permission_state"] == "active"
        assert client.post("/api/suppressions", json={"destination_id": did, "reason": "STOP", "source": "sms_reply"}, headers=h).status_code == 201
    items = client.get("/api/brief?date=2026-10-20", headers=h).json()["items"]
    assert len(items) == 1
    assert items[0]["source_reference"] == commitment["id"]
    assert items[0]["source"]["text"] == "Requested check-in"
    assert items[0]["permission_state"] == "suppressed"
    assert "approve" not in items[0]["controls"]
    assert "blocked" in items[0]["suggested_step"].lower()
    again = client.get("/api/brief?date=2026-10-20", headers=h).json()["items"]
    assert [item["id"] for item in again] == [items[0]["id"]]


def test_golden_brief_candidates_and_ordering(client):
    h = _user(client)
    tz = "America/Chicago"
    customers = {}
    for name, phone in [("Angela", "+15555552001"), ("Bea", "+15555552002"), ("Cara", "+15555552003"),
                        ("Dee", "+15555552004"), ("Eve", "+15555552005"), ("Fay", "+15555552006")]:
        cid, did, fp = _customer(client, h, name=name, phone=phone)
        client.put(f"/api/customers/{cid}/preferences", json={"timezone": tz}, headers=h)
        customers[name] = cid
    today = "2026-10-20"
    # overdue promise (Angela), due today (Bea) at two times, unanswered question (Cara),
    # customer-supplied date window open (Dee → future), promise due next week (Eve → not in brief),
    # explicit request due today (Fay)
    a = _commit(client, h, customers["Angela"], "Check sample", absolute_date="2026-10-18")
    b1 = _commit(client, h, customers["Bea"], "Call about reorder", absolute_date=today)
    cq = _commit(client, h, customers["Cara"], "Does the cleanser suit dry skin?", kind="unanswered_question", absolute_date="2026-10-19")
    d = _commit(client, h, customers["Dee"], "Customer asked for contact in late October", kind="customer_date", relative_window="this_week")
    _commit(client, h, customers["Eve"], "Follow up on party", absolute_date="2026-10-27")
    f = _commit(client, h, customers["Fay"], "Send the price list", kind="customer_request", absolute_date=today)
    # an open exception for Bea → safety rank first (exceptions are created by the
    # inbound pipeline in WP07; inserted directly here)
    import jwt as pyjwt
    from app import db as dbmod
    from app.models import ExceptionRecord
    tid = pyjwt.decode(h["Authorization"][7:], options={"verify_signature": False})["tid"]
    with dbmod._SessionLocal() as s:
        s.add(ExceptionRecord(tenant_id=tid, customer_id=customers["Bea"], kind="product_concern", source_reference="msg-1"))
        s.commit()

    r = client.get(f"/api/brief?date={today}", headers=h)
    assert r.status_code == 200, r.text
    items = r.json()["items"]
    got = [(i["customer"]["name"], i["rule"], i["rank_category"]) for i in items]
    # Exact expected brief: exception first; overdue; due today; unanswered by due time
    # (Cara 10-19 before Fay 10-20); Dee's this_week window is open but closes 10-25 → future.
    assert got == [
        ("Bea", "exception", 0),
        ("Angela", "commitment_due", 1),
        ("Bea", "commitment_due", 2),
        ("Cara", "unanswered_question", 3),
        ("Fay", "explicit_request", 3),
        ("Dee", "customer_date", 4),
    ], got
    # Every item has a source and a permission observation
    for i in items:
        assert i["source_type"] and i["source_reference"] and i["permission_state"] in ("none", "active", "suppressed")
        assert i["permission_checked_at"] and "historical" in i["permission_note"]
        assert i["rule"] != "purchase_age"      # W4: no depletion heuristics
    # Eve (next week) is absent
    assert "Eve" not in [i["customer"]["name"] for i in items]
    # W6: regenerate → identical, no duplicates
    again = client.get(f"/api/brief?date={today}", headers=h).json()["items"]
    assert [i["id"] for i in again] == [i["id"] for i in items]
    # W7: resolve one → disappears, commitment resolved, outcome recorded; regenerate adds nothing
    bea_item = [i for i in items if i["customer"]["name"] == "Bea" and i["rule"] == "commitment_due"][0]
    rs = client.post(f"/api/brief/items/{bea_item['id']}/resolve", json={"outcome": "resolved", "note": "done"}, headers=h)
    assert rs.status_code == 200
    assert client.get(f"/api/commitments?customer_id={customers['Bea']}", headers=h).json()[0]["status"] == "resolved"
    after = client.get(f"/api/brief?date={today}", headers=h).json()["items"]
    assert len(after) == len(items) - 1
    tl = client.get(f"/api/customers/{customers['Bea']}/timeline", headers=h).json()
    assert [e["type"] for e in tl][-1] == "outcome" and tl[-1]["data"]["note"] == "done"
    # skip + defer
    ang = [i for i in after if i["customer"]["name"] == "Angela"][0]
    assert client.post(f"/api/brief/items/{ang['id']}/defer", json={"relative_window": "next_week"}, headers=h).status_code == 200
    # Deferral keeps the commitment deferred (it is not re-confirmed) ...
    ang_c = client.get(f"/api/commitments?customer_id={customers['Angela']}", headers=h).json()[0]
    assert ang_c["status"] == "deferred", ang_c
    # ... and the brief brings it back once its new window opens (a deferral never drops it).
    later = (date.fromisoformat(today) + timedelta(days=8)).isoformat()
    assert "Angela" in [i["customer"]["name"] for i in client.get(f"/api/brief?date={later}", headers=h).json()["items"]]
    # A deferral without a new date or window is refused rather than silently parking it.
    assert client.post(f"/api/commitments/{ang_c['id']}/defer", json={}, headers=h).status_code == 422
    fay = [i for i in after if i["customer"]["name"] == "Fay"][0]
    assert client.post(f"/api/brief/items/{fay['id']}/skip", headers=h).status_code == 200
    final = client.get(f"/api/brief?date={today}", headers=h).json()["items"]
    assert {i["customer"]["name"] for i in final} == {"Bea", "Cara", "Dee"}


def test_outcomes_are_separate_from_transport_and_cancel_works(client):
    h = _user(client)
    cid, _, _ = _customer(client, h, phone="+15555553001")
    c = _commit(client, h, cid, "Drop off sample", absolute_date="2026-10-20")
    o = client.post("/api/outcomes", json={"customer_id": cid, "kind": "consultant_confirmed_order",
                                           "commitment_id": c["id"], "note": "she ordered"}, headers=h)
    assert o.status_code == 201 and "not verified revenue" in o.json()["note"]
    assert client.get(f"/api/commitments?customer_id={cid}", headers=h).json()[0]["status"] == "resolved"
    assert client.post(f"/api/commitments/{c['id']}/cancel", headers=h).status_code == 409
    c2 = _commit(client, h, cid, "Second", absolute_date="2026-10-21")
    assert client.post(f"/api/commitments/{c2['id']}/cancel", headers=h).json()["status"] == "cancelled"
    assert client.post("/api/outcomes", json={"customer_id": cid, "kind": "delivered"}, headers=h).status_code == 422


def test_cross_tenant_isolation_commitments(client):
    a, b = _user(client), _user(client)
    cid, _, _ = _customer(client, a, phone="+15555554001")
    c = _commit(client, a, cid, "Promise", absolute_date="2026-10-20")
    item = client.get("/api/brief?date=2026-10-20", headers=a).json()["items"][0]
    for method, path, body in [
        ("POST", "/api/commitments", {"customer_id": cid, "text": "promise", "evidence_text": "x"}),
        ("GET", f"/api/commitments?customer_id={cid}", None),
        ("POST", f"/api/commitments/{c['id']}/confirm", {}),
        ("POST", f"/api/commitments/{c['id']}/defer", {"relative_window": "tomorrow"}),
        ("POST", f"/api/commitments/{c['id']}/cancel", None),
        ("POST", f"/api/brief/items/{item['id']}/skip", None),
        ("POST", f"/api/brief/items/{item['id']}/resolve", {"outcome": "resolved"}),
        ("POST", "/api/outcomes", {"customer_id": cid, "kind": "resolved"}),
        ("GET", f"/api/customers/{cid}/timeline", None),
    ]:
        assert client.request(method, path, json=body, headers=b).status_code == 404, path
        assert client.request(method, path, json=body).status_code == 401, path
    assert client.get("/api/brief?date=2026-10-20", headers=b).json()["items"] == []
