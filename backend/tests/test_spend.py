"""M4 — tenant AI spending cap and pre-approval SMS charge disclosure.

The cap stops company-paid model calls before any provider is contacted, covers every
path that resolves a key, ignores last month's spend and personal (BYO) keys, and
can be changed only by an owner with a fresh second factor (audited)."""
import uuid
from datetime import datetime, timezone

import httpx
import pytest
import respx

from app import db as dbmod
from app.config import get_settings
from app.models import UsageRecord, User
from app.providers.router import resolve
from app.spend import SpendLimitReached, charge_disclosure, sms_segments

from .conftest import auth_headers, signup


@pytest.mark.parametrize("text,segs,enc", [
    ("a" * 160, 1, "GSM-7"), ("a" * 161, 2, "GSM-7"), ("a" * 306, 2, "GSM-7"), ("a" * 307, 3, "GSM-7"),
    ("{" * 80, 1, "GSM-7"), ("{" * 81, 2, "GSM-7"),            # extension chars cost two septets
    ("é" * 160, 1, "GSM-7"),                                   # é is in the GSM-7 base set
    ("ê" * 70, 1, "UCS-2"), ("ê" * 71, 2, "UCS-2"),            # ê is not: the whole message is UCS-2
    ("😀" * 35, 1, "UCS-2"), ("😀" * 36, 2, "UCS-2"),          # astral = two UTF-16 units
    ("", 1, "GSM-7"),
])
def test_segment_counting(text, segs, enc):
    assert sms_segments(text) == (segs, enc)


def test_charge_disclosure_states_unknown_price_honestly(monkeypatch):
    d = charge_disclosure("Hi! Reply STOP to opt out.")
    assert d["estimated_millicents"] is None and "not configured" in d["note"]
    monkeypatch.setenv("SMS_PRICE_PER_SEGMENT_MILLICENTS", "830"); get_settings.cache_clear()
    try:
        d = charge_disclosure("x" * 161)
        assert (d["segments"], d["estimated_millicents"]) == (2, 1660)
    finally:
        get_settings.cache_clear()


def _owner(client):
    tag = uuid.uuid4().hex[:8]
    t = signup(client, org=f"Org {tag}", email=f"sp-{tag}@example.com")
    return t, auth_headers(t)


def _spend(user_id, tenant_id, usd, scope="central", at=None):
    db = dbmod._SessionLocal()
    db.add(UsageRecord(tenant_id=tenant_id, user_id=user_id, provider="anthropic", model="m", key_scope=scope,
                       cost_usd=usd, **({"created_at": at} if at else {})))
    db.commit(); db.close()


def test_cap_blocks_company_paid_calls_before_any_provider_call(client, monkeypatch, frozen_clock):
    frozen_clock("2026-11-12T12:00:00+00:00")
    monkeypatch.setenv("ANTHROPIC_API_KEY", "sk-ant-central"); get_settings.cache_clear()
    try:
        t, h = _owner(client)
        me = client.get("/api/auth/me", headers=h).json()
        db = dbmod._SessionLocal()
        user = db.get(User, me["id"])
        assert resolve(db, user, "anthropic").key_scope == "central"
        _spend(user.id, user.tenant_id, 20.0, at=datetime(2026, 10, 30, tzinfo=timezone.utc))   # last month: ignored
        _spend(user.id, user.tenant_id, 30.0, scope="byo")                                    # personal key: ignored
        assert resolve(db, user, "anthropic").key_scope == "central"
        _spend(user.id, user.tenant_id, 50.0)                                                 # this month: at the cap
        with pytest.raises(SpendLimitReached):
            resolve(db, user, "anthropic")
        # Through HTTP: the chat path is refused and the provider is never contacted.
        with respx.mock(assert_all_called=False) as m:
            prov = m.post("https://api.anthropic.com/v1/messages").mock(return_value=httpx.Response(200, json={}))
            r = client.post("/api/chat/stream", json={"message": "hi", "provider": "anthropic"}, headers=h)
            assert '"code": "SPEND_LIMIT_REACHED"' in r.text, r.text
            assert not prov.called
            # Non-streaming paths (drafting, extraction, vision) get a 402 from the app handler.
            cid = client.post("/api/customers", json={"name": "Cap Test"}, headers=h).json()["id"]
            r = client.post("/api/commitments/extract", json={"customer_id": cid, "conversation_text": "Call me Friday please",
                                                             "provider": "anthropic"}, headers=h)
            assert r.status_code == 402 and r.json()["detail"]["code"] == "SPEND_LIMIT_REACHED", r.text
            assert not prov.called
        # A personal key still works for that consultant.
        assert client.put("/api/keys/mine", json={"provider": "anthropic", "api_key": "sk-ant-mine"}, headers=h).status_code in (200, 201)
        db.expire_all()
        assert resolve(db, user, "anthropic").key_scope == "byo"
        # Budget view.
        b = client.get("/api/usage/budget", headers=h).json()
        assert b["monthly_ai_budget_cents"] == 5000 and b["spent_this_month_cents"] == 5000 and b["capped"]
        db.close()
    finally:
        get_settings.cache_clear()


def test_only_an_owner_with_fresh_factor_changes_the_cap(client, frozen_clock):
    frozen_clock("2026-11-12T12:00:00+00:00")
    t, h = _owner(client)
    tag = uuid.uuid4().hex[:6]
    assert client.post("/api/auth/members", json={"email": f"ad-{tag}@example.com", "password": "superSecret123!",
                                                  "role": "admin"}, headers=h).status_code == 201
    from .conftest import login
    ah = auth_headers(login(client, f"ad-{tag}@example.com"))
    assert client.put("/api/usage/budget", json={"monthly_ai_budget_cents": 99999}, headers=ah).status_code == 403
    frozen_clock("2026-11-12T12:30:00+00:00")
    stale = client.put("/api/usage/budget", json={"monthly_ai_budget_cents": 99999}, headers=h)
    assert stale.status_code == 403 and stale.json()["detail"]["code"] == "STEP_UP_REQUIRED"
    from .conftest import step_up
    step_up(client, t)
    ok = client.put("/api/usage/budget", json={"monthly_ai_budget_cents": 12345}, headers=h)
    assert ok.status_code == 200 and ok.json()["monthly_ai_budget_cents"] == 12345
    assert client.put("/api/usage/budget", json={"monthly_ai_budget_cents": -1}, headers=h).status_code == 422
