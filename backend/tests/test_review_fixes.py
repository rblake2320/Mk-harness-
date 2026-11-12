"""Fixes from the PR #38 review.

* The raw kernel relay `/api/agent-ops/approvals/pending` returned every pending
  message in the tenant (exact text) to any role with customers.read; it is now
  book-scoped exactly like `/api/approvals/pending`, and tenant-level (unlinked)
  actions are visible to owners/admins only — on both routes.
* Tenants created before the owner role had only an `admin`; the migration
  promotes the earliest active admin so owner-only permissions stay reachable.
"""
import uuid

import httpx
import respx
from sqlalchemy import select

from app import db as dbmod
from app.models import ActionLink, AuditLog, Tenant, User
from app.tools.migrate import establish_owners

from .conftest import auth_headers, login, signup
from .test_agent_ops import KERNEL
from .test_foundation import kernel_env  # noqa: F401


def _pending_item(aid):
    return {"result": {"action_id": aid, "state": "approval_required", "message_state": "awaiting_approval",
                       "action_digest": "sha256:" + "a" * 64},
            "display": {"rendered_text": f"text for {aid}", "destination_redacted": "****0100", "channel": "sms",
                        "purpose": "p", "workflow": "w", "risk": "high", "evidence_count": 1,
                        "expires_at": "2026-12-01T00:00:00Z", "action_digest": "sha256:" + "a" * 64}}


def test_pending_relay_is_book_scoped(client, kernel_env):  # noqa: F811
    tag = uuid.uuid4().hex[:6]
    owner = auth_headers(signup(client, org=f"Org {tag}", email=f"o-{tag}@example.com"))
    for who, role, extra in (("a", "consultant", {}), ("b", "consultant", {})):
        assert client.post("/api/auth/members", json={"email": f"{who}-{tag}@example.com", "password": "superSecret123!",
                                                      "role": role, **extra}, headers=owner).status_code == 201
    a = auth_headers(login(client, f"a-{tag}@example.com"))
    b = auth_headers(login(client, f"b-{tag}@example.com"))
    a_id = client.get("/api/auth/me", headers=a).json()["id"]
    assert client.post("/api/auth/members", json={"email": f"s-{tag}@example.com", "password": "superSecret123!",
                                                  "role": "assistant", "works_for": a_id}, headers=owner).status_code == 201
    asst = auth_headers(login(client, f"s-{tag}@example.com"))
    ca = client.post("/api/customers", json={"name": "A's customer"}, headers=a).json()["id"]
    cb = client.post("/api/customers", json={"name": "B's customer"}, headers=b).json()["id"]
    aid_a, aid_b, aid_free = (str(uuid.uuid4()) for _ in range(3))
    db = dbmod._SessionLocal()
    tid = db.get(User, a_id).tenant_id
    db.add_all([ActionLink(tenant_id=tid, customer_id=ca, kernel_action_id=aid_a, action_digest="sha256:" + "a" * 64),
                ActionLink(tenant_id=tid, customer_id=cb, kernel_action_id=aid_b, action_digest="sha256:" + "a" * 64)])
    db.commit(); db.close()
    body = [_pending_item(x) for x in (aid_a, aid_b, aid_free)]
    seen = {}
    with respx.mock(assert_all_called=False) as m:
        m.get(f"{KERNEL}/internal/v1/approvals/pending").mock(return_value=httpx.Response(200, json=body))
        m.get(f"{KERNEL}/internal/v1/senders").mock(return_value=httpx.Response(200, json=[]))
        for name, h in (("owner", owner), ("a", a), ("b", b), ("asst", asst)):
            raw = client.get("/api/agent-ops/approvals/pending", headers=h)
            app = client.get("/api/approvals/pending", headers=h)
            assert raw.status_code == 200 and app.status_code == 200, (name, raw.text, app.text)
            seen[name] = ({i["result"]["action_id"] for i in raw.json()}, {i["action_id"] for i in app.json()})
    assert seen["owner"] == ({aid_a, aid_b, aid_free}, {aid_a, aid_b, aid_free})
    assert seen["a"] == ({aid_a}, {aid_a})
    assert seen["b"] == ({aid_b}, {aid_b})
    assert seen["asst"] == ({aid_a}, {aid_a})     # the book the assistant works in, nothing else


def test_founding_admin_becomes_owner_once():
    eng = dbmod._engine
    db = dbmod._SessionLocal()
    t_legacy, t_owned, t_noadmin = Tenant(name="Legacy"), Tenant(name="Owned"), Tenant(name="NoAdmin")
    db.add_all([t_legacy, t_owned, t_noadmin]); db.flush()
    first = User(tenant_id=t_legacy.id, email=f"f-{uuid.uuid4().hex[:6]}@x.com", password_hash="x", role="admin")
    db.add(first); db.flush()
    second = User(tenant_id=t_legacy.id, email=f"s-{uuid.uuid4().hex[:6]}@x.com", password_hash="x", role="admin")
    owner = User(tenant_id=t_owned.id, email=f"o-{uuid.uuid4().hex[:6]}@x.com", password_hash="x", role="owner")
    admin2 = User(tenant_id=t_owned.id, email=f"a-{uuid.uuid4().hex[:6]}@x.com", password_hash="x", role="admin")
    cons = User(tenant_id=t_noadmin.id, email=f"c-{uuid.uuid4().hex[:6]}@x.com", password_hash="x", role="consultant")
    db.add_all([second, owner, admin2, cons]); db.commit()
    ids = (first.id, second.id, admin2.id, cons.id, t_legacy.id)
    db.close()
    assert establish_owners(eng) >= 1
    assert establish_owners(eng) == 0                     # idempotent
    db = dbmod._SessionLocal()
    roles = [db.get(User, i).role for i in ids[:4]]
    assert roles == ["owner", "admin", "admin", "consultant"]
    assert db.scalar(select(AuditLog).where(AuditLog.tenant_id == ids[4], AuditLog.action == "role.migrated_owner"))
    db.close()
