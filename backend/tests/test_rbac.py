"""S3 RBAC, F7/S11 search isolation, S9 break-glass.

* every /api route has exactly one policy (default deny; no stale entries);
* the role matrix holds at the HTTP layer AND the kernel never receives an
  approver role for a non-approving principal;
* assistants/viewers work inside one consultant's book only;
* member administration cannot strand a business without an owner;
* break-glass is tenant-approved, time-boxed, read-only, audited and never
  impersonates; search never crosses books or tenants."""
import base64
import json
import uuid

import httpx
import jwt as pyjwt
import pytest
import respx

from app import identity
from app.config import get_settings
from app.main import app
from app.rbac import BREAKGLASS_READ, ROLE_PERMISSIONS, ROUTE_POLICY
from tests.conftest import auth_headers, login, signup

PW = "superSecret123!"
KERNEL = "http://kernel.test:8090"


def _email(p="r"):
    return f"{p}{uuid.uuid4().hex[:10]}@example.com"


def _member(client, owner_h, role, works_for=None):
    email = _email(role[:2])
    body = {"email": email, "password": PW, "role": role}
    if works_for:
        body["works_for"] = works_for
    r = client.post("/api/auth/members", json=body, headers=owner_h)
    assert r.status_code == 201, r.text
    return r.json()["id"], auth_headers(login(client, email))


def _me(client, h):
    return client.get("/api/auth/me", headers=h).json()


# --------------------------------------------------------------------------- policy table
def _api_routes():
    out = set()
    for r in app.routes:
        path = getattr(r, "path", "")
        if path.startswith("/api/") and path not in ("/api/health", "/api/health/ready"):
            for m in getattr(r, "methods", set()) - {"HEAD", "OPTIONS"}:
                out.add((m, path))
    return out


def test_every_api_route_has_a_policy_and_no_policy_is_stale():
    routes = _api_routes()
    missing = sorted(routes - set(ROUTE_POLICY))
    stale = sorted(set(ROUTE_POLICY) - routes)
    assert not missing, f"routes without a policy (would be denied): {missing}"
    assert not stale, f"policies for routes that do not exist: {stale}"


def test_public_routes_are_exactly_the_sign_in_and_signed_webhook_set():
    public = sorted(k for k, p in ROUTE_POLICY.items() if p.public)
    assert public == sorted([
        ("POST", "/api/auth/signup"), ("POST", "/api/auth/login"), ("POST", "/api/auth/refresh"),
        ("POST", "/api/auth/mfa/verify"), ("POST", "/api/auth/mfa/passkey/options"),
        ("GET", "/api/billing/plans"), ("POST", "/api/billing/webhook"),
    ])


def test_breakglass_scope_is_read_only_and_never_reaches_the_kernel_or_exports():
    for method, path in BREAKGLASS_READ:
        assert method == "GET" and "/agent-ops/" not in path and "export" not in path and path != "/api/brief"


def test_unknown_route_is_denied_by_default(client):
    from fastapi import APIRouter, Depends

    from app.rbac import route_guard
    r = APIRouter()

    @r.get("/zz-test-unlisted")
    def _unlisted():
        return {"leak": True}

    app.include_router(r, prefix="/api", dependencies=[Depends(route_guard)])
    try:
        t = signup(client, email=_email())
        resp = client.get("/api/zz-test-unlisted", headers=auth_headers(t))
        assert resp.status_code == 403 and resp.json()["detail"]["code"] == "ROUTE_NOT_AUTHORIZED"
    finally:
        app.router.routes[:] = [x for x in app.router.routes if getattr(x, "path", "") != "/api/zz-test-unlisted"]


def test_role_matrix_shape():
    assert ROLE_PERMISSIONS["owner"] > ROLE_PERMISSIONS["admin"] > ROLE_PERMISSIONS["consultant"]
    for perm in ("actions.approve", "consent.write", "exports.customers", "exports.audit", "members.manage",
                 "settings.security", "suppression.lift"):
        assert perm not in ROLE_PERMISSIONS["assistant"] and perm not in ROLE_PERMISSIONS["viewer"], perm
    assert {"consent.revoke", "suppression.add", "stop.dispatch"} <= ROLE_PERMISSIONS["assistant"]  # stopping is easy
    assert all(p.endswith(".read") for p in ROLE_PERMISSIONS["viewer"])


# --------------------------------------------------------------------------- HTTP enforcement
@pytest.mark.parametrize("role,method,path,body,expected", [
    ("assistant", "GET", "/api/customers/export.csv", None, 403),
    ("assistant", "POST", "/api/customers/{cid}/consent", {"channel": "sms", "purpose": "customer_requested_follow_up",
                                                            "evidence_source": "verbal", "evidence_text": "x"}, 403),
    ("assistant", "GET", "/api/audit/export.jsonl", None, 403),
    ("assistant", "POST", "/api/auth/members", {"email": "x@example.com", "password": PW}, 403),
    ("assistant", "POST", "/api/agent-ops/actions/{uuid}/approve", {"action_digest": "sha256:" + "0" * 64}, 403),
    ("viewer", "POST", "/api/customers", {"name": "New"}, 403),
    ("viewer", "POST", "/api/suppressions", {"channel": "sms", "destination": "+15555550000", "reason": "x"}, 403),
    ("viewer", "POST", "/api/drafts", {"customer_id": "x"}, 403),
    ("consultant", "POST", "/api/auth/members", {"email": "x@example.com", "password": PW}, 403),
    ("consultant", "PUT", "/api/keys/tenant", {"provider": "anthropic", "api_key": "k"}, 403),
    ("consultant", "GET", "/api/security/members", None, 403),
    ("admin", "POST", "/api/billing/checkout", {"tier": "solo", "interval": "month"}, 403),
])
def test_forbidden_combinations_are_refused_before_any_handler(client, role, method, path, body, expected):
    owner = signup(client, email=_email())
    oh = auth_headers(owner)
    cid = client.post("/api/customers", json={"name": "Angela"}, headers=oh).json()["id"]
    works_for = owner["session_id"] and _me(client, oh)["id"] if role in ("assistant", "viewer") else None
    _, h = _member(client, oh, role, works_for)
    p = path.replace("{cid}", cid).replace("{uuid}", str(uuid.uuid4()))
    r = client.request(method, p, json=body, headers=h)
    assert r.status_code == expected, (role, path, r.text)
    if expected == 403:
        assert r.json()["detail"]["code"] == "PERMISSION_DENIED"


def test_assistant_works_in_one_book_proposes_as_agent_and_cannot_approve(client, monkeypatch):
    from app.kernel.assertions import AssertionMinter
    from app.kernel.client import get_kernel_client
    m = AssertionMinter.generate("k-test")
    monkeypatch.setenv("RUST_ACTION_KERNEL_URL", KERNEL)
    monkeypatch.setenv("KERNEL_ASSERTION_PRIVATE_KEY",
                       base64.urlsafe_b64encode(m._key.private_bytes_raw()).rstrip(b"=").decode())
    monkeypatch.setenv("KERNEL_ASSERTION_KID", "k-test")
    get_settings.cache_clear(); get_kernel_client.cache_clear()
    try:
        owner = signup(client, email=_email())
        oh = auth_headers(owner)
        owner_id = _me(client, oh)["id"]
        mine = client.post("/api/customers", json={"name": "Owner's Angela"}, headers=oh).json()["id"]
        cons_id, ch = _member(client, oh, "consultant")
        theirs = client.post("/api/customers", json={"name": "Consultant's Bea"}, headers=ch).json()["id"]
        _, ah = _member(client, oh, "assistant", owner_id)
        # Sees exactly the owner's book.
        names = [c["name"] for c in client.get("/api/customers", headers=ah).json()]
        assert names == ["Owner's Angela"]
        assert client.get(f"/api/customers/{theirs}", headers=ah).status_code == 404
        # Creates into the owner's book.
        new = client.post("/api/customers", json={"name": "Assistant-added Cara"}, headers=ah).json()["id"]
        assert any(c["id"] == new for c in client.get("/api/customers", headers=oh).json())
        assert client.get(f"/api/customers/{mine}", headers=ah).status_code == 200
        # Kernel sees a non-approving principal with agent origin.
        with respx.mock(assert_all_called=False) as rm:
            calls = []

            def cap(req):
                tok = pyjwt.decode(req.headers["authorization"][7:], options={"verify_signature": False},
                                   algorithms=["EdDSA"])
                calls.append((tok["roles"], json.loads(req.content or b"{}")))
                return httpx.Response(201, json={"action_id": str(uuid.uuid4()), "state": "awaiting_approval"})
            rm.post(f"{KERNEL}/internal/v1/actions").mock(side_effect=cap)
            r = client.post("/api/agent-ops/actions", json={"origin": "human", "request": {
                "workflow": "customer_follow_up", "action_kind": "create_appointment", "tool_id": "calendar.create.v1",
                "resource": {"type": "contact", "id": str(uuid.uuid4())}, "arguments": {"title": "Facial"},
                "purpose": "customer_requested_follow_up", "risk": "low",
                "requested_at": "2026-11-12T12:00:00Z", "expires_at": "2026-11-12T12:30:00Z",
                "idempotency_key": "k-" + uuid.uuid4().hex, "evidence": []}}, headers=ah)
            assert calls, r.text
            roles, body = calls[0]
            assert roles == ["agent"] and body["origin"]["type"] == "agent"
            approve = rm.post(url__regex=rf"{KERNEL}/internal/v1/actions/.*/approve")
            r = client.post(f"/api/agent-ops/actions/{uuid.uuid4()}/approve",
                            json={"action_digest": "sha256:" + "0" * 64}, headers=ah)
            assert r.status_code == 403 and not approve.called
        assert cons_id
    finally:
        get_settings.cache_clear(); get_kernel_client.cache_clear()


def test_member_administration_rules(client):
    owner = signup(client, email=_email())
    oh = auth_headers(owner)
    owner_id = _me(client, oh)["id"]
    admin_id, adh = _member(client, oh, "admin")
    # assistant/viewer must name an active consultant-capable member of THIS tenant
    for bad in (None, uuid.uuid4().hex):
        body = {"email": _email(), "password": PW, "role": "assistant"}
        if bad:
            body["works_for"] = bad
        assert client.post("/api/auth/members", json=body, headers=oh).status_code == 422
    other_owner = signup(client, email=_email())
    foreign_id = _me(client, auth_headers(other_owner))["id"]
    r = client.post("/api/auth/members", json={"email": _email(), "password": PW, "role": "assistant",
                                               "works_for": foreign_id}, headers=oh)
    assert r.status_code == 422
    # only an owner grants admin/owner
    r = client.post("/api/auth/members", json={"email": _email(), "password": PW, "role": "admin"}, headers=adh)
    assert r.status_code == 403 and r.json()["detail"]["code"] == "OWNER_REQUIRED"
    # an admin cannot demote or deactivate the owner; nobody can remove the last owner
    assert client.post(f"/api/security/members/{owner_id}/role", json={"role": "consultant"}, headers=adh).status_code == 403
    assert client.post(f"/api/security/members/{owner_id}/deactivate", headers=adh).status_code == 403
    last = client.post(f"/api/security/members/{owner_id}/role", json={"role": "admin"}, headers=oh)
    assert last.status_code == 409 and last.json()["detail"]["code"] == "LAST_OWNER"
    assert client.post(f"/api/security/members/{owner_id}/deactivate", headers=oh).json()["detail"]["code"] == "SELF_DEACTIVATION"
    # a role change takes effect immediately: the member's sessions end
    cons_id, ch = _member(client, oh, "consultant")
    r = client.post(f"/api/security/members/{cons_id}/role", json={"role": "viewer", "works_for": owner_id}, headers=oh)
    assert r.status_code == 200 and r.json()["sessions_revoked"] >= 1
    assert client.get("/api/auth/me", headers=ch).status_code == 401
    # deactivation ends sessions and blocks sign-in
    v_id, vh = _member(client, oh, "consultant")
    assert client.post(f"/api/security/members/{v_id}/deactivate", headers=oh).status_code == 200
    assert client.get("/api/auth/me", headers=vh).status_code == 401
    # cross-tenant member ids are invisible
    assert client.post(f"/api/security/members/{foreign_id}/deactivate", headers=oh).status_code == 404
    assert admin_id


def test_step_up_marked_routes_refuse_a_fresh_password_only_session(client):
    email = _email()
    t = client.post("/api/auth/signup", json={"org_name": "Org", "email": email, "password": PW}).json()
    h = auth_headers(t)
    for method, path in [("GET", "/api/customers/export.csv"), ("GET", "/api/audit/export.jsonl"),
                         ("GET", "/api/account/export")]:
        r = client.request(method, path, headers=h)
        assert r.status_code == 403 and r.json()["detail"]["code"] == "STEP_UP_REQUIRED", path


# --------------------------------------------------------------------------- search (F7 / S11)
def test_search_never_crosses_books_or_tenants_and_treats_wildcards_literally(client):
    a = auth_headers(signup(client, email=_email()))
    b = auth_headers(signup(client, email=_email()))
    from tests.test_foundation import _customer
    ca, _, _ = _customer(client, a, name="Angela Smith", phone="+15555557701")
    _customer(client, b, name="Angela Smith", phone="+15555557701")   # same name + number in tenant B
    cons_id, ch = _member(client, a, "consultant")
    _customer(client, ch, name="Angela Jones", phone="+15555557702")   # same tenant, other book
    hits = client.get("/api/customers/search", params={"q": "angela"}, headers=a).json()
    assert [h["id"] for h in hits] == [ca]
    by_phone = client.get("/api/customers/search", params={"q": "(555) 555-7701"}, headers=a).json()
    assert [h["id"] for h in by_phone] == [ca]
    assert client.get("/api/customers/search", params={"q": "555-7702"}, headers=a).json() == []
    for q in ("%%", "__", "%_%", "\\%"):
        assert client.get("/api/customers/search", params={"q": q}, headers=a).json() == [], q
    assert client.get("/api/customers/search", params={"q": "a"}, headers=a).status_code == 422
    assert client.get("/api/customers/search", params={"q": "angela"}).status_code == 401


def test_touch_route_records_contact(client):
    h = auth_headers(signup(client, email=_email()))
    cid = client.post("/api/customers", json={"name": "Dee"}, headers=h).json()["id"]
    assert client.post(f"/api/customers/{cid}/touch", headers=h).status_code == 200
    assert client.get(f"/api/customers/{cid}", headers=h).json()["last_contact"]


# --------------------------------------------------------------------------- break-glass (S9)
@pytest.fixture
def support(client, monkeypatch):
    """Factory: a platform support user (own org) with a TOTP factor and an MFA-verified
    session. A factory so tests can freeze the clock first (step-up is time-bound)."""
    made = []

    def make():
        made.append(_make_support(client, monkeypatch))
        return made[-1]
    yield make
    get_settings.cache_clear()


def _make_support(client, monkeypatch):
    t = signup(client, org="Platform Support", email=_email("sup"))
    h = auth_headers(t)
    me = _me(client, h)
    monkeypatch.setenv("PLATFORM_SUPPORT_USERS", f"someone-else,{me['id']}")
    get_settings.cache_clear()
    b = client.post("/api/security/mfa/totp/begin", headers=h).json()
    from app import foundation
    code = identity.totp_code(identity._unb32(b["secret"]), identity.totp_step(foundation.utcnow()))
    assert client.post("/api/security/mfa/totp/confirm", json={"factor_id": b["factor_id"], "code": code},
                       headers=h).status_code == 200
    _SECRETS[me["id"]] = b["secret"]
    return me["id"], h


_SECRETS: dict[str, str] = {}


def _totp_step_up(client, uid, h):
    from app import foundation
    code = identity.totp_code(identity._unb32(_SECRETS[uid]), identity.totp_step(foundation.utcnow()))
    r = client.post("/api/security/step-up", json={"method": "totp", "code": code}, headers=h)
    assert r.status_code == 200, r.text


def _target(client):
    owner = signup(client, email=_email("tgt"))
    oh = auth_headers(owner)
    me = _me(client, oh)
    from tests.test_foundation import _customer
    cid, _, _ = _customer(client, oh, name="Private Customer", phone="+15555558801")
    return me["tenant"]["id"], me["id"], oh, cid


def test_breakglass_lifecycle_is_approved_time_boxed_read_only_and_audited(client, support):
    sup_id, sh = support()
    tid, owner_id, oh, cid = _target(client)
    req = client.post("/api/support/break-glass", json={"tenant_id": tid, "subject_user_id": owner_id,
                                                        "reason": "Customer reports missing brief items since Monday",
                                                        "ticket_ref": "SUP-1234", "duration_minutes": 30}, headers=sh)
    assert req.status_code == 201, req.text
    gid = req.json()["id"]
    # No access before approval.
    assert client.post(f"/api/support/break-glass/{gid}/session", headers=sh).json()["detail"]["code"] == "NOT_APPROVED"
    # The tenant sees the request and approves it (owner, step-up satisfied by signup helper).
    assert any(g["id"] == gid and g["status"] == "pending" for g in client.get("/api/security/break-glass", headers=oh).json())
    assert client.post(f"/api/security/break-glass/{gid}/approve", headers=oh).status_code == 200
    s = client.post(f"/api/support/break-glass/{gid}/session", headers=sh)
    assert s.status_code == 200, s.text
    bg = auth_headers(s.json())
    assert s.json()["refresh_token"] == ""
    # Reads the subject's book; identity stays support's own.
    me = client.get("/api/auth/me", headers=bg).json()
    assert me["id"] == sup_id and me["role"] == "support" and me["breakglass"]["grant_id"] == gid
    assert [c["id"] for c in client.get("/api/customers", headers=bg).json()] == [cid]
    assert client.get(f"/api/customers/{cid}/timeline", headers=bg).status_code == 200
    # Everything else is refused — writes, exports, kernel relay, brief materialization.
    for method, path, body in [("POST", "/api/customers", {"name": "x"}), ("PUT", f"/api/customers/{cid}", {"name": "x"}),
                               ("GET", "/api/customers/export.csv", None), ("GET", "/api/agent-ops/approvals/pending", None),
                               ("GET", "/api/brief", None), ("POST", "/api/security/step-up", {"method": "password"}),
                               ("GET", "/api/audit/export.jsonl", None)]:
        r = client.request(method, path, json=body, headers=bg)
        assert r.status_code == 403 and r.json()["detail"]["code"] == "BREAKGLASS_READ_ONLY", (path, r.text)
    # The tenant's audit trail shows every access and every refused attempt.
    from sqlalchemy import select

    from app import db as dbmod
    from app.models import AuditLog
    with dbmod._SessionLocal() as db:
        acts = [a.action for a in db.scalars(select(AuditLog).where(AuditLog.tenant_id == tid))]
    assert acts.count("breakglass.denied") == 7 and acts.count("breakglass.access") >= 3
    assert {"breakglass.requested", "breakglass.approved", "breakglass.session"} <= set(acts)
    # Revocation ends access immediately.
    assert client.post(f"/api/security/break-glass/{gid}/revoke", headers=oh).status_code == 200
    assert client.get("/api/customers", headers=bg).status_code == 401


def test_breakglass_expires_and_is_refused_in_every_other_way(client, support, frozen_clock):
    frozen_clock("2026-11-12T09:00:00+00:00")
    sup_id, sh = support()
    tid, owner_id, oh, cid = _target(client)
    body = {"tenant_id": tid, "subject_user_id": owner_id, "reason": "Investigating a failed import for this tenant",
            "ticket_ref": "SUP-77", "duration_minutes": 15}
    # validation
    assert client.post("/api/support/break-glass", json={**body, "reason": "too short"}, headers=sh).status_code == 422
    assert client.post("/api/support/break-glass", json={**body, "duration_minutes": 241}, headers=sh).status_code == 422
    assert client.post("/api/support/break-glass", json={**body, "ticket_ref": "x y"}, headers=sh).status_code == 422
    assert client.post("/api/support/break-glass", json={**body, "subject_user_id": sup_id}, headers=sh).status_code == 404
    # non-support users cannot request
    assert client.post("/api/support/break-glass", json=body, headers=oh).json()["detail"]["code"] == "SUPPORT_ONLY"
    gid = client.post("/api/support/break-glass", json=body, headers=sh).json()["id"]
    # a consultant of the tenant cannot approve; another tenant cannot see it
    _, ch = _member(client, oh, "consultant")
    assert client.post(f"/api/security/break-glass/{gid}/approve", headers=ch).status_code == 403
    other = auth_headers(signup(client, email=_email()))
    assert client.post(f"/api/security/break-glass/{gid}/approve", headers=other).status_code == 404
    # denied stays denied
    g2 = client.post("/api/support/break-glass", json=body, headers=sh).json()["id"]
    assert client.post(f"/api/security/break-glass/{g2}/deny", headers=oh).status_code == 200
    assert client.post(f"/api/security/break-glass/{g2}/approve", headers=oh).status_code == 409
    assert client.post(f"/api/support/break-glass/{g2}/session", headers=sh).status_code == 409
    # approve → session → expiry ends it, and no new session can be minted
    assert client.post(f"/api/security/break-glass/{gid}/approve", headers=oh).status_code == 200
    bg = auth_headers(client.post(f"/api/support/break-glass/{gid}/session", headers=sh).json())
    assert client.get("/api/customers", headers=bg).status_code == 200
    frozen_clock("2026-11-12T09:16:00+00:00")
    assert client.get("/api/customers", headers=bg).status_code == 401
    _totp_step_up(client, sup_id, sh)   # even with a fresh second factor, an expired grant mints nothing
    r = client.post(f"/api/support/break-glass/{gid}/session", headers=sh)
    assert r.status_code == 409 and r.json()["detail"]["code"] == "NOT_APPROVED"
    # support cannot read another tenant with this grant's session (tid is pinned)
    assert client.get("/api/customers", headers=bg).status_code == 401
    # removing the user from the support list ends access even within the window
    frozen_clock("2026-11-12T10:00:00+00:00")
    _totp_step_up(client, sup_id, sh)
    assert client.post("/api/security/step-up", json={"method": "password", "password": PW}, headers=oh).status_code == 200
    g3 = client.post("/api/support/break-glass", json=body, headers=sh).json()["id"]
    assert client.post(f"/api/security/break-glass/{g3}/approve", headers=oh).status_code == 200
    bg3 = auth_headers(client.post(f"/api/support/break-glass/{g3}/session", headers=sh).json())
    assert client.get("/api/customers", headers=bg3).status_code == 200
    import os
    os.environ["PLATFORM_SUPPORT_USERS"] = "someone-else"
    get_settings.cache_clear()
    assert client.get("/api/customers", headers=bg3).status_code == 401


def test_breakglass_session_requires_a_second_factor_sign_in(client, monkeypatch):
    t = signup(client, org="Support Two", email=_email("sup"))
    h = auth_headers(t)
    me = _me(client, h)
    monkeypatch.setenv("PLATFORM_SUPPORT_USERS", me["id"])
    get_settings.cache_clear()
    try:
        tid, owner_id, oh, _ = _target(client)
        gid = client.post("/api/support/break-glass", json={
            "tenant_id": tid, "subject_user_id": owner_id, "reason": "Password-only support session attempt",
            "ticket_ref": "SUP-9", "duration_minutes": 10}, headers=h).json()["id"]
        client.post(f"/api/security/break-glass/{gid}/approve", headers=oh)
        r = client.post(f"/api/support/break-glass/{gid}/session", headers=h)
        assert r.status_code == 403 and r.json()["detail"]["code"] == "MFA_REQUIRED"
    finally:
        get_settings.cache_clear()
