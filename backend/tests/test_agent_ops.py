"""/api/agent-ops — the FastAPI → Rust kernel boundary.

What this suite proves (kernel mocked with respx, *assertions verified for real*
with the Ed25519 public key, so a wrong wire format fails here, not in prod):

  fault barrier   kernel not configured → 503 and no outbound call
                  kernel unreachable (connect error / timeout) → 503, writes never retried
  auth            every route 401 without a bearer token
  tenant binding  assertion tenant_id/sub come from the JWT, never from the body;
                  a user in tenant B asking for tenant A's action gets the kernel's 404
  role mapping    consultant → [user]; admin → [user, tenant_admin];
                  origin=agent → [agent] only; approvals never minted as agent
  operator gate   global kill switch 403 unless user id is in KERNEL_PLATFORM_OPERATORS,
                  and only then carries platform_operator
  pass-through    kernel 403/409/422/204 bodies and statuses come back unchanged
  hygiene         forbidden argument keys rejected before any call; invalid ids → 422;
                  jti unique per request; assertion lifetime ≤ 60 s; typ/alg exact
"""
import base64
import json
import os
import uuid

import httpx
import pytest
import respx
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

from app.config import get_settings
from app.kernel import get_kernel_client
from app.kernel.assertions import AssertionMinter, roles_for

from .conftest import auth_headers, signup

KERNEL = "http://kernel.test:8090"
MINTER = AssertionMinter.generate("k-test")


def _b64d(s: str) -> bytes:
    return base64.urlsafe_b64decode(s + "=" * (-len(s) % 4))


def verify_assertion(request: httpx.Request) -> dict:
    """Verify exactly as the kernel does: signature over transmitted bytes first."""
    auth = request.headers["authorization"]
    assert auth.startswith("Bearer ")
    h, p, s = auth[7:].split(".")
    pub = Ed25519PublicKey.from_public_bytes(_b64d(MINTER.public_key_b64url()))
    pub.verify(_b64d(s), f"{h}.{p}".encode())
    header = json.loads(_b64d(h))
    assert header == {"alg": "EdDSA", "typ": "mk-assertion+v1", "kid": "k-test"}
    claims = json.loads(_b64d(p))
    assert set(claims) == {"iss", "aud", "sub", "tenant_id", "roles", "session_id",
                           "request_id", "iat", "exp", "jti"}
    assert claims["iss"] == "mk-fastapi" and claims["aud"] == "mk-action-kernel"
    assert 0 < claims["exp"] - claims["iat"] <= 60
    uuid.UUID(claims["sub"]); uuid.UUID(claims["tenant_id"]); uuid.UUID(claims["jti"])
    assert claims["roles"]
    assert request.headers["x-request-id"] == claims["request_id"]
    return claims


@pytest.fixture
def kernel_env(monkeypatch):
    monkeypatch.setenv("RUST_ACTION_KERNEL_URL", KERNEL)
    # Export the test minter's seed so the app builds an identical signer.
    seed = MINTER._key.private_bytes_raw()
    monkeypatch.setenv("KERNEL_ASSERTION_PRIVATE_KEY",
                       base64.urlsafe_b64encode(seed).rstrip(b"=").decode())
    monkeypatch.setenv("KERNEL_ASSERTION_KID", "k-test")
    get_settings.cache_clear(); get_kernel_client.cache_clear()
    yield
    get_settings.cache_clear(); get_kernel_client.cache_clear()


@pytest.fixture
def no_kernel_env(monkeypatch):
    for k in ("RUST_ACTION_KERNEL_URL", "KERNEL_ASSERTION_PRIVATE_KEY"):
        monkeypatch.delenv(k, raising=False)
    get_settings.cache_clear(); get_kernel_client.cache_clear()
    yield
    get_settings.cache_clear(); get_kernel_client.cache_clear()


def _signup(client, n: str, admin_only=False):
    t = signup(client, org=f"Org {n}", email=f"admin-{n}@example.com")
    return t


def sms_request(contact_hex: str) -> dict:
    return {
        "workflow": "customer_follow_up", "action_kind": "send_sms",
        "tool_id": "mobile.sms.send.v1",
        "resource": {"type": "contact", "id": str(uuid.UUID(contact_hex))},
        "arguments": {"contact_id": str(uuid.UUID(contact_hex)), "to": "+15555550100",
                      "template_id": "reorder_followup.v1",
                      "rendered_text": "Hi! Reply STOP to opt out."},
        "purpose": "customer_requested_follow_up", "risk": "high",
        "requested_at": "2026-10-20T12:00:00Z", "expires_at": "2026-10-20T12:30:00Z",
        "idempotency_key": f"t:{uuid.uuid4().hex}",
        "evidence": [], "tenant_id": "ignored", "requested_by": "ignored",
    }


# --------------------------------------------------------------------------- #
# Fault barrier: no kernel → 503, no fallback, no outbound call
# --------------------------------------------------------------------------- #
ALL_WRITE_ROUTES = [
    ("POST", "/api/agent-ops/actions", {"origin": "human", "request": sms_request(uuid.uuid4().hex)}),
    ("POST", f"/api/agent-ops/actions/{uuid.uuid4()}/cancel", None),
    ("POST", f"/api/agent-ops/actions/{uuid.uuid4()}/approve",
     {"action_digest": "sha256:" + "a" * 64}),
    ("POST", "/api/agent-ops/suppressions",
     {"channel": "sms", "destination": "+15555550100", "reason": "stop", "source": "sms_reply"}),
    ("POST", "/api/agent-ops/kill-switch/tenant", {"dispatch_enabled": False}),
]


@pytest.mark.parametrize("method,path,body", ALL_WRITE_ROUTES)
def test_not_configured_returns_503_and_never_executes(client, no_kernel_env, method, path, body):
    tok = _signup(client, uuid.uuid4().hex[:6])
    with respx.mock(assert_all_called=False) as m:
        route = m.route(host="kernel.test")
        r = client.request(method, path, json=body, headers=auth_headers(tok))
    assert r.status_code == 503, r.text
    assert r.json()["code"] == "KERNEL_NOT_CONFIGURED"
    assert not route.called


@pytest.mark.parametrize("exc", [httpx.ConnectError("refused"), httpx.ReadTimeout("slow")])
def test_unreachable_kernel_is_503_and_writes_are_not_retried(client, kernel_env, exc):
    tok = _signup(client, uuid.uuid4().hex[:6])
    with respx.mock() as m:
        route = m.post(f"{KERNEL}/internal/v1/actions").mock(side_effect=exc)
        r = client.post("/api/agent-ops/actions",
                        json={"origin": "human", "request": sms_request(uuid.uuid4().hex)},
                        headers=auth_headers(tok))
    assert r.status_code == 503
    assert r.json()["code"] == "KERNEL_UNREACHABLE"
    assert route.call_count == 1  # one jti, one attempt — never a blind retry


def test_get_retries_once_on_transport_failure(client, kernel_env):
    tok = _signup(client, uuid.uuid4().hex[:6])
    aid = uuid.uuid4()
    with respx.mock() as m:
        route = m.get(f"{KERNEL}/internal/v1/actions/{aid}").mock(
            side_effect=[httpx.ConnectError("blip"), httpx.Response(200, json={"ok": 1})])
        r = client.get(f"/api/agent-ops/actions/{aid}", headers=auth_headers(tok))
    assert r.status_code == 200 and route.call_count == 2


def test_health_requires_live_kernel(client, kernel_env):
    tok = _signup(client, uuid.uuid4().hex[:6])
    with respx.mock() as m:
        m.get(f"{KERNEL}/health/ready").mock(return_value=httpx.Response(503, json={"db": "down"}))
        r = client.get("/api/agent-ops/health", headers=auth_headers(tok))
    assert r.status_code == 503 and r.json()["kernel_status"] == 503


def test_app_readiness_reflects_kernel_and_needs_no_token(client, kernel_env):
    with respx.mock() as m:
        m.get(f"{KERNEL}/health/ready").mock(return_value=httpx.Response(200, json={"ok": 1}))
        r = client.get("/api/health/ready")
    assert r.status_code == 200 and r.json()["checks"] == {"database": "ok", "kernel": "ok"}
    with respx.mock() as m:
        m.get(f"{KERNEL}/health/ready").mock(return_value=httpx.Response(503, json={"db": "down"}))
        r = client.get("/api/health/ready")
    assert r.status_code == 503 and r.json()["checks"]["kernel"] == "not_ready"
    with respx.mock() as m:
        m.get(f"{KERNEL}/health/ready").mock(side_effect=httpx.ConnectError("down"))
        r = client.get("/api/health/ready")
    assert r.status_code == 503 and r.json()["checks"]["kernel"] == "unavailable"
    # Liveness stays independent of the kernel.
    assert client.get("/api/health").status_code == 200


# --------------------------------------------------------------------------- #
# Auth: 401 on every route without a token
# --------------------------------------------------------------------------- #
@pytest.mark.parametrize("method,path", [
    ("GET", "/api/agent-ops/health"),
    ("POST", "/api/agent-ops/actions"),
    ("GET", f"/api/agent-ops/actions/{uuid.uuid4()}"),
    ("POST", f"/api/agent-ops/actions/{uuid.uuid4()}/approve"),
    ("GET", "/api/agent-ops/approvals/pending"),
    ("POST", "/api/agent-ops/suppressions"),
    ("POST", "/api/agent-ops/adapters"),
    ("POST", "/api/agent-ops/kill-switch/tenant"),
    ("POST", "/api/agent-ops/kill-switch/global"),
])
def test_401_without_token(client, kernel_env, method, path):
    with respx.mock(assert_all_called=False) as m:
        route = m.route(host="kernel.test")
        r = client.request(method, path, json={})
    assert r.status_code == 401
    assert not route.called


# --------------------------------------------------------------------------- #
# Identity binding + cross-tenant isolation
# --------------------------------------------------------------------------- #
def test_identity_is_bound_from_jwt_not_body(client, kernel_env):
    tok = _signup(client, uuid.uuid4().hex[:6])
    import jwt as pyjwt
    me_id = pyjwt.decode(tok["access_token"], options={"verify_signature": False})["sub"]
    seen = {}

    def handler(request: httpx.Request):
        seen["claims"] = verify_assertion(request)
        seen["body"] = json.loads(request.content)
        return httpx.Response(201, json={"result": {"state": "approval_required"}})

    with respx.mock() as m:
        m.post(f"{KERNEL}/internal/v1/actions").mock(side_effect=handler)
        req = sms_request(uuid.uuid4().hex)
        req["tenant_id"] = str(uuid.uuid4())      # attacker-supplied
        req["requested_by"] = str(uuid.uuid4())   # attacker-supplied
        req["action_id"] = str(uuid.uuid4())      # client may not pick ids
        r = client.post("/api/agent-ops/actions", json={"origin": "human", "request": req},
                        headers=auth_headers(tok))
    assert r.status_code == 201
    c, b = seen["claims"], seen["body"]
    assert b["tenant_id"] == c["tenant_id"] and b["requested_by"] == c["sub"]
    assert b["tenant_id"] != req["tenant_id"] and b["requested_by"] != req["requested_by"]
    assert "action_id" not in b
    assert b["origin"] == {"type": "human", "session_id": c["session_id"]}
    assert c["roles"] == ["consultant", "tenant_admin"]  # signup user is the org admin
    assert c["sub"] == str(uuid.UUID(me_id))


def test_cross_tenant_read_is_kernel_404(client, kernel_env):
    tok_a = _signup(client, "a" + uuid.uuid4().hex[:5])
    tok_b = _signup(client, "b" + uuid.uuid4().hex[:5])
    aid = uuid.uuid4()
    tenants = {}

    def handler(request: httpx.Request):
        c = verify_assertion(request)
        tenants.setdefault("first", c["tenant_id"])
        if c["tenant_id"] == tenants["first"]:
            return httpx.Response(200, json={"action_id": str(aid)})
        return httpx.Response(404, json={"code": "NOT_FOUND", "status": 404})

    with respx.mock() as m:
        m.get(f"{KERNEL}/internal/v1/actions/{aid}").mock(side_effect=handler)
        assert client.get(f"/api/agent-ops/actions/{aid}", headers=auth_headers(tok_a)).status_code == 200
        r = client.get(f"/api/agent-ops/actions/{aid}", headers=auth_headers(tok_b))
    assert r.status_code == 404 and r.json()["code"] == "NOT_FOUND"


# --------------------------------------------------------------------------- #
# Role mapping and the agent/human split
# --------------------------------------------------------------------------- #
def test_role_mapping_table():
    assert roles_for("consultant") == ["consultant"]
    assert roles_for("admin") == ["consultant", "tenant_admin"]
    assert roles_for("admin", as_agent=True) == ["agent"]
    assert roles_for("consultant", as_agent=True) == ["agent"]


def test_agent_origin_mints_agent_only_principal(client, kernel_env):
    tok = _signup(client, uuid.uuid4().hex[:6])
    seen = {}

    def handler(request):
        seen["c"] = verify_assertion(request); seen["b"] = json.loads(request.content)
        return httpx.Response(201, json={"ok": True})

    with respx.mock() as m:
        m.post(f"{KERNEL}/internal/v1/actions").mock(side_effect=handler)
        r = client.post("/api/agent-ops/actions",
                        json={"origin": "agent", "request": sms_request(uuid.uuid4().hex)},
                        headers=auth_headers(tok))
    assert r.status_code == 201
    assert seen["c"]["roles"] == ["agent"]
    assert seen["b"]["origin"]["type"] == "agent"


def test_approval_is_never_minted_as_agent(client, kernel_env):
    tok = _signup(client, uuid.uuid4().hex[:6])
    aid = uuid.uuid4(); seen = {}

    def handler(request):
        seen["c"] = verify_assertion(request); seen["b"] = json.loads(request.content)
        return httpx.Response(200, json={"approval": {}, "result": {}})

    with respx.mock() as m:
        m.post(f"{KERNEL}/internal/v1/actions/{aid}/approve").mock(side_effect=handler)
        r = client.post(f"/api/agent-ops/actions/{aid}/approve",
                        json={"action_digest": "sha256:" + "b" * 64, "reason": "ok",
                              "origin": "agent"},  # ignored: no such field
                        headers=auth_headers(tok))
    assert r.status_code == 200
    assert "agent" not in seen["c"]["roles"]
    assert seen["b"] == {"action_digest": "sha256:" + "b" * 64, "reason": "ok"}


def test_each_request_gets_a_fresh_jti(client, kernel_env):
    tok = _signup(client, uuid.uuid4().hex[:6])
    jtis = []
    with respx.mock() as m:
        m.get(f"{KERNEL}/internal/v1/approvals/pending").mock(
            side_effect=lambda req: (jtis.append(verify_assertion(req)["jti"]),
                                     httpx.Response(200, json=[]))[1])
        for _ in range(3):
            client.get("/api/agent-ops/approvals/pending", headers=auth_headers(tok))
    assert len(set(jtis)) == 3


# --------------------------------------------------------------------------- #
# Operator gate for the global kill switch
# --------------------------------------------------------------------------- #
def test_global_kill_switch_requires_listed_operator(client, kernel_env, monkeypatch):
    tok = _signup(client, uuid.uuid4().hex[:6])
    with respx.mock(assert_all_called=False) as m:
        route = m.post(f"{KERNEL}/internal/v1/kill-switch/global")
        r = client.post("/api/agent-ops/kill-switch/global", json={"dispatch_enabled": False},
                        headers=auth_headers(tok))
    assert r.status_code == 403 and not route.called

    # Allow-list this user → role is minted and the kernel is called.
    me_id = None
    seen = {}

    def handler(request):
        seen["c"] = verify_assertion(request)
        return httpx.Response(204)

    # Discover the user id through a tenant-admin-only path the app already has.
    import jwt as pyjwt
    me_id = pyjwt.decode(tok["access_token"], options={"verify_signature": False})["sub"]
    monkeypatch.setenv("KERNEL_PLATFORM_OPERATORS", f"someone-else,{me_id}")
    get_settings.cache_clear(); get_kernel_client.cache_clear()
    with respx.mock() as m:
        m.post(f"{KERNEL}/internal/v1/kill-switch/global").mock(side_effect=handler)
        r = client.post("/api/agent-ops/kill-switch/global", json={"dispatch_enabled": False},
                        headers=auth_headers(tok))
    assert r.status_code == 204, r.text
    assert "platform_operator" in seen["c"]["roles"]


def test_tenant_kill_switch_never_carries_platform_operator(client, kernel_env, monkeypatch):
    tok = _signup(client, uuid.uuid4().hex[:6])
    import jwt as pyjwt
    me_id = pyjwt.decode(tok["access_token"], options={"verify_signature": False})["sub"]
    monkeypatch.setenv("KERNEL_PLATFORM_OPERATORS", me_id)
    get_settings.cache_clear(); get_kernel_client.cache_clear()
    seen = {}
    with respx.mock() as m:
        m.post(f"{KERNEL}/internal/v1/kill-switch/tenant").mock(
            side_effect=lambda req: (seen.update(c=verify_assertion(req)), httpx.Response(204))[1])
        r = client.post("/api/agent-ops/kill-switch/tenant", json={"dispatch_enabled": False},
                        headers=auth_headers(tok))
    assert r.status_code == 204
    assert "platform_operator" not in seen["c"]["roles"]


# --------------------------------------------------------------------------- #
# Pass-through of kernel verdicts
# --------------------------------------------------------------------------- #
@pytest.mark.parametrize("status,body", [
    (403, {"code": "CONTACT_SUPPRESSED", "status": 403, "title": "Policy denied the action"}),
    (409, {"code": "APPROVAL_DIGEST_MISMATCH", "status": 409}),
    (422, {"code": "SCHEMA_INVALID", "status": 422}),
    (401, {"code": "ASSERTION_REPLAYED", "status": 401}),
])
def test_kernel_verdicts_pass_through_unchanged(client, kernel_env, status, body):
    tok = _signup(client, uuid.uuid4().hex[:6])
    with respx.mock() as m:
        m.post(f"{KERNEL}/internal/v1/actions").mock(return_value=httpx.Response(status, json=body))
        r = client.post("/api/agent-ops/actions",
                        json={"origin": "human", "request": sms_request(uuid.uuid4().hex)},
                        headers=auth_headers(tok))
    assert r.status_code == status and r.json() == body


def test_204_passes_through_without_body(client, kernel_env):
    tok = _signup(client, uuid.uuid4().hex[:6])
    sid = uuid.uuid4()
    with respx.mock() as m:
        m.delete(f"{KERNEL}/internal/v1/suppressions/{sid}").mock(return_value=httpx.Response(204))
        r = client.delete(f"/api/agent-ops/suppressions/{sid}", headers=auth_headers(tok))
    assert r.status_code == 204 and r.content == b""


# --------------------------------------------------------------------------- #
# Hygiene
# --------------------------------------------------------------------------- #
@pytest.mark.parametrize("key", ["callback_url", "password", "api_key", "token", "secret"])
def test_forbidden_argument_keys_rejected_before_any_call(client, kernel_env, key):
    tok = _signup(client, uuid.uuid4().hex[:6])
    req = sms_request(uuid.uuid4().hex); req["arguments"][key] = "x"
    with respx.mock(assert_all_called=False) as m:
        route = m.post(f"{KERNEL}/internal/v1/actions")
        r = client.post("/api/agent-ops/actions", json={"origin": "human", "request": req},
                        headers=auth_headers(tok))
    assert r.status_code == 422 and not route.called


def test_invalid_ids_are_422_before_any_call(client, kernel_env):
    tok = _signup(client, uuid.uuid4().hex[:6])
    with respx.mock(assert_all_called=False) as m:
        route = m.route(host="kernel.test")
        assert client.get("/api/agent-ops/actions/not-a-uuid",
                          headers=auth_headers(tok)).status_code == 422
        assert client.post("/api/agent-ops/actions/../../kill-switch/global/cancel",
                           headers=auth_headers(tok)).status_code in (404, 422)
    assert not route.called


def test_bad_origin_value_rejected(client, kernel_env):
    tok = _signup(client, uuid.uuid4().hex[:6])
    r = client.post("/api/agent-ops/actions",
                    json={"origin": "system", "request": sms_request(uuid.uuid4().hex)},
                    headers=auth_headers(tok))
    assert r.status_code == 422


def test_minter_rejects_bad_config():
    from app.kernel.assertions import AssertionConfigError
    with pytest.raises(AssertionConfigError):
        AssertionMinter.from_seed_b64url("k1", "not-base64!!")
    with pytest.raises(AssertionConfigError):
        AssertionMinter.from_seed_b64url("k1", base64.urlsafe_b64encode(b"short").decode())
    with pytest.raises(AssertionConfigError):
        AssertionMinter.from_seed_b64url("", base64.urlsafe_b64encode(b"0" * 32).decode())


def test_minter_round_trips_with_devkeys_format():
    """Seed exported as b64url(32 bytes) == `mk-devkeys gen` DEV_PRIVATE_KEY format."""
    seed = os.urandom(32)
    m = AssertionMinter.from_seed_b64url(
        "k1", base64.urlsafe_b64encode(seed).rstrip(b"=").decode())
    tok = m.mint(user_id=uuid.uuid4().hex, tenant_id=uuid.uuid4().hex, roles=["user"],
                 session_id="s", request_id="r")
    h, p, s = tok.split(".")
    Ed25519PublicKey.from_public_bytes(_b64d(m.public_key_b64url())).verify(
        _b64d(s), f"{h}.{p}".encode())


def test_forwarded_proposal_matches_published_action_contract(client, kernel_env):
    """Doc/code divergence guard: what the proxy sends must validate against
    contracts/action/v1/action-request.schema.json — the kernel's first gate."""
    jsonschema = pytest.importorskip("jsonschema")
    from pathlib import Path
    schema_path = Path(__file__).resolve().parents[2] / "contracts" / "action" / "v1" / "action-request.schema.json"
    schema = json.loads(schema_path.read_text())
    tok = _signup(client, uuid.uuid4().hex[:6])
    seen = {}

    def handler(request):
        verify_assertion(request); seen["b"] = json.loads(request.content)
        return httpx.Response(201, json={"ok": True})

    with respx.mock() as m:
        m.post(f"{KERNEL}/internal/v1/actions").mock(side_effect=handler)
        for origin in ("agent", "human"):
            req = sms_request(uuid.uuid4().hex)
            req["arguments"]["agent_id"] = "moto-1"
            r = client.post("/api/agent-ops/actions", json={"origin": origin, "request": req},
                            headers=auth_headers(tok))
            assert r.status_code == 201
            jsonschema.Draft202012Validator(schema).validate(seen["b"])


# --------------------------------------------------------------------------- #
# WP06 — human-approval authority relays (FastAPI never verifies, never signs)
# --------------------------------------------------------------------------- #
def test_webauthn_bytes_are_relayed_untouched_and_never_as_agent(client, kernel_env):
    tok = _signup(client, uuid.uuid4().hex[:6])
    aid = uuid.uuid4(); seen = {}

    def handler(request):
        seen["c"] = verify_assertion(request); seen["b"] = json.loads(request.content)
        return httpx.Response(200, json={"approval": {"human_binding": "webauthn"}, "result": {}})

    wa = {"credential_id": "AQID", "client_data_json": "eyJ0eXBlIjoid2ViYXV0aG4uZ2V0In0",
          "authenticator_data": "AAAA", "signature": "MEUCIQ"}
    with respx.mock() as m:
        m.post(f"{KERNEL}/internal/v1/actions/{aid}/approve").mock(side_effect=handler)
        r = client.post(f"/api/agent-ops/actions/{aid}/approve",
                        json={"action_digest": "sha256:" + "b" * 64, "webauthn": wa}, headers=auth_headers(tok))
    assert r.status_code == 200
    assert seen["b"]["webauthn"] == wa and "agent" not in seen["c"]["roles"]
    # Non-base64url bytes are refused before reaching the kernel.
    bad = dict(wa, signature="not base64!")
    with respx.mock(assert_all_called=False) as m:
        m.post(f"{KERNEL}/internal/v1/actions/{aid}/approve").mock(return_value=httpx.Response(200, json={}))
        r = client.post(f"/api/agent-ops/actions/{aid}/approve",
                        json={"action_digest": "sha256:" + "b" * 64, "webauthn": bad}, headers=auth_headers(tok))
        assert r.status_code == 422 and not m.calls


def test_passkey_and_challenge_and_revocation_relays(client, kernel_env):
    tok = _signup(client, uuid.uuid4().hex[:6])
    aid = uuid.uuid4(); seen = {}

    def rec(name):
        def h(request):
            seen[name] = (verify_assertion(request), json.loads(request.content or b"{}"))
            return httpx.Response(200, json={"ok": name})
        return h

    with respx.mock() as m:
        m.post(f"{KERNEL}/internal/v1/actions/{aid}/approval-challenge").mock(side_effect=rec("challenge"))
        m.post(f"{KERNEL}/internal/v1/approval-credentials/register/begin").mock(side_effect=rec("begin"))
        m.post(f"{KERNEL}/internal/v1/approval-credentials/register/finish").mock(side_effect=rec("finish"))
        m.get(f"{KERNEL}/internal/v1/approval-credentials").mock(return_value=httpx.Response(200, json=[]))
        m.post(f"{KERNEL}/internal/v1/revocations").mock(side_effect=rec("revoke"))
        h = auth_headers(tok)
        assert client.post(f"/api/agent-ops/actions/{aid}/approval-challenge", headers=h).status_code == 200
        assert client.post("/api/agent-ops/approval-credentials/register/begin", headers=h).status_code == 200
        assert client.post("/api/agent-ops/approval-credentials/register/finish",
                           json={"client_data_json": "e30", "attestation_object": "oWNmbXRkbm9uZQ", "label": "phone"}, headers=h).status_code == 200
        assert client.get("/api/agent-ops/approval-credentials", headers=h).status_code == 200
        # Revoking "my current session" without naming it: FastAPI supplies the kernel session id.
        assert client.post("/api/agent-ops/revocations", json={"reason": "lost phone"}, headers=h).status_code == 200
    assert seen["finish"][1] == {"client_data_json": "e30", "attestation_object": "oWNmbXRkbm9uZQ", "label": "phone"}
    assert seen["revoke"][1]["session_id"] == seen["revoke"][0]["session_id"]
    for k in ("challenge", "begin", "finish", "revoke"):
        assert "agent" not in seen[k][0]["roles"]
    # Unauthenticated → 401 (no kernel call).
    assert client.post("/api/agent-ops/approval-credentials/register/begin").status_code == 401
