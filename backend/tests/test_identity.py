"""S2 / H9: server-side sessions, rotation, revocation, second factors, step-up.

Adversarial by design: forged/crossed session ids, refresh-token replay, TOTP
replay and brute force, recovery-code reuse, passkey origin/UV/signature/counter
attacks, and step-up expiry."""
import base64
import uuid
from datetime import datetime, timedelta, timezone

import httpx
import jwt as pyjwt
import pytest
import respx

from app import foundation, identity
from app.config import get_settings
from tests.conftest import auth_headers, step_up
from tests.softauthn import SoftAuthenticator

RP_ID, ORIGIN = "app.example.test", "https://app.example.test"
PW = "superSecret123!"


def _email():
    return f"id{uuid.uuid4().hex[:10]}@example.com"


def _raw_signup(client, email=None):
    email = email or _email()
    r = client.post("/api/auth/signup", json={"org_name": "Org " + email[:6], "email": email, "password": PW})
    assert r.status_code == 201, r.text
    return email, r.json()


@pytest.fixture
def mfa_on(monkeypatch):
    monkeypatch.setenv("MFA_REQUIRED", "true")
    monkeypatch.setenv("APP_WEBAUTHN_RP_ID", RP_ID)
    monkeypatch.setenv("APP_WEBAUTHN_ORIGINS", ORIGIN)
    get_settings.cache_clear()
    yield
    get_settings.cache_clear()


@pytest.fixture
def passkeys(monkeypatch):
    monkeypatch.setenv("APP_WEBAUTHN_RP_ID", RP_ID)
    monkeypatch.setenv("APP_WEBAUTHN_ORIGINS", ORIGIN)
    get_settings.cache_clear()
    yield
    get_settings.cache_clear()


def _totp_now(secret_b32: str, at: datetime | None = None) -> str:
    return identity.totp_code(identity._unb32(secret_b32), identity.totp_step(at or foundation.utcnow()))


def _enroll_totp(client, h):
    b = client.post("/api/security/mfa/totp/begin", headers=h)
    assert b.status_code == 200, b.text
    secret = b.json()["secret"]
    c = client.post("/api/security/mfa/totp/confirm", json={"factor_id": b.json()["factor_id"],
                                                             "code": _totp_now(secret)}, headers=h)
    assert c.status_code == 200, c.text
    return secret, c.json()["recovery_codes"]


def _login_mfa(client, email, *, code_fn):
    r = client.post("/api/auth/login", json={"email": email, "password": PW})
    assert r.status_code == 200 and r.json()["mfa_required"] is True and "access_token" not in r.json(), r.text
    v = client.post("/api/auth/mfa/verify", json={"mfa_token": r.json()["mfa_token"], "method": "totp",
                                                  "code": code_fn()})
    return r.json(), v


# --------------------------------------------------------------------------- sessions
def test_rfc6238_totp_vectors():
    secret = b"12345678901234567890"
    for t, want in [(59, "94287082"), (1111111109, "07081804"), (1111111111, "14050471"),
                    (1234567890, "89005924"), (2000000000, "69279037"), (20000000000, "65353130")]:
        assert identity.totp_code(secret, t // 30, digits=8) == want


def test_tokens_name_a_server_session_and_logout_ends_every_token(client):
    _, t = _raw_signup(client)
    h = auth_headers(t)
    assert client.get("/api/auth/me", headers=h).status_code == 200
    assert client.post("/api/auth/logout", headers=h).status_code == 200
    assert client.get("/api/auth/me", headers=h).status_code == 401
    assert client.post("/api/auth/refresh", json={"refresh_token": t["refresh_token"]}).status_code == 401


def test_refresh_rotates_and_reuse_of_a_spent_refresh_token_kills_the_session(client):
    _, t = _raw_signup(client)
    r1 = client.post("/api/auth/refresh", json={"refresh_token": t["refresh_token"]})
    assert r1.status_code == 200
    new = r1.json()
    assert client.get("/api/auth/me", headers=auth_headers(new)).status_code == 200
    # The stolen original refresh token is replayed → whole session revoked.
    r2 = client.post("/api/auth/refresh", json={"refresh_token": t["refresh_token"]})
    assert r2.status_code == 401 and r2.json()["detail"]["code"] == "SESSION_ENDED"
    assert client.get("/api/auth/me", headers=auth_headers(new)).status_code == 401
    assert client.post("/api/auth/refresh", json={"refresh_token": new["refresh_token"]}).status_code == 401


def test_forged_or_crossed_session_ids_are_refused(client):
    _, a = _raw_signup(client)
    _, b = _raw_signup(client)
    secret = get_settings().jwt_secret
    pa = pyjwt.decode(a["access_token"], secret, algorithms=["HS256"])
    pb = pyjwt.decode(b["access_token"], secret, algorithms=["HS256"])
    now = datetime.now(timezone.utc)
    for forged in (
        {**pa, "sid": pb["sid"]},                      # A's identity, B's session
        {**pa, "tid": pb["tid"]},                      # A's session, B's tenant
        {k: v for k, v in pa.items() if k != "sid"},   # pre-session token shape
        {**pa, "sid": uuid.uuid4().hex},               # unknown session
    ):
        forged = {**forged, "iat": now, "exp": now + timedelta(minutes=5)}
        tok = pyjwt.encode(forged, secret, algorithm="HS256")
        assert client.get("/api/auth/me", headers={"Authorization": f"Bearer {tok}"}).status_code == 401


def test_password_change_revokes_other_sessions_and_keeps_this_one(client):
    email, t1 = _raw_signup(client)
    t2 = client.post("/api/auth/login", json={"email": email, "password": PW}).json()
    step_up(client, t1, PW)
    r = client.post("/api/auth/change-password", json={"current_password": PW, "new_password": "aNewPassw0rd!!"},
                    headers=auth_headers(t1))
    assert r.status_code == 200 and r.json()["sessions_revoked"] == 1, r.text
    assert client.get("/api/auth/me", headers=auth_headers(t2)).status_code == 401
    assert client.get("/api/auth/me", headers=auth_headers(t1)).status_code == 401   # pv changed
    assert client.get("/api/auth/me", headers=auth_headers(r.json())).status_code == 200


def test_change_password_needs_step_up(client):
    _, t = _raw_signup(client)
    r = client.post("/api/auth/change-password", json={"current_password": PW, "new_password": "aNewPassw0rd!!"},
                    headers=auth_headers(t))
    assert r.status_code == 403 and r.json()["detail"]["code"] == "STEP_UP_REQUIRED"


def test_session_list_is_coarse_and_revocation_is_scoped_to_the_owner(client):
    email, t1 = _raw_signup(client)
    t2 = client.post("/api/auth/login", json={"email": email, "password": PW},
                     headers={"User-Agent": "Mozilla/5.0 (Windows NT 10.0) Chrome/130.0 Secret-Build-1234"}).json()
    rows = client.get("/api/auth/sessions", headers=auth_headers(t1)).json()
    assert len(rows) == 2 and sum(r["current"] for r in rows) == 1
    assert all("Secret-Build" not in r["client"] for r in rows) and any(r["client"] == "Chrome on Windows" for r in rows)
    other = next(r for r in rows if not r["current"])
    _, intruder = _raw_signup(client)
    assert client.post(f"/api/auth/sessions/{other['id']}/revoke", headers=auth_headers(intruder)).status_code == 404
    assert client.post(f"/api/auth/sessions/{other['id']}/revoke", headers=auth_headers(t1)).status_code == 200
    assert client.get("/api/auth/me", headers=auth_headers(t2)).status_code == 401
    assert client.get("/api/auth/me", headers=auth_headers(t1)).status_code == 200


# --------------------------------------------------------------------------- MFA enforcement
def test_mfa_required_blocks_everything_but_enrollment_until_a_factor_is_confirmed(client, mfa_on):
    _, t = _raw_signup(client)
    assert t["mfa_enrollment_required"] is True
    h = auth_headers(t)
    blocked = client.get("/api/customers", headers=h)
    assert blocked.status_code == 403 and blocked.json()["detail"]["code"] == "MFA_ENROLLMENT_REQUIRED"
    assert client.get("/api/auth/me", headers=h).json()["session"]["mfa_enrollment_required"] is True
    # Password step-up is not a factor when MFA is required (blocked before enrollment).
    assert client.post("/api/security/step-up", json={"method": "password", "password": PW},
                       headers=h).status_code in (401, 403)
    secret, codes = _enroll_totp(client, h)
    assert len(codes) == 10 and len(set(codes)) == 10
    assert client.get("/api/customers", headers=h).status_code == 200


def test_login_second_factor_wrong_code_replay_and_lockout(client, mfa_on, frozen_clock):
    frozen_clock("2026-11-12T10:00:10+00:00")
    email, t = _raw_signup(client)
    secret, _ = _enroll_totp(client, auth_headers(t))
    # The enrollment code's step is spent: the same code cannot sign in (replay barrier).
    _, v = _login_mfa(client, email, code_fn=lambda: _totp_now(secret))
    assert v.status_code == 401 and v.json()["detail"]["code"] == "SECOND_FACTOR_INVALID"
    frozen_clock("2026-11-12T10:00:40+00:00")
    first, ok = _login_mfa(client, email, code_fn=lambda: _totp_now(secret))
    assert ok.status_code == 200 and ok.json()["access_token"], ok.text
    # The mfa_token is not an access token and is single-session.
    assert client.get("/api/auth/me", headers={"Authorization": f"Bearer {first['mfa_token']}"}).status_code == 401
    again = client.post("/api/auth/mfa/verify", json={"mfa_token": first["mfa_token"], "method": "totp",
                                                      "code": _totp_now(secret)})
    assert again.status_code == 401
    # Brute force: five wrong codes end the challenge for good.
    r = client.post("/api/auth/login", json={"email": email, "password": PW}).json()
    for i in range(5):
        bad = client.post("/api/auth/mfa/verify", json={"mfa_token": r["mfa_token"], "method": "totp", "code": "000000"})
        assert bad.status_code == 401
    assert bad.json()["detail"]["code"] == "SESSION_ENDED"
    frozen_clock("2026-11-12T10:01:10+00:00")
    dead = client.post("/api/auth/mfa/verify", json={"mfa_token": r["mfa_token"], "method": "totp",
                                                     "code": _totp_now(secret)})
    assert dead.status_code == 401
    # Malformed codes never reach comparison and still count as failures.
    r2 = client.post("/api/auth/login", json={"email": email, "password": PW}).json()
    for junk in ("12345", "1234567", "12345a", " ", "١٢٣٤٥٦"):
        assert client.post("/api/auth/mfa/verify", json={"mfa_token": r2["mfa_token"], "method": "totp",
                                                         "code": junk}).status_code == 401


def test_recovery_codes_are_single_use_and_login_only(client, mfa_on, frozen_clock):
    frozen_clock("2026-11-12T11:00:10+00:00")
    email, t = _raw_signup(client)
    _, codes = _enroll_totp(client, auth_headers(t))
    r = client.post("/api/auth/login", json={"email": email, "password": PW}).json()
    assert "recovery" in r["methods"]
    ok = client.post("/api/auth/mfa/verify", json={"mfa_token": r["mfa_token"], "method": "recovery",
                                                   "code": codes[0].lower()})
    assert ok.status_code == 200
    r = client.post("/api/auth/login", json={"email": email, "password": PW}).json()
    reuse = client.post("/api/auth/mfa/verify", json={"mfa_token": r["mfa_token"], "method": "recovery",
                                                      "code": codes[0]})
    assert reuse.status_code == 401
    # Recovery codes do not satisfy step-up.
    h = auth_headers(ok.json())
    assert client.post("/api/security/step-up", json={"method": "recovery", "code": codes[1]},
                       headers=h).status_code == 422


def test_step_up_window_expires_and_needs_a_factor(client, mfa_on, frozen_clock):
    frozen_clock("2026-11-12T12:00:10+00:00")
    email, t = _raw_signup(client)
    secret, _ = _enroll_totp(client, auth_headers(t))
    frozen_clock("2026-11-12T12:00:40+00:00")
    _, v = _login_mfa(client, email, code_fn=lambda: _totp_now(secret))
    h = auth_headers(v.json())
    assert client.get("/api/customers/export.csv", headers=h).status_code == 200   # fresh MFA counts
    frozen_clock("2026-11-12T12:12:00+00:00")
    stale = client.get("/api/customers/export.csv", headers=h)
    assert stale.status_code == 403 and stale.json()["detail"]["code"] == "STEP_UP_REQUIRED"
    assert stale.json()["detail"]["methods"] == ["totp"]
    bad = client.post("/api/security/step-up", json={"method": "totp", "code": "999999"}, headers=h)
    assert bad.status_code == 403 and bad.json()["detail"]["code"] == "SECOND_FACTOR_INVALID"
    assert client.post("/api/security/step-up", json={"method": "totp", "code": _totp_now(secret)},
                       headers=h).status_code == 200
    assert client.get("/api/customers/export.csv", headers=h).status_code == 200
    # A step-up time in the future (clock skew/forgery) never counts: at 12:11 the
    # sign-in factor (12:00:40) is stale and the 12:12 step-up lies in the future.
    frozen_clock("2026-11-12T12:11:00+00:00")
    fut = client.get("/api/customers/export.csv", headers=h)
    assert fut.status_code == 403 and fut.json()["detail"]["code"] == "STEP_UP_REQUIRED"


def test_adding_a_second_factor_needs_step_up_and_the_last_factor_cannot_be_removed(client, mfa_on, frozen_clock):
    frozen_clock("2026-11-12T13:00:10+00:00")
    email, t = _raw_signup(client)
    h = auth_headers(t)
    secret, _ = _enroll_totp(client, h)
    factors = client.get("/api/security/mfa", headers=h).json()["factors"]
    assert len(factors) == 1
    frozen_clock("2026-11-12T13:20:00+00:00")   # step-up from enrollment has lapsed
    nb = client.post("/api/security/mfa/totp/begin", headers=h)
    assert nb.status_code == 403 and nb.json()["detail"]["code"] == "STEP_UP_REQUIRED"
    rv = client.post(f"/api/security/mfa/{factors[0]['id']}/revoke", headers=h)
    assert rv.status_code == 403 and rv.json()["detail"]["code"] == "STEP_UP_REQUIRED"
    step = client.post("/api/security/step-up", json={"method": "totp", "code": _totp_now(secret)}, headers=h)
    assert step.status_code == 200
    last = client.post(f"/api/security/mfa/{factors[0]['id']}/revoke", headers=h)
    assert last.status_code == 409 and last.json()["detail"]["code"] == "LAST_FACTOR"


# --------------------------------------------------------------------------- passkeys
def test_passkey_enroll_login_and_step_up(client, mfa_on, frozen_clock):
    frozen_clock("2026-11-12T14:00:10+00:00")
    email, t = _raw_signup(client)
    h = auth_headers(t)
    auth = SoftAuthenticator(RP_ID, ORIGIN)
    opts = client.post("/api/security/mfa/passkey/begin", headers=h).json()
    fin = client.post("/api/security/mfa/passkey/finish", json={"credential": auth.register(opts)}, headers=h)
    assert fin.status_code == 200 and len(fin.json()["recovery_codes"]) == 10, fin.text
    r = client.post("/api/auth/login", json={"email": email, "password": PW}).json()
    assert "webauthn" in r["methods"]
    o = client.post("/api/auth/mfa/passkey/options", json={"mfa_token": r["mfa_token"]}).json()
    v = client.post("/api/auth/mfa/verify", json={"mfa_token": r["mfa_token"], "method": "webauthn",
                                                  "credential": auth.get(o)})
    assert v.status_code == 200, v.text
    h2 = auth_headers(v.json())
    frozen_clock("2026-11-12T14:30:00+00:00")
    so = client.post("/api/security/step-up/passkey/options", headers=h2).json()
    assert client.post("/api/security/step-up", json={"method": "webauthn", "credential": auth.get(so)},
                       headers=h2).status_code == 200


@pytest.mark.parametrize("attack", ["wrong_origin", "no_user_verification", "tampered_signature",
                                    "replayed_assertion", "counter_regression", "foreign_credential",
                                    "wrong_challenge"])
def test_passkey_attacks_are_refused(client, mfa_on, frozen_clock, attack):
    frozen_clock("2026-11-12T15:00:10+00:00")
    email, t = _raw_signup(client)
    h = auth_headers(t)
    auth = SoftAuthenticator(RP_ID, ORIGIN)
    opts = client.post("/api/security/mfa/passkey/begin", headers=h).json()
    assert client.post("/api/security/mfa/passkey/finish", json={"credential": auth.register(opts)},
                       headers=h).status_code == 200
    auth.count = 10
    r = client.post("/api/auth/login", json={"email": email, "password": PW}).json()
    o = client.post("/api/auth/mfa/passkey/options", json={"mfa_token": r["mfa_token"]}).json()
    if attack == "counter_regression":
        # Establish a stored counter of 11, then present a lower one (cloned authenticator).
        assert client.post("/api/auth/mfa/verify", json={"mfa_token": r["mfa_token"], "method": "webauthn",
                                                         "credential": auth.get(o)}).status_code == 200
        r = client.post("/api/auth/login", json={"email": email, "password": PW}).json()
        o = client.post("/api/auth/mfa/passkey/options", json={"mfa_token": r["mfa_token"]}).json()
    if attack == "replayed_assertion":
        good = auth.get(o)
        assert client.post("/api/auth/mfa/verify", json={"mfa_token": r["mfa_token"], "method": "webauthn",
                                                         "credential": good}).status_code == 200
        r = client.post("/api/auth/login", json={"email": email, "password": PW}).json()
        client.post("/api/auth/mfa/passkey/options", json={"mfa_token": r["mfa_token"]})
        cred = good
    elif attack == "foreign_credential":
        other = SoftAuthenticator(RP_ID, ORIGIN)
        other.cred_id = auth.cred_id   # claims the victim's credential id, signs with its own key
        cred = other.get(o)
    else:
        cred = auth.get(o, origin="https://evil.example" if attack == "wrong_origin" else None,
                        uv=attack != "no_user_verification", tamper=attack == "tampered_signature",
                        count=3 if attack == "counter_regression" else None,
                        challenge=identity._b64u(b"x" * 32) if attack == "wrong_challenge" else None)
    v = client.post("/api/auth/mfa/verify", json={"mfa_token": r["mfa_token"], "method": "webauthn", "credential": cred})
    assert v.status_code == 401, (attack, v.text)


def test_passkey_registration_refuses_wrong_origin_rp_or_missing_uv(client, mfa_on, frozen_clock):
    frozen_clock("2026-11-12T16:00:10+00:00")
    _, t = _raw_signup(client)
    h = auth_headers(t)
    auth = SoftAuthenticator(RP_ID, ORIGIN)
    for kw in ({"origin": "https://evil.example"}, {"uv": False}, {"rp_id": "evil.example"}):
        opts = client.post("/api/security/mfa/passkey/begin", headers=h).json()
        r = client.post("/api/security/mfa/passkey/finish", json={"credential": auth.register(opts, **kw)}, headers=h)
        assert r.status_code == 400 and r.json()["detail"]["code"] == "PASSKEY_REJECTED", (kw, r.text)
    # The burned challenge cannot be reused even with a now-valid response.
    opts = client.post("/api/security/mfa/passkey/begin", headers=h).json()
    client.post("/api/security/mfa/passkey/finish", json={"credential": auth.register(opts, uv=False)}, headers=h)
    again = client.post("/api/security/mfa/passkey/finish", json={"credential": auth.register(opts)}, headers=h)
    assert again.status_code == 409 and again.json()["detail"]["code"] == "CHALLENGE_EXPIRED"


def test_passkeys_unavailable_without_rp_configuration(client):
    _, t = _raw_signup(client)
    step_up(client, t, PW)
    r = client.post("/api/security/mfa/passkey/begin", headers=auth_headers(t))
    assert r.status_code == 409 and r.json()["detail"]["code"] == "PASSKEYS_NOT_CONFIGURED"


# --------------------------------------------------------------------------- H9: kernel cascade
KERNEL = "http://kernel.test:8090"


@pytest.fixture
def kernel_env(monkeypatch):
    from app.kernel.assertions import AssertionMinter
    from app.kernel.client import get_kernel_client
    m = AssertionMinter.generate("k-test")
    monkeypatch.setenv("RUST_ACTION_KERNEL_URL", KERNEL)
    monkeypatch.setenv("KERNEL_ASSERTION_PRIVATE_KEY",
                       base64.urlsafe_b64encode(m._key.private_bytes_raw()).rstrip(b"=").decode())
    monkeypatch.setenv("KERNEL_ASSERTION_KID", "k-test")
    get_settings.cache_clear(); get_kernel_client.cache_clear()
    yield
    get_settings.cache_clear(); get_kernel_client.cache_clear()


def _claims(req) -> dict:
    tok = req.headers["authorization"][7:]
    return pyjwt.decode(tok, options={"verify_signature": False}, algorithms=["EdDSA"])


def test_logout_revokes_the_same_session_in_the_kernel(client, kernel_env):
    _, t = _raw_signup(client)
    sid = t["session_id"]
    with respx.mock(assert_all_called=False) as m:
        seen = []
        m.get(f"{KERNEL}/internal/v1/approvals/pending").mock(
            side_effect=lambda req: (seen.append(_claims(req)["session_id"]), httpx.Response(200, json=[]))[1])
        assert client.get("/api/agent-ops/approvals/pending", headers=auth_headers(t)).status_code == 200
        # stable across refresh
        t2 = client.post("/api/auth/refresh", json={"refresh_token": t["refresh_token"]}).json()
        client.get("/api/agent-ops/approvals/pending", headers=auth_headers(t2))
        assert seen == [f"app:{sid}", f"app:{sid}"]
        rev = m.post(f"{KERNEL}/internal/v1/revocations").mock(return_value=httpx.Response(201, json={}))
        assert client.post("/api/auth/logout", headers=auth_headers(t2)).status_code == 200
    import json as _json
    body = _json.loads(rev.calls[0].request.content)
    assert body["session_id"] == f"app:{sid}" and "user_id" not in body


def test_kernel_outage_keeps_revocation_pending_until_delivered(client, kernel_env, frozen_clock):
    frozen_clock("2026-11-12T17:00:00+00:00")
    email, t = _raw_signup(client)
    with respx.mock(assert_all_called=False) as m:
        m.post(f"{KERNEL}/internal/v1/revocations").mock(side_effect=httpx.ConnectError("down"))
        m.get(f"{KERNEL}/health/ready").mock(return_value=httpx.Response(200, json={}))
        assert client.post("/api/auth/logout", headers=auth_headers(t)).status_code == 200   # local revocation wins
        assert client.get("/api/auth/me", headers=auth_headers(t)).status_code == 401
        frozen_clock("2026-11-12T17:02:00+00:00")
        ready = client.get("/api/health/ready").json()
        assert int(ready["checks"]["kernel_revocations_backlog"]) >= 1
    with respx.mock(assert_all_called=False) as m:
        rev = m.post(f"{KERNEL}/internal/v1/revocations").mock(return_value=httpx.Response(201, json={}))
        m.get(f"{KERNEL}/health/ready").mock(return_value=httpx.Response(200, json={}))
        client.post("/api/auth/login", json={"email": email, "password": PW})   # opportunistic retry
        assert rev.called
    from sqlalchemy import select

    from app import db as dbmod
    from app.models import KernelRevocationOutbox
    with dbmod._SessionLocal() as s:
        mine = s.scalars(select(KernelRevocationOutbox).where(KernelRevocationOutbox.tenant_id == t["tenant_id"])).all()
        assert mine and all(r.delivered_at is not None for r in mine) and mine[0].attempts == 2
