"""S2: persistent session identity, rotation and revocation receiving controls."""
import json
import uuid
import asyncio
from datetime import datetime, timedelta, timezone

import httpx
import respx
import pytest

from .conftest import auth_headers, signup
from .test_agent_ops import KERNEL, verify_assertion
from .test_foundation import kernel_env  # noqa: F401


@respx.mock
def test_one_session_revocation_kills_access_and_refresh_but_not_other_session(client, kernel_env):
    email = f"sessions-{uuid.uuid4().hex}@example.com"
    first = signup(client, email=email)
    second = client.post("/api/auth/login", json={"email": email, "password": "superSecret123!"}).json()
    rows = client.get("/api/auth/sessions", headers=auth_headers(first))
    assert rows.status_code == 200, rows.text
    assert len(rows.json()) == 2
    target = next(row["id"] for row in rows.json() if row["current"])
    observed = []
    def revoke(request):
        observed.append((verify_assertion(request), json.loads(request.content)))
        return httpx.Response(201, json={"revocation_id": str(uuid.uuid4()), "revoked_at": "2026-10-22T12:00:00Z", "approvals_revoked": 1})
    respx.post(f"{KERNEL}/internal/v1/revocations").mock(side_effect=revoke)
    result = client.post(f"/api/auth/sessions/{target}/revoke", headers=auth_headers(second))
    assert result.status_code == 200, result.text
    assert result.json()["kernel_revocation"] == "confirmed"
    assert observed[0][1]["session_id"] == target
    assert observed[0][0]["session_id"] != target, "stable current session authorizes revocation of the other session"
    assert client.get("/api/auth/me", headers=auth_headers(first)).status_code == 401
    assert client.post("/api/auth/refresh", json={"refresh_token": first["refresh_token"]}).status_code == 401
    assert client.get("/api/auth/me", headers=auth_headers(second)).status_code == 200


def test_refresh_rotates_and_reuse_revokes_the_session(client):
    old = signup(client, email=f"rotate-{uuid.uuid4().hex}@example.com")
    refreshed = client.post("/api/auth/refresh", json={"refresh_token": old["refresh_token"]})
    assert refreshed.status_code == 200
    assert refreshed.json()["refresh_token"] != old["refresh_token"], "refresh credentials are one-use"
    assert client.post("/api/auth/refresh", json={"refresh_token": old["refresh_token"]}).status_code == 401
    assert client.get("/api/auth/me", headers=auth_headers(refreshed.json())).status_code == 401


@respx.mock
def test_revocation_network_failure_is_durable_and_not_reported_confirmed(client, kernel_env):
    first = signup(client, email=f"partition-{uuid.uuid4().hex}@example.com")
    rows = client.get("/api/auth/sessions", headers=auth_headers(first))
    assert rows.status_code == 200, rows.text
    target = rows.json()[0]["id"]
    respx.post(f"{KERNEL}/internal/v1/revocations").mock(side_effect=httpx.ReadTimeout("synthetic partition"))
    result = client.post(f"/api/auth/sessions/{target}/revoke", headers=auth_headers(first))
    assert result.status_code == 202, result.text
    assert result.json()["kernel_revocation"] == "pending"
    assert client.get("/api/auth/me", headers=auth_headers(first)).status_code == 401
    # Retry must remain queued in durable storage after the caller is logged out.
    from sqlalchemy import select
    from sqlalchemy.orm import Session
    from app.models import AuthRevocation
    from .conftest import engine
    with Session(engine) as db:
        row = db.scalar(select(AuthRevocation).where(AuthRevocation.session_id == target))
        assert row is not None and row.confirmed_at is None


def test_logout_and_cross_user_revocation(client):
    one = signup(client, email=f"one-{uuid.uuid4().hex}@example.com")
    two = signup(client, email=f"two-{uuid.uuid4().hex}@example.com")
    sid = client.get('/api/auth/sessions', headers=auth_headers(one)).json()[0]['id']
    assert client.post(f'/api/auth/sessions/{sid}/revoke', headers=auth_headers(two)).status_code == 404
    assert client.get('/api/auth/me', headers=auth_headers(one)).status_code == 200
    result = client.post('/api/auth/logout', headers=auth_headers(one))
    assert result.status_code == 202  # no configured kernel, never claim confirmed
    assert client.get('/api/auth/me', headers=auth_headers(one)).status_code == 401
    assert client.post('/api/auth/refresh', json={'refresh_token': one['refresh_token']}).status_code == 401


@pytest.mark.parametrize('status,body', [
    (200, {'revoked': True}), (201, {}),
    (201, {'revocation_id': 'bad', 'revoked_at': '2026-10-22T12:00:00Z', 'approvals_revoked': 1}),
    (201, {'revocation_id': str(uuid.uuid4()), 'revoked_at': 'bad', 'approvals_revoked': 1}),
    (201, {'revocation_id': str(uuid.uuid4()), 'revoked_at': '2026-10-22T12:00:00Z', 'approvals_revoked': True}),
    (503, {'revocation_id': str(uuid.uuid4()), 'revoked_at': '2026-10-22T12:00:00Z', 'approvals_revoked': 1}),
])
@respx.mock
def test_bad_kernel_receipt_never_confirms(client, kernel_env, status, body):
    token = signup(client, email=f"receipt-{uuid.uuid4().hex}@example.com")
    respx.post(f'{KERNEL}/internal/v1/revocations').mock(return_value=httpx.Response(status, json=body))
    result = client.post('/api/auth/logout', headers=auth_headers(token))
    assert result.status_code == 202
    assert result.json() == {'revoked': True, 'kernel_revocation': 'pending'}


def test_worker_restart_and_two_worker_delivery_lease(tmp_path):
    """File-backed DB: original process/session gone, two new workers race."""
    from sqlalchemy import create_engine, select
    from sqlalchemy.orm import sessionmaker
    from app.models import Base, Tenant, User, AuthSession, AuthRevocation
    from app.auth_sessions import revoke_local, deliver_revocation, revocation_worker
    from app.kernel.client import KernelResponse, KernelUnavailable
    url = f'sqlite:///{tmp_path / "sessions.db"}'
    database = create_engine(url)
    Base.metadata.create_all(database)
    factory = sessionmaker(database, expire_on_commit=False)
    sid = uuid.uuid4().hex
    with factory() as db:
        tenant = Tenant(id=uuid.uuid4().hex, name='restart fixture')
        user = User(id=uuid.uuid4().hex, tenant_id=tenant.id, email='restart@example.com', password_hash='fixture')
        session = AuthSession(id=sid, tenant_id=tenant.id, user_id=user.id, refresh_digest='0' * 64,
                              expires_at=datetime.now(timezone.utc) + timedelta(days=1))
        db.add_all([tenant, user, session]); db.commit()
        revoke_local(db, session, by=user.id, reason='test'); db.commit()
    database.dispose()
    database = create_engine(url)
    factory = sessionmaker(database, expire_on_commit=False)
    class Kernel:
        timeout = 1
        calls = 0
        fail = True
        async def call(self, method, path, **kwargs):
            self.calls += 1
            assert kwargs['session_id'] != kwargs['json']['session_id'] == sid
            assert kwargs['roles'] == ['session_revoker']
            assert kwargs['user_id'] != kwargs['json']['user_id']
            await asyncio.sleep(0.01)  # give competing worker a chance to claim
            if self.fail:
                raise KernelUnavailable('KERNEL_UNREACHABLE', 'synthetic lost response')
            return KernelResponse(201, {'revocation_id': str(uuid.uuid4()),
                'revoked_at': datetime.now(timezone.utc).isoformat(), 'approvals_revoked': 1}, 'fixture')
    kernel = Kernel()
    async def attempt():
        with factory() as db:
            return await deliver_revocation(db, kernel, db.get(AuthRevocation, sid))
    async def scenario():
        assert await asyncio.gather(attempt(), attempt()) == [False, False]
        assert kernel.calls == 1
        # Lease/backoff persists across process restart; an immediate retry is held.
        assert not await attempt()
        assert kernel.calls == 1
        with factory() as db:
            row = db.get(AuthRevocation, sid)
            assert row.attempts == 1 and row.confirmed_at is None
            row.next_attempt_at = datetime.now(timezone.utc) - timedelta(seconds=1)
            db.commit()
        kernel.fail = False
        stop = asyncio.Event()
        task = asyncio.create_task(revocation_worker(stop, interval=0.01, session_factory=factory, client=kernel))
        for _ in range(100):
            with factory() as db:
                if db.get(AuthRevocation, sid).confirmed_at:
                    break
            await asyncio.sleep(0.01)
        stop.set(); await task
        with factory() as db:
            row = db.get(AuthRevocation, sid)
            assert row.confirmed_at is not None and row.attempts == 2 and row.last_error == ''
            assert len(list(db.scalars(select(AuthRevocation)))) == 1
        assert kernel.calls == 2
    asyncio.run(scenario())
    database.dispose()


def test_concurrent_refresh_reuse_fails_closed(client, monkeypatch, tmp_path):
    from concurrent.futures import ThreadPoolExecutor
    from sqlalchemy import create_engine
    from sqlalchemy.orm import sessionmaker
    from app import db as dbmod
    from app.models import Base
    database = create_engine(f'sqlite:///{tmp_path / "refresh.db"}', connect_args={'check_same_thread': False})
    Base.metadata.create_all(database)
    monkeypatch.setattr(dbmod, '_SessionLocal', sessionmaker(database, expire_on_commit=False))
    token = signup(client, email=f'race-{uuid.uuid4().hex}@example.com')
    def rotate(_):
        return client.post('/api/auth/refresh', json={'refresh_token': token['refresh_token']})
    with ThreadPoolExecutor(2) as pool:
        results = list(pool.map(rotate, range(2)))
    assert sorted(r.status_code for r in results) == [200, 401]
    winner = next(r.json() for r in results if r.status_code == 200)
    assert client.get('/api/auth/me', headers=auth_headers(winner)).status_code == 401
    database.dispose()


@pytest.mark.parametrize('operation', ['password', 'delete', 'user_revoke'])
def test_account_security_changes_revoke_all_sessions_durably(client, operation):
    from sqlalchemy import select
    from sqlalchemy.orm import Session
    from app.models import AuthSession, AuthRevocation
    from .conftest import engine
    email = f'account-{uuid.uuid4().hex}@example.com'
    token = signup(client, email=email)
    other = client.post('/api/auth/login', json={'email': email, 'password': 'superSecret123!'}).json()
    uid = client.get('/api/auth/me', headers=auth_headers(token)).json()['id']
    if operation == 'password':
        result = client.post('/api/auth/change-password', headers=auth_headers(token),
                             json={'current_password': 'superSecret123!', 'new_password': 'New-superSecret456!'})
        assert result.status_code == 200
    elif operation == 'delete':
        result = client.request('DELETE', '/api/account', headers=auth_headers(token), json={'password': 'superSecret123!'})
        assert result.status_code == 202
    else:
        result = client.post('/api/agent-ops/revocations', headers=auth_headers(token), json={'user_id': uid})
        assert result.status_code == 503  # local protection commits even with kernel unavailable
        assert client.post('/api/auth/login', json={'email': email, 'password': 'superSecret123!'}).status_code == 403
    for pair in (token, other):
        assert client.get('/api/auth/me', headers=auth_headers(pair)).status_code == 401
        assert client.post('/api/auth/refresh', json={'refresh_token': pair['refresh_token']}).status_code == 401
    with Session(engine) as db:
        rows = list(db.scalars(select(AuthSession).where(AuthSession.user_id == uid)))
        assert len(rows) == 2 and all(row.revoked_at is not None for row in rows)
        assert all(db.get(AuthRevocation, row.id) is not None for row in rows)


@respx.mock
def test_refresh_preserves_kernel_session_binding(client, kernel_env):
    token = signup(client, email=f'binding-{uuid.uuid4().hex}@example.com')
    assertions = []
    def observe(request):
        assertions.append(verify_assertion(request))
        return httpx.Response(200, json=[])
    respx.get(f'{KERNEL}/internal/v1/approval-credentials').mock(side_effect=observe)
    assert client.get('/api/agent-ops/approval-credentials', headers=auth_headers(token)).status_code == 200
    token = client.post('/api/auth/refresh', json={'refresh_token': token['refresh_token']}).json()
    assert client.get('/api/agent-ops/approval-credentials', headers=auth_headers(token)).status_code == 200
    assert assertions[0]['session_id'] == assertions[1]['session_id']
    assert assertions[0]['jti'] != assertions[1]['jti']


def test_delayed_delivery_fails_readiness(client):
    from sqlalchemy.orm import Session
    from app.models import AuthRevocation
    from .conftest import engine
    token = signup(client, email=f'delayed-{uuid.uuid4().hex}@example.com')
    sid = client.get('/api/auth/sessions', headers=auth_headers(token)).json()[0]['id']
    assert client.post('/api/auth/logout', headers=auth_headers(token)).status_code == 202
    with Session(engine) as db:
        row = db.get(AuthRevocation, sid)
        row.created_at = datetime.now(timezone.utc) - timedelta(minutes=2)
        db.commit()
    response = client.get('/api/health/ready')
    assert response.status_code == 503
    assert response.json()['checks']['revocation_delivery'] == 'delayed'
    # Restore this fixture so the session-global test DB does not poison other tests.
    with Session(engine) as db:
        row = db.get(AuthRevocation, sid)
        row.created_at = datetime.now(timezone.utc)
        db.commit()
