"""S2: real MFA enrollment/login and fresh sensitive-action authentication."""
import uuid
from datetime import timedelta

import pyotp
import pytest

from .conftest import signup, auth_headers

pytestmark = pytest.mark.real_mfa


def enroll(client):
    email = f'mfa-{uuid.uuid4().hex}@example.com'
    limited = signup(client, email=email)
    response = client.post('/api/auth/mfa/enroll', headers=auth_headers(limited))
    assert response.status_code == 200
    secret = response.json()['secret']
    used_code = pyotp.TOTP(secret).now()
    completed = client.post('/api/auth/mfa/confirm', headers=auth_headers(limited), json={'code': used_code})
    assert completed.status_code == 200
    result = completed.json()
    result['used_code'] = used_code
    return email, secret, limited, result


def test_password_only_session_cannot_read_customer_data(client):
    token = signup(client, email=f'limited-{uuid.uuid4().hex}@example.com')
    response = client.get('/api/customers', headers=auth_headers(token))
    assert response.status_code == 403
    assert response.json()['detail']['code'] == 'MFA_REQUIRED'
    assert token['mfa_state'] == 'enrollment_required'


def test_enrollment_retires_pre_mfa_credentials_and_returns_backup_codes_once(client):
    email, secret, limited, result = enroll(client)
    assert result['tokens']['mfa_state'] == 'verified'
    assert result['tokens']['session_id'] != limited['session_id']
    assert len(set(result['recovery_codes'])) == 8
    assert client.get('/api/customers', headers=auth_headers(result['tokens'])).status_code == 200
    assert client.get('/api/customers', headers=auth_headers(limited)).status_code == 401
    assert client.post('/api/auth/refresh', json={'refresh_token': limited['refresh_token']}).status_code == 401
    login = client.post('/api/auth/login', json={'email': email, 'password': 'superSecret123!'}).json()
    assert login['mfa_state'] == 'verification_required'
    assert client.get('/api/customers', headers=auth_headers(login)).status_code == 403
    # The enrollment code has already been consumed, even in another session.
    replay = client.post('/api/auth/mfa/verify', headers=auth_headers(login), json={'code': result['used_code']})
    assert replay.status_code == 401
    backup = client.post('/api/auth/mfa/verify', headers=auth_headers(login), json={'recovery_code': result['recovery_codes'][0]})
    assert backup.status_code == 200
    assert not backup.json().get('recovery_codes')
    assert client.get('/api/customers', headers=auth_headers(backup.json()['tokens'])).status_code == 200


def test_sensitive_export_requires_a_separate_fresh_check(client):
    _, _, _, result = enroll(client)
    response = client.get('/api/account/export', headers=auth_headers(result['tokens']))
    assert response.status_code == 403
    assert response.json()['detail']['code'] == 'STEP_UP_REQUIRED'
    step = client.post('/api/auth/step-up', headers=auth_headers(result['tokens']),
        json={'password': 'superSecret123!', 'recovery_code': result['recovery_codes'][0]})
    assert step.status_code == 200
    assert client.get('/api/account/export', headers=auth_headers(result['tokens'])).status_code == 200


def test_every_sensitive_route_is_registered_and_refused_before_validation(client):
    import re
    from app.main import app
    from app.security import SENSITIVE_ROUTES
    _, _, _, result = enroll(client)
    registered = {(method, route.path) for route in app.routes for method in getattr(route, 'methods', [])}
    assert SENSITIVE_ROUTES <= registered
    for method, path in SENSITIVE_ROUTES:
        concrete = re.sub(r'\{[^}]+\}', 'test-id', path)
        response = client.request(method, concrete, headers=auth_headers(result['tokens']), json={})
        assert response.status_code == 403, (method, path, response.status_code)
        assert response.json()['detail']['code'] == 'STEP_UP_REQUIRED', (method, path)


def test_recovery_once_lockout_survives_new_login_and_stepup_expires(client):
    from app import db as dbmod
    from app.models import AuthSession
    from app.mfa import utcnow
    email, _, _, result = enroll(client)
    headers = auth_headers(result['tokens'])
    payload = {'password': 'superSecret123!', 'recovery_code': result['recovery_codes'][0]}
    assert client.post('/api/auth/step-up', headers=headers, json=payload).status_code == 200
    assert client.post('/api/auth/step-up', headers=headers, json=payload).status_code == 401
    with dbmod._SessionLocal() as db:
        row = db.get(AuthSession, result['tokens']['session_id'])
        row.step_up_at = utcnow() - timedelta(minutes=6)
        db.commit()
    assert client.get('/api/account/export', headers=headers).status_code == 403
    for _ in range(4):
        assert client.post('/api/auth/step-up', headers=headers, json={**payload, 'password': 'wrong'}).status_code == 401
    login = client.post('/api/auth/login', json={'email': email, 'password': 'superSecret123!'}).json()
    response = client.post('/api/auth/mfa/verify', headers=auth_headers(login), json={'recovery_code': result['recovery_codes'][1]})
    assert response.status_code == 429
    assert client.post('/api/auth/mfa/enroll', headers=headers).status_code in (403, 429)


def test_factor_storage_is_bound_encrypted_and_backups_are_hashes(client):
    from app import db as dbmod, mfa
    from app.models import AuthFactor, AuthRecoveryCode, User
    from sqlalchemy import select
    from cryptography.exceptions import InvalidTag
    email, secret, _, result = enroll(client)
    with dbmod._SessionLocal() as db:
        user = db.scalar(select(User).where(User.email == email))
        row = db.get(AuthFactor, user.id)
        assert secret not in row.secret_enc and row.pending_secret_enc is None
        assert mfa.unseal(user, row.secret_enc) == secret
        different = User(id=uuid.uuid4().hex, tenant_id=user.tenant_id)
        with pytest.raises(InvalidTag):
            mfa.unseal(different, row.secret_enc)
        for recovery in db.scalars(select(AuthRecoveryCode).where(AuthRecoveryCode.user_id == user.id)):
            assert len(recovery.digest) == 64
            assert recovery.digest not in result['recovery_codes']
    status = client.get('/api/auth/mfa/status', headers=auth_headers(result['tokens']))
    assert status.json() == {'enrolled': True, 'recovery_codes_remaining': 8}
    assert secret not in status.text


def test_limited_refresh_cannot_extend_enrollment_and_can_sign_out(client):
    from app import db as dbmod
    from app.models import AuthSession
    limited = signup(client, email=f'limited-life-{uuid.uuid4().hex}@example.com')
    with dbmod._SessionLocal() as db:
        before = db.get(AuthSession, limited['session_id']).expires_at
    rotated = client.post('/api/auth/refresh', json={'refresh_token': limited['refresh_token']}).json()
    assert rotated['mfa_state'] == 'enrollment_required'
    with dbmod._SessionLocal() as db:
        after = db.get(AuthSession, limited['session_id']).expires_at
    assert before == after
    signed_out = client.post('/api/auth/logout', headers=auth_headers(rotated))
    assert signed_out.status_code == 202  # local revoke durable, kernel not configured in this test
    assert signed_out.json()['kernel_revocation'] == 'pending'
    assert client.post('/api/auth/mfa/enroll', headers=auth_headers(rotated)).status_code == 401


def test_factor_replacement_preserves_old_until_confirm_then_revokes_all(client):
    email, _, _, result = enroll(client)
    headers = auth_headers(result['tokens'])
    assert client.post('/api/auth/mfa/enroll', headers=headers).status_code == 403
    assert client.post('/api/auth/step-up', headers=headers, json={'password': 'superSecret123!', 'recovery_code': result['recovery_codes'][0]}).status_code == 200
    pending = client.post('/api/auth/mfa/enroll', headers=headers)
    assert pending.status_code == 200
    assert pending.headers['cache-control'] == 'no-store'
    login = client.post('/api/auth/login', json={'email': email, 'password': 'superSecret123!'}).json()
    assert client.post('/api/auth/mfa/enroll', headers=auth_headers(login)).status_code == 403
    verified = client.post('/api/auth/mfa/verify', headers=auth_headers(login), json={'recovery_code': result['recovery_codes'][1]})
    assert verified.status_code == 200  # pending replacement did not erase the active factor
    updated = client.post('/api/auth/mfa/confirm', headers=headers, json={'code': pyotp.TOTP(pending.json()['secret']).now()})
    assert updated.status_code == 200
    for old in (result['tokens'], verified.json()['tokens']):
        assert client.get('/api/customers', headers=auth_headers(old)).status_code == 401
    fresh = client.post('/api/auth/login', json={'email': email, 'password': 'superSecret123!'}).json()
    assert client.post('/api/auth/mfa/verify', headers=auth_headers(fresh), json={'recovery_code': result['recovery_codes'][2]}).status_code == 401


@pytest.mark.parametrize('kind', ['totp', 'recovery'])
def test_two_simultaneous_verifications_consume_factor_exactly_once(client, monkeypatch, tmp_path, kind):
    from concurrent.futures import ThreadPoolExecutor
    from sqlalchemy import create_engine
    from sqlalchemy.orm import sessionmaker
    from app import db as dbmod, mfa
    from app.models import Base
    database = create_engine(f'sqlite:///{tmp_path / "mfa.db"}', connect_args={'check_same_thread': False})
    Base.metadata.create_all(database)
    monkeypatch.setattr(dbmod, '_SessionLocal', sessionmaker(database, expire_on_commit=False))
    email, secret, _, result = enroll(client)
    logins = [client.post('/api/auth/login', json={'email': email, 'password': 'superSecret123!'}).json() for _ in range(2)]
    instant = mfa.utcnow() + timedelta(seconds=30)
    monkeypatch.setattr(mfa, 'utcnow', lambda: instant)
    payload = {'code': pyotp.TOTP(secret).at(instant)} if kind == 'totp' else {'recovery_code': result['recovery_codes'][0]}
    def verify(token):
        return client.post('/api/auth/mfa/verify', headers=auth_headers(token), json=payload)
    with ThreadPoolExecutor(2) as pool:
        outcomes = list(pool.map(verify, logins))
    assert sorted(response.status_code for response in outcomes) == [200, 401]
    database.dispose()


def test_lockout_committing_during_recovery_verification_cannot_be_cleared(client, monkeypatch, tmp_path):
    from sqlalchemy import create_engine, select
    from sqlalchemy.orm import sessionmaker
    from app import db as dbmod, mfa
    from app.models import Base, AuthFactor, User
    database = create_engine(f'sqlite:///{tmp_path / "lock.db"}', connect_args={'check_same_thread': False})
    Base.metadata.create_all(database)
    factory = sessionmaker(database, expire_on_commit=False)
    monkeypatch.setattr(dbmod, '_SessionLocal', factory)
    email, _, _, result = enroll(client)
    login = client.post('/api/auth/login', json={'email': email, 'password': 'superSecret123!'}).json()
    original = mfa.check_limit
    def racing_lock(db, factor):
        original(db, factor)
        with factory() as other:
            row = other.get(AuthFactor, factor.user_id)
            row.failed_attempts, row.locked_until = 5, mfa.utcnow() + timedelta(minutes=15)
            other.commit()
    monkeypatch.setattr(mfa, 'check_limit', racing_lock)
    response = client.post('/api/auth/mfa/verify', headers=auth_headers(login), json={'recovery_code': result['recovery_codes'][0]})
    assert response.status_code in (401, 429)
    with factory() as db:
        user = db.scalar(select(User).where(User.email == email))
        assert db.get(AuthFactor, user.id).locked_until is not None
    database.dispose()


def test_enabling_dispatch_needs_stepup_but_emergency_stop_does_not(client, monkeypatch):
    from app.routes import agent_ops
    _, _, _, result = enroll(client)
    calls = []
    async def forward(*args, **kwargs):
        calls.append(kwargs['json'])
        return {'ok': True}
    monkeypatch.setattr(agent_ops, 'forward', forward)
    headers = auth_headers(result['tokens'])
    response = client.post('/api/agent-ops/kill-switch/tenant', headers=headers, json={'dispatch_enabled': True})
    assert response.status_code == 403 and response.json()['detail']['code'] == 'STEP_UP_REQUIRED'
    assert not calls
    response = client.post('/api/agent-ops/kill-switch/tenant', headers=headers, json={'dispatch_enabled': False})
    assert response.status_code == 200 and calls == [{'dispatch_enabled': False}]


def test_recovery_rotation_and_account_deletion_remove_old_credentials(client):
    from sqlalchemy import select
    from app import db as dbmod
    from app.models import AuthFactor, AuthRecoveryCode, User
    email, _, _, result = enroll(client)
    headers = auth_headers(result['tokens'])
    assert client.post('/api/auth/mfa/recovery-codes', headers=headers).status_code == 403
    assert client.post('/api/auth/step-up', headers=headers,
        json={'password': 'superSecret123!', 'recovery_code': result['recovery_codes'][0]}).status_code == 200
    replacement = client.post('/api/auth/mfa/recovery-codes', headers=headers)
    assert replacement.status_code == 200 and replacement.headers['cache-control'] == 'no-store'
    new_codes = replacement.json()['recovery_codes']
    assert len(new_codes) == 8 and not set(new_codes).intersection(result['recovery_codes'])
    login = client.post('/api/auth/login', json={'email': email, 'password': 'superSecret123!'}).json()
    assert client.post('/api/auth/mfa/verify', headers=auth_headers(login), json={'recovery_code': result['recovery_codes'][1]}).status_code == 401
    with dbmod._SessionLocal() as db:
        uid = db.scalar(select(User.id).where(User.email == email))
    deleted = client.request('DELETE', '/api/account', headers=headers, json={'password': 'superSecret123!'})
    assert deleted.status_code == 202
    with dbmod._SessionLocal() as db:
        assert db.get(AuthFactor, uid) is None
        assert not list(db.scalars(select(AuthRecoveryCode).where(AuthRecoveryCode.user_id == uid)))
