"""S3: explicit tenant roles, no implicit consultant fallback, revocable grants."""
import uuid

import pytest
from sqlalchemy import select

from .conftest import auth_headers, signup


def team(client):
    token = signup(client, email=f'rbac-admin-{uuid.uuid4().hex}@example.com')
    return token, auth_headers(token)


def member(client, headers, role):
    email = f'rbac-{uuid.uuid4().hex}@example.com'
    response = client.post('/api/auth/members', headers=headers, json={'email': email, 'password': 'superSecret123!', 'role': role})
    assert response.status_code == 201
    login = client.post('/api/auth/login', json={'email': email, 'password': 'superSecret123!'})
    assert login.status_code == 200
    return response.json()['id'], login.json(), auth_headers(login.json())


def test_unknown_roles_never_receive_consultant_or_agent_authority(client):
    from app import db as dbmod
    from app.models import User
    from app.kernel.assertions import roles_for
    token, headers = team(client)
    with dbmod._SessionLocal() as db:
        user = db.scalar(select(User).where(User.tenant_id == token['tenant_id']))
        user.role = 'unrecognized'
        db.commit()
    assert client.get('/api/customers', headers=headers).status_code == 403
    for as_agent in (False, True):
        with pytest.raises(ValueError):
            roles_for('unrecognized', as_agent=as_agent)


def test_manager_and_auditor_are_distinct_from_admin_and_consultant(client):
    _, admin = team(client)
    _, _, manager = member(client, admin, 'manager')
    _, _, auditor = member(client, admin, 'auditor')
    assert client.get('/api/usage/tenant', headers=manager).status_code == 200
    assert client.get('/api/auth/members', headers=manager).status_code == 403
    assert client.post('/api/auth/members', headers=manager, json={'email': 'deny@example.com', 'password': 'superSecret123!'}).status_code == 403
    assert client.get('/api/audit/export.jsonl', headers=auditor).status_code == 200
    for method, path in [('GET', '/api/customers'), ('POST', '/api/chat/stream'), ('POST', '/api/agent-ops/actions'),
                         ('GET', '/api/agent-ops/senders'), ('PUT', '/api/keys/mine')]:
        response = client.request(method, path, headers=auditor, json={})
        assert response.status_code == 403, (method, path, response.status_code)
    assert client.get('/api/auth/me', headers=auditor).status_code == 200


def test_role_change_is_tenant_scoped_revokes_sessions_and_audits(client):
    from app import db as dbmod
    from app.models import AuditLog, AuthRevocation, User
    token, admin = team(client)
    uid, old, _ = member(client, admin, 'consultant')
    foreign_token, foreign = team(client)
    assert client.patch(f'/api/auth/members/{uid}', headers=foreign, json={'role': 'admin'}).status_code == 404
    response = client.patch(f'/api/auth/members/{uid}', headers=admin, json={'role': 'auditor'})
    assert response.status_code == 200
    assert client.get('/api/customers', headers=auth_headers(old)).status_code == 401
    assert client.post('/api/auth/refresh', json={'refresh_token': old['refresh_token']}).status_code == 401
    with dbmod._SessionLocal() as db:
        user = db.get(User, uid)
        assert user.role == 'auditor' and user.tenant_id == token['tenant_id'] != foreign_token['tenant_id']
        assert db.get(AuthRevocation, old['session_id']) is not None
        assert db.scalar(select(AuditLog).where(AuditLog.tenant_id == token['tenant_id'], AuditLog.action == 'member.access_change'))
    listed = client.get('/api/auth/members', headers=admin)
    assert listed.status_code == 200 and any(item['id'] == uid and item['role'] == 'auditor' for item in listed.json())
    assert uid not in str(client.get('/api/auth/members', headers=foreign).json())


def test_admin_cannot_disable_self_or_assign_platform_operator(client):
    _, admin = team(client)
    uid = client.get('/api/auth/me', headers=admin).json()['id']
    assert client.patch(f'/api/auth/members/{uid}', headers=admin, json={'is_active': False}).status_code == 409
    assert client.patch(f'/api/auth/members/{uid}', headers=admin, json={'role': 'consultant'}).status_code == 409
    assert client.post('/api/auth/members', headers=admin, json={'email': 'platform-denied@example.com', 'password': 'superSecret123!', 'role': 'platform_operator'}).status_code == 422


def test_auditor_allowlist_is_fail_closed_on_every_authenticated_route(client):
    import re
    from app.main import app
    from app.authorization import AUDITOR_ROUTES
    from app.security import get_current_user
    _, admin = team(client)
    _, _, auditor = member(client, admin, 'auditor')
    def protected(dependency):
        return dependency.call == get_current_user or any(protected(child) for child in dependency.dependencies)
    checked = 0
    for route in app.routes:
        if not getattr(route, 'dependant', None) or not protected(route.dependant):
            continue
        for method in route.methods:
            if (method, route.path) in AUDITOR_ROUTES:
                continue
            path = re.sub(r'\{[^}]+\}', 'denied-resource', route.path)
            response = client.request(method, path, headers=auditor, json={})
            assert response.status_code == 403, (method, path, response.status_code)
            assert response.json()['detail']['code'] == 'ROLE_FORBIDDEN'
            checked += 1
    assert checked > 70


def test_concurrent_administrators_cannot_disable_each_other(client, monkeypatch, tmp_path):
    from concurrent.futures import ThreadPoolExecutor
    from threading import Barrier
    from sqlalchemy import create_engine
    from sqlalchemy.orm import sessionmaker
    from app import db as dbmod
    from app.models import Base, User
    database = create_engine(f'sqlite:///{tmp_path / "admins.db"}', connect_args={'check_same_thread': False})
    Base.metadata.create_all(database)
    factory = sessionmaker(database, expire_on_commit=False)
    monkeypatch.setattr(dbmod, '_SessionLocal', factory)
    _, admin = team(client)
    first = client.get('/api/auth/me', headers=admin).json()['id']
    second, _, other = member(client, admin, 'admin')
    ready = Barrier(2)
    def disable(pair):
        headers, target = pair
        ready.wait(timeout=5)
        return client.patch(f'/api/auth/members/{target}', headers=headers, json={'is_active': False})
    with ThreadPoolExecutor(2) as pool:
        responses = list(pool.map(disable, [(admin, second), (other, first)]))
    statuses = [r.status_code for r in responses]
    assert statuses.count(200) == 1 and any(s in (401, 403) for s in statuses), statuses
    with factory() as db:
        assert len(list(db.scalars(select(User).where(User.is_active.is_(True), User.role == 'admin')))) == 1
    database.dispose()
