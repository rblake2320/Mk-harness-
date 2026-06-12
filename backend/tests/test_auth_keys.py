"""Auth lifecycle, RBAC, tenant isolation, key crypto, key policy enforcement."""
import uuid

import pytest

from app.crypto import decrypt_secret, encrypt_secret, key_aad
from tests.conftest import auth_headers, signup


def _email():
    return f"u{uuid.uuid4().hex[:10]}@example.com"


class TestAuth:
    def test_signup_login_refresh_me(self, client):
        email = _email()
        t = signup(client, email=email)
        assert t["role"] == "admin"

        r = client.post("/api/auth/login", json={"email": email, "password": "superSecret123!"})
        assert r.status_code == 200

        r = client.post("/api/auth/refresh", json={"refresh_token": t["refresh_token"]})
        assert r.status_code == 200

        r = client.get("/api/auth/me", headers=auth_headers(t))
        assert r.json()["tenant"]["key_policy"] == "both"

    def test_wrong_password_rejected(self, client):
        email = _email()
        signup(client, email=email)
        r = client.post("/api/auth/login", json={"email": email, "password": "wrongPassword1!"})
        assert r.status_code == 401

    def test_refresh_token_cannot_be_used_as_access(self, client):
        t = signup(client, email=_email())
        r = client.get("/api/auth/me",
                       headers={"Authorization": f"Bearer {t['refresh_token']}"})
        assert r.status_code == 401

    def test_short_password_rejected(self, client):
        r = client.post("/api/auth/signup", json={
            "org_name": "X", "email": _email(), "password": "short"})
        assert r.status_code == 422

    def test_duplicate_email_rejected(self, client):
        email = _email()
        signup(client, email=email)
        r = client.post("/api/auth/signup", json={
            "org_name": "Org Y", "email": email, "password": "superSecret123!"})
        assert r.status_code == 409

    def test_consultant_cannot_add_members(self, client):
        admin = signup(client, email=_email())
        member_email = _email()
        r = client.post("/api/auth/members", headers=auth_headers(admin), json={
            "email": member_email, "password": "consultPass123!"})
        assert r.status_code == 201
        member = client.post("/api/auth/login", json={
            "email": member_email, "password": "consultPass123!"}).json()
        r = client.post("/api/auth/members", headers=auth_headers(member), json={
            "email": _email(), "password": "anotherPass123!"})
        assert r.status_code == 403


class TestTenantIsolation:
    def test_conversations_isolated_across_tenants(self, client):
        a = signup(client, org="Org A", email=_email())
        b = signup(client, org="Org B", email=_email())
        # Tenant A creates a customer; tenant B must not see or mutate it.
        r = client.post("/api/customers", headers=auth_headers(a),
                        json={"name": "Alice Customer"})
        cid = r.json()["id"]
        r = client.get("/api/customers", headers=auth_headers(b))
        assert all(c["id"] != cid for c in r.json())
        r = client.delete(f"/api/customers/{cid}", headers=auth_headers(b))
        assert r.status_code == 404
        r = client.put(f"/api/customers/{cid}", headers=auth_headers(b),
                       json={"name": "Hijacked"})
        assert r.status_code == 404


class TestKeyCrypto:
    def test_roundtrip(self):
        mk = b"1" * 32
        ct = encrypt_secret(mk, "sk-test-12345", key_aad("t1", "u1", "openai"))
        assert decrypt_secret(mk, ct, key_aad("t1", "u1", "openai")) == "sk-test-12345"

    def test_aad_binding_prevents_cross_scope_reuse(self):
        """A ciphertext row copied to another user/tenant must not decrypt."""
        mk = b"1" * 32
        ct = encrypt_secret(mk, "sk-test-12345", key_aad("t1", "u1", "openai"))
        with pytest.raises(Exception):
            decrypt_secret(mk, ct, key_aad("t1", "u2", "openai"))
        with pytest.raises(Exception):
            decrypt_secret(mk, ct, key_aad("t2", "u1", "openai"))

    def test_wrong_master_key_fails(self):
        ct = encrypt_secret(b"1" * 32, "secret", key_aad("t", None, "anthropic"))
        with pytest.raises(Exception):
            decrypt_secret(b"2" * 32, ct, key_aad("t", None, "anthropic"))


class TestKeyPolicy:
    def test_byo_key_set_and_status(self, client):
        t = signup(client, email=_email())
        r = client.put("/api/keys/mine", headers=auth_headers(t),
                       json={"provider": "anthropic", "api_key": "sk-ant-test"})
        assert r.status_code == 200
        status = client.get("/api/keys/status", headers=auth_headers(t)).json()
        assert status["providers"]["anthropic"]["byo_key_set"] is True
        # Key never echoed back anywhere in status payload
        assert "sk-ant-test" not in str(status)

    def test_central_policy_blocks_byo(self, client):
        t = signup(client, email=_email(), key_policy="central")
        r = client.put("/api/keys/mine", headers=auth_headers(t),
                       json={"provider": "openai", "api_key": "sk-test"})
        assert r.status_code == 403

    def test_consultant_cannot_set_tenant_key(self, client):
        admin = signup(client, email=_email())
        member_email = _email()
        client.post("/api/auth/members", headers=auth_headers(admin), json={
            "email": member_email, "password": "consultPass123!"})
        member = client.post("/api/auth/login", json={
            "email": member_email, "password": "consultPass123!"}).json()
        r = client.put("/api/keys/tenant", headers=auth_headers(member),
                       json={"provider": "openai", "api_key": "sk-test"})
        assert r.status_code == 403

    def test_invalid_provider_rejected(self, client):
        t = signup(client, email=_email())
        r = client.put("/api/keys/mine", headers=auth_headers(t),
                       json={"provider": "skynet", "api_key": "k"})
        assert r.status_code == 422
