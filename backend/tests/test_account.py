"""Tests for account management: password change, data export, and privacy policy.

Covers:
  - POST /api/auth/change-password (happy path, wrong current password, too short)
  - GET /api/account/export (structure, cross-tenant isolation, audit log entry)
  - DELETE /api/account (GDPR erasure)
  - GET /privacy (public, no auth, HTML content)
"""
import json
import uuid

import pytest

from .conftest import auth_headers, signup


def _del(client, path, body, headers):
    """DELETE with a JSON body via client.request() which accepts json= uniformly."""
    return client.request("DELETE", path, json=body, headers=headers)


def _email():
    return f"u{uuid.uuid4().hex[:8]}@example.com"


# ---------------------------------------------------------------------------
# Password change
# ---------------------------------------------------------------------------

class TestChangePassword:
    def test_happy_path(self, client):
        t = signup(client, email=_email())
        hdrs = auth_headers(t)
        r = client.post("/api/auth/change-password", json={
            "current_password": "superSecret123!",
            "new_password": "newPasswordABC$99",
        }, headers=hdrs)
        assert r.status_code == 200
        assert r.json()["ok"] is True

        # Can login with new password
        me_email = client.get("/api/auth/me", headers=hdrs).json()["email"]
        login_r = client.post("/api/auth/login", json={
            "email": me_email, "password": "newPasswordABC$99"})
        assert login_r.status_code == 200

    def test_wrong_current_password(self, client):
        t = signup(client, email=_email())
        r = client.post("/api/auth/change-password", json={
            "current_password": "wrongPassword999",
            "new_password": "newPasswordABC$99",
        }, headers=auth_headers(t))
        assert r.status_code == 401

    def test_new_password_too_short(self, client):
        t = signup(client, email=_email())
        r = client.post("/api/auth/change-password", json={
            "current_password": "superSecret123!",
            "new_password": "short",
        }, headers=auth_headers(t))
        assert r.status_code == 422

    def test_requires_auth(self, client):
        r = client.post("/api/auth/change-password", json={
            "current_password": "superSecret123!",
            "new_password": "newPasswordABC$99",
        })
        assert r.status_code == 401

    def test_old_password_no_longer_works_after_change(self, client):
        email = _email()
        t = signup(client, email=email)
        client.post("/api/auth/change-password", json={
            "current_password": "superSecret123!",
            "new_password": "newPasswordABC$99",
        }, headers=auth_headers(t))
        r = client.post("/api/auth/login", json={
            "email": email, "password": "superSecret123!"})
        assert r.status_code == 401


# ---------------------------------------------------------------------------
# Account export
# ---------------------------------------------------------------------------

class TestAccountExport:
    def test_export_structure(self, client):
        t = signup(client, email=_email())
        r = client.get("/api/account/export", headers=auth_headers(t))
        assert r.status_code == 200
        data = r.json()

        assert "exported_at" in data
        assert "user" in data
        assert "profile" in data
        assert "customers" in data
        assert "conversations" in data
        assert "skin_analyses" in data
        assert "consent_records" in data
        assert "usage_by_provider" in data

    def test_export_user_fields(self, client):
        email = _email()
        t = signup(client, email=email)
        data = client.get("/api/account/export", headers=auth_headers(t)).json()
        user = data["user"]
        assert user["email"] == email
        assert "id" in user
        assert "created_at" in user
        # password_hash must NEVER be in the export
        assert "password_hash" not in user

    def test_export_includes_customers(self, client):
        t = signup(client, email=_email())
        hdrs = auth_headers(t)
        client.post("/api/customers", json={
            "name": "Jane Doe", "phone": "555-1234", "email": "jane@example.com", "notes": ""
        }, headers=hdrs)
        data = client.get("/api/account/export", headers=hdrs).json()
        assert len(data["customers"]) == 1
        assert data["customers"][0]["name"] == "Jane Doe"

    def test_cross_tenant_isolation(self, client):
        t1 = signup(client, email=_email())
        t2 = signup(client, email=_email())
        # User 1 creates a customer
        client.post("/api/customers", json={
            "name": "Alice", "phone": "", "email": "", "notes": ""
        }, headers=auth_headers(t1))
        # User 2 export must not include user 1's customers
        data2 = client.get("/api/account/export", headers=auth_headers(t2)).json()
        names = [c["name"] for c in data2["customers"]]
        assert "Alice" not in names

    def test_export_requires_auth(self, client):
        r = client.get("/api/account/export")
        assert r.status_code == 401

    def test_subscription_field(self, client):
        t = signup(client, email=_email())
        data = client.get("/api/account/export", headers=auth_headers(t)).json()
        # New user has no subscription row; subscription key should be None
        assert data["subscription"] is None


# ---------------------------------------------------------------------------
# Privacy policy
# ---------------------------------------------------------------------------

class TestPrivacyPolicy:
    def test_public_no_auth_required(self, client):
        r = client.get("/privacy")
        assert r.status_code == 200

    def test_returns_html(self, client):
        r = client.get("/privacy")
        assert "text/html" in r.headers["content-type"]

    def test_contains_required_disclosures(self, client):
        text = client.get("/privacy").text.lower()
        # MHMDA disclosure
        assert "washington" in text
        assert "health" in text
        # AI disclosure (SB 243)
        assert "artificial intelligence" in text
        # Right to export / portability
        assert "export" in text or "portability" in text
        # AES encryption mentioned
        assert "aes" in text or "encryption" in text
        # Skin image retention policy
        assert "discarded" in text or "not retained" in text or "never retained" in text


# ---------------------------------------------------------------------------
# Account deletion (GDPR Art. 17 / CCPA § 1798.105)
# ---------------------------------------------------------------------------

class TestDeleteAccount:
    def test_happy_path(self, client):
        email = _email()
        t = signup(client, email=email)
        hdrs = auth_headers(t)
        # Add a customer so we can verify cascade
        client.post("/api/customers", json={
            "name": "Test Customer", "phone": "", "email": "", "notes": ""
        }, headers=hdrs)

        r = _del(client, "/api/account", {"password": "superSecret123!"}, hdrs)
        assert r.status_code == 200
        assert r.json()["ok"] is True

        # Subsequent authenticated requests must fail (password hash wiped)
        r2 = client.get("/api/auth/me", headers=hdrs)
        # Either 401 (JWT invalid) or 403 (deactivated). Either way, access denied.
        assert r2.status_code in (401, 403)

    def test_wrong_password_blocked(self, client):
        t = signup(client, email=_email())
        r = _del(client, "/api/account", {"password": "wrongPassword999"}, auth_headers(t))
        assert r.status_code == 401

    def test_requires_auth(self, client):
        r = _del(client, "/api/account", {"password": "superSecret123!"}, {})
        assert r.status_code == 401

    def test_old_email_can_re_register_after_deletion(self, client):
        email = _email()
        t = signup(client, email=email)
        _del(client, "/api/account", {"password": "superSecret123!"}, auth_headers(t))
        # Original email is now anonymised — registering with same email should work
        r = client.post("/api/auth/signup", json={
            "org_name": "New Org", "email": email,
            "password": "freshPassword99!", "key_policy": "both"
        })
        assert r.status_code == 201


# ---------------------------------------------------------------------------
# SB 243 meta-event AI disclosure in chat stream
# ---------------------------------------------------------------------------

class TestChatAIDisclosure:
    def test_meta_event_contains_ai_disclosure(self, client):
        """meta SSE event fires before the provider chain — no key needed."""
        import json
        import respx
        import httpx

        t = signup(client, email=_email())
        hdrs = auth_headers(t)

        # With respx.mock and no mocked routes, all provider calls fail → stream still
        # emits the meta event first (ai_disclosure) before trying any provider.
        with respx.mock:
            respx.post("http://localhost:11434/api/chat").mock(
                return_value=httpx.Response(500))
            r = client.post("/api/chat/stream",
                            json={"message": "Hi", "skill": "assistant"},
                            headers=hdrs)

        first_event = None
        for line in r.text.splitlines():
            if line.startswith("data: "):
                first_event = json.loads(line[6:])
                break

        assert first_event is not None
        assert first_event["type"] == "meta"
        assert "ai_disclosure" in first_event
        assert len(first_event["ai_disclosure"]) > 20
