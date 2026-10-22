"""Built-UI H1/H8 ceremony with explicit HTTP fixtures and a real virtual passkey.

The Rust integration test separately checks policy with PostgreSQL. This script
checks browser rendering, gestures, cancellation boundaries and ES256 assertions;
it is author-run local evidence, not an independent staging record.
"""
import argparse
import base64
import hashlib
import json
import secrets
from pathlib import Path
from urllib.parse import urlsplit

from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from playwright.sync_api import expect, sync_playwright

from submission_resolution_browser import b64, decode


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--web", default="http://localhost:4189")
    parser.add_argument("--output", required=True, type=Path)
    args = parser.parse_args()
    args.output.mkdir(parents=True, exist_ok=True)
    origin, rp_id = args.web.rstrip("/"), urlsplit(args.web).hostname
    private, credential = ec.generate_private_key(ec.SECP256R1()), secrets.token_bytes(32)
    challenge = b""
    phase, completed, signed = "forbidden", False, 0
    calls, errors = [], []
    item = {
        "action_id": "11111111-1111-4111-8111-111111111111", "action_digest": "sha256:" + "b" * 64,
        "state": "approval_required", "message_state": "awaiting_approval", "exact_text": "Hello Brenda. Reply STOP to opt out.",
        "destination_masked": "********0100", "channel": "sms", "purpose": "customer_requested_follow_up",
        "workflow": "customer_follow_up", "risk": "high", "customer": {"id": "c1", "name": "Brenda Lee"},
        "sending_business": {"sender_identity_id": "s2", "display_name": "Selected Business", "from_number": "+15005550006", "registration_status": "registered"},
        "supporting": {"commitment": {"id": "k1", "text": "Customer requested tomorrow", "status": "confirmed", "evidence_digest": "sha256:" + "a" * 64}, "draft_version_id": "d2", "evidence_count": 2},
        "permission": {"state": "active", "checked_at": "2026-10-22T12:00:00Z", "note": "historical observation; checked again at send time"},
        "scheduled_for": "2026-10-23T17:00:00Z", "approval_expires_at": "2026-10-23T18:00:00Z",
        "approval_lifetime_minutes": 5, "self_approval": True, "human_steps": [],
    }
    with sync_playwright() as pw:
        browser = pw.chromium.launch(headless=True)
        page = browser.new_page(viewport={"width": 360, "height": 800}, timezone_id="America/Chicago")
        page.on("pageerror", lambda e: errors.append(str(e)))
        cdp = page.context.new_cdp_session(page)
        cdp.send("WebAuthn.enable")
        authenticator = cdp.send("WebAuthn.addVirtualAuthenticator", {"options": {"protocol": "ctap2", "transport": "internal",
            "hasResidentKey": True, "hasUserVerification": True, "isUserVerified": True, "automaticPresenceSimulation": True}})["authenticatorId"]
        cdp.send("WebAuthn.addCredential", {"authenticatorId": authenticator, "credential": {
            "credentialId": base64.b64encode(credential).decode(), "isResidentCredential": False, "rpId": rp_id,
            "privateKey": base64.b64encode(private.private_bytes(serialization.Encoding.DER, serialization.PrivateFormat.PKCS8,
                                                               serialization.NoEncryption())).decode(), "signCount": 0}})

        def respond(route):
            nonlocal challenge, completed, signed
            path = urlsplit(route.request.url).path
            calls.append({"method": route.request.method, "path": path, "phase": phase})
            status = 200
            if path == "/api/approvals/pending":
                payload = [] if completed else [{**item, "can_approve": phase != "forbidden",
                    "approval_denial": "self_approval_forbidden" if phase == "forbidden" else None,
                    "sending_business": None if phase == "missing_sender" else item["sending_business"]}]
            elif path.endswith("/approval-challenge"):
                assert phase not in ("forbidden", "missing_sender")
                challenge = secrets.token_bytes(32)
                payload = {"challenge": b64(challenge), "rp_id": rp_id, "action_digest": "sha256:" + ("c" if phase == "stale" else "b") * 64,
                    "expires_at": "2026-10-23T18:00:00Z", "allow_credentials": [b64(credential)],
                    "user_verification": "preferred" if phase == "weak_uv" else "required"}
            elif path.endswith("/approve"):
                assert phase in ("deny", "accept")
                body = route.request.post_data_json
                assert body["action_digest"] == item["action_digest"]
                wa = body["webauthn"]
                assert decode(wa["credential_id"]) == credential
                cdj = decode(wa["client_data_json"])
                client_data = json.loads(cdj)
                assert client_data["type"] == "webauthn.get" and client_data["origin"] == origin and client_data["challenge"] == b64(challenge)
                ad = decode(wa["authenticator_data"])
                assert ad[:32] == hashlib.sha256(rp_id.encode()).digest() and ad[32] & 5 == 5
                private.public_key().verify(decode(wa["signature"]), ad + hashlib.sha256(cdj).digest(), ec.ECDSA(hashes.SHA256()))
                signed += 1
                if phase == "deny":
                    status, payload = 403, {"detail": {"code": "self_approval_forbidden"}}
                else:
                    completed, payload = True, {"result": {"state": "queued", "message_state": "queued"}, "approval": {"expires_at": "2026-10-23T17:05:00Z"}}
            else:
                payload = {"/api/auth/me": {"id": "u1", "role": "consultant", "email": "fixture@example.com", "display_name": "Synthetic consultant"},
                           "/api/brief": {"date": "2026-10-22", "items": []}}.get(path)
                assert payload is not None, f"Unmocked endpoint {path}"
            route.fulfill(status=status, content_type="application/json", body=json.dumps(payload))

        page.route("**/api/**", respond)
        page.add_init_script("sessionStorage.setItem('mk_tokens', JSON.stringify({access_token:'fixture',refresh_token:'fixture',role:'consultant'})); sessionStorage.setItem('cs_ai_notice_seen','1');")

        def open_approvals():
            page.goto(origin)
            page.get_by_role("navigation", name="Main").get_by_role("button", name="Approvals").click()
            expect(page.get_by_role("blockquote", name="Exact message text")).to_have_text(item["exact_text"])

        open_approvals()
        button = page.get_by_role("button", name="Approve this message with passkey")
        expect(button).to_be_disabled()
        expect(page.get_by_text("A different authorized person must approve", exact=False)).to_be_visible()
        phase = "missing_sender"
        open_approvals()
        expect(button).to_be_disabled()
        expect(page.get_by_text("Selected sender details are unavailable", exact=False)).to_be_visible()
        phase = "stale"
        open_approvals()
        expect(page.get_by_text("Selected Business", exact=False)).to_be_visible()
        expect(page.get_by_text("5 minute lifetime", exact=False)).to_be_visible()
        expect(page.get_by_text("Oct 23, 2026, 12:00 PM", exact=True)).to_be_visible()
        button.click()
        expect(page.get_by_role("alert")).to_contain_text("changed since it was displayed")
        phase = "weak_uv"
        button.click()
        expect(page.get_by_role("alert")).to_contain_text("requires a verified passkey")
        credentials = cdp.send("WebAuthn.getCredentials", {"authenticatorId": authenticator})["credentials"]
        assert credentials[0]["signCount"] == 0 and signed == 0
        phase = "deny"
        button.click()
        expect(page.get_by_role("alert")).to_contain_text("requires a second person")
        expect(button).to_be_enabled()
        assert signed == 1
        page.screenshot(path=str(args.output / "approval-policy-360.png"), full_page=True)
        page.get_by_role("heading", name="Approvals", exact=True).scroll_into_view_if_needed()
        page.screenshot(path=str(args.output / "approval-preview-360.png"), full_page=True)
        width = page.evaluate("({viewport:innerWidth,document:document.documentElement.scrollWidth})")
        assert width["document"] == 360, width
        phase = "accept"
        button.focus()
        page.keyboard.press("Enter")
        expect(page.get_by_text("Nothing waiting for approval.", exact=True)).to_be_visible()
        expect(page.get_by_role("status")).to_contain_text("Approved — now queued")
        assert signed == 2 and not errors
        assert all(c["method"] == "GET" or c["path"].endswith(("/approval-challenge", "/approve")) for c in calls)
        report = {"environment": "built UI; explicit API fixtures; real Chromium virtual passkey, ES256 verified",
                  "checks": ["selected sender and scheduled time", "self-policy disable", "missing sender disables",
                             "stale digest aborts before signing", "UV downgrade aborts before signing", "policy refusal preserves pending item",
                             "keyboard per-message approval", "success survives queue refresh", "360px no overflow"],
                  "verified_assertions": signed, "browser_errors": errors, "width_360": width, "requests": calls, "provider_calls": 0}
        (args.output / "approval-browser.json").write_text(json.dumps(report, indent=2) + "\n", encoding="utf-8")
        print(json.dumps(report))
        browser.close()


if __name__ == "__main__":
    main()
