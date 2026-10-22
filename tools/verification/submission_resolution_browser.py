"""C4 browser ceremony against a built UI and explicit mock HTTP endpoints.

Uses Chromium's virtual authenticator, verifies its real ES256 assertion, and
checks stale evidence and kernel rejection remain visible. This is not staging
provider evidence; Rust's real-Postgres suite separately verifies the authority.
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


def b64(value):
    return base64.urlsafe_b64encode(value).decode().rstrip("=")


def decode(value):
    return base64.urlsafe_b64decode(value + "=" * (-len(value) % 4))


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--web", default="http://localhost:4189")
    parser.add_argument("--output", required=True, type=Path)
    args = parser.parse_args()
    args.output.mkdir(parents=True, exist_ok=True)
    origin = args.web.rstrip("/")
    rp_id = urlsplit(origin).hostname
    private = ec.generate_private_key(ec.SECP256R1())
    credential = secrets.token_bytes(32)
    challenge = secrets.token_bytes(32)
    phase = "stale"
    completed = False
    signed_count = 0
    calls, errors = [], []
    first = {"delivery_id": "0191f6f0-0000-4000-8000-000000000001", "action_id": "0191f6f0-0000-4000-8000-000000000101",
             "action_state": "reconciliation_required", "delivery_state": "submission_unknown", "message_state": "submission_unknown",
             "provider_message_id": None, "read_status": "unknown", "customer_id": "c1", "customer_name": "Unknown attempt",
             "created_at": "2026-10-21T12:00:00Z", "reconciled_at": None, "replacement_allowed": False, "resolution_options": []}
    second = {**first, "delivery_id": "0191f6f0-0000-4000-8000-000000000002", "action_id": "0191f6f0-0000-4000-8000-000000000102",
              "delivery_state": "failed", "provider_message_id": "SM" + "a" * 32, "customer_name": "Verified failed attempt",
              "resolution_options": ["replacement_permitted"]}
    with sync_playwright() as pw:
        browser = pw.chromium.launch(headless=True)
        page = browser.new_page(viewport={"width": 1280, "height": 900})
        page.on("pageerror", lambda e: errors.append(str(e)))
        cdp = page.context.new_cdp_session(page)
        cdp.send("WebAuthn.enable")
        authenticator = cdp.send("WebAuthn.addVirtualAuthenticator", {"options": {"protocol": "ctap2", "transport": "internal",
            "hasResidentKey": True, "hasUserVerification": True, "isUserVerified": True, "automaticPresenceSimulation": True}})["authenticatorId"]
        cdp.send("WebAuthn.addCredential", {"authenticatorId": authenticator, "credential": {
            "credentialId": base64.b64encode(credential).decode(), "isResidentCredential": False, "rpId": rp_id,
            "privateKey": base64.b64encode(private.private_bytes(serialization.Encoding.DER,
                serialization.PrivateFormat.PKCS8, serialization.NoEncryption())).decode(), "signCount": 0}})

        def respond(route):
            nonlocal completed, signed_count
            path = urlsplit(route.request.url).path
            calls.append({"method": route.request.method, "path": path})
            status = 200
            if path.endswith("/resolution-challenge"):
                assert route.request.post_data_json == {"decision": "replacement_permitted"}
                payload = {"challenge": b64(challenge), "rp_id": rp_id, "action_id": second["action_id"],
                    "decision": "replacement_permitted", "operation_digest": "sha256:" + "b" * 64,
                    "provider_message_id": "SM" + ("c" if phase == "stale" else "a") * 32,
                    "delivery_state": "failed", "allow_credentials": [b64(credential)], "user_verification": "required"}
            elif path.endswith("/resolve-submission"):
                assert phase != "stale", "stale displayed evidence must not reach authenticator or kernel decision"
                body = route.request.post_data_json
                assert body["decision"] == "replacement_permitted" and body["operation_digest"] == "sha256:" + "b" * 64
                assertion = body["webauthn"]
                assert decode(assertion["credential_id"]) == credential
                cdj = decode(assertion["client_data_json"])
                client_data = json.loads(cdj)
                assert client_data["type"] == "webauthn.get" and client_data["origin"] == origin
                assert client_data["challenge"] == b64(challenge)
                ad = decode(assertion["authenticator_data"])
                assert ad[:32] == hashlib.sha256(rp_id.encode()).digest() and ad[32] & 5 == 5
                private.public_key().verify(decode(assertion["signature"]), ad + hashlib.sha256(cdj).digest(), ec.ECDSA(hashes.SHA256()))
                signed_count += 1
                if phase == "reject":
                    status, payload = 409, {"detail": "Provider observation changed; review again"}
                else:
                    completed, payload = True, {"decision": "replacement_permitted"}
            elif path == "/api/delivery-exceptions":
                payload = {"items": [first] if completed else [first, second], "next_cursor": None}
            else:
                payload = {"/api/auth/me": {"id": "u1", "role": "admin", "email": "fixture@example.com", "display_name": "Synthetic operator"},
                    "/api/brief": {"date": "2026-10-21", "items": []}, "/api/exceptions": [],
                    "/api/agent-ops/inbound/health": {"health": {}, "dispatch_blocked": None, "pending_events": 0}}.get(path)
                assert payload is not None, f"Unmocked API: {path}"
            route.fulfill(status=status, content_type="application/json", body=json.dumps(payload))

        page.route("**/api/**", respond)
        page.add_init_script("sessionStorage.setItem('mk_tokens', JSON.stringify({access_token:'fixture',refresh_token:'fixture',role:'admin'})); sessionStorage.setItem('cs_ai_notice_seen','1');")
        page.goto(origin)
        page.wait_for_load_state("networkidle")
        page.get_by_role("navigation", name="Main").get_by_role("button", name="Inbox & exceptions").click()
        page.wait_for_load_state("networkidle")
        queue = page.get_by_role("region", name="Uncertain deliveries")
        expect(queue.get_by_role("listitem")).to_have_count(2)
        assert queue.get_by_role("listitem").first.get_by_role("button", name="passkey").count() == 0
        button = queue.get_by_role("button", name="Permit a newly approved replacement with passkey")
        button.click()
        expect(queue.get_by_text("Provider evidence changed. Refresh and review this attempt before resolving it.", exact=False)).to_be_visible()
        assert signed_count == 0
        phase = "reject"
        button.click()
        expect(queue.get_by_text("Provider observation changed; review again", exact=False)).to_be_visible()
        expect(queue.get_by_role("listitem")).to_have_count(2)
        assert signed_count == 1
        page.set_viewport_size({"width": 360, "height": 800})
        button.scroll_into_view_if_needed()
        page.screenshot(path=str(args.output / "resolution-360.png"), full_page=True)
        width = page.evaluate("({viewport:innerWidth,document:document.documentElement.scrollWidth})")
        assert width["document"] == 360, width
        phase = "accept"
        button.click()
        expect(queue.get_by_text("Resolution recorded. No message was sent.", exact=False)).to_be_visible()
        expect(queue.get_by_role("listitem")).to_have_count(1)
        assert signed_count == 2 and not errors
        assert all(c["method"] == "GET" or c["path"].endswith(("/resolution-challenge", "/resolve-submission")) for c in calls)
        result = {"environment": "built UI with explicit API fixtures; real Chromium virtual passkey, ES256 verified",
            "checks": ["unknown has no resolution control", "changed evidence aborts before signing", "kernel rejection retains exception",
                       "successful resolution refreshes queue, no send", "user-presence and user-verification flags", "360px no overflow"],
            "verified_assertions": signed_count, "browser_errors": errors, "provider_calls": 0, "requests": calls, "width_360": width}
        (args.output / "resolution-browser.json").write_text(json.dumps(result, indent=2) + "\n", encoding="utf-8")
        print(json.dumps(result))
        browser.close()


if __name__ == "__main__":
    main()
