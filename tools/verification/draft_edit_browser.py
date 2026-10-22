"""H2 built-UI edit flow with explicit API fixtures and real virtual passkeys.

Two tabs keep the proposed draft open while a human approves it. The kernel's
actual cancellation/race semantics are tested separately against PostgreSQL.
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
    origin, rp = args.web.rstrip("/"), urlsplit(args.web).hostname
    private, credential = ec.generate_private_key(ec.SECP256R1()), secrets.token_bytes(32)
    drafts = {"d1": {"id": "d1", "customer_id": "c1", "brief_item_id": "b1", "version": 1,
        "text": "Hello Brenda! Reply STOP to opt out.", "text_digest": "sha256:" + "a" * 64,
        "claims_used": [], "source_versions": {}, "generated_by": "ai:fixture", "note": ""}}
    actions, challenges, signed, calls, errors = {}, {}, [], [], []
    late = False
    with sync_playwright() as pw:
        browser = pw.chromium.launch(headless=True)
        context = browser.new_context(viewport={"width": 360, "height": 800})
        context.add_init_script("sessionStorage.setItem('mk_tokens',JSON.stringify({access_token:'fixture',refresh_token:'fixture',role:'consultant'}));sessionStorage.setItem('cs_ai_notice_seen','1');")

        def respond(route):
            path = urlsplit(route.request.url).path
            calls.append({"method": route.request.method, "path": path})
            status = 200
            if path == "/api/auth/me":
                payload = {"id": "u1", "role": "consultant", "email": "fixture@example.com", "display_name": "Synthetic consultant"}
            elif path == "/api/brief":
                payload = {"date": "2026-10-22", "items": [{"id": "b1", "customer": {"id": "c1", "name": "Brenda Lee"},
                    "rule": "due_today", "rank_category": 2, "source_type": "commitment", "source_reference": "k1",
                    "source": {"text": "Send the shade chart", "kind": "promise", "status": "confirmed"}, "due_at": "2026-10-22T14:00:00Z",
                    "state": "open", "permission_state": "active", "permission_checked_at": "2026-10-22T08:00:00Z",
                    "permission_note": "historical observation", "suggested_step": "Send the promised chart.",
                    "draft_version_id": None, "controls": ["approve", "edit", "defer", "resolve", "skip"]}]}
            elif path == "/api/drafts":
                status, payload = 201, {"draft": drafts["d1"], "limitation": None}
            elif path.endswith("/propose"):
                did = path.split("/")[-2]
                assert did in drafts and did not in actions
                actions[did] = "approval_required"
                status, payload = 202, {"state": "approval_required", "human_steps": []}
            elif path.endswith("/edit"):
                did = path.split("/")[-2]
                if late:
                    status, payload = 409, {"detail": {"code": "DRAFT_ALREADY_IN_FLIGHT"}}
                else:
                    assert did == "d1" and actions[did] == "queued"
                    actions[did] = "cancelled"
                    text = route.request.post_data_json["text"]
                    drafts["d2"] = {**drafts[did], "id": "d2", "version": 2, "text": text,
                        "text_digest": "sha256:" + hashlib.sha256(text.encode()).hexdigest()}
                    status, payload = 201, drafts["d2"]
            elif path == "/api/approvals/pending":
                payload = [{"action_id": did, "action_digest": d["text_digest"], "exact_text": d["text"],
                    "destination_masked": "********0100", "channel": "sms", "purpose": "customer_requested_follow_up",
                    "workflow": "customer_follow_up", "risk": "high", "customer": {"id": "c1", "name": "Brenda Lee"},
                    "sending_business": {"sender_identity_id": "s1", "display_name": "Selected Business", "from_number": "+15005550006", "registration_status": "registered"},
                    "supporting": {"commitment": None, "draft_version_id": did, "evidence_count": 1}, "permission": None,
                    "scheduled_for": None, "approval_expires_at": "2026-10-23T18:00:00Z", "approval_lifetime_minutes": 5,
                    "self_approval": True, "can_approve": True, "approval_denial": None, "human_steps": []}
                    for did, d in drafts.items() if actions.get(did) == "approval_required"]
            elif path.endswith("/approval-challenge"):
                did = path.split("/")[-2]
                assert actions[did] == "approval_required"
                challenges[did] = secrets.token_bytes(32)
                payload = {"challenge": b64(challenges[did]), "rp_id": rp, "action_digest": drafts[did]["text_digest"],
                    "expires_at": "2026-10-23T18:00:00Z", "allow_credentials": [b64(credential)], "user_verification": "required"}
            elif path.endswith("/approve"):
                did = path.split("/")[-2]
                body = route.request.post_data_json
                assert actions[did] == "approval_required" and body["action_digest"] == drafts[did]["text_digest"]
                wa = body["webauthn"]
                cdj, ad = decode(wa["client_data_json"]), decode(wa["authenticator_data"])
                cd = json.loads(cdj)
                assert decode(wa["credential_id"]) == credential
                assert cd["type"] == "webauthn.get" and cd["origin"] == origin and cd["challenge"] == b64(challenges[did])
                assert ad[:32] == hashlib.sha256(rp.encode()).digest() and ad[32] & 5 == 5
                private.public_key().verify(decode(wa["signature"]), ad + hashlib.sha256(cdj).digest(), ec.ECDSA(hashes.SHA256()))
                signed.append({"draft": did, "digest": body["action_digest"]})
                actions[did] = "queued"
                payload = {"result": {"state": "queued", "message_state": "queued"}, "approval": {"expires_at": "2026-10-23T17:05:00Z"}}
            else:
                raise AssertionError(f"Unmocked endpoint {path}")
            route.fulfill(status=status, content_type="application/json", body=json.dumps(payload))

        context.route("**/api/**", respond)
        editor, approver = context.new_page(), context.new_page()
        for page in (editor, approver):
            page.on("pageerror", lambda e: errors.append(str(e)))
        cdp = context.new_cdp_session(approver)
        cdp.send("WebAuthn.enable")
        auth = cdp.send("WebAuthn.addVirtualAuthenticator", {"options": {"protocol": "ctap2", "transport": "internal",
            "hasResidentKey": True, "hasUserVerification": True, "isUserVerified": True, "automaticPresenceSimulation": True}})["authenticatorId"]
        cdp.send("WebAuthn.addCredential", {"authenticatorId": auth, "credential": {"credentialId": base64.b64encode(credential).decode(),
            "isResidentCredential": False, "rpId": rp, "privateKey": base64.b64encode(private.private_bytes(serialization.Encoding.DER,
                serialization.PrivateFormat.PKCS8, serialization.NoEncryption())).decode(), "signCount": 0}})
        editor.goto(origin)
        editor.get_by_role("button", name="Draft a message").click()
        editor.get_by_role("button", name="Propose for approval", exact=True).click()
        expect(editor.get_by_text("Proposed for approval.", exact=True)).to_be_visible()

        def approve_current(did):
            approver.goto(origin)
            approver.get_by_role("navigation", name="Main").get_by_role("button", name="Approvals").click()
            expect(approver.get_by_role("blockquote", name="Exact message text")).to_have_text(drafts[did]["text"])
            button = approver.get_by_role("button", name="Approve this message with passkey")
            button.focus()
            approver.keyboard.press("Enter")
            expect(approver.get_by_role("status")).to_contain_text("Approved — now queued")

        approve_current("d1")
        editor.get_by_label("Exact text", exact=False).fill("Hello Brenda. Reply STOP to opt out.")
        editor.get_by_role("button", name="Save as new version").click()
        expect(editor.get_by_text("Old version withdrawn.", exact=False)).to_be_visible()
        assert actions == {"d1": "cancelled"} and len(signed) == 1
        editor.screenshot(path=str(args.output / "edited-version-360.png"), full_page=True)
        editor.get_by_role("button", name="Propose for approval", exact=True).click()
        expect(editor.get_by_text("Proposed for approval.", exact=True)).to_be_visible()
        assert actions["d2"] == "approval_required" and len(signed) == 1
        approve_current("d2")
        assert len(signed) == 2 and signed[0]["digest"] != signed[1]["digest"]
        late = True
        editor.get_by_label("Exact text", exact=False).fill("Hello Brenda!! Reply STOP to opt out.")
        editor.get_by_role("button", name="Save as new version").click()
        expect(editor.get_by_role("alert")).to_contain_text("Your edit was not saved")
        expect(editor.get_by_text("Old version withdrawn.", exact=False)).to_have_count(0)
        assert len(drafts) == 2 and len(signed) == 2 and not errors
        editor.screenshot(path=str(args.output / "late-edit-blocked-360.png"), full_page=True)
        width = editor.evaluate("({viewport:innerWidth,document:document.documentElement.scrollWidth})")
        assert width["document"] == width["viewport"] == 360
        editor.get_by_role("button", name="Close", exact=True).click(timeout=5000)
        expect(editor.get_by_role("dialog")).to_have_count(0)
        report = {"environment": "built UI; explicit API fixtures; real Chromium ES256 passkeys",
            "checks": ["two-tab approved draft edit", "one-byte edit changes digest", "old version withdrawal receipt",
                "replacement requires a fresh proposal and signature", "late edit refused without new version", "360px no overflow"],
            "verified_assertions": signed, "fixture_action_states": actions, "browser_errors": errors,
            "width": width, "requests": calls, "provider_calls": 0}
        (args.output / "draft-edit-browser.json").write_text(json.dumps(report, indent=2) + "\n", encoding="utf-8")
        print(json.dumps(report))
        browser.close()


if __name__ == "__main__":
    main()
