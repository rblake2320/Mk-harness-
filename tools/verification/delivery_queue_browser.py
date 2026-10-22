"""C7 component browser checks against the production web build.

API fixtures are explicit: these checks cover rendering, pagination, fail-visible
refresh, and absence of resend/dismiss controls. Kernel/provider integration is
covered separately by the real-PostgreSQL HTTP suite. No live customer is used.
"""
import argparse
import json
from pathlib import Path
from urllib.parse import urlsplit, parse_qs

from playwright.sync_api import expect, sync_playwright


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--web", default="http://127.0.0.1:4189")
    parser.add_argument("--output", required=True, type=Path)
    args = parser.parse_args()
    args.output.mkdir(parents=True, exist_ok=True)
    failed = False
    calls, errors = [], []
    first = {"delivery_id": "0191f6f0-0000-4000-8000-000000000001", "action_id": "0191f6f0-0000-4000-8000-000000000101",
             "action_state": "reconciliation_required", "delivery_state": "submission_unknown", "message_state": "submission_unknown",
             "provider_message_id": None, "read_status": "unknown", "customer_id": "c1", "customer_name": "Synthetic customer one",
             "created_at": "2026-10-21T12:00:00Z", "reconciled_at": None, "replacement_allowed": False}
    second = {**first, "delivery_id": "0191f6f0-0000-4000-8000-000000000002", "action_id": "0191f6f0-0000-4000-8000-000000000102",
              "message_state": "delivery_unknown", "delivery_state": "delivery_unknown", "customer_name": "Synthetic customer two"}
    with sync_playwright() as playwright:
        browser = playwright.chromium.launch(headless=True)
        page = browser.new_page(viewport={"width": 1280, "height": 900})
        page.on("pageerror", lambda e: errors.append(str(e)))

        def respond(route):
            url = urlsplit(route.request.url)
            calls.append({"method": route.request.method, "path": url.path})
            payloads = {"/api/auth/me": {"id": "u1", "role": "admin", "email": "fixture@example.com", "display_name": "Synthetic operator"},
                        "/api/brief": {"date": "2026-10-21", "items": []}, "/api/exceptions": [],
                        "/api/agent-ops/inbound/health": {"health": {}, "dispatch_blocked": None, "pending_events": 0}}
            status = 200
            if url.path == "/api/delivery-exceptions":
                if failed:
                    payload, status = {"detail": {"code": "KERNEL_UNAVAILABLE"}}, 503
                elif parse_qs(url.query).get("after"):
                    payload = {"items": [second], "next_cursor": None}
                else:
                    payload = {"items": [first], "next_cursor": first["delivery_id"]}
            else:
                payload = payloads.get(url.path)
                assert payload is not None, f"Unmocked API: {url.path}"
            route.fulfill(status=status, content_type="application/json", body=json.dumps(payload))

        page.route("**/api/**", respond)
        page.add_init_script("sessionStorage.setItem('mk_tokens', JSON.stringify({access_token:'fixture',refresh_token:'fixture',role:'admin'})); sessionStorage.setItem('cs_ai_notice_seen','1');")
        page.goto(args.web)
        page.wait_for_load_state("networkidle")
        page.get_by_role("navigation", name="Main").get_by_role("button", name="Inbox & exceptions").click()
        page.wait_for_load_state("networkidle")
        queue = page.get_by_role("region", name="Uncertain deliveries")
        expect(queue.get_by_role("listitem")).to_have_count(1)
        expect(queue.get_by_text("submission_unknown", exact=True)).to_be_visible()
        expect(queue.get_by_role("button", name="More uncertain deliveries")).to_be_visible()
        queue.get_by_role("button", name="More uncertain deliveries").click()
        expect(queue.get_by_role("listitem")).to_have_count(2)
        expect(queue.get_by_role("button", name="More uncertain deliveries")).to_have_count(0)
        assert queue.get_by_role("button", name="Dismiss", exact=True).count() == 0
        assert queue.get_by_role("button", name="Resolved", exact=True).count() == 0
        page.screenshot(path=str(args.output / "delivery-queue-desktop.png"), full_page=True)
        page.set_viewport_size({"width": 360, "height": 800})
        queue.get_by_role("listitem").first.scroll_into_view_if_needed()
        page.screenshot(path=str(args.output / "delivery-queue-360.png"), full_page=True)
        width = page.evaluate("({viewport:innerWidth, document:document.documentElement.scrollWidth})")
        assert width["document"] <= 360, width
        failed = True
        queue.get_by_role("button", name="Refresh delivery evidence").click()
        expect(queue.get_by_role("alert")).to_be_visible()
        expect(queue.get_by_text("Current delivery evidence could not be refreshed. Existing entries may be stale.")).to_be_visible()
        expect(queue.get_by_role("listitem")).to_have_count(2)
        expect(queue.get_by_text("No uncertain deliveries in this page.")).to_have_count(0)
        assert all(c["method"] == "GET" for c in calls), calls
        assert not errors, errors
        report = {"environment": "production web build, explicit mocked API fixtures, native Python Playwright",
                  "checks": ["visible unknown states", "pagination", "no resend/dismiss", "refresh failure preserves warning and entries", "360px no overflow"],
                  "browser_errors": errors, "provider_calls": 0, "requests": calls, "width_360": width}
        (args.output / "delivery-queue-browser.json").write_text(json.dumps(report, indent=2) + "\n", encoding="utf-8")
        print(json.dumps(report))
        browser.close()


if __name__ == "__main__":
    main()
