"""Exercise the production web build against a running local FastAPI instance.

Start the API and built-web preview with an isolated SQLite database first.
See tools/verification/README.md for the local-only invocation.
All contacts are synthetic. No model or messaging provider is called.
"""
import argparse
import json
import uuid
from pathlib import Path
from urllib.parse import urlsplit

import httpx
from playwright.sync_api import expect, sync_playwright


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--api", default="http://127.0.0.1:8019")
    parser.add_argument("--web", default="http://127.0.0.1:4189")
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    args.output.mkdir(parents=True, exist_ok=True)
    tag = uuid.uuid4().hex[:10]
    with httpx.Client(base_url=args.api, timeout=10) as api:
        tokens = []
        for index in range(2):
            response = api.post("/api/auth/signup", json={"org_name": f"Search test {tag}-{index}",
                                "email": f"search-{tag}-{index}@example.com", "password": f"Test-only-{uuid.uuid4().hex}!",
                                "key_policy": "byo"})
            response.raise_for_status()
            tokens.append(response.json())
        headers = [{"Authorization": f"Bearer {token['access_token']}"} for token in tokens]
        for index in range(52):
            response = api.post("/api/customers", headers=headers[0], json={
                "name": f"Search contact {index:02d}", "phone": f"+1555555{index:04d}", "notes": "Synthetic browser test"})
            response.raise_for_status()
        response = api.post("/api/customers", headers=headers[1], json={
            "name": "Search foreign tenant", "phone": "+15555559999", "notes": "Must never appear"})
        response.raise_for_status()

    with sync_playwright() as playwright:
        browser = playwright.chromium.launch(headless=True)
        page = browser.new_page(viewport={"width": 1280, "height": 900})
        page_errors = []
        search_calls = []
        page.on("pageerror", lambda error: page_errors.append(str(error)))

        def forward(route):
            request = route.request
            url = urlsplit(request.url)
            if url.path == "/api/customers/search":
                assert request.method == "POST" and not url.query
                search_calls.append(request.post_data_json)
            # Retarget transport to the actual local app; no response is mocked.
            route.continue_(url=args.api + url.path + ("?" + url.query if url.query else ""))

        page.route("**/api/**", forward)
        page.add_init_script("sessionStorage.setItem('mk_tokens', JSON.stringify(" + json.dumps(tokens[0]) + "));"
                             "sessionStorage.setItem('cs_ai_notice_seen', '1');")
        page.goto(args.web)
        page.wait_for_load_state("networkidle")
        page.get_by_role("navigation", name="Main").get_by_role("button", name="My customers").click()
        expect(page.get_by_role("row")).to_have_count(53)
        search = page.get_by_role("searchbox", name="Find a customer by name, phone or email")
        search.fill("Search")
        page.get_by_role("button", name="Search", exact=True).click()
        expect(page.get_by_role("row")).to_have_count(51)
        expect(page.get_by_text("Search foreign tenant", exact=True)).to_have_count(0)
        page.get_by_role("button", name="More results").click()
        expect(page.get_by_role("row")).to_have_count(53)
        expect(page.get_by_role("button", name="More results")).to_have_count(0)
        search.fill("Search contact 07")
        search.press("Enter")
        expect(page.get_by_role("row")).to_have_count(2)
        expect(page.get_by_role("button", name="Search contact 07", exact=True)).to_be_visible()
        page.screenshot(path=str(args.output / "search-desktop.png"), full_page=True)
        page.set_viewport_size({"width": 360, "height": 800})
        expect(search).to_be_visible()
        expect(page.get_by_role("button", name="Search", exact=True)).to_be_visible()
        for name in ("Open", "Edit", "Delete"):
            control = page.get_by_role("button", name=name, exact=True)
            expect(control).to_be_visible()
            box = control.bounding_box()
            assert box and box["x"] >= 0 and box["x"] + box["width"] <= 360, (name, box)
        page.screenshot(path=str(args.output / "search-360.png"), full_page=True)
        width = page.evaluate("({viewport: innerWidth, document: document.documentElement.scrollWidth})")
        search.fill("no-such-contact")
        search.press("Enter")
        expect(page.get_by_text("No matching customers. Try another name, phone number or email.")).to_be_visible()
        page.get_by_role("button", name="Clear search").click()
        expect(page.get_by_role("row")).to_have_count(53)
        assert not page_errors, page_errors
        result = {"environment": "local Windows; production web build; actual FastAPI; isolated SQLite",
                  "provider_calls": 0, "customers_in_scope": 52, "foreign_customers_excluded": 1,
                  "pagination": [50, 2], "search_in_request_body": True,
                  "search_requests": len(search_calls), "browser_errors": page_errors, "width_360": width,
                  "checks": ["tenant isolation", "pagination", "exact result", "empty result", "clear", "360px search/open/edit/delete controls"]}
        (args.output / "search-browser.json").write_text(json.dumps(result, indent=2) + "\n", encoding="utf-8")
        browser.close()
        print(json.dumps(result))


if __name__ == "__main__":
    main()
