"""S2: native browser -> real FastAPI -> real Rust kernel -> PostgreSQL.

Transport is redirected to the loopback API; no HTTP response fixtures. Tokens,
passwords and private keys are kept only in memory, never written to reports.
"""
import argparse
import json
from pathlib import Path
import uuid
from urllib.parse import urlsplit

import httpx
from playwright.sync_api import expect, sync_playwright


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--api', default='http://127.0.0.1:8019')
    parser.add_argument('--web', default='http://127.0.0.1:4189')
    parser.add_argument('--output', type=Path, required=True)
    args = parser.parse_args()
    args.output.mkdir(parents=True, exist_ok=True)
    email, password = f'session-{uuid.uuid4().hex}@example.com', f'Test-only-{uuid.uuid4().hex}!'
    errors, calls, outcomes = [], [], {}
    with httpx.Client(base_url=args.api, timeout=10) as api:
        first = api.post('/api/auth/signup', json={'org_name': 'Synthetic session acceptance', 'email': email, 'password': password})
        first.raise_for_status()
        first_token = first.json()
        second = api.post('/api/auth/login', json={'email': email, 'password': password})
        second.raise_for_status()
        second_token = second.json()
        with sync_playwright() as pw:
            browser = pw.chromium.launch(headless=True)
            page = browser.new_page(viewport={'width': 1280, 'height': 900})
            page.on('pageerror', lambda error: errors.append(str(error)))
            def forward(route):
                request = route.request
                parsed = urlsplit(request.url)
                calls.append({'method': request.method, 'path': parsed.path})
                route.continue_(url=args.api + parsed.path + ('?' + parsed.query if parsed.query else ''))
            page.route('**/api/**', forward)
            page.goto(args.web)
            # Force authenticated routes to return 401, keeping the genuine
            # refresh token. The SDK must rotate once and persist it for reload.
            page.evaluate('(t) => {sessionStorage.setItem("mk_tokens", JSON.stringify(t)); sessionStorage.setItem("cs_ai_notice_seen", "1");}',
                          {**second_token, 'access_token': 'synthetic-invalid-access'})
            page.reload()
            expect(page.get_by_role('heading', name="Today's brief")).to_be_visible()
            page.wait_for_function('JSON.parse(sessionStorage.getItem("mk_tokens")).access_token !== "synthetic-invalid-access"')
            stored = page.evaluate('JSON.parse(sessionStorage.getItem("mk_tokens"))')
            assert stored['refresh_token'] != second_token['refresh_token']
            page.reload()
            expect(page.get_by_role('heading', name="Today's brief")).to_be_visible()
            assert sum(call['path'] == '/api/auth/refresh' for call in calls) == 1
            page.get_by_role('button', name='Settings', exact=True).click()
            expect(page.get_by_role('region', name='Signed-in sessions')).to_be_visible()
            page.get_by_role('button', name='Revoke session started', exact=False).click()
            expect(page.get_by_text('Session and pending approvals revoked.', exact=True)).to_be_visible()
            auth = lambda token: {'Authorization': 'Bearer ' + token['access_token']}
            outcomes['other_access_after_revoke'] = api.get('/api/auth/me', headers=auth(first_token)).status_code
            outcomes['other_refresh_after_revoke'] = api.post('/api/auth/refresh', json={'refresh_token': first_token['refresh_token']}).status_code
            outcomes['current_access_after_other_revoke'] = api.get('/api/auth/me', headers=auth(second_token)).status_code
            assert outcomes == {'other_access_after_revoke': 401, 'other_refresh_after_revoke': 401, 'current_access_after_other_revoke': 200}
            page.screenshot(path=str(args.output / 'sessions-desktop.png'), full_page=True)
            page.set_viewport_size({'width': 360, 'height': 800})
            page.screenshot(path=str(args.output / 'sessions-360.png'), full_page=True)
            bounds = page.evaluate('({viewport: innerWidth, document: document.documentElement.scrollWidth})')
            page.get_by_role('button', name='Sign out', exact=True).click()
            expect(page.get_by_role('status')).to_have_text('Signed out. This session is revoked.')
            assert page.evaluate('sessionStorage.getItem("mk_tokens")') is None
            outcomes['current_access_after_logout'] = api.get('/api/auth/me', headers=auth(second_token)).status_code
            outcomes['current_refresh_after_logout'] = api.post('/api/auth/refresh', json={'refresh_token': second_token['refresh_token']}).status_code
            assert outcomes['current_access_after_logout'] == outcomes['current_refresh_after_logout'] == 401
            page.screenshot(path=str(args.output / 'signed-out-360.png'), full_page=True)
            signed_out_bounds = page.evaluate('({viewport: innerWidth, document: document.documentElement.scrollWidth})')
            assert signed_out_bounds == {'viewport': 360, 'document': 360}, signed_out_bounds
            # New login has independent session authority, not a permanent user ban.
            page.get_by_placeholder('Email', exact=True).fill(email)
            page.get_by_placeholder('Password (10+ characters)').fill(password)
            page.get_by_role('button', name='Sign in', exact=True).click()
            expect(page.get_by_role('navigation', name='Main')).to_be_visible()
            page.get_by_role('button', name='Sign out', exact=True).click()
            expect(page.get_by_role('status')).to_contain_text('This session is revoked')
            assert not errors, errors
            browser.close()
    report = {'scope': 'author-run loopback real app/kernel/Postgres; no live provider or human qualification',
        'outcomes': outcomes, 'new_login_after_logout': 'worked', 'page_errors': errors, 'mobile_width': bounds,
        'signed_out_mobile_width': signed_out_bounds,
        'single_refresh_and_reload_persistence': 'worked',
        'transport': 'URL redirect only; no HTTP responses mocked', 'requests': calls}
    (args.output / 'session-browser.json').write_text(json.dumps(report, indent=2), encoding='utf-8')
    print(json.dumps({key: report[key] for key in ('outcomes', 'new_login_after_logout', 'page_errors', 'mobile_width')}))


if __name__ == '__main__':
    main()
