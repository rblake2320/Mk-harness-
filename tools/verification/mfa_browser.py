"""Real browser -> mandatory MFA API; secrets stay in memory, masked captures.

Run against session_stack.py and the built web preview. No HTTP fixture, provider
call or live identity; synthetic authenticator (PyOTP) is test equipment.
"""
import argparse
import json
import uuid
from pathlib import Path
from urllib.parse import urlsplit

import httpx
import pyotp
from playwright.sync_api import expect, sync_playwright


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--api', default='http://127.0.0.1:8019')
    parser.add_argument('--web', default='http://127.0.0.1:4189')
    parser.add_argument('--output', type=Path, required=True)
    args = parser.parse_args()
    args.output.mkdir(parents=True, exist_ok=True)
    email, password = f'mfa-browser-{uuid.uuid4().hex}@example.com', f'Test-only-{uuid.uuid4().hex}!'
    errors, requests, outcomes = [], [], {}
    auth = lambda t: {'Authorization': 'Bearer ' + t['access_token']}
    with httpx.Client(base_url=args.api, timeout=10) as api, sync_playwright() as pw:
        browser = pw.chromium.launch(headless=True)
        page = browser.new_page(viewport={'width': 1280, 'height': 900})
        page.on('pageerror', lambda e: errors.append(str(e)))
        def redirect(route):
            parsed = urlsplit(route.request.url)
            requests.append({'method': route.request.method, 'path': parsed.path})
            route.continue_(url=args.api + parsed.path + ('?' + parsed.query if parsed.query else ''))
        page.route('**/api/**', redirect)
        page.goto(args.web)
        page.evaluate('sessionStorage.setItem("cs_ai_notice_seen", "1")')
        page.get_by_role('button', name='New team? Create one').click()
        page.get_by_placeholder('Team or unit name').fill('Synthetic MFA acceptance')
        page.get_by_placeholder('Email', exact=True).fill(email)
        page.get_by_placeholder('Password (10+ characters)').fill(password)
        page.get_by_role('button', name='Create team', exact=True).click()
        expect(page.get_by_role('heading', name='Protect your account')).to_be_visible()
        limited = page.evaluate('JSON.parse(sessionStorage.getItem("mk_tokens"))')
        outcomes['password_only_customers'] = api.get('/api/customers', headers=auth(limited)).status_code
        assert outcomes['password_only_customers'] == 403
        page.get_by_role('button', name='Set up authenticator').click()
        secret = page.get_by_test_id('mfa-setup-key').inner_text()
        used = pyotp.TOTP(secret).now()
        page.get_by_label('Authenticator code', exact=True).fill(used)
        page.get_by_role('button', name='Verify code', exact=True).click()
        expect(page.get_by_role('heading', name='Save your recovery codes')).to_be_visible()
        codes = page.locator('.recovery-codes code').all_text_contents()
        assert len(codes) == len(set(codes)) == 8
        assert not any(code in page.evaluate('JSON.stringify(sessionStorage)') for code in codes)
        # Hide glyphs as well as masking boxes: wrapped text can paint outside
        # the measured mask rectangle while fonts finish loading.
        secret_style = '.recovery-codes, .recovery-codes * { color: transparent !important; text-shadow: none !important; }'
        page.screenshot(path=str(args.output / 'recovery-desktop-masked.png'), full_page=True,
                        style=secret_style, mask=[page.locator('.recovery-codes')])
        page.set_viewport_size({'width': 360, 'height': 800})
        bounds = page.evaluate('({viewport: innerWidth, document: document.documentElement.scrollWidth})')
        assert bounds == {'viewport': 360, 'document': 360}
        page.screenshot(path=str(args.output / 'recovery-360-masked.png'), full_page=True,
                        style=secret_style, mask=[page.locator('.recovery-codes')])
        page.get_by_role('button', name='I saved my recovery codes').click()
        expect(page.get_by_role('heading', name="Today's brief")).to_be_visible()
        full = page.evaluate('JSON.parse(sessionStorage.getItem("mk_tokens"))')
        assert full['session_id'] != limited['session_id']
        outcomes['old_password_bearer'] = api.get('/api/customers', headers=auth(limited)).status_code
        outcomes['verified_customers'] = api.get('/api/customers', headers=auth(full)).status_code
        outcomes['export_before_stepup'] = api.get('/api/account/export', headers=auth(full)).status_code
        assert outcomes['old_password_bearer'] == 401 and outcomes['verified_customers'] == 200 and outcomes['export_before_stepup'] == 403
        page.get_by_role('button', name='Settings', exact=True).click()
        page.get_by_role('button', name='Export my data (JSON)', exact=True).click()
        dialog = page.get_by_role('dialog', name='Confirm this sensitive action')
        expect(dialog).to_be_visible()
        expect(dialog.get_by_label('Password', exact=True)).to_be_focused()
        page.screenshot(path=str(args.output / 'step-up-360.png'), full_page=True)
        page.keyboard.press('Escape')
        expect(dialog).to_have_count(0)
        page.get_by_role('button', name='Export my data (JSON)', exact=True).click()
        dialog.get_by_label('Password', exact=True).fill(password)
        dialog.get_by_role('button', name='Use a recovery code').click()
        dialog.get_by_label('Recovery code', exact=True).fill(codes[0])
        with page.expect_download() as download:
            dialog.get_by_role('button', name='Confirm identity').click()
        assert download.value.suggested_filename == 'my-data.json'
        data = json.loads(Path(download.value.path()).read_text(encoding='utf-8'))
        assert data['user']['email'] == email
        assert secret not in json.dumps(data) and not any(code in json.dumps(data) for code in codes)
        outcomes['export_after_stepup'] = api.get('/api/account/export', headers=auth(full)).status_code
        assert outcomes['export_after_stepup'] == 200
        page.get_by_role('button', name='Sign out', exact=True).click()
        expect(page.get_by_role('button', name='Sign in', exact=True)).to_be_visible()
        page.get_by_placeholder('Email', exact=True).fill(email)
        page.get_by_placeholder('Password (10+ characters)').fill(password)
        page.get_by_role('button', name='Sign in', exact=True).click()
        expect(page.get_by_role('heading', name='Verify your sign-in')).to_be_visible()
        login = page.evaluate('JSON.parse(sessionStorage.getItem("mk_tokens"))')
        outcomes['replayed_recovery'] = api.post('/api/auth/mfa/verify', headers=auth(login), json={'recovery_code': codes[0]}).status_code
        assert outcomes['replayed_recovery'] == 401
        page.get_by_role('button', name='Use a recovery code', exact=True).click()
        page.get_by_label('Recovery code', exact=True).fill(codes[1])
        page.get_by_role('button', name='Verify code', exact=True).click()
        expect(page.get_by_role('heading', name="Today's brief")).to_be_visible()
        new = page.evaluate('JSON.parse(sessionStorage.getItem("mk_tokens"))')
        outcomes['new_session_needs_own_stepup'] = api.get('/api/account/export', headers=auth(new)).status_code
        assert outcomes['new_session_needs_own_stepup'] == 403
        page.get_by_role('button', name='Settings', exact=True).click()
        page.get_by_role('button', name='Replace authenticator', exact=True).click()
        page.get_by_role('button', name='Set up authenticator').click()
        expect(dialog).to_be_visible()
        dialog.get_by_label('Password', exact=True).fill(password)
        dialog.get_by_role('button', name='Use a recovery code').click()
        dialog.get_by_label('Recovery code', exact=True).fill(codes[2])
        dialog.get_by_role('button', name='Confirm identity').click()
        expect(dialog).to_have_count(0)
        replacement_secret = page.get_by_test_id('mfa-setup-key').inner_text()
        assert replacement_secret != secret
        page.get_by_label('Authenticator code', exact=True).fill(pyotp.TOTP(replacement_secret).now())
        page.get_by_role('button', name='Verify code', exact=True).click()
        expect(page.get_by_role('heading', name='Save your recovery codes')).to_be_visible()
        replacement_codes = page.locator('.recovery-codes code').all_text_contents()
        assert len(replacement_codes) == 8 and not set(codes).intersection(replacement_codes)
        page.get_by_role('button', name='I saved my recovery codes').click()
        expect(page.get_by_role('region', name='Second-factor security')).to_be_visible()
        outcomes['old_session_after_factor_replacement'] = api.get('/api/customers', headers=auth(new)).status_code
        assert outcomes['old_session_after_factor_replacement'] == 401
        page.get_by_role('button', name='Sign out', exact=True).click()
        expect(page.get_by_role('button', name='Sign in', exact=True)).to_be_visible()
        assert not errors, errors
        browser.close()
    report = {'scope': 'author-run real loopback app/kernel/Postgres, synthetic authenticator; no response mocks',
              'outcomes': outcomes, 'mfa_mobile_width': bounds, 'page_errors': errors, 'requests': requests,
              'secrets': 'in-memory only; recovery screenshots masked', 'download_content_validated': True}
    (args.output / 'mfa-browser.json').write_text(json.dumps(report, indent=2), encoding='utf-8')
    print(json.dumps({key: report[key] for key in ('outcomes', 'mfa_mobile_width', 'page_errors')}))


if __name__ == '__main__':
    main()
