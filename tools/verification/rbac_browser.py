"""S3 real app/kernel browser checks; synthetic accounts, no mocked responses."""
import argparse
import json
import uuid
from pathlib import Path
from urllib.parse import urlsplit

import httpx
from playwright.sync_api import expect, sync_playwright

from mfa_fixture import complete


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--api', default='http://127.0.0.1:8019')
    parser.add_argument('--web', default='http://127.0.0.1:4189')
    parser.add_argument('--output', type=Path, required=True)
    args = parser.parse_args()
    args.output.mkdir(parents=True, exist_ok=True)
    password = 'Synthetic-' + uuid.uuid4().hex + '!'
    admin_email, member_email = f'admin-{uuid.uuid4().hex}@example.com', f'member-{uuid.uuid4().hex}@example.com'
    auth = lambda token: {'Authorization': 'Bearer ' + token['access_token']}
    outcomes, errors, calls = {}, [], []
    with httpx.Client(base_url=args.api, timeout=10) as api, sync_playwright() as pw:
        def login(email, backup):
            limited = api.post('/api/auth/login', json={'email': email, 'password': password})
            limited.raise_for_status()
            verified = api.post('/api/auth/mfa/verify', headers=auth(limited.json()), json={'recovery_code': backup})
            verified.raise_for_status()
            return verified.json()['tokens']
        created = api.post('/api/auth/signup', json={'org_name': 'Synthetic RBAC', 'email': admin_email, 'password': password})
        created.raise_for_status()
        admin = complete(api, created.json()['access_token'], password)
        created_member = api.post('/api/auth/members', headers=auth(admin['tokens']), json={'email': member_email, 'password': password})
        created_member.raise_for_status()
        uid = created_member.json()['id']
        limited_member = api.post('/api/auth/login', json={'email': member_email, 'password': password})
        limited_member.raise_for_status()
        member = complete(api, limited_member.json()['access_token'], password)
        administrator = login(admin_email, admin['recovery_codes'][1])
        assert api.patch(f'/api/auth/members/{uid}', headers=auth(administrator), json={'role': 'auditor'}).status_code == 403
        browser = pw.chromium.launch(headless=True)
        page = browser.new_page(viewport={'width': 1280, 'height': 900})
        page.on('pageerror', lambda e: errors.append(str(e)))
        def redirect(route):
            parsed = urlsplit(route.request.url)
            calls.append({'method': route.request.method, 'path': parsed.path})
            route.continue_(url=args.api + parsed.path + ('?' + parsed.query if parsed.query else ''))
        page.route('**/api/**', redirect)
        page.goto(args.web)
        page.evaluate('(t) => {sessionStorage.setItem("mk_tokens", JSON.stringify(t)); sessionStorage.setItem("cs_ai_notice_seen", "1");}', administrator)
        page.reload()
        page.get_by_role('button', name='Settings', exact=True).click()
        team = page.get_by_role('region', name='Team access')
        expect(team.get_by_label(f'Role for {admin_email}', exact=True)).to_be_disabled()
        team.get_by_label(f'Role for {member_email}', exact=True).select_option('auditor')
        dialog = page.get_by_role('dialog', name='Confirm this sensitive action')
        expect(dialog).to_be_visible()
        dialog.get_by_label('Password', exact=True).fill(password)
        dialog.get_by_role('button', name='Use a recovery code').click()
        dialog.get_by_label('Recovery code', exact=True).fill(admin['recovery_codes'][2])
        dialog.get_by_role('button', name='Confirm identity').click()
        expect(team.get_by_role('status')).to_contain_text('Old app sessions are revoked')
        expect(team.get_by_label(f'Role for {member_email}', exact=True)).to_have_value('auditor')
        outcomes['old_member_access'] = api.get('/api/customers', headers=auth(member['tokens'])).status_code
        outcomes['old_member_refresh'] = api.post('/api/auth/refresh', json={'refresh_token': member['tokens']['refresh_token']}).status_code
        assert outcomes['old_member_access'] == outcomes['old_member_refresh'] == 401
        page.screenshot(path=str(args.output / 'member-access-desktop.png'), full_page=True)
        page.get_by_role('button', name='Sign out', exact=True).click()
        expect(page.get_by_role('button', name='Sign in', exact=True)).to_be_visible()
        auditor = login(member_email, member['recovery_codes'][1])
        assert auditor['role'] == 'auditor'
        outcomes['auditor_customers'] = api.get('/api/customers', headers=auth(auditor)).status_code
        outcomes['auditor_kernel'] = api.get('/api/agent-ops/senders', headers=auth(auditor)).status_code
        assert outcomes['auditor_customers'] == outcomes['auditor_kernel'] == 403
        page.evaluate('(t) => sessionStorage.setItem("mk_tokens", JSON.stringify(t))', auditor)
        page.reload()
        expect(page.get_by_role('heading', name='Settings', exact=True)).to_be_visible()
        expect(page.get_by_role('button', name='My customers', exact=True)).to_have_count(0)
        expect(page.get_by_role('region', name='Team access')).to_have_count(0)
        page.get_by_role('button', name='Export audit log (auditor)', exact=True).click()
        expect(dialog).to_be_visible()
        dialog.get_by_label('Password', exact=True).fill(password)
        dialog.get_by_role('button', name='Use a recovery code').click()
        dialog.get_by_label('Recovery code', exact=True).fill(member['recovery_codes'][2])
        with page.expect_download() as download:
            dialog.get_by_role('button', name='Confirm identity').click()
        payload = Path(download.value.path()).read_text(encoding='utf-8')
        records = [json.loads(line) for line in payload.splitlines() if line.strip()]
        assert any(row['action'] == 'member.access_change' for row in records)
        assert uid in payload
        outcomes['auditor_audit_export'] = 200
        page.set_viewport_size({'width': 360, 'height': 800})
        bounds = page.evaluate('({viewport: innerWidth, document: document.documentElement.scrollWidth})')
        assert bounds == {'viewport': 360, 'document': 360}
        page.screenshot(path=str(args.output / 'auditor-360.png'), full_page=True)
        page.get_by_role('button', name='Sign out', exact=True).click()
        expect(page.get_by_role('button', name='Sign in', exact=True)).to_be_visible()
        assert not errors, errors
        browser.close()
    report = {'scope': 'author-run real loopback app/kernel/Postgres; synthetic accounts; no HTTP fixtures',
              'outcomes': outcomes, 'auditor_mobile_width': bounds, 'page_errors': errors, 'requests': calls}
    (args.output / 'rbac-browser.json').write_text(json.dumps(report, indent=2), encoding='utf-8')
    print(json.dumps({'outcomes': outcomes, 'auditor_mobile_width': bounds, 'page_errors': errors}))


if __name__ == '__main__':
    main()
