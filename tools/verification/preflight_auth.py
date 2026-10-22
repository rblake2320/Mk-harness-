"""Authenticate an operator for read-only preflight; never enroll or bypass MFA.

Secrets are supplied via environment, not command arguments or retained files.
The verified access token is printed only for shell capture (disable tracing).
"""
import os
import sys
from urllib.parse import urlsplit

import httpx


def authenticate(api: httpx.Client, env: dict) -> str:
    access = env.get('MK_PREFLIGHT_ACCESS_TOKEN', '')
    if not access:
        email, password = env.get('MK_PREFLIGHT_EMAIL'), env.get('MK_PREFLIGHT_PASSWORD')
        if not email or not password:
            raise ValueError('Supply an MFA-verified access token or operator login with a fresh second factor')
        response = api.post('/api/auth/login', json={'email': email, 'password': password})
        if response.status_code != 200:
            raise ValueError('Operator login refused')
        limited = response.json()
        if limited.get('mfa_state') != 'verification_required':
            raise ValueError('Operator must complete authenticator enrollment before preflight')
        code, recovery = env.get('MK_PREFLIGHT_TOTP'), env.get('MK_PREFLIGHT_RECOVERY_CODE')
        if bool(code) == bool(recovery):
            raise ValueError('Supply exactly one fresh authenticator or one-use recovery code')
        factor = {'code': code} if code else {'recovery_code': recovery}
        completed = api.post('/api/auth/mfa/verify', headers={'Authorization': 'Bearer ' + limited['access_token']}, json=factor)
        if completed.status_code != 200 or completed.json().get('tokens', {}).get('mfa_state') != 'verified':
            raise ValueError('Operator second-factor verification refused')
        access = completed.json()['tokens']['access_token']
    # A supplied token is not trusted by declaration: the live server checks
    # session revocation, MFA, account activity and tenant binding here.
    if api.get('/api/auth/me', headers={'Authorization': 'Bearer ' + access}).status_code != 200:
        raise ValueError('Operator session is not currently authorized with MFA')
    return access


if __name__ == '__main__':
    url = os.environ.get('APP_URL', '')
    parsed = urlsplit(url)
    if parsed.scheme != 'https' and not (parsed.scheme == 'http' and parsed.hostname in ('127.0.0.1', 'localhost')):
        raise SystemExit('Preflight credentials require HTTPS (except loopback test stacks)')
    try:
        with httpx.Client(base_url=url, timeout=10) as api:
            token = authenticate(api, os.environ)
    except (ValueError, KeyError, TypeError, httpx.HTTPError):
        print('MFA-authenticated preflight session unavailable; check supplied operator credentials and second factor.', file=sys.stderr)
        raise SystemExit(1)
    print(token)
