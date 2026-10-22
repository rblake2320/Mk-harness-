"""Complete real mandatory MFA for synthetic loopback smoke-test identities.

Reads a password-only access token from stdin, prints only the verified token
for shell capture. No policy bypass, files, external provider or live identity.
"""
import argparse
import sys
from urllib.parse import urlsplit

import httpx
import pyotp


def complete(api: httpx.Client, access: str, password: str) -> dict:
    headers = {'Authorization': 'Bearer ' + access}
    setup = api.post('/api/auth/mfa/enroll', headers=headers)
    setup.raise_for_status()
    finish = api.post('/api/auth/mfa/confirm', headers=headers,
                      json={'code': pyotp.TOTP(setup.json()['secret']).now()})
    finish.raise_for_status()
    result = finish.json()
    step = api.post('/api/auth/step-up', headers={'Authorization': 'Bearer ' + result['tokens']['access_token']},
                    json={'password': password, 'recovery_code': result['recovery_codes'][0]})
    step.raise_for_status()
    return result


if __name__ == '__main__':
    parser = argparse.ArgumentParser()
    parser.add_argument('--api', required=True)
    parser.add_argument('--password', default='superSecret123!')
    args = parser.parse_args()
    if urlsplit(args.api).hostname not in ('127.0.0.1', 'localhost'):
        raise SystemExit('Synthetic fixture accepts loopback only')
    with httpx.Client(base_url=args.api, timeout=10) as api:
        result = complete(api, sys.stdin.read().strip(), args.password)
    print(result['tokens']['access_token'])
