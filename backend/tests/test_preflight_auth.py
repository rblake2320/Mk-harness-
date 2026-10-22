import importlib.util
from pathlib import Path

import httpx
import pytest

spec = importlib.util.spec_from_file_location('preflight_auth', Path(__file__).resolve().parents[2] / 'tools/verification/preflight_auth.py')
module = importlib.util.module_from_spec(spec)
spec.loader.exec_module(module)


@pytest.mark.parametrize('status', [401, 403, 503])
def test_supplied_preflight_session_must_pass_live_authorization(status):
    with httpx.Client(base_url='https://fixture.invalid', transport=httpx.MockTransport(lambda req: httpx.Response(status))) as api:
        with pytest.raises(ValueError):
            module.authenticate(api, {'MK_PREFLIGHT_ACCESS_TOKEN': 'synthetic-token'})


def test_password_without_second_factor_is_not_a_preflight_session():
    calls = []
    def handler(request):
        calls.append(request.url.path)
        return httpx.Response(200, json={'access_token': 'limited', 'mfa_state': 'verification_required'})
    with httpx.Client(base_url='https://fixture.invalid', transport=httpx.MockTransport(handler)) as api:
        with pytest.raises(ValueError, match='exactly one'):
            module.authenticate(api, {'MK_PREFLIGHT_EMAIL': 'fixture@example.com', 'MK_PREFLIGHT_PASSWORD': 'fixture'})
    assert calls == ['/api/auth/login']


def test_preflight_completes_real_second_factor_flow_before_reading_identity():
    calls = []
    def handler(request):
        calls.append(request.url.path)
        if request.url.path == '/api/auth/login':
            return httpx.Response(200, json={'access_token': 'limited', 'mfa_state': 'verification_required'})
        if request.url.path == '/api/auth/mfa/verify':
            assert request.headers['authorization'] == 'Bearer limited'
            assert request.content == b'{"code":"123456"}'
            return httpx.Response(200, json={'tokens': {'access_token': 'verified', 'mfa_state': 'verified'}})
        assert request.headers['authorization'] == 'Bearer verified'
        return httpx.Response(200, json={'id': 'operator'})
    with httpx.Client(base_url='https://fixture.invalid', transport=httpx.MockTransport(handler)) as api:
        assert module.authenticate(api, {'MK_PREFLIGHT_EMAIL': 'fixture@example.com', 'MK_PREFLIGHT_PASSWORD': 'fixture', 'MK_PREFLIGHT_TOTP': '123456'}) == 'verified'
    assert calls == ['/api/auth/login', '/api/auth/mfa/verify', '/api/auth/me']
