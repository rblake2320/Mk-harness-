/**
 * MKClient against a scripted fetch: error bodies reach callers with their codes, the
 * governance status never turns a 503 into an exception, a refreshed token is the one
 * retried with, and the passkey ceremony never starts when the challenge digest differs.
 */
import { afterEach, beforeEach, test } from 'node:test';
import assert from 'node:assert/strict';
import { ApiError, MKClient, dispatchSummary, governanceStatusFrom } from '../src/index';

type Call = { url: string; method: string; auth: string | null; body: unknown };
let calls: Call[] = [];
let script: Array<(c: Call) => Response> = [];
const realFetch = globalThis.fetch;

const res = (status: number, body: unknown, headers: Record<string, string> = {}) =>
  new Response(body === undefined ? null : typeof body === 'string' ? body : JSON.stringify(body), { status, headers: { 'Content-Type': 'application/json', ...headers } });

beforeEach(() => {
  calls = []; script = [];
  globalThis.fetch = (async (input: RequestInfo | URL, init?: RequestInit) => {
    const h = new Headers(init?.headers);
    const c: Call = { url: String(input), method: init?.method ?? 'GET', auth: h.get('Authorization'), body: init?.body ? JSON.parse(String(init.body)) : undefined };
    calls.push(c);
    const next = script.shift();
    if (!next) throw new Error(`unscripted fetch ${c.method} ${c.url}`);
    return next(c);
  }) as typeof fetch;
});
afterEach(() => { globalThis.fetch = realFetch; });

function client() {
  const c = new MKClient('https://api.example/');
  c.tokens = { access_token: 'old', refresh_token: 'r', role: 'consultant', display_name: 'A', tenant_id: 't' };
  return c;
}
const problem = (status: number, code: string) => res(status, { type: `urn:mk:error:${code.toLowerCase()}`, title: 't', status, code, request_id: 'rq' }, { 'Content-Type': 'application/problem+json' });

test('a kernel problem from approve() reaches the caller as ApiError with code and request id', async () => {
  script.push(() => problem(403, 'SELF_APPROVAL_FORBIDDEN'));
  const c = client();
  await assert.rejects(c.approve('11111111-1111-4111-8111-111111111111', 'sha256:' + 'b'.repeat(64), { credential_id: 'a', client_data_json: 'b', authenticator_data: 'c', signature: 'd' }),
    (e: unknown) => e instanceof ApiError && e.status === 403 && e.code === 'SELF_APPROVAL_FORBIDDEN' && e.requestId === 'rq');
  assert.equal(calls[0].url, 'https://api.example/api/agent-ops/actions/11111111-1111-4111-8111-111111111111/approve');
});

test('Retry-After on a 429 is kept on the error', async () => {
  script.push(() => res(429, { detail: 'Rate limit exceeded. Try again shortly.' }, { 'Retry-After': '12' }));
  await assert.rejects(client().brief(), (e: unknown) => e instanceof ApiError && e.retryAfter === 12);
});

test('401 → refresh → the retry carries the NEW token (exports too)', async () => {
  script.push(() => res(401, { detail: 'expired' }));
  script.push(() => res(200, { access_token: 'new', refresh_token: 'r2', role: 'consultant', display_name: 'A', tenant_id: 't' }));
  script.push(() => new Response('id,name\n', { status: 200 }));
  const text = await client().exportCustomersCsv();
  assert.equal(text, 'id,name\n');
  assert.deepEqual(calls.map(c => [c.url.replace('https://api.example', ''), c.auth]), [
    ['/api/customers/export.csv', 'Bearer old'], ['/api/auth/refresh', null], ['/api/customers/export.csv', 'Bearer new']]);
});

test('a failed export is an ApiError, never error text handed back as file content', async () => {
  script.push(() => res(403, { detail: 'Admin only' }));
  await assert.rejects(client().exportAudit(), (e: unknown) => e instanceof ApiError && e.status === 403);
});

test('approveWithPasskey: a challenge for a different digest stops before any passkey prompt or approve call', async () => {
  let prompted = 0;
  const nav = globalThis.navigator as unknown as { credentials?: unknown } | undefined;
  const fakeNavigator = { credentials: { get: async () => { prompted += 1; return null; } } };
  Object.defineProperty(globalThis, 'navigator', { value: fakeNavigator, configurable: true });
  try {
    script.push(() => res(200, { challenge: 'AAAA', rp_id: 'x', action_digest: 'sha256:' + 'c'.repeat(64), expires_at: '2026-10-21T15:00:00Z', allow_credentials: [], user_verification: 'required' }));
    await assert.rejects(client().approveWithPasskey('11111111-1111-4111-8111-111111111111', 'sha256:' + 'b'.repeat(64)),
      (e: unknown) => e instanceof ApiError && e.code === 'APPROVAL_DIGEST_MISMATCH');
    assert.equal(prompted, 0);
    assert.equal(calls.length, 1, 'only the challenge was requested');
  } finally {
    Object.defineProperty(globalThis, 'navigator', { value: nav, configurable: true });
  }
});

test('ids are URL-encoded into paths (no path injection through an action id)', async () => {
  script.push(() => res(200, { action: {}, link: null, message_state_definitions: {} }));
  await client().actionStatus('../../admin?x=1');
  assert.equal(calls[0].url, 'https://api.example/api/actions/..%2F..%2Fadmin%3Fx%3D1');
});

test('proposeDraft never sends a schedule (the approval list cannot show it yet)', async () => {
  script.push(() => res(202, { action_id: 'a', state: 'approval_required', message_state: 'awaiting_approval', action_digest: 'd', decision: null, human_steps: [] }));
  await client().proposeDraft('dv1');
  assert.deepEqual(calls[0].body, {});
});

test('governanceStatus: 503 is a status, not an exception; 401 still throws', async () => {
  script.push(() => problem(503, 'KERNEL_NOT_CONFIGURED'));
  assert.equal((await client().governanceStatus()).kernel, 'not_configured');
  script.push(() => problem(503, 'KERNEL_UNREACHABLE'));
  assert.equal((await client().governanceStatus()).kernel, 'unreachable');
  script.push(() => res(401, { detail: 'x' }));
  script.push(() => res(401, { detail: 'refresh refused' }));
  await assert.rejects(client().governanceStatus(), (e: unknown) => e instanceof ApiError && e.status === 401);
});

test('governanceStatusFrom maps the real /api/agent-ops/health bodies', () => {
  const ready = { kernel_status: 200, configured: true, kernel: { database: true, dispatch_enabled: true, rust_kernel_enabled: true, effective: { approval_binding: 'webauthn' } } };
  assert.deepEqual(governanceStatusFrom(200, ready), { kernel: 'connected', code: null, global_dispatch_enabled: true, kernel_execution_enabled: true, approval_binding: 'webauthn', team_dispatch_enabled: null });
  const dbDown = { kernel_status: 503, configured: true, kernel: { database: false, dispatch_enabled: false, rust_kernel_enabled: true } };
  assert.equal(governanceStatusFrom(503, dbDown).kernel, 'not_ready');
  assert.equal(governanceStatusFrom(200, { ...ready, configured: false }).kernel, 'not_configured');
  // Wrong types are "not reported", never coerced to true.
  const weird = governanceStatusFrom(200, { configured: true, kernel: { database: true, dispatch_enabled: 'yes', rust_kernel_enabled: 1 } });
  assert.equal(weird.global_dispatch_enabled, null);
  assert.equal(weird.kernel_execution_enabled, null);
  assert.equal(governanceStatusFrom(503, undefined).kernel, 'unreachable');
  assert.throws(() => governanceStatusFrom(500, { detail: 'boom' }), ApiError);
});

test('dispatchSummary: every gate open → allowed (team switch still not reported); any closed gate → blocked with its name', () => {
  const ok = governanceStatusFrom(200, { configured: true, kernel: { database: true, dispatch_enabled: true, rust_kernel_enabled: true, effective: { approval_binding: 'webauthn' } } });
  const healthy = { health: null, dispatch_blocked: null, pending_events: 0, stale_after_secs: 60 };
  const s = dispatchSummary(ok, healthy);
  assert.equal(s.allowed, true);
  assert.equal(s.lines.find(l => l.key === 'team_switch')!.level, 'unknown');
  assert.match(s.headline, /Each message still needs its own approval/);

  const killed = dispatchSummary({ ...ok, global_dispatch_enabled: false }, healthy);
  assert.equal(killed.allowed, false);
  assert.match(killed.headline, /platform kill switch/);
  assert.equal(killed.lines.find(l => l.key === 'global_switch')!.value, 'On — sending is stopped for every team');

  const paused = dispatchSummary(ok, { ...healthy, dispatch_blocked: 'inbound_stale' });
  assert.equal(paused.allowed, false);
  assert.match(paused.lines.find(l => l.key === 'reply_path')!.value, /^Paused — The reply path failed/);

  const unknownReason = dispatchSummary(ok, { ...healthy, dispatch_blocked: 'brand_new_reason' });
  assert.match(unknownReason.lines.find(l => l.key === 'reply_path')!.value, /Sending is paused \(brand_new_reason\)/);

  const noExec = dispatchSummary({ ...ok, kernel_execution_enabled: false }, healthy);
  assert.equal(noExec.allowed, false);

  const down = dispatchSummary(governanceStatusFrom(503, { type: 'urn:mk:error:kernel_unreachable', title: 't', status: 503, code: 'KERNEL_UNREACHABLE', request_id: '' }), null);
  assert.equal(down.allowed, false);
  assert.match(down.headline, /action kernel/);
  assert.equal(down.lines.find(l => l.key === 'global_switch')!.value, 'Not reported');

  const unbound = dispatchSummary({ ...ok, approval_binding: 'unbound' }, healthy);
  assert.equal(unbound.allowed, false, 'approvals without a kernel-verified passkey are never "allowed"');
});
