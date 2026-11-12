/**
 * Plain-language errors: every body shape the API produces keeps its machine code and
 * request id, and maps to wording with a recovery step. The original bug: kernel
 * problem+json forwarded by /api/agent-ops lost its code (the SDK only read `.detail`),
 * so SELF_APPROVAL_FORBIDDEN and APPROVAL_DIGEST_MISMATCH reached people as "HTTP 403/409".
 */
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { ApiError, EXPLANATIONS, apiErrorFrom, errorDetailFromBody, explain } from '../src/index';

const problem = (status: number, code: string, title: string, extra: Record<string, unknown> = {}) =>
  ({ type: `urn:mk:error:${code.toLowerCase()}`, title, status, code, request_id: 'req-1', ...extra });

test('kernel problem+json (forwarded verbatim by /api/agent-ops) keeps code and request id', () => {
  const e = apiErrorFrom(403, problem(403, 'SELF_APPROVAL_FORBIDDEN', 'Policy denied the action'));
  assert.equal(e.status, 403);
  assert.equal(e.code, 'SELF_APPROVAL_FORBIDDEN');
  assert.equal(e.requestId, 'req-1');
  const x = explain(e);
  assert.equal(x.what, EXPLANATIONS.SELF_APPROVAL_FORBIDDEN.what);
  assert.match(x.next, /Nothing was approved/);
  assert.equal(x.code, 'SELF_APPROVAL_FORBIDDEN');
  assert.equal(x.requestId, 'req-1');
});

test('409 APPROVAL_DIGEST_MISMATCH is explained, not "HTTP 409"', () => {
  const x = explain(apiErrorFrom(409, problem(409, 'APPROVAL_DIGEST_MISMATCH', 'The action changed since it was displayed')));
  assert.equal(x.what, 'This message changed since it was displayed.');
  assert.match(x.next, /needs its own approval/);
  assert.doesNotMatch(x.what, /HTTP/);
});

test('a kernel problem wrapped by a FastAPI route ({detail: problem}) keeps its code', () => {
  const e = apiErrorFrom(422, { detail: problem(422, 'CONTRACT_VIOLATION', 'Payload does not match contract', { detail: 'bad field' }) });
  assert.equal(e.code, 'CONTRACT_VIOLATION');
  assert.equal(e.requestId, 'req-1');
  assert.equal(explain(e).what, EXPLANATIONS.CONTRACT_VIOLATION.what);
});

test('FastAPI dict details ({detail: {code, detail}}) keep the code, lower-case codes are normalised', () => {
  const e = apiErrorFrom(409, { detail: { code: 'SUPPRESSED', detail: 'destination is suppressed' } });
  assert.equal(e.code, 'SUPPRESSED');
  assert.equal(e.message, 'destination is suppressed');
  assert.equal(apiErrorFrom(422, { detail: { code: 'channel_mismatch', detail: 'x' } }).code, 'CHANNEL_MISMATCH');
  assert.equal(apiErrorFrom(403, { detail: { decision: { code: 'self_approval_forbidden' } } }).code, 'SELF_APPROVAL_FORBIDDEN');
});

test('string details are shown as the server wrote them', () => {
  const x = explain(apiErrorFrom(409, { detail: 'already closed' }));
  assert.match(x.what, /already closed/);
  const y = explain(apiErrorFrom(403, { detail: 'Platform operator required' }));
  assert.equal(y.what, 'Not allowed: Platform operator required');
  assert.match(y.next, /Nothing was changed/);
});

test('pydantic validation lists become a readable summary, not "[object Object]"', () => {
  const e = apiErrorFrom(422, { detail: [{ loc: ['body', 'destination_id'], msg: 'Field required', type: 'missing' }, { loc: ['body', 'reason'], msg: 'String should have at least 1 character' }] });
  assert.equal(e.code, 'VALIDATION_ERROR');
  const x = explain(e);
  assert.match(x.what, /Some details were not accepted/);
  assert.match(x.what, /destination_id: Field required/);
  assert.match(x.what, /reason: String should have at least 1 character/);
  assert.doesNotMatch(x.what, /object Object/);
});

test('non-JSON and empty bodies fall back to the status, and the explanation still has a next step', () => {
  for (const body of [undefined, null, '<html>502</html>', 42, [], { unexpected: true }]) {
    const e = apiErrorFrom(502, body);
    assert.equal(e.detail, 'HTTP 502');
    const x = explain(e);
    assert.equal(x.what, 'The request failed (HTTP 502).');
    assert.ok(x.next.length > 0);
  }
});

test('status fallbacks: 401, 404, 503 (kernel), 429 with Retry-After', () => {
  assert.equal(explain(apiErrorFrom(401, { detail: 'Not authenticated' })).what, 'Your sign-in expired.');
  assert.equal(explain(apiErrorFrom(404, { detail: 'Draft not found' })).what, 'That item was not found.');
  assert.equal(explain(apiErrorFrom(503, problem(503, 'KERNEL_NOT_CONFIGURED', 'Action kernel unavailable'))).what, EXPLANATIONS.KERNEL_NOT_CONFIGURED.what);
  assert.equal(explain(apiErrorFrom(503, problem(503, 'KERNEL_UNREACHABLE', 'Action kernel unavailable'))).what, EXPLANATIONS.KERNEL_UNREACHABLE.what);
  assert.equal(explain(apiErrorFrom(503, undefined)).what, EXPLANATIONS.KERNEL_UNAVAILABLE.what);
  const rl = explain(apiErrorFrom(429, { detail: 'Rate limit exceeded. Try again shortly.' }, '7'));
  assert.equal(rl.next, 'Wait 7 seconds and try again.');
  assert.equal(explain(apiErrorFrom(429, problem(429, 'TENANT_RATE_LIMITED', 'Too many requests'), 'soon')).next, EXPLANATIONS.TENANT_RATE_LIMITED.next);
});

test('hostile codes never reach Object.prototype, never crash, and are bounded', () => {
  for (const code of ['__proto__', 'constructor', 'toString', 'hasOwnProperty', 'x'.repeat(500), 'BAD CODE', '../../etc', '']) {
    const e = apiErrorFrom(400, problem(400, code, 'title'));
    const x = explain(e);
    assert.equal(typeof x.what, 'string');
    assert.equal(typeof x.next, 'string');
    assert.ok(!x.code || /^[A-Z][A-Z0-9_.-]{1,63}$/.test(x.code), String(x.code));
  }
});

test('ApiError built directly (client-side digest check) is explained like the kernel answer', () => {
  const e = new ApiError(409, { code: 'APPROVAL_DIGEST_MISMATCH', message: 'This message changed since it was displayed.', detected: 'client' });
  assert.equal(e.code, 'APPROVAL_DIGEST_MISMATCH');
  assert.equal(explain(e).what, EXPLANATIONS.APPROVAL_DIGEST_MISMATCH.what);
});

test('plain errors and junk are explained without throwing', () => {
  assert.equal(explain(new Error('The operation was not allowed.')).what, 'The operation was not allowed.');
  for (const junk of [undefined, null, 'oops', 42, {}, { message: '' }]) assert.equal(explain(junk).what, 'Something went wrong.');
});

test('errorDetailFromBody is pure and total', () => {
  assert.equal(errorDetailFromBody(500, undefined), 'HTTP 500');
  assert.deepEqual(errorDetailFromBody(400, { detail: 'x' }), 'x');
});
