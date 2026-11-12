import type { Page, Route } from '@playwright/test';

export const TOKENS = { access_token: 'a', refresh_token: 'r', role: 'admin', display_name: 'Angela', tenant_id: 't1' };
/** Tests run on a fixed clock so expiry wording is deterministic (15 min before the fixture expiry). */
export const NOW = new Date('2026-10-21T14:45:00Z');
export const ACTION_ID = '11111111-1111-4111-8111-111111111111';
export const NEW_ACTION_ID = '22222222-2222-4222-8222-222222222222';
export const DIGEST = 'sha256:' + 'b'.repeat(64);
export const NEW_DIGEST = 'sha256:' + 'd'.repeat(64);
const CUST = { id: 'c1', name: 'Brenda Lee', phone: '+15555550100', email: '', notes: 'private', last_contact: null };
const COMMIT = { id: 'k1', customer_id: 'c1', kind: 'promise', text: 'Send the shade chart', status: 'confirmed', due_at: '2026-10-21T14:00:00Z',
  due_window: [null, null], timezone: 'America/Chicago', source_type: 'conversation', source_reference: 'conv-1', evidence_digest: 'sha256:' + 'a'.repeat(64),
  created_by: 'ai:anthropic:x', confirmed_by: 'u1', version: 2 };

/** One `/api/approvals/pending` item exactly as `backend/app/routes/outreach.py::pending_approvals` builds it. */
export function pendingItem(over: Record<string, unknown> = {}) {
  return {
    action_id: ACTION_ID, action_digest: DIGEST, state: 'approval_required', message_state: 'awaiting_approval',
    exact_text: 'Hi Brenda! Here is the shade chart I promised. Reply STOP to opt out.', destination_masked: '********0100', channel: 'sms',
    purpose: 'customer_requested_follow_up', workflow: 'customer_follow_up', risk: 'high', customer: { id: 'c1', name: 'Brenda Lee' },
    sending_business: { sender_identity_id: 's1', display_name: "Angela's Business", from_number: '+15005550006', registration_status: 'registered' },
    supporting: { commitment: { id: 'k1', text: 'Send the shade chart', status: 'confirmed', evidence_digest: 'sha256:' + 'a'.repeat(64) }, draft_version_id: 'd1', evidence_count: 2 },
    permission: { state: 'active', checked_at: '2026-10-21T08:00:00Z', note: 'historical observation; the kernel re-checks consent and suppression at send time' },
    scheduled_for: null, approval_expires_at: '2026-10-21T15:00:00Z', approval_lifetime_minutes: 15,
    human_steps: ['Your passkey signs this exact text.', 'Approval is single-use and expires.'],
    ...over,
  };
}

/** RFC 9457 problem details exactly as the kernel returns them and `/api/agent-ops/*` forwards them
 *  (`contracts/action/v1/error.schema.json`) — top-level `code`, no FastAPI `detail` wrapper. */
export function problem(status: number, code: string, title: string, requestId = 'req-test-1') {
  return { status, contentType: 'application/problem+json',
    body: JSON.stringify({ type: `urn:mk:error:${code.toLowerCase()}`, title, status, code, request_id: requestId }) };
}

/** A kernel `ActionResult` (contracts/action/v1/action-result.schema.json). */
export function actionResult(over: Record<string, unknown> = {}) {
  return { schema_version: 'mk.action.v1', action_id: ACTION_ID, tenant_id: '00000000-0000-4000-8000-000000000001', state: 'queued',
    action_digest: DIGEST, attempt: 0, updated_at: '2026-10-21T14:45:01Z', message_state: 'queued', read_status: 'unknown', ...over };
}

/** A kernel approve/reject response (`mk-api::routes::approvals::DecisionResponse`). */
export function decision(over: { approver_id?: string; decision?: string; result?: Record<string, unknown> } = {}) {
  return {
    approval: { schema_version: 'mk.action.v1', approval_id: '33333333-3333-4333-8333-333333333333', tenant_id: '00000000-0000-4000-8000-000000000001',
      action_id: (over.result?.action_id as string) ?? ACTION_ID, action_digest: (over.result?.action_digest as string) ?? DIGEST,
      approver_id: over.approver_id ?? 'u1', approver_roles: ['consultant'], decision: over.decision ?? 'approved',
      created_at: '2026-10-21T14:45:01Z', expires_at: '2026-10-21T15:00:01Z', consumed_at: null },
    result: actionResult(over.result ?? {}),
  };
}

export function challenge(digest = DIGEST) {
  return { challenge: 'AAAA', rp_id: 'localhost', action_id: ACTION_ID, action_digest: digest, expires_at: '2026-10-21T14:47:00Z',
    allow_credentials: ['AQID'], user_verification: 'required' };
}

export const json = (route: Route, body: unknown, status = 200) =>
  route.fulfill({ status, contentType: 'application/json', body: JSON.stringify(body) });

/** Stand in for the platform authenticator with deterministic bytes, and count ceremonies
 *  (`window.__passkeyCalls`) so a test can prove no prompt was shown. */
export async function fakePasskey(page: Page) {
  await page.addInitScript(() => {
    (window as any).__passkeyCalls = 0;
    (window as any).__passkeyRequests = [];
    const bytes = (n: number) => new Uint8Array(Array.from({ length: n }, (_, i) => i)).buffer;
    (navigator.credentials as any).get = async (opts: { publicKey: { rpId: string; challenge: Uint8Array; userVerification: string; allowCredentials: { id: Uint8Array }[] } }) => {
      (window as any).__passkeyCalls += 1;
      const pk = opts.publicKey;
      (window as any).__passkeyRequests.push({ rpId: pk.rpId, challengeBytes: Array.from(new Uint8Array(pk.challenge)), userVerification: pk.userVerification,
        allowCredentials: pk.allowCredentials.map(c => Array.from(new Uint8Array(c.id))) });
      return { rawId: bytes(32), response: { clientDataJSON: bytes(40), authenticatorData: bytes(37), signature: bytes(70) } };
    };
  });
}

export const passkeyCalls = (page: Page) => page.evaluate(() => (window as any).__passkeyCalls as number);
export const passkeyRequests = (page: Page) => page.evaluate(() => (window as any).__passkeyRequests as
  { rpId: string; challengeBytes: number[]; userVerification: string; allowCredentials: number[][] }[]);

/** Mock every API the screens call. Responses mirror the real route shapes. */
export async function mockApi(page: Page) {
  await page.clock.setFixedTime(NOW);
  await page.route('**/api/**', async route => {
    const url = new URL(route.request().url());
    const p = url.pathname; const m = route.request().method();
    const reply = (body: unknown, status = 200) => json(route, body, status);
    if (p === '/api/auth/me') return reply({ id: 'u1', email: 'a@x', role: 'admin', display_name: 'Angela' });
    if (p === '/api/brief') return reply({ date: '2026-10-21', items: [{
      id: 'b1', customer: { id: 'c1', name: 'Brenda Lee' }, rule: 'commitment_due', rank_category: 2, source_type: 'commitment', source_reference: 'k1', source: COMMIT,
      due_at: '2026-10-21T14:00:00Z', state: 'open', permission_state: 'active', permission_checked_at: '2026-10-21T08:00:00Z',
      permission_note: 'historical observation; execution re-checks the kernel', suggested_step: 'Due today — follow through', draft_version_id: null,
      controls: ['approve', 'edit', 'defer', 'resolve', 'skip'] }],
      ranking: ['safety/opt-out attention', 'overdue confirmed', 'due today', 'unanswered requests', 'future scheduled'] });
    if (p === '/api/approvals/pending') return reply([pendingItem()]);
    if (p === '/api/exceptions') return reply([{ id: 'x1', customer_id: 'c1', kind: 'product_concern', state: 'open', source_reference: 'inbound:SM1', detail: 'rash — this gave me a rash', created_at: '2026-10-21T09:00:00Z', resolved_at: null }]);
    if (p === '/api/agent-ops/inbound/health') return reply({ health: { last_ok_at: '2026-10-21T09:00:00Z', last_failure_at: null, last_failure_reason: '', paused_since: null, resumed_at: null }, dispatch_blocked: null, pending_events: 0, stale_after_secs: 60 });
    if (p === '/api/agent-ops/health') return reply({ kernel_status: 200, configured: true, kernel: { database: true, dispatch_enabled: true, rust_kernel_enabled: true,
      effective: { approval_binding: 'webauthn', approval_require_uv: true, key_versions: [1], current_key_version: 1, legacy_seal_accepted: false, fingerprint_kids: ['f1'], public_webhook_base_https: true } } });
    if (p === '/api/agent-ops/approval-credentials') return reply([{ credential_row_id: 'r1', user_id: 'u1', credential_id_b64: 'AQID', label: 'my phone', alg: 'ES256', created_at: '2026-10-20T00:00:00Z', last_used_at: null, revoked_at: null }]);
    if (p === '/api/agent-ops/senders') return reply([{ sender_identity_id: 's1', owner_user_id: 'u1', provider: 'twilio', display_name: "Angela's Business", account_sid_redacted: 'AC…0000', from_number: '+15005550006', messaging_service_sid: null, registration_status: 'registered', status: 'active', created_at: '2026-10-01T00:00:00Z' }]);
    if (p === '/api/customers' && m === 'GET') return reply([CUST]);
    if (p === '/api/customers/c1/timeline') return reply([{ at: '2026-10-20T10:00:00Z', type: 'commitment', data: COMMIT }]);
    if (p === '/api/commitments') return reply([COMMIT]);
    if (p === '/api/customers/c1/permissions') return reply({ observed_at: '2026-10-21T09:00:00Z', note: 'historical observation', consent_events: [{ id: 'e1', channel: 'sms', purposes: ['customer_requested_follow_up'], status: 'active', source: 'web_form', effective_at: '2026-10-01T00:00:00Z', expires_at: '2027-10-01T00:00:00Z', revoked_at: null }], suppressions: [] });
    if (p === '/api/customers/c1/destinations') return reply([{ id: 'd1', channel: 'sms', value_masked: '••••••••0100', fingerprint: 'f'.repeat(64), is_primary: true, source: 'manual', suppressed: false }]);
    if (p === '/api/keys/status') return reply({ policy: 'both', mine: [], tenant: [], server: [] });
    if (p === '/api/usage/me' || p === '/api/usage/tenant') return reply([]);
    if (p === '/api/chat/skills') return reply({});
    if (p === '/api/chat/models') return reply({});
    if (p === '/api/chat/conversations') return reply([]);
    if (p === '/api/billing/me') return reply({ status: 'trialing', tier: 'solo', interval: 'year', trial_end: null, current_period_end: null, active: true, referral_code: null, referral_credits_earned_cents: 0, referral_count: 0 });
    if (p === '/api/billing/plans') return reply({ configured: false, trial_days: 90, plans: [] });
    if (p === '/api/consent/skin') return reply({ version: '1', operator_consent: true, operator_granted_at: '2026-10-01T00:00:00Z', operator_text: 'x', customer_text: 'y', ai_disclosure: 'z' });
    if (p === '/api/skin/history') return reply([]);
    return reply({ detail: `unmocked ${m} ${p}` }, 404);
  });
  await page.addInitScript((t) => { sessionStorage.setItem('mk_tokens', JSON.stringify(t)); sessionStorage.setItem('cs_ai_notice_seen', '1'); }, TOKENS);
}

/** Open the approvals screen from the main navigation. */
export async function openApprovals(page: Page) {
  await page.goto('/');
  await page.getByRole('navigation', { name: 'Main' }).getByRole('button', { name: 'Approvals' }).click();
}
