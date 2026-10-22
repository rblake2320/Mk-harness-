import type { Page } from '@playwright/test';

export const TOKENS = { access_token: 'a', refresh_token: 'r', role: 'admin', display_name: 'Angela', tenant_id: 't1' };
const CUST = { id: 'c1', name: 'Brenda Lee', phone: '+15555550100', email: '', notes: 'private', last_contact: null };
const COMMIT = { id: 'k1', customer_id: 'c1', kind: 'promise', text: 'Send the shade chart', status: 'confirmed', due_at: '2026-10-21T14:00:00Z',
  due_window: [null, null], timezone: 'America/Chicago', source_type: 'conversation', source_reference: 'conv-1', evidence_digest: 'sha256:' + 'a'.repeat(64),
  created_by: 'ai:anthropic:x', confirmed_by: 'u1', version: 2 };

/** Mock every API the screens call. Responses mirror the real route shapes. */
export async function mockApi(page: Page, permission: 'active' | 'none' | 'suppressed' = 'active') {
  await page.route('**/api/**', async route => {
    const url = new URL(route.request().url());
    const p = url.pathname; const m = route.request().method();
    const json = (body: unknown, status = 200) => route.fulfill({ status, contentType: 'application/json', body: JSON.stringify(body) });
    if (p === '/api/auth/me') return json({ id: 'u1', email: 'a@x', role: 'admin', display_name: 'Angela' });
    if (p === '/api/brief') return json({ date: '2026-10-21', items: [{
      id: 'b1', customer: { id: 'c1', name: 'Brenda Lee' }, rule: 'due_today', rank_category: 2, source_type: 'commitment', source_reference: 'k1', source: COMMIT,
      due_at: '2026-10-21T14:00:00Z', state: 'open', permission_state: permission, permission_checked_at: '2026-10-21T08:00:00Z',
      permission_note: 'historical observation; execution re-checks the kernel',
      suggested_step: permission === 'suppressed' ? 'Outreach is blocked. Review the suppression before any contact.' : 'Send the shade chart you promised.',
      draft_version_id: null, controls: [...(permission === 'active' ? ['approve', 'edit'] : []), 'defer', 'resolve', 'skip'] }] });
    if (p === '/api/approvals/pending') return json([{
      action_id: '11111111-1111-4111-8111-111111111111', action_digest: 'sha256:' + 'b'.repeat(64), state: 'approval_required', message_state: 'awaiting_approval',
      exact_text: 'Hi Brenda! Here is the shade chart I promised. Reply STOP to opt out.', destination_masked: '********0100', channel: 'sms',
      purpose: 'customer_requested_follow_up', workflow: 'customer_follow_up', risk: 'high', customer: { id: 'c1', name: 'Brenda Lee' },
      sending_business: { sender_identity_id: 's1', display_name: "Angela's Business", from_number: '+15005550006', registration_status: 'registered' },
      supporting: { commitment: { id: 'k1', text: 'Send the shade chart', status: 'confirmed', evidence_digest: 'sha256:' + 'a'.repeat(64) }, draft_version_id: 'd1', evidence_count: 2 },
      permission: { state: 'active', checked_at: '2026-10-21T08:00:00Z', note: 'historical observation; the kernel re-checks consent and suppression at send time' },
      scheduled_for: null, approval_expires_at: '2026-10-21T15:00:00Z', approval_lifetime_minutes: 15,
      human_steps: ['Your passkey signs this exact text.', 'Approval is single-use and expires.'] }]);
    if (p === '/api/exceptions') return json([{ id: 'x1', customer_id: 'c1', kind: 'product_concern', state: 'open', source_reference: 'inbound:SM1', detail: 'rash — this gave me a rash', created_at: '2026-10-21T09:00:00Z', resolved_at: null }]);
    if (p === '/api/delivery-exceptions') return json({ items: [], next_cursor: null });
    if (p === '/api/agent-ops/inbound/health') return json({ health: { last_ok_at: '2026-10-21T09:00:00Z' }, dispatch_blocked: null, pending_events: 0, stale_after_secs: 60 });
    if (p === '/api/agent-ops/health') return json({ status: 'ok' });
    if (p === '/api/agent-ops/approval-credentials') return json([{ credential_row_id: 'r1', label: 'my phone', alg: 'ES256', created_at: '2026-10-20T00:00:00Z', last_used_at: null, revoked_at: null }]);
    if (p === '/api/agent-ops/senders') return json([{ sender_identity_id: 's1', display_name: "Angela's Business", from_number: '+15005550006', registration_status: 'registered', status: 'active', owner_user_id: 'u1' }]);
    if (p === '/api/customers' && m === 'GET') return json([CUST]);
    if (p === '/api/customers/c1/timeline') return json([{ at: '2026-10-20T10:00:00Z', type: 'commitment', data: COMMIT }]);
    if (p === '/api/commitments') return json([COMMIT]);
    if (p === '/api/customers/c1/permissions') return json({ observed_at: '2026-10-21T09:00:00Z', note: 'historical observation', consent_events: [{ id: 'e1', channel: 'sms', purposes: ['customer_requested_follow_up'], status: 'active', source: 'web_form', effective_at: '2026-10-01T00:00:00Z', expires_at: '2027-10-01T00:00:00Z', revoked_at: null }], suppressions: [] });
    if (p === '/api/customers/c1/destinations') return json([{ id: 'd1', channel: 'sms', masked: '********0100', is_primary: true }]);
    if (p === '/api/keys/status') return json({ policy: 'both', mine: [], tenant: [], server: [] });
    if (p === '/api/usage/me' || p === '/api/usage/tenant') return json([]);
    if (p === '/api/chat/skills') return json({});
    if (p === '/api/chat/models') return json({});
    if (p === '/api/chat/conversations') return json([]);
    if (p === '/api/billing/me') return json({ status: 'trialing', tier: 'solo', interval: 'year', trial_end: null, current_period_end: null, active: true, referral_code: null, referral_credits_earned_cents: 0, referral_count: 0 });
    if (p === '/api/billing/plans') return json({ configured: false, trial_days: 90, plans: [] });
    if (p === '/api/consent/skin') return json({ version: '1', operator_consent: true, operator_granted_at: '2026-10-01T00:00:00Z', operator_text: 'x', customer_text: 'y', ai_disclosure: 'z' });
    if (p === '/api/skin/history') return json([]);
    return json({ detail: `unmocked ${m} ${p}` }, 404);
  });
  await page.addInitScript((t) => { sessionStorage.setItem('mk_tokens', JSON.stringify(t)); sessionStorage.setItem('cs_ai_notice_seen', '1'); }, TOKENS);
}
