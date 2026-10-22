import { test, expect } from '@playwright/test';
import { mockApi } from './fixtures';

/** Rows H1 and H4 at the interface: every required field is shown; approval is one
 *  explicit gesture per message that triggers the passkey ceremony over the digest
 *  shown; no pre-selection, no approve-all. */
test('approval screen shows every H1 field and requires an explicit per-message passkey gesture', async ({ page }) => {
  await mockApi(page);
  const calls: string[] = [];
  await page.route('**/api/agent-ops/actions/*/approval-challenge', async route => {
    calls.push('challenge');
    await route.fulfill({ status: 200, contentType: 'application/json', body: JSON.stringify({
      challenge: 'AAAA', rp_id: 'localhost', action_digest: 'sha256:' + 'b'.repeat(64), expires_at: '2026-10-21T15:02:00Z',
      allow_credentials: ['AQID'], user_verification: 'required' }) });
  });
  await page.route('**/api/agent-ops/actions/*/approve', async route => { calls.push('approve'); await route.fulfill({ status: 403, contentType: 'application/json', body: JSON.stringify({ detail: { code: 'WEBAUTHN_BAD_SIGNATURE', title: 'x' } }) }); });
  // Stand in for the platform authenticator: deterministic bytes.
  await page.addInitScript(() => {
    const bytes = (n: number) => new Uint8Array(Array.from({ length: n }, (_, i) => i)).buffer;
    (navigator.credentials as any).get = async () => ({ rawId: bytes(32), response: { clientDataJSON: bytes(40), authenticatorData: bytes(37), signature: bytes(70) } });
  });
  await page.goto('/');
  await page.getByRole('navigation', { name: 'Main' }).getByRole('button', { name: 'Approvals' }).click();
  const item = page.getByRole('listitem').filter({ hasText: 'Brenda Lee' });
  // H1 fields
  for (const text of ['Brenda Lee', '********0100', "Angela's Business", '+15005550006', 'customer_requested_follow_up', 'Send the shade chart',
                      'active', 'As soon as policy allows', 'expires', 'digest bbbbbbbbbbbbbbbb']) {
    await expect(item.getByText(text, { exact: false }).first()).toBeVisible();
  }
  await expect(item.getByRole('blockquote', { name: 'Exact message text' })).toHaveText('Hi Brenda! Here is the shade chart I promised. Reply STOP to opt out.');
  // H4: no checkbox / default selection / approve-all anywhere
  expect(await page.getByRole('checkbox').count()).toBe(0);
  expect(await page.getByRole('button', { name: /approve all/i }).count()).toBe(0);
  const btn = item.getByRole('button', { name: 'Approve this message with passkey' });
  await expect(btn).toBeVisible();
  expect(calls).toEqual([]);
  await btn.click();
  await expect.poll(() => calls).toEqual(['challenge', 'approve']);
  // Plain-language error with recovery step for the kernel's refusal
  await expect(page.getByRole('alert')).toContainText('The passkey signature did not verify.');
  await expect(page.getByRole('alert')).toContainText('Try again');
});

test('a changed digest between display and approval is refused client-side', async ({ page }) => {
  await mockApi(page);
  let approved = false;
  await page.route('**/api/agent-ops/actions/*/approval-challenge', r => r.fulfill({ status: 200, contentType: 'application/json', body: JSON.stringify({
    challenge: 'AAAA', rp_id: 'localhost', action_digest: 'sha256:' + 'c'.repeat(64), expires_at: '2026-10-21T15:02:00Z', allow_credentials: ['AQID'], user_verification: 'required' }) }));
  await page.route('**/api/agent-ops/actions/*/approve', r => { approved = true; r.fulfill({ status: 200, body: '{}' }); });
  await page.goto('/');
  await page.getByRole('navigation', { name: 'Main' }).getByRole('button', { name: 'Approvals' }).click();
  await page.getByRole('button', { name: 'Approve this message with passkey' }).click();
  await expect(page.getByRole('alert')).toContainText('changed since it was displayed');
  expect(approved).toBe(false);
});

test('self-approval policy is displayed and refusal disables the ceremony', async ({ page }) => {
  await mockApi(page, 'active', { can_approve: false, self_approval: true, approval_denial: 'self_approval_forbidden', approval_lifetime_minutes: 5 });
  let calls = 0;
  await page.route('**/approval-challenge', route => { calls++; return route.fulfill({ status: 500 }); });
  await page.goto('/');
  await page.getByRole('navigation', { name: 'Main' }).getByRole('button', { name: 'Approvals' }).click();
  await expect(page.getByText(/5 minute lifetime/)).toBeVisible();
  await expect(page.getByText(/A different authorized person must approve/)).toBeVisible();
  await expect(page.getByRole('button', { name: 'Approve this message with passkey' })).toBeDisabled();
  expect(calls).toBe(0);
});

test('a missing selected sender disables approval instead of guessing another identity', async ({ page }) => {
  await mockApi(page, 'active', { sending_business: null });
  await page.goto('/');
  await page.getByRole('navigation', { name: 'Main' }).getByRole('button', { name: 'Approvals' }).click();
  await expect(page.getByText(/Selected sender details are unavailable/)).toBeVisible();
  await expect(page.getByRole('button', { name: 'Approve this message with passkey' })).toBeDisabled();
});

test('approval refuses a user-verification downgrade before requesting a signature', async ({ page }) => {
  await mockApi(page);
  await page.addInitScript(() => { (navigator.credentials as any).get = () => { throw new Error('AUTHENTICATOR_WAS_CALLED'); }; });
  await page.route('**/approval-challenge', route => route.fulfill({ status: 200, contentType: 'application/json', body: JSON.stringify({
    action_digest: 'sha256:' + 'b'.repeat(64), user_verification: 'preferred', challenge: 'AAAA', rp_id: 'localhost', allow_credentials: ['AQID'] }) }));
  await page.goto('/');
  await page.getByRole('navigation', { name: 'Main' }).getByRole('button', { name: 'Approvals' }).click();
  await page.getByRole('button', { name: 'Approve this message with passkey' }).click();
  await expect(page.getByRole('alert')).toContainText('Approval requires a verified passkey');
  await expect(page.getByRole('alert')).not.toContainText('AUTHENTICATOR_WAS_CALLED');
});

/** Codex finding on #35: the brief compared permission to 'granted', a value the backend
 *  never returns (it reports none | active | suppressed), so consultants with valid
 *  consent never saw the draft action. The fixture carries the backend's real value. */
test('brief offers drafting when the permission observation is active', async ({ page }) => {
  await mockApi(page);
  await page.goto('/');
  await expect(page.getByText('Permission:')).toBeVisible();
  await expect(page.getByRole('button', { name: 'Draft a message' })).toBeVisible();
});

for (const permission of ['none', 'suppressed'] as const) {
  test(`brief retains source and safe controls without drafting when permission is ${permission}`, async ({ page }) => {
    await mockApi(page, permission);
    await page.goto('/');
    const item = page.getByRole('listitem').filter({ hasText: 'Brenda Lee' });
    await expect(item.getByText('Send the shade chart', { exact: false }).first()).toBeVisible();
    await expect(item.getByRole('button', { name: 'Draft a message' })).toHaveCount(0);
    for (const name of ['Defer to tomorrow', 'Mark resolved', 'Skip']) {
      await expect(item.getByRole('button', { name, exact: true })).toBeVisible();
    }
    if (permission === 'suppressed') await expect(item).toContainText('Outreach is blocked.');
  });
}
