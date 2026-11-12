import { test, expect } from '@playwright/test';
import { DIGEST, challenge, fakePasskey, json, mockApi, openApprovals, passkeyCalls, problem } from './fixtures';

/** Rows H1 and H4 at the interface: every required field is shown; approval is one
 *  explicit gesture per message that triggers the passkey ceremony over the digest
 *  shown; no pre-selection, no approve-all. */
test('approval screen shows every H1 field and requires an explicit per-message passkey gesture', async ({ page }) => {
  await mockApi(page);
  await fakePasskey(page);
  const calls: string[] = [];
  await page.route('**/api/agent-ops/actions/*/approval-challenge', async route => { calls.push('challenge'); await json(route, challenge(DIGEST)); });
  await page.route('**/api/agent-ops/actions/*/approve', async route => { calls.push('approve'); await route.fulfill(problem(403, 'WEBAUTHN_BAD_SIGNATURE', 'WebAuthn signature invalid')); });
  await openApprovals(page);
  const item = page.getByRole('listitem').filter({ hasText: 'Brenda Lee' });
  // H1 fields: destination, customer, sending business + number, purpose, supporting commitment,
  // permission state, scheduled time, approval expiry, digest.
  for (const text of ['Brenda Lee', '********0100', "Angela's Business", '+15005550006', 'customer_requested_follow_up', 'Send the shade chart',
                      'Permission on record', 'As soon as policy allows', 'Expires in 15 min', 'lasts 15 minutes', 'digest bbbbbbbbbbbbbbbb']) {
    await expect(item.getByText(text, { exact: false }).first()).toBeVisible();
  }
  await expect(item.getByRole('blockquote', { name: 'Exact message text' })).toHaveText('Hi Brenda! Here is the shade chart I promised. Reply STOP to opt out.');
  await expect(item.getByText('Estimated 1 SMS segment (GSM-7')).toBeVisible();
  // The message state comes from the shared vocabulary, label and verbatim definition.
  await expect(item.getByText('Awaiting approval', { exact: true })).toBeVisible();
  await expect(item.getByText('Waiting for an explicit human approval gesture.')).toBeVisible();
  // H4: no checkbox / default selection / approve-all anywhere
  expect(await page.getByRole('checkbox').count()).toBe(0);
  expect(await page.getByRole('button', { name: /approve all/i }).count()).toBe(0);
  const btn = item.getByRole('button', { name: 'Approve this message with passkey' });
  await expect(btn).toBeVisible();
  expect(calls).toEqual([]);
  await btn.click();
  await expect.poll(() => calls).toEqual(['challenge', 'approve']);
  expect(await passkeyCalls(page)).toBe(1);
  // Plain-language error with recovery step for the kernel's refusal; the code is not swallowed.
  const alert = page.getByRole('alert');
  await expect(alert).toContainText('The passkey signature did not verify.');
  await expect(alert).toContainText('Try again');
  await expect(alert).toContainText('WEBAUTHN_BAD_SIGNATURE');
  await expect(alert).toContainText('request req-test-1');
});

test('a changed digest between display and approval is refused client-side', async ({ page }) => {
  await mockApi(page);
  await fakePasskey(page);
  let approved = false;
  await page.route('**/api/agent-ops/actions/*/approval-challenge', r => json(r, challenge('sha256:' + 'c'.repeat(64))));
  await page.route('**/api/agent-ops/actions/*/approve', r => { approved = true; return json(r, {}); });
  await openApprovals(page);
  await page.getByRole('button', { name: 'Approve this message with passkey' }).click();
  await expect(page.getByRole('alert')).toContainText('changed since it was displayed');
  expect(approved).toBe(false);
  expect(await passkeyCalls(page)).toBe(0);
});

/** Codex finding on #35: the brief compared permission to 'granted', a value the backend
 *  never returns (it reports none | active | suppressed), so consultants with valid
 *  consent never saw the draft action. The fixture carries the backend's real value. */
test('brief offers drafting when the permission observation is active', async ({ page }) => {
  await mockApi(page);
  await page.goto('/');
  await expect(page.getByText('Permission:')).toBeVisible();
  await expect(page.getByRole('button', { name: 'Draft a message' })).toBeVisible();
  // Real rule value (`commitment_due`) and rank category (2) get human labels, never the raw identifier.
  await expect(page.getByText('Due today · Your promise')).toBeVisible();
  await expect(page.getByText('commitment_due')).toHaveCount(0);
});
