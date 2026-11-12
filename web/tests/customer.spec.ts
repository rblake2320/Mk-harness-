import { test, expect, type Page } from '@playwright/test';
import { json, mockApi } from './fixtures';

/** Customer page gaps closed with this change: consent was posted without the destination the
 *  route requires (422), destinations read a field the API does not return, nothing could
 *  record a do-not-contact, and "opted out" looked like it stopped messages. */
async function openCustomer(page: Page) {
  await page.goto('/');
  await page.getByRole('navigation', { name: 'Main' }).getByRole('button', { name: 'My customers' }).click();
  await page.getByRole('button', { name: 'Brenda Lee' }).click();
  await expect(page.getByText('Permission & suppression')).toBeVisible();
}

test('consent is recorded for the primary, unsuppressed number on file', async ({ page }) => {
  await mockApi(page);
  const bodies: unknown[] = [];
  await page.route('**/api/customers/c1/consent', r => { bodies.push(r.request().postDataJSON()); return json(r, { id: 'e2', status: 'active' }, 201); });
  await openCustomer(page);
  await expect(page.getByText('sms · ••••••••0100')).toBeVisible();
  await page.getByLabel(/Record consent/).fill('Yes, text me about my orders — said at the party');
  await page.getByRole('button', { name: 'Record consent for order follow-ups' }).click();
  await expect.poll(() => bodies.length).toBe(1);
  expect(bodies[0]).toEqual({ destination_id: 'd1', purposes: ['customer_requested_follow_up'], source: 'verbal_confirmed',
    evidence_type: 'consultant_attestation', evidence_text: 'Yes, text me about my orders — said at the party' });
});

test('"mark do not contact" needs a confirming click, then files a permanent suppression for that number', async ({ page }) => {
  await mockApi(page);
  let suppressed = false;
  const bodies: unknown[] = [];
  await page.route('**/api/suppressions', r => { bodies.push(r.request().postDataJSON()); suppressed = true; return json(r, { id: 's1', fingerprint: 'f', channel: 'sms', kernel_suppression_id: 'k' }, 201); });
  await page.route('**/api/customers/c1/destinations', r => json(r, [{ id: 'd1', channel: 'sms', value_masked: '••••••••0100', fingerprint: 'f'.repeat(64), is_primary: true, source: 'manual', suppressed }]));
  await openCustomer(page);
  await page.getByRole('button', { name: 'mark do not contact: ••••••••0100' }).click();
  expect(bodies).toEqual([]);
  await page.getByRole('button', { name: 'Confirm: never message ••••••••0100' }).click();
  await expect.poll(() => bodies.length).toBe(1);
  expect(bodies[0]).toEqual({ destination_id: 'd1', reason: 'customer asked not to be contacted', source: 'consultant', permanent: true });
  await expect(page.getByText('· do not contact')).toBeVisible();
  await expect(page.getByRole('button', { name: /mark do not contact/ })).toHaveCount(0);
});

test('"keep" cancels the do-not-contact confirmation without filing anything', async ({ page }) => {
  await mockApi(page);
  let calls = 0;
  await page.route('**/api/suppressions', r => { calls += 1; return json(r, {}, 201); });
  await openCustomer(page);
  await page.getByRole('button', { name: 'mark do not contact: ••••••••0100' }).click();
  await page.getByRole('button', { name: 'keep' }).click();
  await expect(page.getByRole('button', { name: 'Confirm: never message ••••••••0100' })).toHaveCount(0);
  expect(calls).toBe(0);
});

test('choosing the "opted out" outcome says it does not stop messages', async ({ page }) => {
  await mockApi(page);
  await openCustomer(page);
  await page.getByRole('combobox', { name: 'Outcome' }).selectOption('opted_out');
  await expect(page.getByText('Recording this outcome does not stop messages.')).toBeVisible();
});
