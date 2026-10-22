import { test, expect } from '@playwright/test';
import { mockApi } from './fixtures';

const receipt = { ok: true, request_id: 'erasure-fixture', active_store_erased: true,
  status: 'pending_downstream', pending: ['kernel_account', 'backup_expiry'],
  due_at: '2026-11-22T00:00:00Z', backup_expires_at: '2026-11-27T00:00:00Z',
  detail: 'Active application data erased; downstream and backup processing is pending.',
  status_token: 'synthetic-receipt-only' };

test('account deletion clears auth and shows a saveable pending receipt', async ({ page }) => {
  await mockApi(page);
  await page.route('**/api/account', route => route.fulfill({ status: 202, contentType: 'application/json', body: JSON.stringify(receipt) }));
  await page.goto('/');
  await page.getByRole('navigation', { name: 'Main' }).getByRole('button', { name: 'Settings', exact: true }).click();
  await page.getByText('Delete my account', { exact: true }).click();
  await page.getByLabel('Confirm with your password').fill('synthetic-password');
  await page.getByRole('button', { name: 'Delete account', exact: true }).click();
  await expect(page.getByRole('heading', { name: 'Deletion request accepted' })).toBeVisible();
  await expect(page.getByText(receipt.detail, { exact: true })).toBeVisible();
  expect(await page.evaluate(() => sessionStorage.getItem('mk_tokens'))).toBeNull();
  await expect(page.getByRole('navigation', { name: 'Main' })).toHaveCount(0);
  const download = page.waitForEvent('download');
  await page.getByRole('button', { name: 'Save deletion receipt' }).click();
  expect((await download).suggestedFilename()).toBe('deletion-receipt.json');
});

test('customer deletion reports downstream pending and displays server refusal', async ({ page }) => {
  await mockApi(page);
  let calls = 0;
  await page.route('**/api/customers/c1', route => {
    calls += 1;
    return route.fulfill({ status: calls === 1 ? 409 : 202, contentType: 'application/json',
      body: JSON.stringify(calls === 1 ? { detail: 'Deletion request refused' } : receipt) });
  });
  await page.goto('/');
  await page.getByRole('navigation', { name: 'Main' }).getByRole('button', { name: 'My customers', exact: true }).click();
  await page.getByRole('button', { name: 'Delete', exact: true }).click();
  await expect(page.getByRole('alert')).toContainText('Deletion request refused');
  await page.getByRole('button', { name: 'Delete', exact: true }).click();
  await expect(page.getByText(receipt.detail, { exact: true })).toBeVisible();
});
