import { test, expect } from '@playwright/test';
import { mockApi } from './fixtures';

test('editing after proposal withdraws the old version and offers a fresh proposal', async ({ page }) => {
  await mockApi(page);
  const draft = { id: 'd1', customer_id: 'c1', brief_item_id: 'b1', text: 'Hi Brenda! Reply STOP to opt out.',
    text_digest: 'sha256:' + 'a'.repeat(64), claims_used: [], source_versions: {}, generated_by: 'ai:test', version: 1, note: '' };
  const calls: string[] = [];
  let blocked = true;
  await page.route('**/api/drafts', route => route.fulfill({ json: { draft, limitation: null } }));
  await page.route('**/api/drafts/*/propose', async route => {
    calls.push(new URL(route.request().url()).pathname);
    await route.fulfill({ status: 202, json: { state: 'approval_required', human_steps: [] } });
  });
  await page.route('**/api/drafts/d1/edit', async route => {
    calls.push('withdraw');
    if (blocked) return route.fulfill({ status: 409, json: { detail: { code: 'DRAFT_ALREADY_IN_FLIGHT' } } });
    await route.fulfill({ status: 201, json: { ...draft, id: 'd2', version: 2, text: route.request().postDataJSON().text,
      text_digest: 'sha256:' + 'c'.repeat(64) } });
  });
  await page.goto('/');
  await page.getByRole('button', { name: 'Draft a message' }).click();
  await page.getByRole('button', { name: 'Propose for approval', exact: true }).click();
  await expect(page.getByText('Proposed for approval.', { exact: true })).toBeVisible();
  await page.getByLabel('Exact text', { exact: false }).fill('Hello Brenda! Reply STOP to opt out.');
  await page.getByRole('button', { name: 'Save as new version' }).click();
  await expect(page.getByRole('alert')).toContainText('Your edit was not saved');
  await expect(page.getByText('Old version withdrawn.', { exact: false })).toHaveCount(0);
  await expect(page.getByRole('button', { name: 'Propose for approval', exact: true })).toHaveCount(0);
  blocked = false;
  await page.getByRole('button', { name: 'Save as new version' }).click();
  await expect(page.getByText('Old version withdrawn.', { exact: false })).toContainText('fresh passkey approval');
  await expect(page.getByLabel('Exact text', { exact: false })).toHaveValue('Hello Brenda! Reply STOP to opt out.');
  await page.getByRole('button', { name: 'Propose for approval', exact: true }).click();
  expect(calls).toEqual(['/api/drafts/d1/propose', 'withdraw', 'withdraw', '/api/drafts/d2/propose']);
});
