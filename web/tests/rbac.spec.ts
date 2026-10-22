import { test, expect } from '@playwright/test';
import AxeBuilder from '@axe-core/playwright';
import { mockApi, TOKENS } from './fixtures';

test('auditor sees only account security and audit evidence, never customer or action UI', async ({ page }) => {
  await mockApi(page);
  await page.addInitScript(tokens => sessionStorage.setItem('mk_tokens', JSON.stringify(tokens)), { ...TOKENS, role: 'auditor' });
  const paths: string[] = [];
  page.on('request', request => { if (request.url().includes('/api/')) paths.push(new URL(request.url()).pathname); });
  await page.goto('/');
  await expect(page.getByRole('heading', { name: 'Settings', exact: true })).toBeVisible();
  await expect(page.getByRole('button', { name: 'Export audit log (auditor)' })).toBeVisible();
  await expect(page.getByRole('button', { name: 'My customers', exact: true })).toHaveCount(0);
  await expect(page.getByRole('button', { name: 'Add passkey', exact: true })).toHaveCount(0);
  await expect(page.getByRole('heading', { name: 'AI engines' })).toHaveCount(0);
  await expect(page.getByRole('region', { name: 'Team access' })).toHaveCount(0);
  expect(paths.some(path => path.startsWith('/api/agent-ops/') || path === '/api/brief' || path === '/api/customers')).toBe(false);
  await page.setViewportSize({ width: 360, height: 800 });
  expect((await new AxeBuilder({ page }).withTags(['wcag2a', 'wcag2aa', 'wcag21aa', 'wcag22aa']).analyze()).violations).toEqual([]);
});

test('administrator can change another member role but not own access', async ({ page }) => {
  await mockApi(page);
  let role = 'consultant';
  await page.route('**/api/auth/members', route => route.fulfill({ json: [
    { id: 'u1', email: 'self@example.com', display_name: 'Self', role: 'admin', is_active: true },
    { id: 'u2', email: 'other@example.com', display_name: 'Other', role, is_active: true },
  ] }));
  await page.route('**/api/auth/members/u2', route => {
    role = route.request().postDataJSON().role;
    return route.fulfill({ json: { id: 'u2', role, is_active: true, kernel_revocation: 'pending' } });
  });
  await page.goto('/');
  await page.getByRole('button', { name: 'Settings', exact: true }).click();
  const section = page.getByRole('region', { name: 'Team access' });
  await expect(section.getByLabel('Role for self@example.com')).toBeDisabled();
  await expect(section.getByRole('button', { name: 'Disable Self' })).toBeDisabled();
  await section.getByLabel('Role for other@example.com').selectOption('auditor');
  await expect(section.getByRole('status')).toContainText('Old app sessions are revoked');
  await expect(section.getByLabel('Role for other@example.com')).toHaveValue('auditor');
});
