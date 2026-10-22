import { test, expect } from '@playwright/test';
import AxeBuilder from '@axe-core/playwright';
import { MKClient } from '../../packages/sdk/src/index';
import { mockApi, TOKENS } from './fixtures';

test('SDK coalesces step-up, retries only explicit refusal and guards changed sessions', async () => {
  const client = new MKClient('https://fixture.invalid');
  client.tokens = { ...TOKENS, session_id: 'first' };
  const original = globalThis.fetch;
  let release: () => void = () => {};
  let confirmed = false, prompts = 0, calls = 0;
  const pending = new Promise<void>(resolve => { release = resolve; });
  client.onStepUpRequired = async () => { prompts++; await pending; confirmed = true; return true; };
  globalThis.fetch = async () => {
    calls++;
    return confirmed ? new Response('exported') : Response.json({ detail: { code: 'STEP_UP_REQUIRED' } }, { status: 403 });
  };
  try {
    const one = client.exportAudit(), two = client.exportCustomersCsv();
    await new Promise(resolve => setTimeout(resolve, 10));
    release();
    expect(await Promise.all([one, two])).toEqual(['exported', 'exported']);
    expect(prompts).toBe(1); expect(calls).toBe(4);
    confirmed = false; calls = 0;
    client.onStepUpRequired = async () => { client.tokens = { ...TOKENS, session_id: 'other' }; return true; };
    await expect(client.exportAudit()).rejects.toMatchObject({ status: 403 });
    expect(calls).toBe(1);
    globalThis.fetch = async () => { calls++; return Response.json({ detail: 'unavailable' }, { status: 503 }); };
    await expect(client.exportAudit()).rejects.toMatchObject({ status: 503 });
    expect(calls).toBe(2); // failed exports are errors, never downloaded as successful files
  } finally { globalThis.fetch = original; }
});

test('enrollment keeps recovery codes out of storage, gates the app and fits 360px', async ({ page }) => {
  await mockApi(page);
  await page.addInitScript(tokens => sessionStorage.setItem('mk_tokens', JSON.stringify(tokens)), { ...TOKENS, mfa_state: 'enrollment_required', session_id: 'limited' });
  const codes = Array.from({ length: 8 }, (_, i) => `fixture-code-${i}-not-a-real-secret`);
  await page.route('**/api/auth/mfa/enroll', r => r.fulfill({ json: { secret: 'SYNTHETICSETUPKEY' } }));
  await page.route('**/api/auth/mfa/confirm', r => r.fulfill({ json: { tokens: { ...TOKENS, mfa_state: 'verified', session_id: 'verified' }, recovery_codes: codes } }));
  await page.goto('/');
  await page.setViewportSize({ width: 360, height: 800 });
  await expect(page.getByRole('navigation', { name: 'Main' })).toHaveCount(0);
  await page.getByRole('button', { name: 'Set up authenticator' }).click();
  await expect(page.getByTestId('mfa-setup-key')).toHaveText('SYNTHETICSETUPKEY');
  await page.getByLabel('Authenticator code', { exact: true }).fill('123456');
  await page.getByRole('button', { name: 'Verify code', exact: true }).click();
  await expect(page.getByRole('heading', { name: 'Save your recovery codes' })).toBeVisible();
  expect(await page.evaluate(() => sessionStorage.getItem('mk_tokens'))).not.toContain(codes[0]);
  expect(await page.evaluate(() => document.documentElement.scrollWidth)).toBe(360);
  expect((await new AxeBuilder({ page }).withTags(['wcag2a', 'wcag2aa', 'wcag21aa', 'wcag22aa']).analyze()).violations).toEqual([]);
  await page.getByRole('button', { name: 'I saved my recovery codes' }).click();
  await expect(page.getByRole('heading', { name: "Today's brief" })).toBeVisible();
  expect(JSON.parse((await page.evaluate(() => sessionStorage.getItem('mk_tokens')))!).session_id).toBe('verified');
});

test('sensitive change uses a modal keyboard check, cancel sends nothing, then confirmation retries once', async ({ page }) => {
  await mockApi(page);
  let verified = false, writes = 0;
  await page.route('**/api/keys/mine', route => {
    if (!verified) return route.fulfill({ status: 403, json: { detail: { code: 'STEP_UP_REQUIRED' } } });
    writes++; return route.fulfill({ json: { ok: true } });
  });
  await page.route('**/api/auth/step-up', route => { verified = true; return route.fulfill({ json: { verified: true } }); });
  await page.goto('/');
  await page.getByRole('button', { name: 'Settings', exact: true }).click();
  await page.getByPlaceholder('API key', { exact: true }).fill('synthetic-key');
  await page.getByRole('button', { name: 'Save key', exact: true }).click();
  const dialog = page.getByRole('dialog', { name: 'Confirm this sensitive action' });
  await expect(dialog).toBeVisible();
  await expect(dialog.getByLabel('Password', { exact: true })).toBeFocused();
  await page.keyboard.press('Escape');
  await expect(dialog).toHaveCount(0); expect(writes).toBe(0);
  await page.getByRole('button', { name: 'Save key', exact: true }).click();
  await page.setViewportSize({ width: 360, height: 800 });
  expect((await new AxeBuilder({ page }).withTags(['wcag2a', 'wcag2aa', 'wcag21aa', 'wcag22aa']).analyze()).violations).toEqual([]);
  await dialog.getByLabel('Password', { exact: true }).fill('test-password');
  await dialog.getByRole('button', { name: 'Use a recovery code' }).click();
  await dialog.getByLabel('Recovery code', { exact: true }).fill('a'.repeat(32));
  await dialog.getByRole('button', { name: 'Confirm identity' }).click();
  await expect(dialog).toHaveCount(0); expect(writes).toBe(1);
});
