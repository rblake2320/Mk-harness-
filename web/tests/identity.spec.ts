import { test, expect, type Page } from '@playwright/test';
import AxeBuilder from '@axe-core/playwright';
import { mockApi, TOKENS } from './fixtures';

/** S2 at the interface: second sign-in step, first-sign-in enrollment gate (with
 *  one-time recovery codes), and step-up that retries the original request only
 *  after a fresh factor — and never after Cancel. API mocked at the network layer. */
const AXE_TAGS = ['wcag2a', 'wcag2aa', 'wcag21a', 'wcag21aa', 'wcag22aa'];
async function axe(page: Page) {
  const r = await new AxeBuilder({ page }).withTags(AXE_TAGS).analyze();
  expect(r.violations, JSON.stringify(r.violations.map(v => ({ id: v.id, nodes: v.nodes.map(n => n.target) })), null, 2)).toEqual([]);
}
const fulfill = (route: any, body: unknown, status = 200) =>
  route.fulfill({ status, contentType: 'application/json', body: JSON.stringify(body) });

test('sign-in with a second factor: wrong code shows attempts left, right code opens the app', async ({ page }) => {
  await mockApi(page);
  await page.addInitScript(() => sessionStorage.removeItem('mk_tokens'));
  const verifyBodies: any[] = [];
  await page.route('**/api/auth/login', r => fulfill(r, { mfa_required: true, mfa_token: 'm1', methods: ['recovery', 'totp'], expires_in: 300 }));
  await page.route('**/api/auth/mfa/verify', r => {
    const b = r.request().postDataJSON(); verifyBodies.push(b);
    return b.code === '123456' ? fulfill(r, TOKENS)
      : fulfill(r, { detail: { code: 'SECOND_FACTOR_INVALID', detail: 'x', attempts_left: 4 } }, 401);
  });
  await page.goto('/');
  await page.getByPlaceholder('Email').fill('a@x.example');
  await page.getByPlaceholder(/Password/).fill('correct horse battery');
  await page.getByRole('button', { name: 'Sign in' }).click();
  await expect(page.getByRole('heading', { name: 'Second step' })).toBeVisible();
  await axe(page);
  const code = page.getByLabel('Code from your authenticator app');
  await code.fill('12ab34');                        // non-digits are dropped as typed
  await expect(code).toHaveValue('1234');
  await code.fill('654321');
  await page.getByRole('button', { name: 'Verify' }).click();
  await expect(page.getByRole('alert')).toContainText('4 attempt(s) left');
  await code.fill('123456');
  await page.getByRole('button', { name: 'Verify' }).click();
  await expect(page.getByRole('navigation', { name: 'Main' })).toBeVisible();
  expect(verifyBodies.map(b => [b.mfa_token, b.method, b.code])).toEqual([['m1', 'totp', '654321'], ['m1', 'totp', '123456']]);
});

test('recovery code path is offered and sent as method=recovery', async ({ page }) => {
  await mockApi(page);
  await page.addInitScript(() => sessionStorage.removeItem('mk_tokens'));
  let sent: any = null;
  await page.route('**/api/auth/login', r => fulfill(r, { mfa_required: true, mfa_token: 'm1', methods: ['recovery', 'totp'], expires_in: 300 }));
  await page.route('**/api/auth/mfa/verify', r => { sent = r.request().postDataJSON(); return fulfill(r, TOKENS); });
  await page.goto('/');
  await page.getByPlaceholder('Email').fill('a@x.example');
  await page.getByPlaceholder(/Password/).fill('correct horse battery');
  await page.getByRole('button', { name: 'Sign in' }).click();
  await page.getByRole('button', { name: 'Use a recovery code instead' }).click();
  await page.getByLabel('One of your recovery codes').fill(' abcd-efgh-1234 ');
  await page.getByRole('button', { name: 'Verify' }).click();
  await expect(page.getByRole('navigation', { name: 'Main' })).toBeVisible();
  expect(sent).toEqual({ mfa_token: 'm1', method: 'recovery', code: 'abcd-efgh-1234' });
});

test('first sign-in must enroll a factor and acknowledge recovery codes before the app opens', async ({ page }) => {
  await mockApi(page);
  await page.addInitScript((t) => sessionStorage.setItem('mk_tokens', JSON.stringify({ ...t, mfa_enrollment_required: true })), TOKENS);
  await page.route('**/api/security/mfa/totp/begin', r => fulfill(r, { factor_id: 'f9', secret: 'JBSWY3DPEHPK3PXP', otpauth_uri: 'otpauth://totp/x', human_steps: [] }));
  await page.route('**/api/security/mfa/totp/confirm', r => fulfill(r, { factor: { id: 'f9', kind: 'totp', label: 'Authenticator app', created_at: 'x', last_used_at: null },
    recovery_codes: Array.from({ length: 10 }, (_, i) => `code-${i}`) }));
  await page.goto('/');
  await expect(page.getByRole('heading', { name: 'Protect your account' })).toBeVisible();
  await expect(page.getByRole('navigation', { name: 'Main' })).toHaveCount(0);   // nothing else reachable
  await axe(page);
  await page.getByRole('button', { name: 'Use an authenticator app' }).click();
  await expect(page.getByLabel('Setup key')).toHaveText('JBSW Y3DP EHPK 3PXP');
  await page.getByLabel('Enter the 6-digit code the app shows').fill('123456');
  await page.getByRole('button', { name: 'Finish' }).click();
  await expect(page.getByRole('region', { name: 'Recovery codes' })).toContainText('code-9');
  const cont = page.getByRole('button', { name: 'Continue' });
  await expect(cont).toBeDisabled();                     // codes must be acknowledged
  await page.getByLabel('I saved them').check();
  await cont.click();
  await expect(page.getByRole('navigation', { name: 'Main' })).toBeVisible();
});

test('step-up: a sensitive request prompts, retries once after a fresh factor, and Cancel retries nothing', async ({ page }) => {
  await mockApi(page);
  let exportCalls = 0; const stepUps: any[] = [];
  let fresh = false;
  await page.route('**/api/customers/export.csv', r => {
    exportCalls++;
    return fresh ? r.fulfill({ status: 200, contentType: 'text/csv', body: 'name\nBrenda Lee\n' })
      : fulfill(r, { detail: { code: 'STEP_UP_REQUIRED', detail: 'confirm', methods: ['totp'] } }, 403);
  });
  await page.route('**/api/security/step-up', r => { stepUps.push(r.request().postDataJSON()); fresh = true; return fulfill(r, { ok: true }); });
  await page.goto('/');
  await page.getByRole('navigation', { name: 'Main' }).getByRole('button', { name: 'Settings' }).click();
  // Cancel: no step-up call, no retry, no download.
  await page.getByRole('button', { name: 'Export customers (CSV)' }).click();
  const dialog = page.getByRole('dialog', { name: "Confirm it's you" });
  await expect(dialog).toBeVisible();
  await axe(page);
  await dialog.getByRole('button', { name: 'Cancel' }).click();
  await expect(dialog).toHaveCount(0);
  expect([exportCalls, stepUps.length]).toEqual([1, 0]);
  // Confirm: one step-up, then exactly one retry of the original request.
  const download = page.waitForEvent('download');
  await page.getByRole('button', { name: 'Export customers (CSV)' }).click();
  await dialog.getByLabel('Code from your authenticator app').fill('246810');
  await dialog.getByRole('button', { name: 'Confirm' }).click();
  await download;
  expect(stepUps).toEqual([{ method: 'totp', code: '246810' }]);
  expect(exportCalls).toBe(3);
});

test('security settings: sessions, factors, team roles and support-access requests are listed for an admin', async ({ page }) => {
  await mockApi(page);
  await page.goto('/');
  await page.getByRole('navigation', { name: 'Main' }).getByRole('button', { name: 'Settings' }).click();
  const sec = page.getByRole('region', { name: 'Sign-in security' });
  await expect(sec.getByText('Chrome on Windows')).toBeVisible();
  await expect(sec.getByText('this device')).toBeVisible();
  await expect(sec.getByRole('button', { name: 'Sign out all other devices' })).toBeVisible();
  await expect(sec.getByText("works in Angela's book")).toBeVisible();
  await expect(sec.getByText('SUP-1042', { exact: false })).toBeVisible();
  await expect(sec.getByRole('button', { name: 'Approve' })).toBeVisible();
});
