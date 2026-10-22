import { test, expect } from '@playwright/test';
import { MKClient } from '../../packages/sdk/src/index';
import { mockApi, TOKENS } from './fixtures';

test('SDK coalesces refreshes and handles a delayed old-token 401 without a second refresh', async () => {
  const client = new MKClient('https://fixture.invalid');
  client.tokens = { ...TOKENS };
  const saved: string[] = [];
  client.onTokensChanged = t => { if (t) saved.push(t.refresh_token); };
  let refreshes = 0;
  const original = globalThis.fetch;
  let releaseLate: () => void = () => {};
  const late = new Promise<void>(resolve => { releaseLate = resolve; });
  globalThis.fetch = async (url, init) => {
    if (String(url).endsWith('/refresh')) {
      refreshes++;
      await new Promise(resolve => setTimeout(resolve, 10));
      return Response.json({ ...TOKENS, access_token: 'new', refresh_token: 'rotated' });
    }
    const auth = (init?.headers as Record<string, string>)?.Authorization;
    if (String(url).endsWith('/sessions') && auth === 'Bearer a') await late;
    return auth === 'Bearer a' ? Response.json({}, { status: 401 }) : Response.json({ ok: true });
  };
  try {
    const delayed = client.sessions();
    const fast = [client.me(), client.me(), client.me()];
    await Promise.all(fast);
    releaseLate(); await delayed;
    expect(refreshes).toBe(1);
    expect(saved).toEqual(['rotated']);
    expect(client.tokens?.refresh_token).toBe('rotated');
  } finally { globalThis.fetch = original; }
});

test('SDK cannot resurrect a session if sign-out happens during refresh', async () => {
  const client = new MKClient('https://fixture.invalid');
  client.tokens = { ...TOKENS };
  const original = globalThis.fetch;
  let release: () => void = () => {};
  const waiting = new Promise<void>(resolve => { release = resolve; });
  globalThis.fetch = async () => { await waiting; return Response.json({ ...TOKENS, access_token: 'new' }); };
  try {
    const refreshing = client.refresh();
    client.tokens = null;
    release();
    expect(await refreshing).toBe(false);
    expect(client.tokens).toBeNull();
  } finally { globalThis.fetch = original; }
});

test('SDK never replays an old-session operation under a new login', async () => {
  const client = new MKClient('https://fixture.invalid');
  client.tokens = { ...TOKENS, session_id: 'old' };
  const original = globalThis.fetch;
  let release: () => void = () => {};
  let calls = 0;
  const waiting = new Promise<void>(resolve => { release = resolve; });
  globalThis.fetch = async () => { calls++; await waiting; return Response.json({}, { status: 401 }); };
  try {
    const operation = client.addMember('example@example.com', 'synthetic-password');
    client.tokens = { ...TOKENS, access_token: 'other', session_id: 'new' };
    release();
    await expect(operation).rejects.toThrow('Session changed');
    expect(calls).toBe(1);
    expect(client.tokens.session_id).toBe('new');
  } finally { globalThis.fetch = original; }
});

for (const outcome of ['confirmed', 'pending', 'offline'] as const) {
  test(`Sign out reports ${outcome} and clears browser tokens`, async ({ page }) => {
    await mockApi(page);
    let calls = 0;
    await page.route('**/api/auth/logout', route => {
      calls++;
      return outcome === 'offline' ? route.abort('internetdisconnected') : route.fulfill({
        status: outcome === 'confirmed' ? 200 : 202, json: { revoked: true, kernel_revocation: outcome } });
    });
    await page.goto('/');
    await page.setViewportSize({ width: 360, height: 800 });
    await page.getByRole('button', { name: 'Sign out', exact: true }).click();
    await expect(page.getByRole('button', { name: 'Sign in', exact: true })).toBeVisible();
    await expect(page.getByRole('status')).toContainText(outcome === 'confirmed' ? 'This session is revoked'
      : outcome === 'pending' ? 'awaiting delivery' : 'Local sign-out only');
    expect(calls).toBe(1);
    expect(await page.evaluate(() => sessionStorage.getItem('mk_tokens'))).toBeNull();
    expect(await page.evaluate(() => document.documentElement.scrollWidth)).toBe(360);
  });
}

test('Session list revokes another session and reports pending delivery honestly', async ({ page }) => {
  await mockApi(page);
  let revoked = false;
  await page.route('**/api/auth/sessions', route => route.fulfill({ json: [
    { id: 'current', current: true, created_at: '2026-10-22T00:00:00Z', expires_at: '2026-11-05T00:00:00Z', revoked_at: null },
    { id: 'old', current: false, created_at: '2026-10-21T00:00:00Z', expires_at: '2026-11-04T00:00:00Z', revoked_at: revoked ? '2026-10-22T01:00:00Z' : null },
  ] }));
  await page.route('**/api/auth/sessions/old/revoke', route => {
    revoked = true;
    return route.fulfill({ status: 202, json: { revoked: true, kernel_revocation: 'pending' } });
  });
  await page.goto('/');
  await page.getByRole('button', { name: 'Settings', exact: true }).click();
  await page.getByRole('button', { name: 'Revoke session started', exact: false }).click();
  await expect(page.getByText('App session revoked. Kernel approval revocation is pending delivery.')).toBeVisible();
  await expect(page.getByRole('button', { name: 'Revoke session started', exact: false })).toHaveCount(0);
});
