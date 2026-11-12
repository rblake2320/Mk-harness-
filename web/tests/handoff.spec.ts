import { test, expect, type Page, type Request } from '@playwright/test';
import { ACTION_ID, DIGEST, NEW_ACTION_ID, NEW_DIGEST, challenge, decision, fakePasskey, json, mockApi, pendingItem } from './fixtures';

/**
 * Mobile → web passkey hand-off. The app opens
 * `/?view=approvals&action=<id>&return_to=consultantstudio://approvals/done` in an auth
 * session; after a completed decision the page returns to EXACTLY
 * `consultantstudio://approvals/done?action=<id>`. Any other `return_to` is ignored and
 * the page stays put. (Chromium reports custom-scheme navigations as requests, which is
 * how these tests observe the redirect.)
 */
const RETURN = 'consultantstudio://approvals/done';
const enc = encodeURIComponent;

/** Every attempt to leave the app: a navigation to another origin or any non-http(s) URL.
 *  (Sub-resource requests such as web fonts are not navigations and are ignored.) */
function watchNavigations(page: Page) {
  const seen: string[] = [];
  page.on('request', (r: Request) => {
    const url = r.url();
    if (/^https?:\/\/127\.0\.0\.1:4173\//.test(url)) return;
    if (!/^https?:/.test(url) || r.isNavigationRequest()) seen.push(url);
  });
  return seen;
}

async function approveSetup(page: Page) {
  await mockApi(page);
  await fakePasskey(page);
  await page.route('**/api/approvals/pending', r => json(r, [pendingItem(), pendingItem({ action_id: NEW_ACTION_ID, action_digest: NEW_DIGEST, exact_text: 'A different message to someone else. Reply STOP to opt out.', customer: { id: 'c2', name: 'Carla Diaz' } })]));
  await page.route('**/api/agent-ops/actions/*/approval-challenge', r => json(r, challenge(DIGEST)));
  await page.route('**/api/agent-ops/actions/*/approve', r => json(r, decision({ result: { state: 'queued', message_state: 'queued' } })));
}

test('a valid hand-off focuses the one action and returns to the app with only the action id after approval', async ({ page }) => {
  await approveSetup(page);
  const nav = watchNavigations(page);
  await page.goto(`/?view=approvals&action=${ACTION_ID}&return_to=${enc(RETURN)}`);
  await expect(page.getByRole('note', { name: 'Approval requested from the mobile app' })).toBeVisible();
  // Only the requested message is offered, so the wrong one cannot be approved by accident.
  await expect(page.getByRole('blockquote', { name: 'Exact message text' })).toHaveCount(1);
  await expect(page.getByText('Carla Diaz')).toHaveCount(0);
  const redirect = page.waitForRequest(r => r.url().startsWith('consultantstudio:'));
  await page.getByRole('button', { name: 'Approve this message with passkey' }).click();
  expect((await redirect).url()).toBe(`${RETURN}?action=${ACTION_ID}`);
  await expect(page.getByRole('link', { name: 'Return to the app' })).toHaveAttribute('href', `${RETURN}?action=${ACTION_ID}`);
  expect(nav).toEqual([`${RETURN}?action=${ACTION_ID}`]);
});

test('no redirect happens when the decision fails — the page stays with the explanation', async ({ page }) => {
  await approveSetup(page);
  await page.route('**/api/agent-ops/actions/*/approve', r => r.fulfill({ status: 403, contentType: 'application/problem+json',
    body: JSON.stringify({ type: 'urn:mk:error:self_approval_forbidden', title: 'Policy denied the action', status: 403, code: 'SELF_APPROVAL_FORBIDDEN', request_id: 'r' }) }));
  const nav = watchNavigations(page);
  await page.goto(`/?view=approvals&action=${ACTION_ID}&return_to=${enc(RETURN)}`);
  await page.getByRole('button', { name: 'Approve this message with passkey' }).click();
  await expect(page.getByRole('alert')).toContainText('second person');
  await page.waitForTimeout(300);
  expect(nav).toEqual([]);
});

/** Each value is placed in the query exactly as written (no extra encoding) unless noted. */
const REFUSED: Array<[string, string]> = [
  ['https URL', enc('https://evil.example/steal')],
  ['javascript: URL', enc('javascript:alert(document.domain)')],
  ['lookalike suffix', enc('consultantstudio://approvals/done.evil')],
  ['path traversal', enc('consultantstudio://approvals/done/../x')],
  ['trailing slash', enc('consultantstudio://approvals/done/')],
  ['extra query', enc('consultantstudio://approvals/done?action=x&next=https://evil.example')],
  ['fragment', enc('consultantstudio://approvals/done#x')],
  ['uppercase scheme', enc('CONSULTANTSTUDIO://approvals/done')],
  ['double-encoded slashes', enc('consultantstudio:%2F%2Fapprovals%2Fdone')],
  ['encoded path separator', 'consultantstudio%3A%2F%2Fapprovals%252Fdone'],
  ['leading space', enc(' consultantstudio://approvals/done')],
  ['trailing newline', enc('consultantstudio://approvals/done\n')],
  ['userinfo host', enc('consultantstudio://evil@approvals/done')],
  ['other scheme', enc('otherapp://approvals/done')],
  ['very long value', enc(RETURN + 'a'.repeat(5000))],
  ['duplicate return_to', `${enc(RETURN)}&return_to=${enc('https://evil.example')}`],
];

for (const [name, value] of REFUSED) {
  test(`refused return_to (${name}): no redirect after approval, the page says it will not redirect`, async ({ page }) => {
    await approveSetup(page);
    const nav = watchNavigations(page);
    await page.goto(`/?view=approvals&action=${ACTION_ID}&return_to=${value}`);
    await expect(page.getByText('The return link in this address was not recognised')).toBeVisible();
    await page.getByRole('button', { name: 'Approve this message with passkey' }).click();
    await expect(page.getByLabel('Decisions made on this page')).toContainText('You approved the message to Brenda Lee');
    await expect(page.getByRole('link', { name: 'Return to the app' })).toHaveCount(0);
    await page.waitForTimeout(300);
    expect(nav).toEqual([]);
    expect(page.url()).toContain('127.0.0.1:4173');
  });
}

test('an action that is not waiting shows a notice and, with a valid return_to, only a manual return link', async ({ page }) => {
  await approveSetup(page);
  const gone = '99999999-9999-4999-8999-999999999999';
  const nav = watchNavigations(page);
  await page.goto(`/?view=approvals&action=${gone}&return_to=${enc(RETURN)}`);
  await expect(page.getByText('This message is not waiting for your approval.')).toBeVisible();
  await expect(page.getByRole('link', { name: 'Return to the app' })).toHaveAttribute('href', `${RETURN}?action=${gone}`);
  await expect(page.getByRole('button', { name: 'Approve this message with passkey' })).toHaveCount(0);
  expect(nav).toEqual([]);
});

test('a malformed action id is ignored: no focus, every pending message listed, nothing echoed', async ({ page }) => {
  await approveSetup(page);
  await page.goto(`/?view=approvals&action=${enc('11111111-1111-4111-8111-111111111111&return_to=x')}&return_to=${enc(RETURN)}`);
  await expect(page.getByRole('note', { name: 'Approval requested from the mobile app' })).toHaveCount(0);
  await expect(page.getByRole('blockquote', { name: 'Exact message text' })).toHaveCount(2);
});
