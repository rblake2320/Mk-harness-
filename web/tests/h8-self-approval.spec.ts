import { test, expect } from '@playwright/test';
import { DIGEST, challenge, decision, fakePasskey, json, mockApi, openApprovals, passkeyCalls, passkeyRequests, problem } from './fixtures';

/**
 * Row H8 at the interface. The kernel decides whether the signed-in consultant may approve
 * a message they proposed (`allow_self_approval`, per workflow). The API does not tell the
 * screen in advance (see report: no `requested_by` on pending items), so the screen
 * discloses the rule up front, runs the passkey flow, and shows the kernel's answer —
 * approval when permitted, the 403 with its code when forbidden. Never swallowed.
 */
const SELF_NOTE = 'If your team requires a second person, the kernel refuses your approval of a message you proposed yourself';

test('policy permits self-approval: the consultant approves their own message through the passkey ceremony', async ({ page }) => {
  await mockApi(page);
  await fakePasskey(page);
  const approveBodies: Record<string, unknown>[] = [];
  await page.route('**/api/agent-ops/actions/*/approval-challenge', r => json(r, challenge(DIGEST)));
  await page.route('**/api/agent-ops/actions/*/approve', r => {
    approveBodies.push(r.request().postDataJSON());
    // Approver u1 is the same user who proposed it; the kernel accepted (tenant allows self-approval).
    return json(r, decision({ approver_id: 'u1', result: { state: 'queued', message_state: 'queued' } }));
  });
  await openApprovals(page);
  await expect(page.getByText(SELF_NOTE)).toBeVisible();
  await page.getByRole('button', { name: 'Approve this message with passkey' }).click();
  const decided = page.getByLabel('Decisions made on this page');
  await expect(decided).toContainText('You approved the message to Brenda Lee with your passkey.');
  await expect(decided.getByText('Queued', { exact: true })).toBeVisible();
  await expect(decided).toContainText('Queued for execution; policy will be re-evaluated before any send.');
  await expect(decided).toContainText('single-use');
  await expect(page.getByRole('alert')).toHaveCount(0);
  // The ceremony was real: the kernel's challenge, RP id, UV requirement and allowed credential
  // reached the authenticator, and the assertion was submitted bound to the displayed digest.
  expect(await passkeyCalls(page)).toBe(1);
  const [req] = await passkeyRequests(page);
  expect(req).toEqual({ rpId: 'localhost', challengeBytes: [0, 0, 0], userVerification: 'required', allowCredentials: [[1, 2, 3]] });
  expect(approveBodies).toHaveLength(1);
  expect(approveBodies[0].action_digest).toBe(DIGEST);
  expect(Object.keys(approveBodies[0].webauthn as object).sort()).toEqual(['authenticator_data', 'client_data_json', 'credential_id', 'signature']);
});

test('policy forbids self-approval: the kernel 403 is shown with its code, nothing is approved, and approval is no longer offered', async ({ page }) => {
  await mockApi(page);
  await fakePasskey(page);
  let approveCalls = 0;
  await page.route('**/api/agent-ops/actions/*/approval-challenge', r => json(r, challenge(DIGEST)));
  await page.route('**/api/agent-ops/actions/*/approve', r => {
    approveCalls += 1;
    return r.fulfill(problem(403, 'SELF_APPROVAL_FORBIDDEN', 'Policy denied the action', 'req-403'));
  });
  await openApprovals(page);
  await expect(page.getByText(SELF_NOTE)).toBeVisible();
  const card = page.getByRole('listitem').filter({ hasText: 'Brenda Lee' });
  await card.getByRole('button', { name: 'Approve this message with passkey' }).click();
  const alert = page.getByRole('alert');
  await expect(alert).toContainText('Your team requires a second person to approve this kind of message.');
  await expect(alert).toContainText('Nothing was approved. Ask another consultant or your admin to approve it.');
  await expect(alert).toContainText('SELF_APPROVAL_FORBIDDEN');
  await expect(alert).toContainText('request req-403');
  await expect(alert).not.toContainText('HTTP 403');
  // Nothing is shown as approved; the message is still waiting, for someone else.
  await expect(page.getByLabel('Decisions made on this page')).toHaveCount(0);
  await expect(card.getByText('Awaiting approval', { exact: true })).toBeVisible();
  await expect(card.getByText('Your team requires a second person to approve this message.')).toBeVisible();
  await expect(card.getByRole('button', { name: 'Approve this message with passkey' })).toHaveCount(0);
  await expect(card.getByRole('button', { name: 'Reject' })).toBeVisible();
  expect(approveCalls).toBe(1);
  // Dismissing the error does not bring the approve gesture back.
  await alert.getByRole('button', { name: 'Dismiss' }).click();
  await expect(card.getByRole('button', { name: 'Approve this message with passkey' })).toHaveCount(0);
});

test('any other kernel 403 is surfaced with its code, never swallowed', async ({ page }) => {
  await mockApi(page);
  await fakePasskey(page);
  await page.route('**/api/agent-ops/actions/*/approval-challenge', r => json(r, challenge(DIGEST)));
  await page.route('**/api/agent-ops/actions/*/approve', r => r.fulfill(problem(403, 'TENANT_POLICY_DENIED', 'Policy denied the action', 'req-403b')));
  await openApprovals(page);
  await page.getByRole('button', { name: 'Approve this message with passkey' }).click();
  const alert = page.getByRole('alert');
  await expect(alert).toContainText('Not allowed: Policy denied the action');
  await expect(alert).toContainText('TENANT_POLICY_DENIED');
  await expect(alert).toContainText('request req-403b');
  await expect(page.getByLabel('Decisions made on this page')).toHaveCount(0);
});

test('a refused challenge (412 NO_APPROVAL_CREDENTIAL) stops before any passkey prompt and is surfaced', async ({ page }) => {
  await mockApi(page);
  await fakePasskey(page);
  let approveCalls = 0;
  await page.route('**/api/agent-ops/actions/*/approval-challenge', r => r.fulfill(problem(412, 'NO_APPROVAL_CREDENTIAL', 'Register a passkey before approving', 'req-412')));
  await page.route('**/api/agent-ops/actions/*/approve', r => { approveCalls += 1; return json(r, {}); });
  await openApprovals(page);
  await page.getByRole('button', { name: 'Approve this message with passkey' }).click();
  await expect(page.getByRole('alert')).toContainText('You have no passkey registered for approvals.');
  await expect(page.getByRole('alert')).toContainText('NO_APPROVAL_CREDENTIAL');
  expect(await passkeyCalls(page)).toBe(0);
  expect(approveCalls).toBe(0);
});
