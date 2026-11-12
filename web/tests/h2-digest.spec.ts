import { test, expect, type Page } from '@playwright/test';
import {
  ACTION_ID, DIGEST, NEW_ACTION_ID, NEW_DIGEST, actionResult, challenge, decision, fakePasskey, json, mockApi, openApprovals,
  passkeyCalls, pendingItem, problem,
} from './fixtures';

/**
 * Row H2 at the interface — "an edit cannot leave an old digest approved".
 * The kernel binds approval to the exact digest (Independently verified); these tests
 * prove the UI never offers, and never shows as approved, a version that changed.
 */
const OLD_TEXT = 'Hi Brenda! Here is the shade chart I promised. Reply STOP to opt out.';
const NEW_TEXT = 'Hi Brenda! Here is the shade chart I promised, plus the new spring colours. Reply STOP to opt out.';
const NEW_ITEM = pendingItem({ action_id: NEW_ACTION_ID, action_digest: NEW_DIGEST, exact_text: NEW_TEXT, supporting: { commitment: null, draft_version_id: 'dv2', evidence_count: 1 } });

function draft(id: string, text: string, digest: string, version: number) {
  return { id, customer_id: 'c1', brief_item_id: 'b1', text, text_digest: digest, claims_used: [], source_versions: {}, generated_by: 'ai:anthropic:x', version,
    note: 'Approval binds to the exact text digest; any edit produces a new version and a new digest.' };
}

/** Expect that no element on the page claims an approval happened. */
async function expectNothingApproved(page: Page) {
  await expect(page.getByLabel('Decisions made on this page')).toHaveCount(0);
  await expect(page.getByText(/you approved/i)).toHaveCount(0);
}

test('changing a proposed draft withdraws the old proposal before the new version is proposed; approvals then offer only the new digest', async ({ page }) => {
  await mockApi(page);
  const calls: string[] = [];
  let oldCancelled = false;
  await page.route('**/api/drafts', r => { calls.push('generate'); return json(r, { draft: draft('dv1', OLD_TEXT, DIGEST, 1), limitation: null }, 201); });
  await page.route('**/api/drafts/dv1/propose', r => { calls.push('propose dv1'); return json(r, { action_id: ACTION_ID, state: 'approval_required', message_state: 'awaiting_approval', action_digest: DIGEST, decision: { code: 'approval_required' }, human_steps: ['A human must approve this exact text with their passkey before anything is sent.'] }, 202); });
  await page.route(`**/api/agent-ops/actions/${ACTION_ID}/cancel`, r => { calls.push('cancel old'); oldCancelled = true; return json(r, actionResult({ state: 'cancelled', message_state: 'cancelled' })); });
  await page.route('**/api/drafts/dv1/edit', r => { calls.push('edit dv1'); expect(r.request().postDataJSON()).toEqual({ text: NEW_TEXT }); return json(r, draft('dv2', NEW_TEXT, NEW_DIGEST, 2), 201); });
  await page.route('**/api/drafts/dv2/propose', r => { calls.push('propose dv2'); return json(r, { action_id: NEW_ACTION_ID, state: 'approval_required', message_state: 'awaiting_approval', action_digest: NEW_DIGEST, decision: { code: 'approval_required' }, human_steps: [] }, 202); });
  await page.route('**/api/approvals/pending', r => json(r, oldCancelled ? [NEW_ITEM] : [pendingItem(), NEW_ITEM]));

  await page.goto('/');
  await page.getByRole('button', { name: 'Draft a message' }).click();
  const editor = page.getByRole('dialog');
  const box = editor.getByRole('textbox');
  await expect(box).toHaveValue(OLD_TEXT);
  await editor.getByRole('button', { name: 'Propose for approval' }).click();
  await expect(editor.getByText('Proposed for approval.')).toBeVisible();
  await expect(editor.getByText('Awaiting approval', { exact: true })).toBeVisible();
  // While a proposal is pending its text cannot be changed in place.
  await expect(box).toHaveAttribute('readonly', '');
  await editor.getByRole('button', { name: 'Withdraw this proposal to change the text' }).click();
  await expect(editor.getByText('The earlier proposal was withdrawn')).toBeVisible();
  await box.fill(NEW_TEXT);
  await editor.getByRole('button', { name: 'Save as new version' }).click();
  await expect(editor.getByText(/version 2, digest dddddddddddd/)).toBeVisible();
  await editor.getByRole('button', { name: 'Propose for approval' }).click();
  await expect(editor.getByText('Proposed for approval.')).toBeVisible();
  // The old proposal was withdrawn by the kernel BEFORE the new text was saved or proposed.
  expect(calls).toEqual(['generate', 'propose dv1', 'cancel old', 'edit dv1', 'propose dv2']);
  await editor.getByRole('button', { name: 'Close' }).click();

  await page.getByRole('navigation', { name: 'Main' }).getByRole('button', { name: 'Approvals' }).click();
  await expect(page.getByRole('blockquote', { name: 'Exact message text' })).toHaveText(NEW_TEXT);
  await expect(page.getByText(OLD_TEXT, { exact: true })).toHaveCount(0);
  await expect(page.getByText('digest bbbbbbbbbbbbbbbb')).toHaveCount(0);
  await expect(page.getByText('digest dddddddddddddddd')).toBeVisible();
  await expect(page.getByRole('button', { name: 'Approve this message with passkey' })).toHaveCount(1);
});

test('if the kernel cannot withdraw the old proposal, no new version is saved or proposed', async ({ page }) => {
  await mockApi(page);
  const calls: string[] = [];
  await page.route('**/api/drafts', r => json(r, { draft: draft('dv1', OLD_TEXT, DIGEST, 1), limitation: null }, 201));
  await page.route('**/api/drafts/dv1/propose', r => json(r, { action_id: ACTION_ID, state: 'approval_required', message_state: 'awaiting_approval', action_digest: DIGEST, decision: null, human_steps: [] }, 202));
  // Already approved and queued elsewhere: the kernel refuses the cancel.
  await page.route(`**/api/agent-ops/actions/${ACTION_ID}/cancel`, r => { calls.push('cancel'); return r.fulfill(problem(409, 'ILLEGAL_TRANSITION', 'Illegal state transition', 'req-cancel')); });
  await page.route('**/api/drafts/dv1/edit', r => { calls.push('edit'); return json(r, {}, 500); });
  await page.goto('/');
  await page.getByRole('button', { name: 'Draft a message' }).click();
  const editor = page.getByRole('dialog');
  await editor.getByRole('button', { name: 'Propose for approval' }).click();
  await editor.getByRole('button', { name: 'Withdraw this proposal to change the text' }).click();
  await expect(editor.getByRole('alert')).toContainText('no longer waiting for that decision');
  await expect(editor.getByRole('alert')).toContainText('ILLEGAL_TRANSITION');
  await expect(editor.getByRole('textbox')).toHaveAttribute('readonly', '');
  await expect(editor.getByRole('button', { name: 'Save as new version' })).toHaveCount(0);
  expect(calls).toEqual(['cancel']);
});

test('a stale screen cannot approve the old digest: the challenge digest differs, so no passkey prompt, a clear message, and only the new version is offered', async ({ page }) => {
  await mockApi(page);
  await fakePasskey(page);
  let edited = false;
  const challenges: string[] = [];
  const approvals: unknown[] = [];
  // The screen loaded before the edit; after it, the pending list carries only the new version.
  await page.route('**/api/approvals/pending', r => json(r, edited ? [NEW_ITEM] : [pendingItem()]));
  // The kernel issues challenges over each action's CURRENT digest: after the edit that is the
  // new digest, which no longer matches what the stale card displayed.
  await page.route('**/api/agent-ops/actions/*/approval-challenge', r => {
    const id = r.request().url().split('/actions/')[1].split('/')[0];
    challenges.push(id);
    return json(r, { ...challenge(NEW_DIGEST), action_id: id });
  });
  await page.route('**/api/agent-ops/actions/*/approve', r => {
    approvals.push(r.request().postDataJSON());
    return json(r, decision({ result: { action_id: NEW_ACTION_ID, action_digest: NEW_DIGEST, state: 'queued', message_state: 'queued' } }));
  });
  await openApprovals(page);
  await expect(page.getByRole('blockquote', { name: 'Exact message text' })).toHaveText(OLD_TEXT);
  edited = true;
  await page.getByRole('button', { name: 'Approve this message with passkey' }).click();
  const alert = page.getByRole('alert');
  await expect(alert).toContainText('This message changed since it was displayed.');
  await expect(alert).toContainText('Nothing was approved');
  expect(await passkeyCalls(page)).toBe(0);
  expect(approvals).toEqual([]);
  await expectNothingApproved(page);
  // The list reloaded: the old digest is gone, the new version is offered with its own gesture.
  await expect(page.getByRole('blockquote', { name: 'Exact message text' })).toHaveText(NEW_TEXT);
  await expect(page.getByText('digest bbbbbbbbbbbbbbbb')).toHaveCount(0);
  await page.getByRole('button', { name: 'Approve this message with passkey' }).click();
  await expect(page.getByLabel('Decisions made on this page')).toContainText('You approved the message to Brenda Lee with your passkey.');
  expect(challenges).toEqual([ACTION_ID, NEW_ACTION_ID]);
  expect(await passkeyCalls(page)).toBe(1);
  expect(approvals).toHaveLength(1);
  expect((approvals[0] as { action_digest: string }).action_digest).toBe(NEW_DIGEST);
  expect(Object.keys((approvals[0] as { webauthn: object }).webauthn).sort()).toEqual(['authenticator_data', 'client_data_json', 'credential_id', 'signature']);
});

test("the kernel's 409 for the old digest is shown as a clear message, nothing is shown as approved, and the new version needs its own approval", async ({ page }) => {
  await mockApi(page);
  await fakePasskey(page);
  let attempts = 0;
  const approveBodies: { action_digest: string }[] = [];
  // The challenge still matched what was displayed, but the action changed before approve
  // committed: the kernel answers 409 APPROVAL_DIGEST_MISMATCH (problem+json, verbatim).
  await page.route('**/api/approvals/pending', r => json(r, attempts === 0 ? [pendingItem()] : [pendingItem(), NEW_ITEM]));
  await page.route('**/api/agent-ops/actions/*/approval-challenge', r => {
    const id = r.request().url().split('/actions/')[1].split('/')[0];
    return json(r, { ...challenge(id === NEW_ACTION_ID ? NEW_DIGEST : DIGEST), action_id: id });
  });
  await page.route('**/api/agent-ops/actions/*/approve', r => {
    attempts += 1;
    const body = r.request().postDataJSON() as { action_digest: string };
    approveBodies.push(body);
    if (body.action_digest === DIGEST) return r.fulfill(problem(409, 'APPROVAL_DIGEST_MISMATCH', 'The action changed since it was displayed', 'req-409'));
    return json(r, decision({ result: { action_id: NEW_ACTION_ID, action_digest: NEW_DIGEST, state: 'queued', message_state: 'queued' } }));
  });
  await openApprovals(page);
  await page.getByRole('button', { name: 'Approve this message with passkey' }).click();
  const alert = page.getByRole('alert');
  await expect(alert).toContainText('This message changed since it was displayed.');
  await expect(alert).toContainText('APPROVAL_DIGEST_MISMATCH');
  await expect(alert).toContainText('request req-409');
  await expect(alert).not.toContainText('HTTP 409');
  await expectNothingApproved(page);
  // Even though the (inconsistent) list still returns the old digest, it is never offered again.
  const oldCard = page.getByRole('listitem').filter({ hasText: 'digest bbbbbbbbbbbbbbbb' });
  await expect(oldCard.getByText('This version changed after it was shown')).toBeVisible();
  await expect(oldCard.getByRole('button', { name: 'Approve this message with passkey' })).toHaveCount(0);
  const newCard = page.getByRole('listitem').filter({ hasText: 'digest dddddddddddddddd' });
  await newCard.getByRole('button', { name: 'Approve this message with passkey' }).click();
  await expect(page.getByLabel('Decisions made on this page')).toContainText('You approved the message to Brenda Lee with your passkey.');
  await expect(page.getByLabel('Decisions made on this page')).toContainText('Queued for execution; policy will be re-evaluated before any send.');
  expect(approveBodies.map(b => b.action_digest)).toEqual([DIGEST, NEW_DIGEST]);
  expect(await passkeyCalls(page)).toBe(2);
});
