/**
 * After the web approval page closes, the app ALWAYS re-reads the action it opened and
 * never reports an approval from the redirect. Adversarial returns (other action, forged
 * "approved" flags, malformed links, closed or locked sessions) change only the note.
 */
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { afterHandoffHint, interpretAuthSessionResult, type AuthSessionResult } from './approvalReturn';

const ID = 'aaaaaaaa-bbbb-4ccc-8ddd-eeeeeeeeeeee';
const OTHER = '99999999-9999-4999-8999-999999999999';
const RET = 'consultantstudio://approvals/done';

const CASES: Array<[string, AuthSessionResult | null | undefined, string]> = [
  ['matching return', { type: 'success', url: `${RET}?action=${ID}` }, 'matching'],
  ['return for another action', { type: 'success', url: `${RET}?action=${OTHER}` }, 'other_action'],
  ['forged approved flag', { type: 'success', url: `${RET}?action=${ID}&approved=true` }, 'unrecognised'],
  ['forged state', { type: 'success', url: `${RET}?state=approved&action=${ID}` }, 'unrecognised'],
  ['other scheme', { type: 'success', url: `https://evil.example/?action=${ID}` }, 'unrecognised'],
  ['lookalike path', { type: 'success', url: `${RET}.evil?action=${ID}` }, 'unrecognised'],
  ['empty url', { type: 'success', url: '' }, 'unrecognised'],
  ['user closed (iOS)', { type: 'cancel' }, 'closed'],
  ['dismissed', { type: 'dismiss' }, 'closed'],
  ['opened (Android)', { type: 'opened' }, 'closed'],
  ['another session open', { type: 'locked' }, 'busy'],
  ['nothing', null, 'none'],
  ['undefined', undefined, 'none'],
  ['junk', { type: 42 } as unknown as AuthSessionResult, 'none'],
];

for (const [name, result, returned] of CASES) {
  test(`${name}: re-reads the opened action and claims nothing`, () => {
    const d = interpretAuthSessionResult(result, ID);
    assert.equal(d.refetchActionId, ID);
    assert.equal(d.returned, returned);
    assert.match(d.note, /Checking what the kernel reports/);
    assert.doesNotMatch(d.note, /\bapproved\b(?! there)/i, 'never says the message was approved');
  });
}

test('after the hand-off: awaiting approval and missing states get guidance; others rely on the shown state', () => {
  assert.match(afterHandoffHint('awaiting_approval')!, /Not approved yet/);
  assert.match(afterHandoffHint(undefined)!, /Do not assume/);
  assert.match(afterHandoffHint(null)!, /Do not assume/);
  for (const st of ['queued', 'approved', 'denied', 'cancelled', 'expired', 'delivered']) assert.equal(afterHandoffHint(st), null);
});
