/**
 * Row H1 display logic shared by web and mobile: every field is present, absent data says
 * it is absent (with a warning where it matters), expiry and SMS segments are computed
 * exactly, and text the approver cannot see is flagged — reordering characters block approval.
 */
import { test } from 'node:test';
import assert from 'node:assert/strict';
import type { PendingApproval } from '../src/index';
import {
  SELF_APPROVAL_NOTE, approvalView, digestShort, expiryDisplay, formatDuration, hiddenCharacterWarning, hiddenCharacters, segmentText, smsSegments,
} from '../src/index';

const NOW = Date.parse('2026-10-21T14:45:00Z');
const fmt = (iso: string) => `<${iso}>`;

function item(over: Partial<PendingApproval> = {}): PendingApproval {
  return {
    action_id: '11111111-1111-4111-8111-111111111111', action_digest: 'sha256:' + 'b'.repeat(64), state: 'approval_required', message_state: 'awaiting_approval',
    exact_text: 'Hi Brenda! Here is the shade chart I promised. Reply STOP to opt out.', destination_masked: '********0100', channel: 'sms',
    purpose: 'customer_requested_follow_up', workflow: 'customer_follow_up', risk: 'high', customer: { id: 'c1', name: 'Brenda Lee' },
    sending_business: { sender_identity_id: 's1', display_name: "Angela's Business", from_number: '+15005550006', registration_status: 'registered' },
    supporting: { commitment: { id: 'k1', text: 'Send the shade chart', status: 'confirmed', evidence_digest: 'sha256:' + 'a'.repeat(64) }, draft_version_id: 'd1', evidence_count: 2 },
    permission: { state: 'active', checked_at: '2026-10-21T08:00:00Z', note: 'historical observation' },
    scheduled_for: null, approval_expires_at: '2026-10-21T15:00:00Z', approval_lifetime_minutes: 15, human_steps: [],
    ...over,
  };
}

const row = (v: ReturnType<typeof approvalView>, key: string) => v.rows.find(r => r.key === key)!;

test('a complete item shows every H1 field in a fixed order, with no warnings, and is approvable', () => {
  const v = approvalView(item(), { nowMs: NOW, formatWhen: fmt });
  assert.deepEqual(v.rows.map(r => r.key), ['to', 'from', 'purpose', 'because', 'permission', 'when', 'expiry', 'digest']);
  assert.equal(row(v, 'to').value, 'Brenda Lee · ********0100 (sms)');
  assert.equal(row(v, 'from').value, "Angela's Business · +15005550006 (registration: registered)");
  assert.equal(row(v, 'purpose').value, 'customer_requested_follow_up · customer_follow_up · risk high');
  assert.equal(row(v, 'because').value, '“Send the shade chart” (confirmed, evidence aaaaaaaaaaaa…)');
  assert.equal(row(v, 'permission').value, 'Permission on record (checked <2026-10-21T08:00:00Z>) — historical observation');
  assert.equal(row(v, 'when').value, 'As soon as policy allows (inside the customer’s contact hours)');
  assert.equal(row(v, 'expiry').value, 'Expires in 15 min (<2026-10-21T15:00:00Z>) · once approved, the approval is single-use and lasts 15 minutes');
  assert.equal(row(v, 'digest').value, 'digest bbbbbbbbbbbbbbbb…');
  assert.deepEqual(v.rows.filter(r => r.warning), []);
  assert.equal(v.exactText, 'Hi Brenda! Here is the shade chart I promised. Reply STOP to opt out.');
  assert.equal(v.approvable, true);
});

test('a scheduled time is shown when the API supplies one', () => {
  assert.equal(row(approvalView(item({ scheduled_for: '2026-10-22T16:00:00Z' }), { nowMs: NOW, formatWhen: fmt }), 'when').value, '<2026-10-22T16:00:00Z>');
});

test('missing fields say so and warn; nothing plausible is invented', () => {
  const v = approvalView(item({ customer: null, destination_masked: '', sending_business: null, permission: null,
    supporting: { commitment: null, draft_version_id: null, evidence_count: 0 } }), { nowMs: NOW, formatWhen: fmt });
  assert.equal(row(v, 'to').value, 'Unknown customer · destination not reported');
  assert.match(row(v, 'to').warning!, /could not be identified/);
  assert.equal(row(v, 'from').value, 'No registered sending number');
  assert.match(row(v, 'from').warning!, /kernel will refuse/);
  assert.equal(row(v, 'because').value, 'No supporting commitment or request');
  assert.match(row(v, 'because').warning!, /Review carefully/);
  assert.match(row(v, 'permission').value, /^Not recorded on this item/);
});

test('an unregistered sender and an inactive permission are warned about', () => {
  const v = approvalView(item({ sending_business: { sender_identity_id: 's', display_name: 'B', from_number: '+1', registration_status: 'pending' },
    permission: { state: 'suppressed', checked_at: null, note: 'n' } }), { nowMs: NOW, formatWhen: fmt });
  assert.match(row(v, 'from').warning!, /not registered/);
  assert.match(row(v, 'permission').value, /^Do not contact \(suppressed\) \(checked time not reported\)/);
  assert.match(row(v, 'permission').warning!, /not active/);
});

test('approval is not offered for an expired request, a malformed digest, reordering text or empty text', () => {
  const expired = approvalView(item({ approval_expires_at: '2026-10-21T14:44:00Z' }), { nowMs: NOW, formatWhen: fmt });
  assert.equal(expired.approvable, false);
  assert.match(row(expired, 'expiry').value, /^This request expired 1 min ago/);
  for (const d of ['sha256:' + 'B'.repeat(64), 'sha256:' + 'b'.repeat(63), 'md5:' + 'b'.repeat(64), '', 'sha256:' + 'b'.repeat(64) + ' ']) {
    const v = approvalView(item({ action_digest: d }), { nowMs: NOW, formatWhen: fmt });
    assert.equal(v.approvable, false, d);
    assert.equal(row(v, 'digest').value, 'digest not reported');
  }
  const rlo = approvalView(item({ exact_text: 'Pay ‮eno‬ now. Reply STOP to opt out.' }), { nowMs: NOW, formatWhen: fmt });
  assert.equal(rlo.approvable, false);
  assert.match(rlo.blockedReason!, /change how it is displayed/);
  assert.equal(approvalView(item({ exact_text: '' }), { nowMs: NOW, formatWhen: fmt }).approvable, false);
});

test('expiryDisplay: open, soon, expired, and unknown for anything that is not a zoned ISO instant', () => {
  assert.deepEqual(expiryDisplay('2026-10-22T15:46:00Z', NOW), { status: 'open', text: 'Expires in 1 d 1 h', remainingMs: 25 * 3600_000 + 60_000 });
  assert.equal(expiryDisplay('2026-10-21T16:00:00Z', NOW).text, 'Expires in 1 h 15 min');
  assert.equal(expiryDisplay('2026-10-21T14:49:59Z', NOW).status, 'soon');
  assert.equal(expiryDisplay('2026-10-21T14:45:30Z', NOW).text, 'Expires in less than a minute');
  assert.equal(expiryDisplay('2026-10-21T14:45:00Z', NOW).status, 'expired');
  assert.equal(expiryDisplay('2026-10-21T09:45:00-05:00', NOW).status, 'expired');
  for (const bad of ['2026-10-21T15:00:00', '2026-10-21', 'tomorrow', '2026-13-45T99:99:99Z', '', null, undefined, 1761058800000]) {
    assert.deepEqual(expiryDisplay(bad, NOW), { status: 'unknown', text: 'Expiry not reported', remainingMs: null }, String(bad));
  }
  const unknown = approvalView(item({ approval_expires_at: 'soon' }), { nowMs: NOW, formatWhen: fmt });
  assert.match(row(unknown, 'expiry').warning!, /not reported/);
});

test('formatDuration is symmetric and bounded', () => {
  assert.equal(formatDuration(59_999), 'less than a minute');
  assert.equal(formatDuration(-3 * 60_000), '3 min');
  assert.equal(formatDuration(24 * 3600_000), '1 d 0 h');
});

test('smsSegments: GSM-7 boundaries 160/153, extension characters count double and never split', () => {
  assert.deepEqual(smsSegments(''), { encoding: 'GSM-7', units: 0, segments: 0, perSegment: 160 });
  assert.equal(smsSegments('a'.repeat(160)).segments, 1);
  assert.deepEqual(smsSegments('a'.repeat(161)), { encoding: 'GSM-7', units: 161, segments: 2, perSegment: 153 });
  assert.equal(smsSegments('a'.repeat(306)).segments, 2);
  assert.equal(smsSegments('a'.repeat(307)).segments, 3);
  assert.equal(smsSegments('€'.repeat(80)).units, 160);
  assert.equal(smsSegments('€'.repeat(80)).segments, 1);
  assert.equal(smsSegments('€'.repeat(81)).segments, 2);
  // 152 single septets + one escape pair: the pair does not fit in segment 1 (153) and moves whole.
  assert.equal(smsSegments('a'.repeat(152) + '{' + 'a'.repeat(152)).segments, 3);
  assert.equal(smsSegments('Ça coûte 5 £ — ').encoding, 'UCS-2', 'em dash is not GSM-7');
});

test('smsSegments: UCS-2 boundaries 70/67; astral characters count two units and never split', () => {
  assert.deepEqual(smsSegments('é'.repeat(69) + 'ű'), { encoding: 'UCS-2', units: 70, segments: 1, perSegment: 70 });
  assert.equal(smsSegments('ű'.repeat(71)).segments, 2);
  assert.equal(smsSegments('😀'.repeat(35)).units, 70);
  assert.equal(smsSegments('😀'.repeat(35)).segments, 1);
  assert.equal(smsSegments('😀'.repeat(36)).segments, 2);
  // 66 units + one surrogate pair: the pair would straddle 67 and moves to segment 2.
  assert.equal(smsSegments('ű'.repeat(66) + '😀' + 'ű'.repeat(66)).segments, 3);
  assert.equal(segmentText(smsSegments('hi')), 'Estimated 1 SMS segment (GSM-7, 2 characters)');
  assert.equal(segmentText(smsSegments('😀'.repeat(36))), 'Estimated 2 SMS segments (UCS-2, 72 code units)');
  assert.equal(segmentText(smsSegments('')), 'Empty message');
});

test('hiddenCharacters: zero-width, soft hyphen, controls and bidi characters are reported; emoji joiners are not', () => {
  assert.deepEqual(hiddenCharacters('Plain text. Reply STOP to opt out.'), { found: [], reorders: false });
  const zw = hiddenCharacters('Hi​there​­');
  assert.equal(zw.reorders, false);
  assert.deepEqual(zw.found.map(f => [f.codePoint, f.count]), [['U+200B', 2], ['U+00AD', 1]]);
  assert.match(hiddenCharacterWarning(zw)!, /cannot see: ZERO WIDTH SPACE \(U\+200B\) ×2, SOFT HYPHEN \(U\+00AD\)/);
  const bidi = hiddenCharacters('abc⁦def⁩');
  assert.equal(bidi.reorders, true);
  assert.match(hiddenCharacterWarning(bidi)!, /cannot be approved here/);
  assert.deepEqual(hiddenCharacters('family 👩‍👩‍👧 and 👍🏽 ❤️‍🔥').found, []);
  assert.equal(hiddenCharacters('a‍b').found[0].name, 'ZERO WIDTH JOINER', 'a joiner between letters hides');
  assert.equal(hiddenCharacters('bell\u0007').found[0].name, 'CONTROL CHARACTER');
  assert.equal(hiddenCharacters('line one\nline two\ttab').found.length, 0);
  assert.equal(hiddenCharacterWarning({ found: [], reorders: false }), null);
});

test('digestShort accepts only well-formed sha256 digests', () => {
  assert.equal(digestShort('sha256:' + '0123456789abcdef'.repeat(4)), '0123456789abcdef');
  for (const bad of [null, undefined, 42, 'sha256:', 'SHA256:' + 'a'.repeat(64), 'sha256:' + 'g'.repeat(64)]) assert.equal(digestShort(bad), null);
});

test('the self-approval disclosure states that the kernel decides and nothing is approved on refusal', () => {
  assert.match(SELF_APPROVAL_NOTE, /second person/);
  assert.match(SELF_APPROVAL_NOTE, /nothing is approved/);
});
