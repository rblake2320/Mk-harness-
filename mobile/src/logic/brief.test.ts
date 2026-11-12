import { test } from 'node:test';
import assert from 'node:assert/strict';
import type { BriefItem } from '../../../packages/sdk/src/index';
import { briefItemTag, canDraft, groupBrief, permissionLine } from './brief';
import { fmtWhen } from './format';

function item(id: string, rank: number, over: Partial<BriefItem> = {}): BriefItem {
  return { id, customer: { id: 'c1', name: 'Brenda' }, rule: 'commitment_due', rank_category: rank, source_type: 'commitment', source_reference: 'k1',
    source: null, due_at: null, state: 'open', permission_state: 'active', permission_checked_at: '2026-10-21T08:00:00Z',
    permission_note: 'historical observation', suggested_step: 'Due today', draft_version_id: null, controls: [], ...over };
}

test('sections follow the server ranking: safety → overdue → due today → unanswered → coming up', () => {
  const g = groupBrief([item('a', 2), item('b', 0), item('c', 4), item('d', 1), item('e', 3)]);
  assert.deepEqual(g.map(s => s.title), ['Needs attention', 'Overdue', 'Due today', 'Unanswered requests', 'Coming up']);
});

test('order within a section is exactly the server order (never re-sorted on the device)', () => {
  const g = groupBrief([item('z', 2), item('a', 2), item('m', 2)]);
  assert.deepEqual(g[0].items.map(i => i.id), ['z', 'a', 'm']);
});

test('nothing is dropped: unknown categories go to a labelled "Other" section at the end', () => {
  const g = groupBrief([item('x', 9), item('a', 0), item('y', -1), item('w', NaN as unknown as number)]);
  assert.deepEqual(g.map(s => s.title), ['Needs attention', 'Other']);
  assert.deepEqual(g[1].items.map(i => i.id), ['x', 'y', 'w']);
  assert.equal(g.reduce((n, s) => n + s.items.length, 0), 4);
});

test('a repeated id is shown once; malformed entries are skipped; empty input has no sections', () => {
  const g = groupBrief([item('a', 2), item('a', 2), null as unknown as BriefItem, { id: 5 } as unknown as BriefItem]);
  assert.equal(g[0].items.length, 1);
  assert.deepEqual(groupBrief([]), []);
});

test('drafting is offered only with a customer and an active permission observation', () => {
  assert.equal(canDraft(item('a', 2)), true);
  for (const p of ['none', 'suppressed', 'granted', '', 'ACTIVE']) assert.equal(canDraft(item('a', 2, { permission_state: p })), false, p);
  assert.equal(canDraft(item('a', 2, { customer: null })), false);
});

test('rule tags use the real backend rule values and never echo an unknown one raw', () => {
  assert.equal(briefItemTag(item('a', 2, { rule: 'commitment_due' })), 'Your promise');
  assert.equal(briefItemTag(item('a', 3, { rule: 'explicit_request' })), 'Customer request');
  assert.equal(briefItemTag(item('a', 3, { rule: 'unanswered_question' })), 'Unanswered question');
  assert.equal(briefItemTag(item('a', 0, { rule: 'exception' })), 'Exception to review');
  assert.equal(briefItemTag(item('a', 2, { rule: 'customer_date' })), 'Customer date');
  assert.equal(briefItemTag(item('a', 2, { rule: 'toString' })), 'Other (toString)');
});

test('the permission line is the historical observation, labelled, with its check time', () => {
  const fixed = (iso: string) => `<${iso}>`;
  assert.equal(permissionLine(item('a', 2), fixed), 'Permission on record (checked <2026-10-21T08:00:00Z>) — historical observation');
  assert.equal(permissionLine(item('a', 2, { permission_state: 'suppressed', permission_checked_at: null }), fixed),
    'Do not contact (suppressed) (checked time not reported) — historical observation');
});

test('fmtWhen says when a time is missing or invalid, never invents one', () => {
  assert.equal(fmtWhen(null), 'not reported');
  assert.equal(fmtWhen(''), 'not reported');
  assert.equal(fmtWhen('soon'), 'unknown time');
  assert.notEqual(fmtWhen('2026-10-21T08:00:00Z'), 'unknown time');
});
