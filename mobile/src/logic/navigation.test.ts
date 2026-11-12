import { test } from 'node:test';
import assert from 'node:assert/strict';
import { MAX_STACK, TABS, canGoBack, currentRoute, initialNav, navReducer, type NavAction, type NavState } from './navigation';

const run = (...actions: NavAction[]) => actions.reduce<NavState>(navReducer, initialNav());
const customer = { name: 'customer' as const, customerId: 'c1', customerName: 'Brenda' };

test('starts on the brief with empty stacks and nothing to go back to', () => {
  const s = initialNav();
  assert.equal(s.tab, 'brief');
  assert.equal(canGoBack(s), false);
  assert.equal(currentRoute(s), null);
  assert.deepEqual(TABS.map(t => t.id), ['brief', 'approvals', 'inbox', 'customers', 'more']);
});

test('push and back work per tab; back on an empty stack is a no-op (Android then exits)', () => {
  const s = run({ type: 'tab', tab: 'customers' }, { type: 'push', route: customer });
  assert.deepEqual(currentRoute(s), customer);
  const b = navReducer(s, { type: 'back' });
  assert.equal(currentRoute(b), null);
  assert.equal(navReducer(b, { type: 'back' }), b, 'same object: nothing changed');
});

test('switching tabs keeps each stack; re-selecting the current tab returns to its root', () => {
  const s = run({ type: 'tab', tab: 'customers' }, { type: 'push', route: customer }, { type: 'tab', tab: 'inbox' });
  assert.equal(currentRoute(s), null);
  const back = navReducer(s, { type: 'tab', tab: 'customers' });
  assert.deepEqual(currentRoute(back), customer);
  assert.equal(currentRoute(navReducer(back, { type: 'tab', tab: 'customers' })), null);
});

test('a double tap does not push the same screen twice, and stacks are bounded', () => {
  const s = run({ type: 'push', route: customer }, { type: 'push', route: customer });
  assert.equal(s.stacks.brief.length, 1);
  let t = initialNav();
  for (let i = 0; i < MAX_STACK + 5; i++) t = navReducer(t, { type: 'push', route: { ...customer, customerId: `c${i}` } });
  assert.equal(t.stacks.brief.length, MAX_STACK);
  assert.equal((currentRoute(t) as typeof customer).customerId, `c${MAX_STACK + 4}`);
});

test('a return link focuses the approvals tab at its root; clearing focus is idempotent', () => {
  const s = run({ type: 'tab', tab: 'approvals' }, { type: 'push', route: { name: 'status' } }, { type: 'tab', tab: 'brief' },
    { type: 'focusApproval', actionId: 'a1' });
  assert.equal(s.tab, 'approvals');
  assert.equal(s.stacks.approvals.length, 0);
  assert.equal(s.focusActionId, 'a1');
  const c = navReducer(s, { type: 'clearFocus' });
  assert.equal(c.focusActionId, null);
  assert.equal(navReducer(c, { type: 'clearFocus' }), c);
});

test('unknown actions leave the state untouched', () => {
  const s = initialNav();
  assert.equal(navReducer(s, { type: 'nope' } as unknown as NavAction), s);
});
