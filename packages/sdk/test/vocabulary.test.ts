/**
 * Contract row C3: the SDK vocabulary is identical to the declared single source
 * (mk-contracts::MessageState), to the action contract enum, to what the API serves, to the
 * completion contract's own definitions, and to the support/marketing reference.
 */
import { test } from 'node:test';
import assert from 'node:assert/strict';
import {
  MESSAGE_STATES, MESSAGE_STATE_IDS, READ_STATUSES, READ_STATUS_IDS, describeMessageState, describeReadStatus,
  isMessageState, labelFromIdentifier, messageStateOf,
} from '../src/index';
import { readRepo } from './helpers';

const camelToSnake = (s: string) => s.replace(/([a-z0-9])([A-Z])/g, '$1_$2').toLowerCase();

function rustDefinitions(): { order: string[]; defs: Record<string, string> } {
  const src = readRepo('rust', 'crates', 'mk-contracts', 'src', 'message_state.rs');
  const all = /pub const ALL: \[Self; \d+\] = \[([\s\S]*?)\];/.exec(src);
  assert.ok(all, 'MessageState::ALL not found');
  const order = [...all[1].matchAll(/Self::(\w+)/g)].map(m => camelToSnake(m[1]));
  const body = /pub const fn definition\(self\) -> &'static str \{([\s\S]*?)\n {4}\}/.exec(src);
  assert.ok(body, 'MessageState::definition not found');
  const defs: Record<string, string> = {};
  for (const m of body[1].matchAll(/Self::(\w+)\s*=>\s*\{?\s*"((?:[^"\\]|\\.)*)"/g)) defs[camelToSnake(m[1])] = m[2];
  return { order, defs };
}

function apiDefinitions(): Record<string, string> {
  const src = readRepo('backend', 'app', 'routes', 'outreach.py');
  const block = /MESSAGE_STATE_DEFINITIONS = \{([\s\S]*?)\n\}/.exec(src);
  assert.ok(block, 'MESSAGE_STATE_DEFINITIONS not found');
  const out: Record<string, string> = {};
  for (const m of block[1].matchAll(/"(\w+)":\s*"((?:[^"\\]|\\.)*)"/g)) out[m[1]] = m[2];
  return out;
}

const schema = JSON.parse(readRepo('contracts', 'action', 'v1', 'action-result.schema.json'));

test('identifiers and order equal the action contract enum', () => {
  assert.deepEqual([...MESSAGE_STATE_IDS], schema.properties.message_state.enum);
  assert.deepEqual(MESSAGE_STATES.map(s => s.id), schema.properties.message_state.enum);
  assert.deepEqual([...READ_STATUS_IDS], schema.properties.read_status.enum);
});

test('identifiers, order and every definition equal mk-contracts::MessageState (the declared single source)', () => {
  const rust = rustDefinitions();
  assert.equal(rust.order.length, 15);
  assert.deepEqual(MESSAGE_STATES.map(s => s.id), rust.order);
  assert.equal(Object.keys(rust.defs).length, 15, 'every Rust state has a definition');
  for (const s of MESSAGE_STATES) assert.equal(s.definition, rust.defs[s.id], `definition of ${s.id}`);
});

test('every definition equals what the API serves (outreach.py MESSAGE_STATE_DEFINITIONS)', () => {
  const api = apiDefinitions();
  assert.deepEqual(Object.keys(api), MESSAGE_STATES.map(s => s.id));
  for (const s of MESSAGE_STATES) assert.equal(s.definition, api[s.id], `definition of ${s.id}`);
});

test('the completion contract lists exactly these states and its own definitions match verbatim', () => {
  const doc = readRepo('docs', 'production-completion-contract.md');
  const section = doc.slice(doc.indexOf('### State model'), doc.indexOf('### Ambiguous submission'));
  const listed = section.slice(section.indexOf('Use distinct states:'), section.indexOf('Store read status')).split('\n')
    .map(l => l.trim()).filter(l => /^[a-z_]+$/.test(l) && l !== 'text');
  assert.deepEqual(listed, [...MESSAGE_STATE_IDS]);
  const lower = (s: string) => s.charAt(0).toLowerCase() + s.slice(1);
  for (const id of ['provider_accepted', 'sent', 'delivered'] as const) {
    const s = MESSAGE_STATES.find(x => x.id === id)!;
    assert.ok(section.includes(`${s.label}: ${lower(s.definition)}`), `contract wording for ${id}`);
  }
  assert.ok(section.includes(`Read: ${lower(READ_STATUSES.read.definition)}`));
  assert.ok(section.includes(`Unknown: ${lower(READ_STATUSES.unknown.definition)}`));
});

test('labels are the identifier in sentence case — never a paraphrase', () => {
  for (const s of MESSAGE_STATES) assert.equal(s.label, labelFromIdentifier(s.id));
  assert.equal(labelFromIdentifier('provider_accepted'), 'Provider accepted');
  assert.equal(labelFromIdentifier('submission_unknown'), 'Submission unknown');
  const banned = ['Accepted by provider', 'Authorized to send', 'Submitting', 'Awaiting your approval', 'Denied by policy', 'Message sent'];
  for (const s of MESSAGE_STATES) assert.ok(!banned.includes(s.label), s.label);
});

test('the support/marketing reference (docs/release/message-states.md) quotes the vocabulary verbatim', () => {
  const doc = readRepo('docs', 'release', 'message-states.md');
  const rows = [...doc.matchAll(/^\| ([^|]+) \| `([a-z_]+)` \| ([^|]+) \|$/gm)].map(m => ({ label: m[1].trim(), id: m[2], definition: m[3].trim() }));
  const states = rows.slice(0, 15), reads = rows.slice(15);
  assert.deepEqual(states, MESSAGE_STATES.map(s => ({ label: s.label, id: s.id, definition: s.definition })));
  assert.deepEqual(reads, READ_STATUS_IDS.map(id => ({ label: READ_STATUSES[id].label, id, definition: READ_STATUSES[id].definition })));
});

test('every state has a tone, and evidence tones are only the three provider-reported states', () => {
  for (const s of MESSAGE_STATES) assert.ok(['pending', 'progress', 'evidence', 'problem', 'stopped'].includes(s.tone), s.id);
  assert.deepEqual(MESSAGE_STATES.filter(s => s.tone === 'evidence').map(s => s.id), ['provider_accepted', 'sent', 'delivered']);
  for (const id of ['delivery_unknown', 'submission_unknown', 'failed']) assert.equal(MESSAGE_STATES.find(s => s.id === id)!.tone, 'problem');
});

test('describeMessageState: known states resolve; everything else is reported as unknown, never as a state', () => {
  const d = describeMessageState('delivered');
  assert.equal(d.known, true);
  assert.equal(d.label, 'Delivered');
  for (const raw of ['Delivered', 'DELIVERED', ' sent', 'sent ', 'approval_required', 'completed', 'read', 'unknown', 'dispatching']) {
    const x = describeMessageState(raw);
    assert.equal(x.known, false, raw);
    assert.equal(x.id, null);
    assert.equal(x.label, 'Unrecognised state');
    assert.match(x.definition, /Do not assume anything was sent/);
  }
  for (const raw of [null, undefined, '']) assert.equal(describeMessageState(raw).label, 'Not reported');
});

test('prototype keys and non-strings never resolve to Object.prototype members', () => {
  for (const raw of ['constructor', '__proto__', 'toString', 'hasOwnProperty', 'valueOf', 42, {}, [], true, Symbol.iterator.toString()]) {
    const d = describeMessageState(raw);
    assert.equal(d.known, false, String(raw));
    assert.equal(typeof d.label, 'string');
    assert.equal(typeof d.definition, 'string');
    assert.equal(isMessageState(raw), false);
  }
});

test('an unexpected value is echoed bounded and without control or bidi characters', () => {
  const d = describeMessageState('x'.repeat(500) + '‮\u0000\n');
  assert.equal(d.known, false);
  if (!d.known) {
    assert.ok(d.raw.length <= 64);
    assert.doesNotMatch(d.raw, /[\u0000-\u001f‮]/);
  }
});

test('messageStateOf reads message_state only — the kernel action state is never used', () => {
  assert.equal(messageStateOf({ message_state: 'queued', state: 'delivered' } as any).label, 'Queued');
  assert.equal(messageStateOf({ state: 'completed' } as any).label, 'Not reported');
  assert.equal(messageStateOf(null).label, 'Not reported');
});

test('read status is "Unknown" unless the API says exactly "read"', () => {
  assert.equal(describeReadStatus('read').label, 'Read');
  for (const raw of [undefined, null, '', 'READ', 'delivered', 'seen', 'opened', 1, 'unknown']) assert.equal(describeReadStatus(raw).id, 'unknown', String(raw));
});

test('the vocabulary tables are frozen at runtime', () => {
  assert.ok(Object.isFrozen(MESSAGE_STATES));
  assert.ok(Object.isFrozen(MESSAGE_STATES[0]));
  try { (MESSAGE_STATES[0] as { label: string }).label = 'Sent!'; } catch { /* strict mode throws; sloppy mode ignores */ }
  assert.equal(MESSAGE_STATES[0].label, 'Proposed');
  assert.ok(Object.isFrozen(READ_STATUSES.read));
});
