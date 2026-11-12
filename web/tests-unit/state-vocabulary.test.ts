/**
 * Contract row C3: every web and mobile screen renders message/delivery state only through
 * the shared SDK vocabulary. Fails on hard-coded state words ("Delivered", "Sent!",
 * "Message sent", local label maps) anywhere in UI code, and proves with fixtures that the
 * lint catches each violation family and stays quiet on ordinary copy.
 */
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { existsSync, readdirSync, readFileSync, statSync } from 'node:fs';
import { dirname, join, relative, resolve } from 'node:path';
import { lintSource, normalize } from './state-vocabulary-lint';

function repoRoot(): string {
  for (let dir = resolve(process.cwd()); ; dir = dirname(dir)) {
    if (existsSync(join(dir, 'contracts', 'action', 'v1', 'action-result.schema.json'))) return dir;
    if (dirname(dir) === dir) throw new Error('repository root not found');
  }
}
const ROOT = repoRoot();
/** UI code: the web app, the mobile app, and shared SDK code other than the vocabulary itself. */
const SCAN = ['web/src', 'mobile/src', 'mobile/App.tsx', 'packages/sdk/src'];
const EXEMPT = new Set(['packages/sdk/src/vocabulary.ts']);

function files(rel: string): string[] {
  const abs = join(ROOT, rel);
  if (!existsSync(abs)) return [];
  if (statSync(abs).isFile()) return [rel];
  return readdirSync(abs).flatMap(name => {
    const child = `${rel}/${name}`;
    if (name === 'node_modules' || name.startsWith('.')) return [];
    if (statSync(join(ROOT, child)).isDirectory()) return files(child);
    return /\.(ts|tsx)$/.test(name) && !/\.(test|spec)\.tsx?$/.test(name) ? [child] : [];
  });
}

test('UI code uses message-state words only through the shared vocabulary', () => {
  const scanned = SCAN.flatMap(files).filter(f => !EXEMPT.has(f));
  assert.ok(scanned.some(f => f.startsWith('web/src/views/')), 'web views were scanned');
  assert.ok(scanned.some(f => f.startsWith('mobile/src/screens/')), 'mobile screens were scanned');
  assert.ok(scanned.includes('mobile/App.tsx'), 'mobile/App.tsx was scanned');
  const violations = scanned.flatMap(f => lintSource(f, readFileSync(join(ROOT, f), 'utf8')));
  assert.deepEqual(violations, [], violations.map(v => `${v.file}:${v.line} ${v.rule} ${JSON.stringify(v.text)}`).join('\n'));
});

test('negative fixture: every violation family is caught, on the right line, with the right rule', () => {
  const rel = relative(ROOT, join(ROOT, 'web/tests-unit/fixtures/state-vocabulary/violations.tsx'));
  const found = lintSource(rel, readFileSync(join(ROOT, rel), 'utf8')).map(v => `${v.line} ${v.rule}`).sort();
  const expected = [
    '4 R1', '4 R2', '5 R1', '5 R2', '6 R1', '6 R2', // local label map (also whole-copy labels)
    '8 R2', // single message-only key mapped to words
    '11 R1', '12 R1', '13 R3', '14 R1', '15 R3', '16 R1', // literals and templates
    '18 R1', '19 R1', '20 R1', '21 R1', '22 R3', '23 R1', // JSX attribute copy, JSX text
  ].sort();
  assert.deepEqual(found, expected);
});

test('clean fixture: identifiers in code, negated or ordinary copy, comments and types are not flagged', () => {
  const rel = 'web/tests-unit/fixtures/state-vocabulary/clean.tsx';
  assert.deepEqual(lintSource(rel, readFileSync(join(ROOT, rel), 'utf8')), []);
});

test('the lint would have caught the label table the web app used before C3', () => {
  const before = `export const STATE_LABEL: Record<string, string> = {
  proposed: 'Proposed', awaiting_approval: 'Awaiting your approval', approved: 'Approved', queued: 'Queued',
  dispatch_authorized: 'Authorized to send', submission_started: 'Submitting', provider_accepted: 'Accepted by provider',
};`;
  const v = lintSource('before.tsx', before);
  assert.ok(v.filter(x => x.rule === 'R2').length >= 7, JSON.stringify(v));
});

test('normalisation ignores case, separators, punctuation and symbols but not words', () => {
  assert.equal(normalize('  Delivered ✓ '), 'delivered');
  assert.equal(normalize('SENT!!'), 'sent');
  assert.equal(normalize('provider_accepted'), 'provider accepted');
  assert.equal(normalize('Provider-accepted.'), 'provider accepted');
  assert.equal(normalize('Not delivered'), 'not delivered');
  assert.equal(normalize('Sentence'), 'sentence');
});
