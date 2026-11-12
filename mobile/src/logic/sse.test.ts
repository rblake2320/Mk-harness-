import { test } from 'node:test';
import assert from 'node:assert/strict';
import { createSseParser } from './sse';

function collect() {
  const out: unknown[] = [];
  return { out, parser: createSseParser(d => out.push(d)) };
}
const frame = (o: unknown) => `data: ${JSON.stringify(o)}\n\n`;

test('whole frames are delivered in order', () => {
  const { out, parser } = collect();
  parser.push(frame({ type: 'meta', conversation_id: 'c' }) + frame({ type: 'delta', text: 'Hi' }));
  assert.deepEqual(out, [{ type: 'meta', conversation_id: 'c' }, { type: 'delta', text: 'Hi' }]);
});

test('a frame split across chunks at every possible position is delivered exactly once', () => {
  const stream = frame({ type: 'delta', text: 'Héllo — “world” 😀' }) + frame({ type: 'done', provider: 'p', model: 'm' });
  for (let cut = 0; cut <= stream.length; cut++) {
    const { out, parser } = collect();
    parser.push(stream.slice(0, cut));
    parser.push(stream.slice(cut));
    assert.deepEqual(out, [{ type: 'delta', text: 'Héllo — “world” 😀' }, { type: 'done', provider: 'p', model: 'm' }], `cut at ${cut}`);
  }
});

test('one character per chunk still works (worst-case progress events)', () => {
  const { out, parser } = collect();
  for (const ch of frame({ type: 'delta', text: 'abc' })) parser.push(ch);
  assert.deepEqual(out, [{ type: 'delta', text: 'abc' }]);
});

test('CRLF framing, including a CR/LF pair split across chunks', () => {
  const { out, parser } = collect();
  parser.push('data: {"type":"delta","text":"x"}\r');
  parser.push('\n\r\n');
  assert.deepEqual(out, [{ type: 'delta', text: 'x' }]);
});

test('a final frame without the blank line is flushed by end(); junk and comments are ignored', () => {
  const { out, parser } = collect();
  parser.push(': keep-alive\n\n');
  parser.push('data: not json\n\n');
  parser.push('event: x\ndata: {"type":"done","provider":"p","model":"m"}');
  assert.deepEqual(out, []);
  parser.end();
  assert.deepEqual(out, [{ type: 'done', provider: 'p', model: 'm' }]);
  parser.end();
  assert.equal(out.length, 1, 'end() is idempotent');
});
