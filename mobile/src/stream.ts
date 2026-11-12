/**
 * React Native chat streaming via XMLHttpRequest onprogress.
 * RN's fetch does not expose ReadableStream, so the shared SDK's chatStream
 * is web-only; this helper hits the same /api/chat/stream SSE endpoint.
 * Framing is done by `createSseParser` (frames split across chunks are kept), and a
 * non-2xx response ends the stream with a plain-language error instead of hanging.
 */
import { apiErrorFrom, explain } from '../../packages/sdk/src/index';
import type { MKClient, StreamEvent } from '../../packages/sdk/src/index';
import { createSseParser } from './logic/sse';

export function rnChatStream(
  client: MKClient,
  body: { message: string; conversation_id?: string; skill?: string; provider?: string; model?: string },
  onEvent: (ev: StreamEvent) => void,
): { abort: () => void } {
  const xhr = new XMLHttpRequest();
  let seen = 0;
  const parser = createSseParser(data => onEvent(data as StreamEvent));

  xhr.open('POST', client.baseUrl + '/api/chat/stream');
  xhr.setRequestHeader('Content-Type', 'application/json');
  if (client.tokens) {
    xhr.setRequestHeader('Authorization', `Bearer ${client.tokens.access_token}`);
  }

  const failed = () => xhr.status >= 400;
  const pump = () => {
    if (failed()) return;
    const chunk = xhr.responseText.slice(seen);
    seen = xhr.responseText.length;
    parser.push(chunk);
  };

  xhr.onprogress = pump;
  xhr.onload = () => {
    if (failed()) {
      let parsed: unknown;
      try { parsed = JSON.parse(xhr.responseText); } catch { parsed = undefined; }
      onEvent({ type: 'error', message: explain(apiErrorFrom(xhr.status, parsed)).what });
      return;
    }
    pump();
    parser.end();
  };
  xhr.onerror = () => onEvent({ type: 'error', message: 'Network error — check your connection.' });
  xhr.send(JSON.stringify(body));
  return { abort: () => xhr.abort() };
}
