/**
 * React Native chat streaming via XMLHttpRequest onprogress.
 * RN's fetch does not expose ReadableStream, so the shared SDK's chatStream
 * is web-only; this helper hits the same /api/chat/stream SSE endpoint.
 */
import type { MKClient, StreamEvent } from '../../packages/sdk/src/index';

export function rnChatStream(
  client: MKClient,
  body: { message: string; conversation_id?: string; skill?: string; provider?: string; model?: string },
  onEvent: (ev: StreamEvent) => void,
): { abort: () => void } {
  const xhr = new XMLHttpRequest();
  let seen = 0;

  xhr.open('POST', client.baseUrl + '/api/chat/stream');
  xhr.setRequestHeader('Content-Type', 'application/json');
  if (client.tokens) {
    xhr.setRequestHeader('Authorization', `Bearer ${client.tokens.access_token}`);
  }

  const pump = () => {
    const chunk = xhr.responseText.slice(seen);
    seen = xhr.responseText.length;
    for (const block of chunk.split('\n\n')) {
      const line = block.trim();
      if (!line.startsWith('data:')) continue;
      try { onEvent(JSON.parse(line.slice(5).trim())); } catch { /* partial frame */ }
    }
  };

  xhr.onprogress = pump;
  xhr.onload = pump;
  xhr.onerror = () => onEvent({ type: 'error', message: 'Network error — check your connection.' });
  xhr.send(JSON.stringify(body));
  return { abort: () => xhr.abort() };
}
