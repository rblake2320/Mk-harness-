/**
 * Server-sent-event framing for the chat stream. React Native delivers the response in
 * arbitrary chunks (XHR onprogress), so a frame can be split anywhere — even inside
 * "\r\n" or a multi-byte character's JSON escape. The previous parser parsed each chunk
 * on its own and silently dropped any frame that straddled two chunks.
 */
export interface SseParser {
  push(chunk: string): void;
  /** Flush a final frame that arrived without the trailing blank line. */
  end(): void;
}

export function createSseParser(onData: (data: unknown) => void): SseParser {
  let buf = '';
  const emit = (block: string) => {
    const data = block.split('\n').filter(l => l.startsWith('data:')).map(l => l.slice(5).replace(/^ /, '')).join('\n');
    if (!data) return;
    try { onData(JSON.parse(data)); } catch { /* not JSON: ignored, never half-applied */ }
  };
  return {
    push(chunk: string) {
      buf = (buf + chunk).replace(/\r\n?/g, (m, offset: number, whole: string) =>
        // keep a trailing lone "\r": its "\n" may arrive in the next chunk
        (m === '\r' && offset === whole.length - 1) ? '\r' : '\n');
      const blocks = buf.split('\n\n');
      buf = blocks.pop() ?? '';
      for (const b of blocks) emit(b);
    },
    end() {
      const rest = buf.replace(/\r$/, '');
      buf = '';
      if (rest.trim()) emit(rest);
    },
  };
}
