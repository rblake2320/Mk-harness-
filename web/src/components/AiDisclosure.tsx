import { useEffect, useState } from 'react';

/**
 * California SB 243 (eff. Jan 2026): users must be told they're interacting with AI,
 * before/at the start of the interaction — and the disclosure must be visible during it,
 * not a buried one-time dismissible popup.
 *
 * We satisfy this three ways:
 *  - <AiNoticeModal/>  : shown before the first AI surface each session
 *  - <AiStrip/>        : a persistent, non-dismissible banner on every AI surface
 *  - <AiBadge/>        : a per-output marker on each AI-generated response
 */

const SEEN_KEY = 'cs_ai_notice_seen';

export function AiNoticeModal() {
  const [open, setOpen] = useState(false);
  useEffect(() => {
    if (!sessionStorage.getItem(SEEN_KEY)) setOpen(true);
  }, []);
  if (!open) return null;
  return (
    <div className="modal-backdrop" role="dialog" aria-modal="true" aria-label="AI disclosure">
      <div className="card modal">
        <h3 style={{ marginTop: 0 }}>You're working with an AI assistant</h3>
        <p className="muted" style={{ marginTop: 0 }}>
          Consultant Studio uses AI to generate content that helps you run your business —
          follow-ups, talking points, captions, and cosmetic skin observations. It is{' '}
          <strong>not a human consultant</strong> and its output is not medical, legal, or
          financial advice. Always review before you send anything to a customer.
        </p>
        <button className="btn" onClick={() => { sessionStorage.setItem(SEEN_KEY, '1'); setOpen(false); }}>
          Got it
        </button>
      </div>
    </div>
  );
}

export function AiStrip() {
  return (
    <div className="ai-strip" role="note">
      <AiBadge /> You're interacting with an AI assistant — review its output before sharing.
    </div>
  );
}

export function AiBadge() {
  return <span className="ai-badge" title="AI-generated">AI</span>;
}
