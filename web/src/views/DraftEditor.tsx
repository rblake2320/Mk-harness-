import { useEffect, useRef, useState } from 'react';
import { client } from '../App.tsx';
import type { Draft } from '../../../packages/sdk/src/index.ts';
import { ErrorNote, HumanSteps } from '../components/Common.tsx';
import { AiBadge } from '../components/AiDisclosure.tsx';

/**
 * Draft editor (W5): the text you see is the text that will be approved and sent.
 * Any edit creates a NEW version with a new digest; an approval of the previous
 * version cannot cover it. Product statements are limited to approved wording.
 */
export default function DraftEditor({ customerName, initial, limitation, neutralText, onClose }: {
  customerName: string; initial: Draft | null; limitation: string | null; neutralText?: string; onClose: () => void;
}) {
  const [draft, setDraft] = useState<Draft | null>(initial);
  const [text, setText] = useState(initial?.text ?? '');
  const [err, setErr] = useState<unknown>(null);
  const [busy, setBusy] = useState(false);
  const [proposed, setProposed] = useState<any>(null);
  const [saved, setSaved] = useState(false);
  const first = useRef<HTMLTextAreaElement>(null);
  useEffect(() => { first.current?.focus(); }, []);

  const dirty = draft ? text !== draft.text : false;

  async function saveEdit() {
    if (!draft) return;
    setBusy(true); setErr(null);
    try { const d = await client.editDraft(draft.id, text); setDraft(d); setText(d.text); setProposed(null); setSaved(true); }
    catch (e) { setErr(e); } finally { setBusy(false); }
  }

  async function propose() {
    if (!draft || dirty) return;
    setBusy(true); setErr(null);
    try { setProposed(await client.proposeDraft(draft.id)); }
    catch (e) { setErr(e); } finally { setBusy(false); }
  }

  return (
    <div className="modal-backdrop" role="dialog" aria-modal="true" aria-labelledby="draft-title">
      <div className="card modal wide">
        <h3 id="draft-title" style={{ marginTop: 0 }}>Message to {customerName} <AiBadge /></h3>
        {limitation && (
          <div className="limitation" role="status">
            <strong>No product recommendation was drafted.</strong> {limitation}
            {neutralText && <p style={{ marginBottom: 0 }}>You can send a neutral check-in instead:<br /><em>{neutralText}</em></p>}
          </div>
        )}
        {draft && (
          <>
            <label htmlFor="draft-text" className="muted small">Exact text (version {draft.version}, digest {draft.text_digest.slice(7, 19)}…)</label>
            <textarea id="draft-text" ref={first} rows={5} value={text} disabled={busy} onChange={e => setText(e.target.value)} maxLength={480}
                      aria-describedby="draft-help" />
            <div id="draft-help" className="muted small">
              {draft.claims_used.length > 0
                ? <>Approved product wording in this draft: {draft.claims_used.join(', ')} (source versions {Object.values(draft.source_versions).join(', ')}). Edit the relationship text freely; product statements must stay within the approved list.</>
                : <>No product statements. Edit freely; product claims that are not on the approved list are refused.</>}
              {' '}{text.length}/480
            </div>
            <ErrorNote error={err} onDismiss={() => setErr(null)} />
            {saved && !dirty && !proposed && <div className="ok-note" role="status">Old version withdrawn. This new version needs a new proposal and fresh passkey approval.</div>}
            {proposed && !dirty ? (
              <div className="ok-note" role="status">
                <strong>Proposed for approval.</strong> Kernel decision: {proposed.decision?.code ?? proposed.state}. This proposal did not send a message. Check Approvals for its current status.
                <HumanSteps steps={proposed.human_steps ?? []} />
              </div>
            ) : (
              <div className="row" style={{ marginTop: 12 }}>
                {dirty
                  ? <button className="btn" disabled={busy} onClick={saveEdit}>Save as new version</button>
                  : <button className="btn" disabled={busy} onClick={propose}>Propose for approval</button>}
                <span className="muted small">{dirty ? 'Saving withdraws the old version and its queued approvals before creating a new version. If sending already started, saving is blocked.' : 'Proposing never sends. You (or a second approver) must approve the exact text with a passkey.'}</span>
              </div>
            )}
          </>
        )}
        {!draft && !limitation && <ErrorNote error={err} />}
        <div className="row" style={{ marginTop: 14, justifyContent: 'flex-end' }}>
          <button className="btn ghost" disabled={busy} onClick={onClose}>Close</button>
        </div>
      </div>
    </div>
  );
}
