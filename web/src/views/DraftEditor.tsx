import { useEffect, useRef, useState } from 'react';
import { client } from '../App.tsx';
import { describeMessageState } from '../../../packages/sdk/src/index.ts';
import type { Draft, ProposeResult } from '../../../packages/sdk/src/index.ts';
import { ErrorNote, HumanSteps, StateBadge } from '../components/Common.tsx';
import { AiBadge } from '../components/AiDisclosure.tsx';

/**
 * Draft editor (W5/H2): the text you see is the text that will be approved and submitted.
 * Any edit creates a NEW version with a new digest. Changing the text after proposing
 * first withdraws the earlier proposal through the kernel, so the old digest can never
 * be approved; if the kernel cannot withdraw it, no new version is proposed.
 * Product statements are limited to approved wording.
 */
export default function DraftEditor({ customerName, initial, limitation, neutralText, onClose }: {
  customerName: string; initial: Draft | null; limitation: string | null; neutralText?: string; onClose: () => void;
}) {
  const [draft, setDraft] = useState<Draft | null>(initial);
  const [text, setText] = useState(initial?.text ?? '');
  const [err, setErr] = useState<unknown>(null);
  const [busy, setBusy] = useState(false);
  const [proposed, setProposed] = useState<ProposeResult | null>(null);
  const [withdrawn, setWithdrawn] = useState<string | null>(null);
  const first = useRef<HTMLTextAreaElement>(null);
  useEffect(() => { first.current?.focus(); }, []);

  const dirty = draft ? text !== draft.text : false;

  async function saveEdit() {
    if (!draft || proposed) return;
    setBusy(true); setErr(null);
    try { const d = await client.editDraft(draft.id, text); setDraft(d); setText(d.text); }
    catch (e) { setErr(e); } finally { setBusy(false); }
  }

  async function propose() {
    if (!draft || dirty || proposed) return;
    setBusy(true); setErr(null);
    try { setProposed(await client.proposeDraft(draft.id)); setWithdrawn(null); }
    catch (e) { setErr(e); } finally { setBusy(false); }
  }

  /** Withdraw the pending proposal before the text can change (H2). */
  async function withdrawToEdit() {
    if (!proposed) return;
    setBusy(true); setErr(null);
    try {
      const r = await client.cancelAction(proposed.action_id);
      const d = describeMessageState(r.message_state);
      if (d.id !== 'cancelled') throw new Error(`The earlier proposal was not withdrawn (the kernel reports "${d.label}"). Check Approvals before proposing another version.`);
      setWithdrawn(proposed.action_id); setProposed(null);
    } catch (e) { setErr(e); } finally { setBusy(false); }
  }

  return (
    <div className="modal-backdrop" role="dialog" aria-modal="true" aria-labelledby="draft-title">
      <div className="card modal wide">
        <h3 id="draft-title" style={{ marginTop: 0 }}>Message to {customerName} <AiBadge /></h3>
        {limitation && (
          <div className="limitation" role="status">
            <strong>No product recommendation was drafted.</strong> {limitation}
            {neutralText && <p style={{ marginBottom: 0 }}>A neutral check-in you could write instead:<br /><em>{neutralText}</em></p>}
          </div>
        )}
        {draft && (
          <>
            <label htmlFor="draft-text" className="muted small">Exact text (version {draft.version}, digest {draft.text_digest.slice(7, 19)}…)</label>
            <textarea id="draft-text" ref={first} rows={5} value={text} onChange={e => setText(e.target.value)} maxLength={480}
                      readOnly={proposed !== null} aria-describedby="draft-help" />
            <div id="draft-help" className="muted small">
              {draft.claims_used.length > 0
                ? <>Approved product wording in this draft: {draft.claims_used.join(', ')} (source versions {Object.values(draft.source_versions).join(', ')}). Edit the relationship text freely; product statements must stay within the approved list.</>
                : <>No product statements. Edit freely; product claims that are not on the approved list are refused.</>}
              {' '}{text.length}/480
            </div>
            <ErrorNote error={err} onDismiss={() => setErr(null)} />
            {withdrawn && <div className="ok-note" role="status">The earlier proposal was withdrawn; its version can no longer be approved. Save your change as a new version, then propose it — it needs its own approval.</div>}
            {proposed ? (
              <div className="ok-note" role="status">
                <strong>Proposed for approval.</strong> The kernel reports: <StateBadge state={proposed.message_state} showDefinition />
                <HumanSteps steps={proposed.human_steps ?? []} />
                <div className="row">
                  <button className="btn ghost" disabled={busy} onClick={withdrawToEdit}>Withdraw this proposal to change the text</button>
                  <span className="muted small">The earlier version is withdrawn first, so it can never be approved.</span>
                </div>
              </div>
            ) : (
              <div className="row" style={{ marginTop: 12 }}>
                {dirty
                  ? <button className="btn" disabled={busy} onClick={saveEdit}>Save as new version</button>
                  : <button className="btn" disabled={busy} onClick={propose}>Propose for approval</button>}
                <span className="muted small">{dirty ? 'Saving creates a new version; any earlier approval no longer applies.' : 'Proposing never submits anything. You (or a second approver) must approve the exact text with a passkey.'}</span>
              </div>
            )}
          </>
        )}
        {!draft && !limitation && <ErrorNote error={err} />}
        <div className="row" style={{ marginTop: 14, justifyContent: 'flex-end' }}>
          <button className="btn ghost" onClick={onClose}>Close</button>
        </div>
      </div>
    </div>
  );
}
