import { useEffect, useState } from 'react';
import { client } from '../App.tsx';
import type { Commitment, Customer, Draft } from '../../../packages/sdk/src/index.ts';
import { ErrorNote, HumanSteps, fmtWhen } from '../components/Common.tsx';
import DraftEditor from './DraftEditor.tsx';

const TZS = ['America/New_York', 'America/Chicago', 'America/Denver', 'America/Phoenix', 'America/Los_Angeles', 'America/Anchorage', 'Pacific/Honolulu'];
const OUTCOMES = ['resolved', 'deferred', 'opted_out', 'no_response', 'customer_reported_order', 'consultant_confirmed_order', 'exception_open', 'cancelled'];

/** Customer page: timeline, commitments, permission & suppression view, destinations, outcomes. */
export default function CustomerDetail({ customer, onBack }: { customer: Customer; onBack: () => void }) {
  const [timeline, setTimeline] = useState<any[]>([]);
  const [commitments, setCommitments] = useState<Commitment[]>([]);
  const [perm, setPerm] = useState<any>(null);
  const [dests, setDests] = useState<any[]>([]);
  const [err, setErr] = useState<unknown>(null);
  const [tz, setTz] = useState('');
  const [newDest, setNewDest] = useState('');
  const [consentText, setConsentText] = useState('');
  const [newCommit, setNewCommit] = useState({ kind: 'promise', text: '', window: 'this_week' });
  const [outcome, setOutcome] = useState({ kind: 'resolved', commitment_id: '', note: '' });
  const [draft, setDraft] = useState<{ draft: Draft | null; limitation: string | null; neutral?: string } | null>(null);
  const [extractText, setExtractText] = useState('');
  const [extracted, setExtracted] = useState<any>(null);

  function load() {
    setErr(null);
    Promise.all([client.customerTimeline(customer.id), client.listCommitments(customer.id), client.customerPermissions(customer.id), client.customerDestinations(customer.id)])
      .then(([t, c, p, d]) => { setTimeline(t); setCommitments(c); setPerm(p); setDests(d); })
      .catch(setErr);
  }
  useEffect(load, [customer.id]);

  const run = (fn: () => Promise<unknown>) => fn().then(load).catch(setErr);

  return (
    <div>
      <button className="link" onClick={onBack}>← All customers</button>
      <h1 style={{ margin: '6px 0' }}>{customer.name}</h1>
      <ErrorNote error={err} onDismiss={() => setErr(null)} />

      <section className="grid-2">
        <div className="card">
          <h3 style={{ marginTop: 0 }}>Permission & suppression</h3>
          <p className="muted small">{perm?.note ?? 'Historical observation; the kernel re-checks at send time.'}</p>
          {perm?.suppressions?.length > 0 && (
            <div className="limitation" role="status"><strong>Do not contact.</strong> {perm.suppressions.map((s: any) => `${s.channel}: ${s.reason} (${s.source}, ${fmtWhen(s.created_at)})`).join('; ')}
              <div className="small">Suppression is never cleared by a reply. Re-consent needs fresh, purpose-specific evidence through this form.</div></div>
          )}
          <ul className="plain">
            {(perm?.consent_events ?? []).map((e: any) => (
              <li key={e.id}><strong>{e.status}</strong> · {e.channel} · {e.purposes.join(', ')} · from {e.source} · {fmtWhen(e.effective_at)} → {fmtWhen(e.expires_at)}
                {e.status === 'active' && <button className="link" onClick={() => run(() => client.revokeConsent(customer.id, e.id, 'consultant'))}>revoke</button>}</li>
            ))}
            {(perm?.consent_events ?? []).length === 0 && <li className="muted">No consent recorded. An imported number is not permission.</li>}
          </ul>
          <label className="muted small" htmlFor="consent-text">Record consent (what the customer actually said or signed)</label>
          <textarea id="consent-text" rows={2} value={consentText} onChange={e => setConsentText(e.target.value)} placeholder="e.g. 'Yes, text me about my orders' — verbal, confirmed at the party on 10/18" />
          <button className="btn ghost" disabled={consentText.trim().length < 8} onClick={() => run(async () => {
            await client.recordConsent(customer.id, { purposes: ['customer_requested_follow_up'], source: 'verbal_confirmed', evidence_type: 'consultant_attestation', evidence_text: consentText });
            setConsentText('');
          })}>Record consent for order follow-ups</button>
        </div>

        <div className="card">
          <h3 style={{ marginTop: 0 }}>Contact details</h3>
          <label className="muted small" htmlFor="tz">Timezone (required before any automated message)</label>
          <select id="tz" value={tz} onChange={e => setTz(e.target.value)}>
            <option value="">Choose…</option>{TZS.map(z => <option key={z} value={z}>{z}</option>)}
          </select>
          <button className="btn ghost" disabled={!tz} onClick={() => run(() => client.setPreferences(customer.id, { timezone: tz }))}>Save timezone</button>
          <h4>SMS destinations</h4>
          <ul className="plain">{dests.map(d => <li key={d.id}>{d.channel} · {d.masked ?? d.label ?? 'on file'} {d.is_primary && <em className="muted small">primary</em>}</li>)}</ul>
          <label className="muted small" htmlFor="dest">Add mobile number (E.164)</label>
          <div className="row">
            <input id="dest" value={newDest} onChange={e => setNewDest(e.target.value)} placeholder="+1 555 555 0100" />
            <button className="btn ghost" disabled={!newDest} onClick={() => run(async () => { await client.addDestination(customer.id, 'sms', newDest); setNewDest(''); })}>Add</button>
          </div>
        </div>
      </section>

      <section className="card" style={{ marginTop: 16 }}>
        <h3 style={{ marginTop: 0 }}>Commitments</h3>
        <HumanSteps steps={['AI-extracted commitments are drafts until you confirm the date or window. Nothing is scheduled from a draft.']} />
        <ul className="plain">
          {commitments.map(c => (
            <li key={c.id} className="commit-row">
              <div><strong>{c.kind.replace('_', ' ')}</strong> · <span className={`tag status-${c.status}`}>{c.status}</span> · {c.text}</div>
              <div className="muted small">{c.due_at ? `due ${fmtWhen(c.due_at)}` : c.due_window[0] ? `window ${fmtWhen(c.due_window[0])} – ${fmtWhen(c.due_window[1])}` : 'no date'} · {c.timezone} · by {c.created_by}{c.confirmed_by ? ' · confirmed' : ''}</div>
              <div className="row">
                {(c.status === 'draft' || c.status === 'deferred') && (
                  <>
                    <button className="link" onClick={() => run(() => client.confirmCommitment(c.id, { relative_window: 'this_week' }))}>confirm this week</button>
                    <button className="link" onClick={() => run(() => client.confirmCommitment(c.id, { relative_window: 'next_week' }))}>confirm next week</button>
                  </>
                )}
                {c.status === 'confirmed' && <button className="link" onClick={() => run(() => client.deferCommitment(c.id, { relative_window: 'next_week', reason: 'consultant' }))}>defer</button>}
                {c.status !== 'cancelled' && c.status !== 'resolved' && <button className="link" onClick={() => run(() => client.cancelCommitment(c.id, 'consultant'))}>cancel</button>}
                <button className="link" onClick={() => client.generateDraft({ customer_id: customer.id, commitment_id: c.id }).then(r => setDraft({ draft: r.draft, limitation: r.limitation, neutral: r.neutral_text })).catch(setErr)}>draft message</button>
              </div>
            </li>
          ))}
        </ul>
        <div className="row" style={{ marginTop: 8 }}>
          <select aria-label="Commitment kind" value={newCommit.kind} onChange={e => setNewCommit({ ...newCommit, kind: e.target.value })} style={{ width: 'auto' }}>
            {['promise', 'customer_request', 'unanswered_question', 'customer_date'].map(k => <option key={k}>{k}</option>)}
          </select>
          <input aria-label="Commitment text" placeholder="What did you promise or what did they ask?" value={newCommit.text} onChange={e => setNewCommit({ ...newCommit, text: e.target.value })} style={{ flex: 1 }} />
          <select aria-label="Window" value={newCommit.window} onChange={e => setNewCommit({ ...newCommit, window: e.target.value })} style={{ width: 'auto' }}>
            {['today', 'tomorrow', 'this_week', 'next_week', 'next_month'].map(w => <option key={w}>{w}</option>)}
          </select>
          <button className="btn ghost" disabled={newCommit.text.trim().length < 3} onClick={() => run(async () => {
            await client.createCommitment({ customer_id: customer.id, kind: newCommit.kind, text: newCommit.text, relative_window: newCommit.window, source_type: 'consultant_note', evidence_text: newCommit.text });
            setNewCommit({ ...newCommit, text: '' });
          })}>Add</button>
        </div>
        <details style={{ marginTop: 10 }}>
          <summary>Extract commitments from a conversation (AI, drafts only)</summary>
          <textarea rows={4} aria-label="Conversation text" value={extractText} onChange={e => setExtractText(e.target.value)} placeholder="Paste the conversation. Only verbatim quotes become evidence; dates are never invented." />
          <button className="btn ghost" disabled={extractText.length < 10} onClick={() => client.extractCommitments(customer.id, extractText).then(r => { setExtracted(r); load(); }).catch(setErr)}>Extract drafts</button>
          {extracted && <div className="muted small">Created {extracted.created?.length ?? extracted.length ?? 0} draft(s). Confirm each one above.</div>}
        </details>
      </section>

      <section className="grid-2" style={{ marginTop: 16 }}>
        <div className="card">
          <h3 style={{ marginTop: 0 }}>Record an outcome</h3>
          <p className="muted small">Business outcomes are separate from delivery. A delivered text is not a resolved commitment.</p>
          <select aria-label="Outcome" value={outcome.kind} onChange={e => setOutcome({ ...outcome, kind: e.target.value })}>{OUTCOMES.map(k => <option key={k}>{k}</option>)}</select>
          <select aria-label="Related commitment" value={outcome.commitment_id} onChange={e => setOutcome({ ...outcome, commitment_id: e.target.value })}>
            <option value="">(no commitment)</option>{commitments.map(c => <option key={c.id} value={c.id}>{c.text.slice(0, 60)}</option>)}
          </select>
          <input aria-label="Note" placeholder="Note (kept private)" value={outcome.note} onChange={e => setOutcome({ ...outcome, note: e.target.value })} />
          <button className="btn ghost" onClick={() => run(() => client.recordOutcome({ customer_id: customer.id, kind: outcome.kind, commitment_id: outcome.commitment_id || undefined, note: outcome.note }))}>Record</button>
        </div>
        <div className="card">
          <h3 style={{ marginTop: 0 }}>Timeline</h3>
          <ol className="plain timeline">
            {timeline.map((e, i) => (
              <li key={i}><span className="muted small">{fmtWhen(e.at)}</span> · <strong>{e.type}</strong> · {e.type === 'commitment' ? `${e.data.kind}: ${e.data.text} (${e.data.status})` : `${e.data.kind}${e.data.note ? ` — ${e.data.note}` : ''}`}</li>
            ))}
            {timeline.length === 0 && <li className="muted">Nothing yet.</li>}
          </ol>
        </div>
      </section>
      {draft && <DraftEditor customerName={customer.name} initial={draft.draft} limitation={draft.limitation} neutralText={draft.neutral} onClose={() => { setDraft(null); load(); }} />}
    </div>
  );
}
