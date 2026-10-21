import { useEffect, useState } from 'react';
import { client } from '../App.tsx';
import type { BriefItem, Draft } from '../../../packages/sdk/src/index.ts';
import { ErrorNote, HumanSteps, fmtWhen } from '../components/Common.tsx';
import { AiBadge } from '../components/AiDisclosure.tsx';
import DraftEditor from './DraftEditor.tsx';

const RULE_LABEL: Record<string, string> = {
  exception: 'Needs attention', overdue: 'Overdue promise', due_today: 'Due today',
  unanswered: 'Unanswered request', future: 'Coming up', customer_date: 'Customer date',
};

export default function BriefView({ onOpenCustomer }: { onOpenCustomer: (id: string) => void }) {
  const [items, setItems] = useState<BriefItem[]>([]);
  const [date, setDate] = useState<string>(new Date().toISOString().slice(0, 10));
  const [err, setErr] = useState<unknown>(null);
  const [busy, setBusy] = useState('');
  const [draftFor, setDraftFor] = useState<{ item: BriefItem; draft: Draft | null; limitation: string | null; neutral?: string } | null>(null);

  function load() {
    setErr(null);
    client.brief(date).then(b => setItems(b.items)).catch(setErr);
  }
  useEffect(load, [date]);

  async function act(it: BriefItem, action: 'defer' | 'resolve' | 'skip') {
    setBusy(it.id); setErr(null);
    try {
      const body = action === 'defer' ? { relative_window: 'tomorrow' } : action === 'resolve' ? { outcome: 'resolved' } : { reason: 'skipped by consultant' };
      await client.briefItemAction(it.id, action, body); load();
    } catch (e) { setErr(e); } finally { setBusy(''); }
  }

  async function draft(it: BriefItem) {
    if (!it.customer) return;
    setBusy(it.id); setErr(null);
    try {
      const r = await client.generateDraft({ customer_id: it.customer.id, brief_item_id: it.id,
        commitment_id: it.source_type === 'commitment' ? it.source_reference : undefined });
      setDraftFor({ item: it, draft: r.draft, limitation: r.limitation, neutral: r.neutral_text });
    } catch (e) { setErr(e); } finally { setBusy(''); }
  }

  return (
    <div>
      <div className="row" style={{ justifyContent: 'space-between' }}>
        <h1 style={{ margin: 0 }}>Today's brief</h1>
        <label className="row">
          <span className="muted">Day</span>
          <input type="date" value={date} onChange={e => setDate(e.target.value)} aria-label="Brief date" style={{ width: 'auto' }} />
        </label>
      </div>
      <p className="muted">
        Every item comes from a rule you can see: a promise you made, a request you haven't answered, a date the customer
        gave, or an exception. Nothing here is a guess about what a customer "probably needs".
      </p>
      <HumanSteps steps={[
        'Drafts are suggestions. You read, edit if needed, and approve each message yourself with your passkey.',
        'Permission shown here is what was last recorded; the kernel re-checks consent and suppression at send time.',
      ]} />
      <ErrorNote error={err} onDismiss={() => setErr(null)} />
      {items.length === 0 && <div className="card" style={{ marginTop: 16 }}>Nothing due. Promises you confirm and customer dates will appear here on their day.</div>}
      <ol className="brief-list" aria-label="Brief items">
        {items.map(it => (
          <li key={it.id} className="card brief-item">
            <div className="row" style={{ justifyContent: 'space-between' }}>
              <div>
                <span className={`tag rank-${it.rank_category}`}>{RULE_LABEL[it.rule] ?? it.rule}</span>
                {it.customer && <button className="link" onClick={() => onOpenCustomer(it.customer!.id)}>{it.customer.name}</button>}
              </div>
              <span className="muted small">{it.due_at ? `due ${fmtWhen(it.due_at)}` : ''}</span>
            </div>
            {it.source && <p className="quote">“{it.source.text}” <span className="muted small">— {it.source.kind.replace('_', ' ')}, {it.source.status}</span></p>}
            <p style={{ margin: '6px 0' }}>{it.suggested_step}</p>
            <div className="muted small">
              Permission: <strong>{it.permission_state}</strong> (checked {fmtWhen(it.permission_checked_at)}) — {it.permission_note}
            </div>
            <div className="row" style={{ marginTop: 10 }}>
              {it.customer && it.permission_state === 'active' && (
                <button className="btn" disabled={busy === it.id} onClick={() => draft(it)}>Draft a message</button>
              )}
              <button className="btn ghost" disabled={busy === it.id} onClick={() => act(it, 'defer')}>Defer to tomorrow</button>
              <button className="btn ghost" disabled={busy === it.id} onClick={() => act(it, 'resolve')}>Mark resolved</button>
              <button className="btn ghost" disabled={busy === it.id} onClick={() => act(it, 'skip')}>Skip</button>
            </div>
          </li>
        ))}
      </ol>
      {draftFor && (
        <DraftEditor
          customerName={draftFor.item.customer?.name ?? ''}
          initial={draftFor.draft}
          limitation={draftFor.limitation}
          neutralText={draftFor.neutral}
          onClose={() => { setDraftFor(null); load(); }}
        />
      )}
      <p className="muted small" style={{ marginTop: 24 }}><AiBadge /> Drafts are AI-generated from approved product wording and your confirmed context.</p>
    </div>
  );
}
