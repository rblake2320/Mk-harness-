import { useEffect, useState } from 'react';
import { client } from '../App.tsx';
import type { PendingApproval } from '../../../packages/sdk/src/index.ts';
import { ErrorNote, HumanSteps, StateBadge, fmtWhen } from '../components/Common.tsx';

/**
 * Approval screen (rows H1, H4, W5).
 *  - Shows destination (masked), customer, sending business + number, the EXACT text,
 *    purpose, supporting commitment/request, permission state, scheduled time, expiry.
 *  - One explicit gesture per message: a dedicated button per item, never pre-selected,
 *    no "approve all", no standing approval. Each press runs a fresh passkey ceremony
 *    over a challenge bound to this message's digest.
 *  - The digest is displayed; the kernel refuses if it differs from what you saw.
 */
export default function ApprovalsView() {
  const [items, setItems] = useState<PendingApproval[]>([]);
  const [err, setErr] = useState<unknown>(null);
  const [busy, setBusy] = useState('');
  const [done, setDone] = useState<Record<string, string>>({});
  const [reason, setReason] = useState<Record<string, string>>({});

  function load() { setErr(null); client.pendingApprovals().then(setItems).catch(setErr); }
  useEffect(load, []);

  async function approve(it: PendingApproval) {
    setBusy(it.action_id); setErr(null);
    try {
      const r = await client.approveWithPasskey(it.action_id, it.action_digest, reason[it.action_id] || undefined);
      setDone(d => ({ ...d, [it.action_id]: `Approved — now ${r.result?.message_state ?? r.result?.state}. Approval is single-use and expires ${fmtWhen(r.approval?.expires_at)}.` }));
      load();
    } catch (e) { setErr(e); } finally { setBusy(''); }
  }

  async function reject(it: PendingApproval) {
    setBusy(it.action_id); setErr(null);
    try { await client.reject(it.action_id, it.action_digest, reason[it.action_id] || 'rejected by approver'); setDone(d => ({ ...d, [it.action_id]: 'Rejected. Nothing will be sent.' })); load(); }
    catch (e) { setErr(e); } finally { setBusy(''); }
  }

  return (
    <div>
      <h1 style={{ marginTop: 0 }}>Approvals</h1>
      <p className="muted">Each message needs its own approval with your passkey. There is no "approve all" and no standing approval for future AI messages.</p>
      <HumanSteps steps={[
        'Read the exact text. What you approve is exactly what is sent — one byte different and the approval is void.',
        'Your passkey signs a challenge tied to this message. Approvals are single-use and expire under the tenant policy shown on each item.',
        'The kernel re-checks consent, suppression, contact hours and the kill switch when it sends.',
      ]} />
      <ErrorNote error={err} onDismiss={() => setErr(null)} />
      {Object.entries(done).map(([id, message]) => <div key={id} className="ok-note" role="status">{message}</div>)}
      {items.length === 0 && <div className="card">Nothing waiting for approval.</div>}
      <ul className="approval-list" aria-label="Pending approvals">
        {items.map(it => (
          <li key={it.action_id} className="card approval">
            <div className="row" style={{ justifyContent: 'space-between' }}>
              <div><StateBadge state={it.message_state ?? it.state} /> <span className="muted small">action expires {fmtWhen(it.approval_expires_at)}</span></div>
              <span className="muted small">digest {it.action_digest?.slice(7, 23)}…</span>
            </div>
            <dl className="facts">
              <dt>To</dt><dd>{it.customer?.name ?? 'Unknown customer'} · {it.destination_masked} ({it.channel})</dd>
              <dt>From</dt><dd>{it.sending_business ? `${it.sending_business.display_name} · ${it.sending_business.from_number} (${it.sending_business.registration_status})` : 'No registered sending number'}</dd>
              <dt>Purpose</dt><dd>{it.purpose} · {it.workflow} · risk {it.risk}</dd>
              <dt>Because</dt><dd>{it.supporting.commitment ? <>“{it.supporting.commitment.text}” <span className="muted small">({it.supporting.commitment.status}, evidence {it.supporting.commitment.evidence_digest?.slice(7, 19)}…)</span></> : <span className="muted">No supporting commitment — review carefully.</span>}</dd>
              <dt>Permission</dt><dd>{it.permission ? <>{it.permission.state} (checked {fmtWhen(it.permission.checked_at)}) — {it.permission.note}</> : <span className="muted">not recorded on this item; the kernel checks at send time</span>}</dd>
              <dt>When</dt><dd>{it.scheduled_for ? fmtWhen(it.scheduled_for) : 'As soon as policy allows (inside the customer’s contact hours)'}</dd>
              <dt>Approval policy</dt><dd>{it.approval_lifetime_minutes} minute lifetime. {it.self_approval
                ? (it.can_approve ? 'You may approve your own proposal with your passkey.' : 'A different authorized person must approve this proposal.')
                : (it.can_approve ? 'You may review and approve this proposal.' : 'You are not authorized to approve this proposal.')}</dd>
            </dl>
            <blockquote className="exact-text" aria-label="Exact message text">{it.exact_text}</blockquote>
            {!it.sending_business && <p role="status">Selected sender details are unavailable. Refresh after your administrator restores the sender configuration; approval is disabled.</p>}
            {!done[it.action_id] && (
              <>
                <label className="muted small" htmlFor={`reason-${it.action_id}`}>Note (optional)</label>
                <input id={`reason-${it.action_id}`} value={reason[it.action_id] ?? ''} onChange={e => setReason(r => ({ ...r, [it.action_id]: e.target.value }))} />
                <div className="row" style={{ marginTop: 10 }}>
                  <button className="btn" disabled={Boolean(busy) || !it.can_approve || !it.sending_business} onClick={() => approve(it)}
                          aria-describedby={`approve-help-${it.action_id}`}>Approve this message with passkey</button>
                  <button className="btn ghost" disabled={Boolean(busy) || !it.can_approve} onClick={() => reject(it)}>Reject</button>
                  <span id={`approve-help-${it.action_id}`} className="muted small">Your device will ask for your passkey.</span>
                </div>
              </>
            )}
          </li>
        ))}
      </ul>
    </div>
  );
}
