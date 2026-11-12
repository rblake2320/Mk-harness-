import { useEffect, useState } from 'react';
import { client } from '../App.tsx';
import {
  ApiError, SELF_APPROVAL_NOTE, approvalView, buildApprovalReturnUrl, hiddenCharacterWarning, segmentText,
} from '../../../packages/sdk/src/index.ts';
import type { DecisionResponse, PendingApproval } from '../../../packages/sdk/src/index.ts';
import { ErrorNote, HumanSteps, StateBadge, fmtWhen } from '../components/Common.tsx';

/**
 * Approval screen (rows H1, H2, H4, H8; mobile hand-off for H6).
 *  - H1: every field from the shared SDK `approvalView`, identical on mobile.
 *  - H4: one explicit gesture per message; never pre-selected; no approve-all; each
 *    press runs a fresh passkey ceremony over a challenge bound to this message's digest.
 *  - H2: a digest that changed (client check against the challenge, or the kernel's 409)
 *    is never offered again; the list reloads and the new version needs its own approval.
 *  - H8: the kernel decides self-approval; its 403 is shown with code and request id,
 *    and the item then says it needs a second person instead of offering approval.
 *  - Hand-off: `?view=approvals&action=<id>&return_to=consultantstudio://approvals/done`
 *    focuses one action; after a completed decision the page returns to the app with
 *    the action id only. `return_to` is accepted only on an exact allowlist match.
 */
export interface Handoff { actionId: string | null; returnTo: string | null; returnToRefused: boolean }

interface Decided { actionId: string; who: string; kind: 'approved' | 'rejected'; result: DecisionResponse['result']; expiresAt?: string; returnUrl: string | null }

function code(e: unknown) { return e instanceof ApiError ? e.code : undefined; }
/** Kernel answers meaning "the version you were shown is not the one that can be decided". */
const SUPERSEDED = new Set(['APPROVAL_DIGEST_MISMATCH', 'ILLEGAL_TRANSITION']);

export default function ApprovalsView({ handoff }: { handoff?: Handoff }) {
  const [items, setItems] = useState<PendingApproval[] | null>(null);
  const [err, setErr] = useState<unknown>(null);
  const [busy, setBusy] = useState('');
  const [decided, setDecided] = useState<Decided[]>([]);
  const [reason, setReason] = useState<Record<string, string>>({});
  /** action_id → digest that was refused as changed; that exact digest is never offered again. */
  const [stale, setStale] = useState<Record<string, string>>({});
  /** action_id → the kernel refused this approver (self-approval forbidden). */
  const [needsSecond, setNeedsSecond] = useState<Record<string, true>>({});
  const [focus, setFocus] = useState<string | null>(handoff?.actionId ?? null);
  const returnTo = focus ? handoff?.returnTo ?? null : null;

  function load() { client.pendingApprovals().then(setItems).catch(e => { setErr(e); setItems(i => i ?? []); }); }
  useEffect(load, []);

  function finish(d: Decided) {
    setDecided(list => [d, ...list.filter(x => x.actionId !== d.actionId)]);
    if (d.returnUrl) window.location.assign(d.returnUrl);
  }

  async function approve(it: PendingApproval) {
    setBusy(it.action_id); setErr(null);
    try {
      const r = await client.approveWithPasskey(it.action_id, it.action_digest, reason[it.action_id] || undefined);
      finish({ actionId: it.action_id, who: it.customer?.name ?? 'Unknown customer', kind: 'approved', result: r.result, expiresAt: r.approval?.expires_at,
        returnUrl: returnTo && it.action_id === focus ? buildApprovalReturnUrl(returnTo, it.action_id) : null });
      load();
    } catch (e) {
      setErr(e);
      const c = code(e);
      if (c && SUPERSEDED.has(c)) { setStale(s => ({ ...s, [it.action_id]: it.action_digest })); load(); }
      if (c === 'SELF_APPROVAL_FORBIDDEN' || c === 'APPROVER_NOT_AUTHORIZED') setNeedsSecond(n => ({ ...n, [it.action_id]: true }));
    } finally { setBusy(''); }
  }

  async function reject(it: PendingApproval) {
    setBusy(it.action_id); setErr(null);
    try {
      const r = await client.reject(it.action_id, it.action_digest, reason[it.action_id] || 'rejected by approver');
      finish({ actionId: it.action_id, who: it.customer?.name ?? 'Unknown customer', kind: 'rejected', result: r.result,
        returnUrl: returnTo && it.action_id === focus ? buildApprovalReturnUrl(returnTo, it.action_id) : null });
      load();
    } catch (e) {
      setErr(e);
      const c = code(e);
      if (c && SUPERSEDED.has(c)) { setStale(s => ({ ...s, [it.action_id]: it.action_digest })); load(); }
    } finally { setBusy(''); }
  }

  const shown = (items ?? []).filter(it => !focus || it.action_id === focus);
  const focusMissing = focus !== null && items !== null && shown.length === 0 && !decided.some(d => d.actionId === focus);
  const now = Date.now();

  return (
    <div>
      <h1 style={{ marginTop: 0 }}>Approvals</h1>
      <p className="muted">Each message needs its own approval with your passkey. There is no "approve all" and no standing approval for future AI messages.</p>
      {focus && (
        <div className="limitation" role="note" aria-label="Approval requested from the mobile app">
          <strong>Approving one message from the mobile app.</strong> Review it below and approve or reject it with your passkey.
          {returnTo ? ' You will be returned to the app afterwards; the app then reads the result from the server.' : ''}
          {' '}<button className="link" onClick={() => setFocus(null)}>Show all pending approvals</button>
        </div>
      )}
      {handoff?.returnToRefused && (
        <div className="limitation" role="note">The return link in this address was not recognised, so this page will not redirect anywhere. Return to the app yourself when you are done.</div>
      )}
      <HumanSteps steps={[
        'Read the exact text. What you approve is exactly what is submitted — one byte different and the approval is void.',
        'Your passkey signs a challenge tied to this message. Approvals are single-use and expire after 15 minutes.',
        'The kernel re-checks consent, suppression, contact hours and the kill switch before submitting.',
        SELF_APPROVAL_NOTE,
      ]} />
      <ErrorNote error={err} onDismiss={() => setErr(null)} />
      {decided.length > 0 && (
        <ul className="plain" aria-label="Decisions made on this page">
          {decided.map(d => (
            <li key={d.actionId} className="ok-note" role="status">
              <strong>{d.kind === 'approved' ? `You approved the message to ${d.who} with your passkey.` : `You rejected the message to ${d.who}.`}</strong>
              <div>The kernel now reports: <StateBadge state={d.result?.message_state} showDefinition /></div>
              {d.kind === 'approved' && <div className="muted small">The approval is single-use and expires {fmtWhen(d.expiresAt)}.</div>}
              {d.returnUrl && <div><a href={d.returnUrl}>Return to the app</a></div>}
            </li>
          ))}
        </ul>
      )}
      {focusMissing && (
        <div className="card" role="status">
          This message is not waiting for your approval. It may already be decided, have expired, or belong to another consultant.
          {returnTo && <div style={{ marginTop: 8 }}><a href={buildApprovalReturnUrl(returnTo, focus) ?? undefined}>Return to the app</a></div>}
        </div>
      )}
      {items !== null && items.length === 0 && !focus && <div className="card">Nothing waiting for approval.</div>}
      <ul className="approval-list" aria-label="Pending approvals">
        {shown.map(it => {
          const v = approvalView(it, { nowMs: now, formatWhen: fmtWhen });
          const hidden = hiddenCharacterWarning(v.hidden);
          const isStale = stale[it.action_id] === it.action_digest;
          const second = needsSecond[it.action_id] === true;
          const blocked = isStale ? 'This version changed after it was shown. It cannot be approved; the current version is listed separately.'
            : second ? 'Your team requires a second person to approve this message. Ask another consultant or your admin.'
            : v.approvable ? null : `This message cannot be approved here: ${v.blockedReason}`;
          return (
            <li key={`${it.action_id}:${it.action_digest}`} className="card approval" aria-label={`Message to ${it.customer?.name ?? 'unknown customer'}`}>
              <StateBadge state={it.message_state} showDefinition />
              <dl className="facts">
                {v.rows.map(r => (
                  <div key={r.key} className="fact">
                    <dt>{r.label}</dt>
                    <dd>{r.value}{r.warning && <div className="warn small">{r.warning}</div>}</dd>
                  </div>
                ))}
              </dl>
              <blockquote className="exact-text" aria-label="Exact message text">{v.exactText}</blockquote>
              <div className="muted small">{segmentText(v.segments)}</div>
              {hidden && <div className="warn" role="note">{hidden}</div>}
              {blocked ? <div className="limitation" role="note">{blocked}</div> : (
                <>
                  <label className="muted small" htmlFor={`reason-${it.action_id}`}>Note (optional)</label>
                  <input id={`reason-${it.action_id}`} value={reason[it.action_id] ?? ''} onChange={e => setReason(r => ({ ...r, [it.action_id]: e.target.value }))} />
                </>
              )}
              <div className="row" style={{ marginTop: 10 }}>
                {!blocked && (
                  <>
                    <button className="btn" disabled={busy === it.action_id} onClick={() => approve(it)}
                            aria-describedby={`approve-help-${it.action_id}`}>Approve this message with passkey</button>
                    <span id={`approve-help-${it.action_id}`} className="muted small">Your device will ask for your passkey.</span>
                  </>
                )}
                {!isStale && <button className="btn ghost" disabled={busy === it.action_id} onClick={() => reject(it)}>Reject</button>}
              </div>
            </li>
          );
        })}
      </ul>
    </div>
  );
}
