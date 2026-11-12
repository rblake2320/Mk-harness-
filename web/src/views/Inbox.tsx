import { useEffect, useState } from 'react';
import { client } from '../App.tsx';
import { exceptionKindLabel, inboundBlockLabel } from '../../../packages/sdk/src/index.ts';
import type { ExceptionItem, InboundHealth, InboundProcessResult } from '../../../packages/sdk/src/index.ts';
import { ErrorNote, HumanSteps, fmtWhen } from '../components/Common.tsx';

/** Conversation inbox + exception queue (C7). Inbound messages are received and
 *  classified by the kernel/application; here a person processes and resolves. */
export default function InboxView({ onOpenCustomer }: { onOpenCustomer: (id: string) => void }) {
  const [exceptions, setExceptions] = useState<ExceptionItem[]>([]);
  const [state, setState] = useState<'open' | 'resolved' | 'dismissed'>('open');
  const [err, setErr] = useState<unknown>(null);
  const [last, setLast] = useState<InboundProcessResult | null>(null);
  const [health, setHealth] = useState<InboundHealth | null>(null);
  const [busy, setBusy] = useState(false);

  function load() {
    setErr(null);
    client.listExceptions(state).then(setExceptions).catch(setErr);
    client.inboundHealth().then(setHealth).catch(() => setHealth(null));
  }
  useEffect(load, [state]);

  async function process() {
    setBusy(true); setErr(null);
    try { setLast(await client.processInbound()); load(); } catch (e) { setErr(e); } finally { setBusy(false); }
  }

  return (
    <div>
      <div className="row" style={{ justifyContent: 'space-between' }}>
        <h1 style={{ margin: 0 }}>Inbox & exceptions</h1>
        <button className="btn" disabled={busy} onClick={process}>Process new replies</button>
      </div>
      <p className="muted">Customer replies are received and checked for opt-outs before anyone sees them. Processing turns the rest into
        commitments, exceptions and outcomes — it never sends anything.</p>
      {health && (
        <div className={`card small ${health.dispatch_blocked ? 'limitation' : ''}`} role="status">
          Reply path: {health.dispatch_blocked ? <strong>sending paused — {inboundBlockLabel(health.dispatch_blocked)}</strong> : <strong>healthy</strong>} · {health.pending_events} unprocessed
          {health.health?.last_ok_at && <> · last check {fmtWhen(health.health.last_ok_at)}</>}
        </div>
      )}
      <HumanSteps steps={[
        'Possible opt-outs are held, not cleared: decide, and if the customer meant stop, record it permanently.',
        'Product or skin concerns stop sales follow-up until you resolve the exception.',
        'Replies that could not be matched to one customer need you to identify the person.',
      ]} />
      <ErrorNote error={err} onDismiss={() => setErr(null)} />
      {last && (
        <div className="ok-note" role="status">
          Processed {last.processed} new repl{last.processed === 1 ? 'y' : 'ies'}.
          {last.events?.length > 0 && <ul className="plain small">{last.events.map(e => <li key={e.event_id}>{e.class.replace(/_/g, ' ')}{e.customer_id ? '' : ' (no single customer match)'}{e.created?.length ? ` → ${e.created.join(', ')}` : ''}{e.hold === 201 ? ' · follow-up held' : ''}{e.retry ? ' · will be retried' : ''}</li>)}</ul>}
        </div>
      )}
      <div className="row" role="tablist" aria-label="Exception state">
        {(['open', 'resolved', 'dismissed'] as const).map(s => (
          <button key={s} role="tab" aria-selected={state === s} className={`btn ghost small ${state === s ? 'active' : ''}`} onClick={() => setState(s)}>{s}</button>
        ))}
      </div>
      <ul className="plain" aria-label="Exceptions">
        {exceptions.length === 0 && <li className="card">No {state} exceptions.</li>}
        {exceptions.map(x => (
          <li key={x.id} className="card exception">
            <div className="row" style={{ justifyContent: 'space-between' }}>
              <strong>{exceptionKindLabel(x.kind)}</strong>
              <span className="muted small">{fmtWhen(x.created_at)}</span>
            </div>
            <div className="small">{x.detail}</div>
            <div className="row" style={{ marginTop: 8 }}>
              {x.customer_id && <button className="link" onClick={() => onOpenCustomer(x.customer_id!)}>open customer</button>}
              {x.state === 'open' && (
                <>
                  <button className="btn ghost small" onClick={() => client.resolveException(x.id, 'resolved').then(load).catch(setErr)}>Resolved</button>
                  <button className="btn ghost small" onClick={() => client.resolveException(x.id, 'dismissed').then(load).catch(setErr)}>Dismiss</button>
                </>
              )}
            </div>
          </li>
        ))}
      </ul>
    </div>
  );
}
