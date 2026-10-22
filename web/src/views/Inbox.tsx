import { useEffect, useState } from 'react';
import { client } from '../App.tsx';
import type { DeliveryException, ExceptionItem, SubmissionResolution } from '../../../packages/sdk/src/index.ts';
import { ErrorNote, HumanSteps, StateBadge, fmtWhen } from '../components/Common.tsx';

const KIND_LABEL: Record<string, string> = {
  product_concern: 'Product or skin concern — sales follow-up stopped', complaint: 'Complaint', wrong_number: 'Wrong number — follow-up stopped',
  identity_ambiguity: 'Could not tell which customer this is', delivery_uncertain: 'Delivery uncertain', missing_permission: 'Missing permission',
  ambiguous_reply: 'Ambiguous reply', ambiguous_opt_out: 'Possible opt-out — on hold until you decide', draft_review: 'Draft needs review',
};

/** Conversation inbox + exception queue (C7). Inbound messages are received and
 *  classified by the kernel/application; here a person processes and resolves. */
export default function InboxView({ onOpenCustomer }: { onOpenCustomer: (id: string) => void }) {
  const [exceptions, setExceptions] = useState<ExceptionItem[]>([]);
  const [state, setState] = useState<'open' | 'resolved' | 'dismissed'>('open');
  const [err, setErr] = useState<unknown>(null);
  const [last, setLast] = useState<any>(null);
  const [health, setHealth] = useState<any>(null);
  const [busy, setBusy] = useState(false);
  const [deliveries, setDeliveries] = useState<DeliveryException[]>([]);
  const [deliveryCursor, setDeliveryCursor] = useState<string | null>(null);
  const [deliveryError, setDeliveryError] = useState<unknown>(null);
  const [deliveryLoaded, setDeliveryLoaded] = useState(false);
  const [deliveryBusy, setDeliveryBusy] = useState(false);
  const [resolving, setResolving] = useState<string | null>(null);
  const [resolutionNote, setResolutionNote] = useState('');
  const [resolutionError, setResolutionError] = useState<unknown>(null);

  async function resolveDelivery(item: DeliveryException, decision: SubmissionResolution) {
    setResolving(item.delivery_id); setResolutionError(null); setResolutionNote('');
    try {
      await client.resolveSubmissionWithPasskey(item, decision);
      setResolutionNote('Resolution recorded. No message was sent. Any further send requires a fresh review and approval.');
      await loadDeliveries();
    } catch (e) { setResolutionError(e); } finally { setResolving(null); }
  }

  async function loadDeliveries(after?: string) {
    setDeliveryBusy(true);
    try {
      const result = await client.deliveryExceptions(after);
      setDeliveries(old => after ? [...new Map([...old, ...result.items].map(x => [x.delivery_id, x])).values()] : result.items);
      setDeliveryCursor(result.next_cursor); setDeliveryError(null); setDeliveryLoaded(true);
    } catch (e) { setDeliveryError(e); } finally { setDeliveryBusy(false); }
  }
  useEffect(() => {
    void loadDeliveries();
    const timer = window.setInterval(() => { void loadDeliveries(); }, 30000);
    return () => window.clearInterval(timer);
  }, []);

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
          Inbound path: {health.dispatch_blocked ? <strong>sending paused ({health.dispatch_blocked})</strong> : <strong>healthy</strong>} · {health.pending_events} unprocessed
          {health.health?.last_ok_at && <> · last check {fmtWhen(health.health.last_ok_at)}</>}
        </div>
      )}
      <HumanSteps steps={[
        'Possible opt-outs are held, not cleared: decide, and if the customer meant stop, record it permanently.',
        'Product or skin concerns stop sales follow-up until you resolve the exception.',
        'Replies that could not be matched to one customer need you to identify the person.',
      ]} />
      <ErrorNote error={err} onDismiss={() => setErr(null)} />
      <section aria-label="Uncertain deliveries">
        <div className="row">
          <h2>Uncertain deliveries</h2>
          <button className="btn ghost small" disabled={deliveryBusy} onClick={() => void loadDeliveries()}>Refresh delivery evidence</button>
        </div>
        <p className="small">Do not send a replacement while submission is uncertain. Provider checks run automatically;
          a missing receipt is not a failure. Contact your operator to resolve an unknown attempt.</p>
        <ErrorNote error={deliveryError} />
        <ErrorNote error={resolutionError} onDismiss={() => setResolutionError(null)} />
        {resolutionNote && <p role="status">{resolutionNote}</p>}
        {deliveryError != null && <p role="status">Current delivery evidence could not be refreshed. Existing entries may be stale.</p>}
        {deliveryLoaded && !deliveryError && deliveries.length === 0 && <p>No uncertain deliveries in this page.</p>}
        <ul className="plain">
          {deliveries.map(item => (
            <li key={item.delivery_id} className="card exception">
              <div className="row"><strong>{item.customer_name ?? 'Message attempt'}</strong><StateBadge state={item.message_state} /></div>
              <p className="small">Provider evidence: {item.delivery_state.replace(/_/g, ' ')}. Read status: {item.read_status}.</p>
              <div className="small wrap">Action reference: {item.action_id}</div>
              {item.provider_message_id && <div className="small wrap">Provider reference: {item.provider_message_id}</div>}
              <div className="muted small">Submission started {fmtWhen(item.created_at)}{item.reconciled_at && <> · provider checked {fmtWhen(item.reconciled_at)}</>}</div>
              <p className="limitation small">Replacement sending is not authorized by this screen. This exception cannot be dismissed as delivered.</p>
              {(item.resolution_options ?? []).length > 0 && <p className="small">Resolve only the provider evidence shown here. Previously queued approvals will not resume; any further send needs a fresh review and approval.</p>}
              {(item.resolution_options ?? []).map(decision => (
                <button key={decision} className="btn ghost small" disabled={resolving !== null || deliveryBusy || deliveryError != null}
                  onClick={() => void resolveDelivery(item, decision)}>
                  {resolving === item.delivery_id ? 'Waiting for passkey…' : decision === 'closed_no_replacement'
                    ? 'Resolve without replacement with passkey' : 'Permit a newly approved replacement with passkey'}
                </button>
              ))}
              {item.customer_id && <button className="link" onClick={() => onOpenCustomer(item.customer_id!)}>Open customer</button>}
            </li>
          ))}
        </ul>
        {deliveryCursor && <button className="btn ghost" disabled={deliveryBusy} onClick={() => void loadDeliveries(deliveryCursor)}>More uncertain deliveries</button>}
      </section>
      {last && (
        <div className="ok-note" role="status">
          Processed {last.processed} new repl{last.processed === 1 ? 'y' : 'ies'}.
          {last.events?.length > 0 && <ul className="plain small">{last.events.map((e: any) => <li key={e.event_id}>{e.class.replace('_', ' ')}{e.customer_id ? '' : ' (no single customer match)'}{e.created?.length ? ` → ${e.created.join(', ')}` : ''}{e.hold === 201 ? ' · follow-up held' : ''}</li>)}</ul>}
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
              <strong>{KIND_LABEL[x.kind] ?? x.kind}</strong>
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
