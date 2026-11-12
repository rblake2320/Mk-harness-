import { useCallback, useEffect, useState } from 'react';
import { Text } from 'react-native';
import { exceptionKindLabel, inboundBlockLabel } from '../../../packages/sdk/src/index';
import type { ExceptionItem, InboundHealth, InboundProcessResult } from '../../../packages/sdk/src/index';
import { client } from '../api';
import { Button, Card, Choices, ErrorNote, H1, HumanSteps, LinkButton, Loading, Notice, P, Row, Screen, s } from '../components/ui';
import { fmtWhen } from '../logic/format';
import type { Route } from '../logic/navigation';

type State = 'open' | 'resolved' | 'dismissed';
const STATES: readonly { id: State; label: string }[] = [{ id: 'open', label: 'Open' }, { id: 'resolved', label: 'Resolved' }, { id: 'dismissed', label: 'Dismissed' }];

/** Conversation inbox + exception queue (C7). Replies are received and checked for
 *  opt-outs by the kernel before anyone sees them; processing never sends anything. */
export default function InboxScreen({ push }: { push: (r: Route) => void }) {
  const [state, setState] = useState<State>('open');
  const [items, setItems] = useState<ExceptionItem[] | null>(null);
  const [health, setHealth] = useState<InboundHealth | null>(null);
  const [last, setLast] = useState<InboundProcessResult | null>(null);
  const [err, setErr] = useState<unknown>(null);
  const [busy, setBusy] = useState('');
  const [refreshing, setRefreshing] = useState(false);

  const load = useCallback(async () => {
    setErr(null);
    client.inboundHealth().then(setHealth).catch(() => setHealth(null));
    try { setItems(await client.listExceptions(state)); } catch (e) { setErr(e); setItems(i => i ?? []); }
  }, [state]);
  useEffect(() => { setItems(null); load(); }, [load]);

  async function process() {
    setBusy('process'); setErr(null);
    try { setLast(await client.processInbound()); await load(); } catch (e) { setErr(e); } finally { setBusy(''); }
  }

  async function close(x: ExceptionItem, resolution: 'resolved' | 'dismissed') {
    setBusy(x.id); setErr(null);
    try { await client.resolveException(x.id, resolution); await load(); } catch (e) { setErr(e); } finally { setBusy(''); }
  }

  const block = health ? inboundBlockLabel(health.dispatch_blocked) : null;
  return (
    <Screen refreshing={refreshing} onRefresh={async () => { setRefreshing(true); await load(); setRefreshing(false); }}>
      <H1>Inbox & exceptions</H1>
      <P muted>Customer replies are received and checked for opt-outs before anyone sees them. Processing turns the rest into commitments, exceptions and outcomes — it never sends anything.</P>
      {health && (
        <Notice tone={block ? 'warn' : 'info'}>
          {`Reply path: ${block ? `sending paused — ${block}` : 'healthy'} · ${health.pending_events} unprocessed${health.health?.last_ok_at ? ` · last check ${fmtWhen(health.health.last_ok_at)}` : ''}`}
        </Notice>
      )}
      <Button label="Process new replies" busy={busy === 'process'} onPress={process} />
      <HumanSteps steps={[
        'Possible opt-outs are held, not cleared: decide, and if the customer meant stop, use "Mark do not contact" on their page.',
        'Product or skin concerns stop sales follow-up until you resolve the exception.',
        'Replies that could not be matched to one customer need you to identify the person.',
      ]} />
      <ErrorNote error={err} onDismiss={() => setErr(null)} />
      {last && (
        <Notice tone="ok">
          <Text style={s.p}>Processed {last.processed} new repl{last.processed === 1 ? 'y' : 'ies'}.</Text>
          {last.events.map(e => (
            <Text key={e.event_id} style={[s.p, s.small]}>
              • {e.class.replace(/_/g, ' ')}{e.customer_id ? '' : ' (no single customer match)'}{e.created?.length ? ` → ${e.created.join(', ')}` : ''}{e.hold === 201 ? ' · follow-up held' : ''}{e.retry ? ' · will be retried' : ''}
            </Text>
          ))}
        </Notice>
      )}
      <Choices label="Exception state" role="tab" options={STATES} value={state} onChange={setState} />
      {items === null && <Loading label="Loading exceptions" />}
      {items !== null && items.length === 0 && <Notice tone="info">{`No ${state} exceptions.`}</Notice>}
      {(items ?? []).map(x => (
        <Card key={x.id}>
          <Text style={s.noteTitle}>{exceptionKindLabel(x.kind)}</Text>
          <Text style={[s.small, s.muted]}>{fmtWhen(x.created_at)}{x.resolved_at ? ` · closed ${fmtWhen(x.resolved_at)}` : ''}</Text>
          {!!x.detail && <P>{x.detail}</P>}
          <Row>
            {x.customer_id && <LinkButton label="Open the customer for this exception" text="Open customer"
                                          onPress={() => push({ name: 'customer', customerId: x.customer_id!, customerName: '' })} />}
            {x.state === 'open' && (
              <>
                <Button kind="ghost" label="Mark this exception resolved" text="Resolved" disabled={busy === x.id} onPress={() => close(x, 'resolved')} />
                <Button kind="ghost" label="Dismiss this exception" text="Dismiss" disabled={busy === x.id} onPress={() => close(x, 'dismissed')} />
              </>
            )}
          </Row>
        </Card>
      ))}
    </Screen>
  );
}
