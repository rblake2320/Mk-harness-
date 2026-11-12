import { useCallback, useEffect, useState } from 'react';
import { Text, View } from 'react-native';
import { localDay, shiftDay } from '../../../packages/sdk/src/index';
import type { BriefItem } from '../../../packages/sdk/src/index';
import { client } from '../api';
import { AiBadge, Button, Card, ErrorNote, H1, H2, HumanSteps, LinkButton, Loading, Notice, P, Row, Screen, s } from '../components/ui';
import { briefItemTag, canDraft, groupBrief, permissionLine } from '../logic/brief';
import { fmtWhen } from '../logic/format';
import type { Route } from '../logic/navigation';

/** Daily brief (W2/W3): server-ranked items grouped by category, each with its source,
 *  permission observation and the next step. Nothing here sends anything. */
export default function BriefScreen({ push }: { push: (r: Route) => void }) {
  const [day, setDay] = useState(() => localDay());
  const [items, setItems] = useState<BriefItem[] | null>(null);
  const [err, setErr] = useState<unknown>(null);
  const [busy, setBusy] = useState('');
  const [refreshing, setRefreshing] = useState(false);

  const load = useCallback(async () => {
    setErr(null);
    try { setItems((await client.brief(day)).items); } catch (e) { setErr(e); setItems(i => i ?? []); }
  }, [day]);
  useEffect(() => { setItems(null); load(); }, [load]);

  async function act(it: BriefItem, action: 'defer' | 'resolve' | 'skip') {
    setBusy(it.id); setErr(null);
    try {
      const body = action === 'defer' ? { relative_window: 'tomorrow' } : action === 'resolve' ? { outcome: 'resolved' } : { reason: 'skipped by consultant' };
      await client.briefItemAction(it.id, action, body);
      await load();
    } catch (e) { setErr(e); } finally { setBusy(''); }
  }

  const today = localDay();
  return (
    <Screen refreshing={refreshing} onRefresh={async () => { setRefreshing(true); await load(); setRefreshing(false); }}>
      <H1>{day === today ? "Today's brief" : `Brief for ${day}`}</H1>
      <Row>
        <Button kind="ghost" label="Previous day" text="‹ Previous" onPress={() => setDay(d => shiftDay(d, -1))} />
        {day !== today && <Button kind="ghost" label="Back to today" text="Today" onPress={() => setDay(today)} />}
        <Button kind="ghost" label="Next day" text="Next ›" onPress={() => setDay(d => shiftDay(d, 1))} />
      </Row>
      <P muted>Every item comes from a rule you can see: a promise you made, a request you haven't answered, a date the customer gave, or an exception. Nothing here is a guess about what a customer "probably needs".</P>
      <HumanSteps steps={[
        'Drafts are suggestions. You read, edit if needed, and approve each message yourself with your passkey.',
        'Permission shown here is what was last recorded; the kernel re-checks consent and suppression at send time.',
      ]} />
      <ErrorNote error={err} onDismiss={() => setErr(null)} />
      {items === null && <Loading label="Loading the brief" />}
      {items !== null && items.length === 0 && <Notice tone="info">Nothing due. Promises you confirm and customer dates appear here on their day.</Notice>}
      {items !== null && groupBrief(items).map(sec => (
        <View key={String(sec.rank)} style={{ gap: 10 }}>
          <H2>{sec.title} ({sec.items.length})</H2>
          <P muted small>{sec.description}</P>
          {sec.items.map(it => (
            <Card key={it.id}>
              <Text style={[s.small, s.muted]}>{briefItemTag(it)}{it.due_at ? ` · due ${fmtWhen(it.due_at)}` : ''}</Text>
              {it.customer
                ? <LinkButton label={`Open customer ${it.customer.name}`} text={it.customer.name}
                              onPress={() => push({ name: 'customer', customerId: it.customer!.id, customerName: it.customer!.name })} />
                : <P muted>No single customer attached</P>}
              {it.source && <P>“{it.source.text}” <Text style={[s.small, s.muted]}>— {it.source.kind.replace(/_/g, ' ')}, {it.source.status}</Text></P>}
              <P>{it.suggested_step}</P>
              <P small muted>Permission: {permissionLine(it, fmtWhen)}</P>
              <Row>
                {canDraft(it) && (
                  <Button label={`Draft a message to ${it.customer!.name}`} text="Draft a message" busy={busy === it.id}
                          onPress={() => push({ name: 'draft', customerId: it.customer!.id, customerName: it.customer!.name, briefItemId: it.id,
                            commitmentId: it.source_type === 'commitment' ? it.source_reference : undefined })} />
                )}
                <Button kind="ghost" label="Defer to tomorrow" disabled={busy === it.id} onPress={() => act(it, 'defer')} />
                <Button kind="ghost" label="Mark resolved" disabled={busy === it.id} onPress={() => act(it, 'resolve')} />
                <Button kind="ghost" label="Skip" disabled={busy === it.id} onPress={() => act(it, 'skip')} />
              </Row>
            </Card>
          ))}
        </View>
      ))}
      <Row><AiBadge /><Text style={[s.small, s.muted, { flex: 1 }]}>Drafts are AI-generated from approved product wording and your confirmed context.</Text></Row>
    </Screen>
  );
}
