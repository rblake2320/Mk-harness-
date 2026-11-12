import { useCallback, useEffect, useState } from 'react';
import { Alert, Text, View } from 'react-native';
import {
  COMMITMENT_KINDS, OUTCOME_KINDS, OUTCOME_SEPARATION_NOTE, RELATIVE_WINDOWS, outcomeLabel,
} from '../../../packages/sdk/src/index';
import type { Commitment, CustomerDestination, PermissionView, TimelineEvent } from '../../../packages/sdk/src/index';
import { client } from '../api';
import { Button, Card, Choices, ErrorNote, Fact, Field, H1, H2, HumanSteps, Loading, Notice, P, Row, Screen, s } from '../components/ui';
import { fmtWhen } from '../logic/format';
import type { Route } from '../logic/navigation';

const TZS = ['America/New_York', 'America/Chicago', 'America/Denver', 'America/Phoenix', 'America/Los_Angeles', 'America/Anchorage', 'Pacific/Honolulu']
  .map(id => ({ id, label: id.split('/')[1].replace('_', ' ') }));

/**
 * Customer page: contact details and preferences, permission and suppression (read-only
 * here — recording or revoking consent needs evidence and is done on the web app),
 * commitments, outcome recording and the timeline.
 */
export default function CustomerDetailScreen({ customerId, customerName, push }: { customerId: string; customerName: string; push: (r: Route) => void }) {
  const [name, setName] = useState(customerName);
  const [timeline, setTimeline] = useState<TimelineEvent[] | null>(null);
  const [commitments, setCommitments] = useState<Commitment[]>([]);
  const [perm, setPerm] = useState<PermissionView | null>(null);
  const [dests, setDests] = useState<CustomerDestination[]>([]);
  const [err, setErr] = useState<unknown>(null);
  const [msg, setMsg] = useState('');
  const [busy, setBusy] = useState('');
  const [tz, setTz] = useState<string | null>(null);
  const [savedTz, setSavedTz] = useState<string | null>(null);
  const [newKind, setNewKind] = useState('promise');
  const [newText, setNewText] = useState('');
  const [newWindow, setNewWindow] = useState('this_week');
  const [outKind, setOutKind] = useState('resolved');
  const [outCommitment, setOutCommitment] = useState<string>('none');
  const [outNote, setOutNote] = useState('');
  const [refreshing, setRefreshing] = useState(false);

  const load = useCallback(async () => {
    setErr(null);
    try {
      const [t, c, p, d] = await Promise.all([client.customerTimeline(customerId), client.listCommitments(customerId),
        client.customerPermissions(customerId), client.customerDestinations(customerId)]);
      setTimeline(t); setCommitments(c); setPerm(p); setDests(d);
    } catch (e) { setErr(e); setTimeline(x => x ?? []); }
  }, [customerId]);
  useEffect(() => { load(); }, [load]);
  useEffect(() => {
    if (name) return;
    client.listCustomers().then(l => setName(l.find(c => c.id === customerId)?.name ?? 'Customer')).catch(() => setName('Customer'));
  }, [customerId, name]);

  async function run(key: string, fn: () => Promise<unknown>, ok: string) {
    setBusy(key); setErr(null); setMsg('');
    try { await fn(); setMsg(ok); await load(); } catch (e) { setErr(e); } finally { setBusy(''); }
  }

  function confirmStop(d: CustomerDestination) {
    Alert.alert('Never message this number?', `${d.value_masked} will be permanently marked do not contact. This cannot be undone from the app.`, [
      { text: 'Keep', style: 'cancel' },
      { text: 'Mark do not contact', style: 'destructive', onPress: () => {
        void run(`stop:${d.id}`, () => client.suppress({ destination_id: d.id, reason: 'customer asked not to be contacted', source: 'consultant', permanent: true }),
          `${d.value_masked} is marked do not contact.`);
      } },
    ]);
  }

  const openCommitments = commitments.filter(c => c.status !== 'resolved' && c.status !== 'cancelled');
  return (
    <Screen refreshing={refreshing} onRefresh={async () => { setRefreshing(true); await load(); setRefreshing(false); }}>
      <H1>{name || 'Customer'}</H1>
      <ErrorNote error={err} onDismiss={() => setErr(null)} />
      {!!msg && <Notice tone="ok">{msg}</Notice>}
      {timeline === null && <Loading label="Loading the customer" />}

      <H2>Permission & suppression</H2>
      <Card>
        <P small muted>{perm?.note ?? 'Historical observation; the kernel re-checks at send time.'}</P>
        {perm && perm.suppressions.length > 0 && (
          <Notice>
            <Text style={s.noteTitle}>Do not contact.</Text>
            {perm.suppressions.map(x => <P key={x.id} small>{`${x.channel}: ${x.reason} (${x.source}, ${fmtWhen(x.created_at)})`}</P>)}
            <P small>Suppression is never cleared by a reply. Re-consent needs fresh, purpose-specific evidence.</P>
          </Notice>
        )}
        {(perm?.consent_events ?? []).map(e => (
          <Fact key={e.id} label={`Consent · ${e.channel}`}
                value={`${e.status} · ${e.purposes.join(', ')} · from ${e.source} · ${fmtWhen(e.effective_at)} → ${fmtWhen(e.expires_at)}${e.revoked_at ? ` · revoked ${fmtWhen(e.revoked_at)}` : ''}`} />
        ))}
        {perm && perm.consent_events.length === 0 && <P muted small>No consent recorded. An imported number is not permission.</P>}
        <P small muted>Recording or revoking consent needs the customer's actual words as evidence; do it on the web app.</P>
      </Card>

      <H2>Contact details</H2>
      <Card>
        {dests.map(d => (
          <View key={d.id} style={{ gap: 4 }}>
            <Fact label={d.channel === 'sms' ? 'Mobile number' : 'Email'}
                  value={`${d.value_masked}${d.is_primary ? ' · primary' : ''}${d.suppressed ? ' · do not contact' : ''}`} />
            {!d.suppressed && <Button kind="danger" label={`Mark ${d.value_masked} do not contact`} text="Mark do not contact" disabled={!!busy}
                                      onPress={() => confirmStop(d)} />}
          </View>
        ))}
        <P small muted>Use "Mark do not contact" when a customer asks you to stop. It is permanent, revokes consent for that number and is enforced by the kernel. A STOP reply is suppressed automatically.</P>
        {dests.length === 0 && <P muted small>No destination on file. Add a mobile number on the web app before proposing messages.</P>}
        <Text style={[s.small, s.muted]}>Timezone (required before any message can be proposed){savedTz ? ` — saved: ${savedTz}` : ''}</Text>
        <Choices label="Customer timezone" options={TZS} value={tz} onChange={setTz} />
        <Button kind="ghost" label="Save timezone" disabled={!tz} busy={busy === 'tz'}
                onPress={() => run('tz', async () => { const r = await client.setPreferences(customerId, { timezone: tz! }); setSavedTz(r.timezone); }, 'Timezone saved.')} />
        <P small muted>The API does not return the current timezone, so it is shown only after you save it here.</P>
      </Card>

      <H2>Commitments</H2>
      <HumanSteps steps={['AI-extracted commitments are drafts until you confirm the date or window. Nothing is scheduled from a draft.']} />
      {commitments.map(c => (
        <Card key={c.id}>
          <Text style={s.noteTitle}>{COMMITMENT_KINDS.find(k => k.id === c.kind)?.label ?? c.kind} · {c.status}</Text>
          <P>{c.text}</P>
          <Text style={[s.small, s.muted]}>
            {c.due_at ? `due ${fmtWhen(c.due_at)}` : c.due_window[0] ? `window ${fmtWhen(c.due_window[0])} – ${fmtWhen(c.due_window[1])}` : 'no date'} · {c.timezone} · {c.confirmed_by ? 'confirmed' : 'not confirmed'}
          </Text>
          <Row>
            {(c.status === 'draft' || c.status === 'deferred') && (
              <>
                <Button kind="ghost" label={`Confirm for this week: ${c.text}`} text="Confirm this week" disabled={!!busy}
                        onPress={() => run(c.id, () => client.confirmCommitment(c.id, { relative_window: 'this_week' }), 'Commitment confirmed.')} />
                <Button kind="ghost" label={`Confirm for next week: ${c.text}`} text="Confirm next week" disabled={!!busy}
                        onPress={() => run(c.id, () => client.confirmCommitment(c.id, { relative_window: 'next_week' }), 'Commitment confirmed.')} />
              </>
            )}
            {c.status === 'confirmed' && <Button kind="ghost" label={`Defer to next week: ${c.text}`} text="Defer" disabled={!!busy}
                                                 onPress={() => run(c.id, () => client.deferCommitment(c.id, { relative_window: 'next_week', reason: 'consultant' }), 'Commitment deferred.')} />}
            {c.status !== 'cancelled' && c.status !== 'resolved' && <Button kind="ghost" label={`Cancel commitment: ${c.text}`} text="Cancel" disabled={!!busy}
                                                 onPress={() => run(c.id, () => client.cancelCommitment(c.id, 'consultant'), 'Commitment cancelled.')} />}
            {c.status === 'confirmed' && <Button label={`Draft a message about: ${c.text}`} text="Draft message"
                                                 onPress={() => push({ name: 'draft', customerId, customerName: name, commitmentId: c.id })} />}
          </Row>
        </Card>
      ))}
      {commitments.length === 0 && timeline !== null && <P muted small>No commitments yet.</P>}
      <Card label="Add a commitment">
        <Text style={s.noteTitle}>Add a commitment</Text>
        <Choices label="Commitment kind" options={COMMITMENT_KINDS} value={newKind} onChange={setNewKind} />
        <Field label="What did you promise, or what did they ask?" value={newText} onChangeText={setNewText} multiline maxLength={500} />
        <Choices label="When" options={RELATIVE_WINDOWS} value={newWindow} onChange={setNewWindow} />
        <Button kind="ghost" label="Add commitment" disabled={newText.trim().length < 3} busy={busy === 'add'}
                onPress={() => run('add', async () => {
                  await client.createCommitment({ customer_id: customerId, kind: newKind, text: newText.trim(), relative_window: newWindow, source_type: 'consultant_note', evidence_text: newText.trim() });
                  setNewText('');
                }, 'Commitment added as a draft. Confirm it above.')} />
      </Card>

      <H2>Record an outcome</H2>
      <Card>
        <P small muted>{OUTCOME_SEPARATION_NOTE}</P>
        <Choices label="Outcome" options={OUTCOME_KINDS} value={outKind} onChange={setOutKind} />
        {!!OUTCOME_KINDS.find(k => k.id === outKind)?.note && <P small muted>{OUTCOME_KINDS.find(k => k.id === outKind)!.note}</P>}
        <Choices label="Related commitment" value={outCommitment} onChange={setOutCommitment}
                 options={[{ id: 'none', label: 'No commitment' }, ...openCommitments.map(c => ({ id: c.id, label: c.text.slice(0, 40) }))]} />
        <Field label="Note (kept private)" value={outNote} onChangeText={setOutNote} multiline maxLength={2000} />
        <Button label="Record outcome" busy={busy === 'outcome'}
                onPress={() => run('outcome', async () => {
                  await client.recordOutcome({ customer_id: customerId, kind: outKind, commitment_id: outCommitment === 'none' ? undefined : outCommitment, note: outNote });
                  setOutNote('');
                }, `Outcome recorded: ${outcomeLabel(outKind)}.`)} />
      </Card>

      <H2>Timeline</H2>
      <View style={{ gap: 6 }}>
        {(timeline ?? []).map((e, i) => (
          <Fact key={i} label={fmtWhen(e.at)}
                value={e.type === 'commitment' ? `Commitment · ${e.data.kind.replace(/_/g, ' ')}: ${e.data.text} (${e.data.status})` : `Outcome · ${outcomeLabel(e.data.kind)}${e.data.note ? ` — ${e.data.note}` : ''}`} />
        ))}
        {timeline !== null && timeline.length === 0 && <P muted small>Nothing yet.</P>}
      </View>
    </Screen>
  );
}
