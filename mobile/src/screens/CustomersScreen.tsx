import { useCallback, useEffect, useState } from 'react';
import { Text } from 'react-native';
import type { Customer } from '../../../packages/sdk/src/index';
import { client } from '../api';
import { Button, Card, ErrorNote, Field, H1, Loading, Notice, P, Screen, s } from '../components/ui';
import type { Route } from '../logic/navigation';

/** Customer list; each opens the customer page (timeline, commitments, outcomes). */
export default function CustomersScreen({ push }: { push: (r: Route) => void }) {
  const [list, setList] = useState<Customer[] | null>(null);
  const [q, setQ] = useState('');
  const [err, setErr] = useState<unknown>(null);
  const [refreshing, setRefreshing] = useState(false);

  const load = useCallback(async () => {
    setErr(null);
    try { setList(await client.listCustomers()); } catch (e) { setErr(e); setList(l => l ?? []); }
  }, []);
  useEffect(() => { load(); }, [load]);

  const needle = q.trim().toLowerCase();
  const shown = (list ?? []).filter(c => !needle || c.name.toLowerCase().includes(needle));
  return (
    <Screen refreshing={refreshing} onRefresh={async () => { setRefreshing(true); await load(); setRefreshing(false); }}>
      <H1>My customers</H1>
      <P muted small>Follow-ups come from your brief (confirmed promises, requests and customer dates) — never from guesses about purchase age. Add or edit customers on the web app.</P>
      <Field label="Find a customer" value={q} onChangeText={setQ} placeholder="Name" autoCapitalize="none" />
      <ErrorNote error={err} onDismiss={() => setErr(null)} />
      {list === null && <Loading label="Loading customers" />}
      {list !== null && shown.length === 0 && <Notice tone="info">{list.length === 0 ? 'No customers yet.' : 'No customer matches that name.'}</Notice>}
      {shown.map(c => (
        <Card key={c.id}>
          <Text style={s.noteTitle}>{c.name}</Text>
          <Text style={[s.small, s.muted]}>{c.last_contact ? `Last contact ${new Date(c.last_contact).toLocaleDateString()}` : 'No contact recorded'}</Text>
          <Button kind="ghost" label={`Open ${c.name}`} text="Open" onPress={() => push({ name: 'customer', customerId: c.id, customerName: c.name })} />
        </Card>
      ))}
    </Screen>
  );
}
