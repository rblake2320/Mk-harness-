import { useCallback, useEffect, useState } from 'react';
import { Text } from 'react-native';
import { dispatchSummary } from '../../../packages/sdk/src/index';
import type { GovernanceStatus, InboundHealth, PasskeyInfo, SenderIdentity } from '../../../packages/sdk/src/index';
import { WEB_URL, client } from '../api';
import { Card, ErrorNote, Fact, H1, H2, Loading, Notice, P, Screen, s } from '../components/ui';

/**
 * Read-only sending status and governance (X2 "settings and sender status"): whether the
 * kernel is connected, the platform kill switch, kernel execution, the reply path, the
 * approval method, sending numbers and approval passkeys. Nothing here changes anything;
 * switches, senders and passkeys are managed on the web app.
 */
export default function StatusScreen() {
  const [status, setStatus] = useState<GovernanceStatus | null>(null);
  const [health, setHealth] = useState<InboundHealth | null>(null);
  const [senders, setSenders] = useState<SenderIdentity[] | null>(null);
  const [passkeys, setPasskeys] = useState<PasskeyInfo[] | null>(null);
  const [err, setErr] = useState<unknown>(null);
  const [refreshing, setRefreshing] = useState(false);

  const load = useCallback(async () => {
    setErr(null);
    const [g, h, sd, pk] = await Promise.allSettled([client.governanceStatus(), client.inboundHealth(), client.senders(), client.passkeys()]);
    if (g.status === 'fulfilled') setStatus(g.value); else { setStatus(null); setErr(g.reason); }
    setHealth(h.status === 'fulfilled' ? h.value : null);
    setSenders(sd.status === 'fulfilled' ? sd.value : []);
    setPasskeys(pk.status === 'fulfilled' ? pk.value : []);
  }, []);
  useEffect(() => { load(); }, [load]);

  const summary = status ? dispatchSummary(status, health) : null;
  const livePasskeys = (passkeys ?? []).filter(p => !p.revoked_at);
  return (
    <Screen refreshing={refreshing} onRefresh={async () => { setRefreshing(true); await load(); setRefreshing(false); }}>
      <H1>Status & governance</H1>
      <ErrorNote error={err} onDismiss={() => setErr(null)} />
      {!summary && !err && <Loading label="Checking sending status" />}
      {summary && (
        <>
          <Notice tone={summary.allowed ? 'ok' : 'warn'}><Text style={s.noteTitle}>{summary.headline}</Text></Notice>
          <Card label="Sending status">
            {summary.lines.map(l => <Fact key={l.key} label={l.label} value={l.value} />)}
          </Card>
          {status && status.kernel !== 'connected' && <P>Nothing can be approved or sent until the kernel is connected. No local fallback exists.</P>}
        </>
      )}
      <H2>Sending numbers</H2>
      <Card>
        {(senders ?? []).map(x => <Fact key={x.sender_identity_id} label={x.display_name} value={`${x.from_number ?? x.messaging_service_sid ?? 'number not reported'} · registration: ${x.registration_status} · ${x.status}`} />)}
        {senders !== null && senders.length === 0 && <P muted small>No sending number registered for this team.</P>}
        <P small muted>Registration status is recorded, not assumed: messages to real customers require a registered number. Admins register numbers on the web app.</P>
      </Card>
      <H2>Approval passkeys</H2>
      <Card>
        <P>{passkeys === null ? 'Checking…' : livePasskeys.length === 0
          ? 'You have no approval passkey, so you cannot approve messages yet. Add one in Settings on the web app.'
          : `You have ${livePasskeys.length} approval passkey${livePasskeys.length === 1 ? '' : 's'}. Approving from this app opens the secure web approval page, where your passkey signs each message.`}</P>
        {WEB_URL === null && <P small>This build has no web approval address configured, so approval from this app is unavailable.</P>}
      </Card>
    </Screen>
  );
}
