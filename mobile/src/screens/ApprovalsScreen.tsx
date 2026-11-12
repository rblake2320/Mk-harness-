import { useCallback, useEffect, useState } from 'react';
import { Alert, Text, View } from 'react-native';
import {
  ApiError, SELF_APPROVAL_NOTE, approvalView, describeReadStatus, hiddenCharacterWarning, segmentText,
} from '../../../packages/sdk/src/index';
import type { ActionResult, PendingApproval } from '../../../packages/sdk/src/index';
import { client } from '../api';
import { approveOnWeb } from '../approvalHandoff';
import { Button, Card, ErrorNote, Fact, Field, H1, H2, HumanSteps, Loading, Notice, P, Row, Screen, StateBadge, s } from '../components/ui';
import { afterHandoffHint } from '../logic/approvalReturn';
import { fmtWhen } from '../logic/format';

/**
 * Approvals on mobile (H1, H2, H4, H6, H8). Every H1 field comes from the shared SDK
 * `approvalView`, identical to the web. Approval itself happens on the web approval
 * page with the consultant's passkey (React Native has no WebAuthn); the app then reads
 * the action back from the API and shows exactly what the kernel reports. Rejecting
 * needs no passkey and is done here, after a confirmation.
 */
interface Outcome { who: string; note: string; action: ActionResult | null; error: unknown }
const SUPERSEDED = new Set(['APPROVAL_DIGEST_MISMATCH', 'ILLEGAL_TRANSITION']);

export default function ApprovalsScreen({ focusActionId, onFocusHandled }: { focusActionId: string | null; onFocusHandled: () => void }) {
  const [items, setItems] = useState<PendingApproval[] | null>(null);
  const [err, setErr] = useState<unknown>(null);
  const [busy, setBusy] = useState('');
  const [outcomes, setOutcomes] = useState<Record<string, Outcome>>({});
  const [stale, setStale] = useState<Record<string, string>>({});
  const [reason, setReason] = useState<Record<string, string>>({});
  const [now, setNow] = useState(() => Date.now());
  const [refreshing, setRefreshing] = useState(false);

  const load = useCallback(async () => {
    setErr(null);
    try { setItems(await client.pendingApprovals()); } catch (e) { setErr(e); setItems(i => i ?? []); }
    setNow(Date.now());
  }, []);
  useEffect(() => { load(); }, [load]);
  useEffect(() => { const t = setInterval(() => setNow(Date.now()), 30_000); return () => clearInterval(t); }, []);

  // A return link opened the app (cold start or while running): re-read that action.
  useEffect(() => {
    if (!focusActionId) return;
    const id = focusActionId;
    onFocusHandled();
    client.actionStatus(id)
      .then(status => setOutcomes(o => ({ ...o, [id]: { who: o[id]?.who ?? 'this message', note: 'Opened from the approval page. The kernel reports:', action: status.action, error: null } })))
      .catch(error => setOutcomes(o => ({ ...o, [id]: { who: 'this message', note: 'Could not read the message state.', action: null, error } })));
    load();
  }, [focusActionId, onFocusHandled, load]);

  async function approve(it: PendingApproval) {
    setBusy(it.action_id); setErr(null);
    try {
      const r = await approveOnWeb(it.action_id);
      if (r.kind === 'unavailable') { setErr(new Error(r.note)); return; }
      setOutcomes(o => ({ ...o, [it.action_id]: { who: it.customer?.name ?? 'Unknown customer', note: r.decision.note, action: r.status?.action ?? null, error: r.error } }));
      await load();
    } finally { setBusy(''); }
  }

  async function doReject(it: PendingApproval) {
    setBusy(it.action_id); setErr(null);
    try {
      const r = await client.reject(it.action_id, it.action_digest, reason[it.action_id] || 'rejected by approver');
      setOutcomes(o => ({ ...o, [it.action_id]: { who: it.customer?.name ?? 'Unknown customer', note: 'You rejected this message. Nothing will be submitted. The kernel reports:',
        action: r.result, error: null } }));
      await load();
    } catch (e) {
      setErr(e);
      if (e instanceof ApiError && e.code && SUPERSEDED.has(e.code)) { setStale(st => ({ ...st, [it.action_id]: it.action_digest })); await load(); }
    } finally { setBusy(''); }
  }

  function confirmReject(it: PendingApproval) {
    Alert.alert('Reject this message?', `The message to ${it.customer?.name ?? 'this customer'} will not be submitted.`, [
      { text: 'Keep it', style: 'cancel' },
      { text: 'Reject', style: 'destructive', onPress: () => { void doReject(it); } },
    ]);
  }

  const outcomeIds = Object.keys(outcomes);
  return (
    <Screen refreshing={refreshing} onRefresh={async () => { setRefreshing(true); await load(); setRefreshing(false); }}>
      <H1>Approvals</H1>
      <P muted>Each message needs its own approval with your passkey. There is no "approve all" and no standing approval for future AI messages.</P>
      <HumanSteps steps={[
        'Read the exact text. What you approve is exactly what is submitted — one byte different and the approval is void.',
        'Approving opens the secure approval page, where your passkey signs this one message. Approvals are single-use and expire after 15 minutes.',
        'The kernel re-checks consent, suppression, contact hours and the kill switch before submitting.',
        SELF_APPROVAL_NOTE,
      ]} />
      <ErrorNote error={err} onDismiss={() => setErr(null)} />
      {outcomeIds.length > 0 && (
        <View style={{ gap: 10 }} accessibilityLabel="Results">
          <H2>Results</H2>
          {outcomeIds.map(id => {
            const o = outcomes[id];
            const hint = o.action ? afterHandoffHint(o.action.message_state) : null;
            return (
              <Card key={id}>
                <Text style={s.noteTitle}>Message to {o.who}</Text>
                <P>{o.note}</P>
                {o.action && <StateBadge state={o.action.message_state} />}
                {o.action && <P small muted>Read status: {describeReadStatus(o.action.read_status).label} — {describeReadStatus(o.action.read_status).definition}</P>}
                {hint && <P small>{hint}</P>}
                <ErrorNote error={o.error} />
              </Card>
            );
          })}
        </View>
      )}
      {items === null && <Loading label="Loading messages waiting for approval" />}
      {items !== null && items.length === 0 && <Notice tone="info">Nothing waiting for approval.</Notice>}
      {(items ?? []).map(it => {
        const v = approvalView(it, { nowMs: now, formatWhen: fmtWhen });
        const hidden = hiddenCharacterWarning(v.hidden);
        const isStale = stale[it.action_id] === it.action_digest;
        const blocked = isStale ? 'This version changed after it was shown. It cannot be approved; the current version is listed separately.'
          : v.approvable ? null : `This message cannot be approved: ${v.blockedReason}`;
        return (
          <Card key={`${it.action_id}:${it.action_digest}`} label={`Message to ${it.customer?.name ?? 'unknown customer'}`}>
            <StateBadge state={it.message_state} />
            {v.rows.map(r => <Fact key={r.key} label={r.label} value={r.value} warning={r.warning} />)}
            <Text style={[s.small, s.muted]}>Exact text</Text>
            <Text style={s.exact} selectable accessibilityLabel={`Exact message text: ${v.exactText}`}>{v.exactText}</Text>
            <P small muted>{segmentText(v.segments)}</P>
            {hidden && <Notice>{hidden}</Notice>}
            {blocked ? <Notice>{blocked}</Notice> : (
              <>
                <Field label="Note (optional, kept with a rejection)" value={reason[it.action_id] ?? ''} onChangeText={t => setReason(r => ({ ...r, [it.action_id]: t }))} />
                <Row>
                  <Button label={`Approve the message to ${it.customer?.name ?? 'this customer'} with your passkey`} text="Approve with passkey"
                          hint="Opens the secure approval page; your passkey signs this exact message." busy={busy === it.action_id} onPress={() => approve(it)} />
                </Row>
              </>
            )}
            {!isStale && <Button kind="danger" label={`Reject the message to ${it.customer?.name ?? 'this customer'}`} text="Reject" disabled={busy === it.action_id} onPress={() => confirmReject(it)} />}
          </Card>
        );
      })}
    </Screen>
  );
}
