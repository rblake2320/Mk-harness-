import { useEffect, useRef, useState } from 'react';
import { Text } from 'react-native';
import { describeMessageState, segmentText, smsSegments } from '../../../packages/sdk/src/index';
import type { Draft, ProposeResult } from '../../../packages/sdk/src/index';
import { client } from '../api';
import { AiBadge, AiStrip, Button, ErrorNote, Field, H1, HumanSteps, Loading, Notice, P, Row, Screen, StateBadge, s } from '../components/ui';

/**
 * Draft editor (W5/H2), same rules as the web: the text shown is the text that will be
 * approved and submitted; saving an edit creates a new version and digest; changing a
 * proposed draft first withdraws the proposal through the kernel so the old digest can
 * never be approved. Proposing never sends. Scheduling is not offered (see report).
 */
export default function DraftEditorScreen({ customerId, customerName, briefItemId, commitmentId, onDone }: {
  customerId: string; customerName: string; briefItemId?: string; commitmentId?: string; onDone: () => void;
}) {
  const [draft, setDraft] = useState<Draft | null>(null);
  const [limitation, setLimitation] = useState<{ text: string; neutral?: string } | null>(null);
  const [text, setText] = useState('');
  const [loading, setLoading] = useState(true);
  const [busy, setBusy] = useState(false);
  const [err, setErr] = useState<unknown>(null);
  const [proposed, setProposed] = useState<ProposeResult | null>(null);
  const [withdrawn, setWithdrawn] = useState(false);
  const started = useRef(false);

  useEffect(() => {
    if (started.current) return; // one generation per visit, even if React re-runs effects
    started.current = true;
    client.generateDraft({ customer_id: customerId, brief_item_id: briefItemId, commitment_id: commitmentId })
      .then(r => {
        if (r.draft) { setDraft(r.draft); setText(r.draft.text); }
        if (r.limitation) setLimitation({ text: r.limitation, neutral: r.neutral_text });
      })
      .catch(setErr)
      .finally(() => setLoading(false));
  }, [customerId, briefItemId, commitmentId]);

  const dirty = draft ? text !== draft.text : false;

  async function saveEdit() {
    if (!draft || proposed) return;
    setBusy(true); setErr(null);
    try { const d = await client.editDraft(draft.id, text); setDraft(d); setText(d.text); }
    catch (e) { setErr(e); } finally { setBusy(false); }
  }

  async function propose() {
    if (!draft || dirty || proposed) return;
    setBusy(true); setErr(null);
    try { setProposed(await client.proposeDraft(draft.id)); setWithdrawn(false); }
    catch (e) { setErr(e); } finally { setBusy(false); }
  }

  async function withdrawToEdit() {
    if (!proposed) return;
    setBusy(true); setErr(null);
    try {
      const r = await client.cancelAction(proposed.action_id);
      const d = describeMessageState(r.message_state);
      if (d.id !== 'cancelled') throw new Error(`The earlier proposal was not withdrawn (the kernel reports "${d.label}"). Check Approvals before proposing another version.`);
      setProposed(null); setWithdrawn(true);
    } catch (e) { setErr(e); } finally { setBusy(false); }
  }

  return (
    <Screen>
      <H1>Message to {customerName}</H1>
      <AiStrip />
      {loading && <Loading label="Drafting a message" />}
      {limitation && (
        <Notice>
          <Text style={s.noteTitle}>No product recommendation was drafted.</Text>
          <P>{limitation.text}</P>
          {!!limitation.neutral && <P>A neutral check-in you could write instead: {limitation.neutral}</P>}
        </Notice>
      )}
      <ErrorNote error={err} onDismiss={() => setErr(null)} />
      {draft && (
        <>
          <Row><AiBadge /><Text style={[s.small, s.muted]}>Version {draft.version} · digest {draft.text_digest.slice(7, 19)}…</Text></Row>
          <Field label="Exact text" value={text} onChangeText={setText} multiline maxLength={480} readOnly={proposed !== null} />
          <P small muted>
            {draft.claims_used.length > 0
              ? `Approved product wording in this draft: ${draft.claims_used.join(', ')}. Product statements must stay within the approved list.`
              : 'No product statements. Product claims that are not on the approved list are refused.'}
            {` ${text.length}/480 · ${segmentText(smsSegments(text))}`}
          </P>
          {withdrawn && <Notice tone="ok">The earlier proposal was withdrawn; its version can no longer be approved. Save your change as a new version, then propose it — it needs its own approval.</Notice>}
          {proposed ? (
            <Notice tone="ok">
              <Text style={s.noteTitle}>Proposed for approval.</Text>
              <Text style={s.p}>The kernel reports:</Text>
              <StateBadge state={proposed.message_state} />
              <HumanSteps steps={proposed.human_steps ?? []} />
              <Button kind="ghost" label="Withdraw this proposal to change the text" busy={busy} onPress={withdrawToEdit}
                      hint="The earlier version is withdrawn first, so it can never be approved." />
            </Notice>
          ) : dirty ? (
            <>
              <Button label="Save as new version" busy={busy} onPress={saveEdit} />
              <P small muted>Saving creates a new version; any earlier approval no longer applies.</P>
            </>
          ) : (
            <>
              <Button label="Propose for approval" busy={busy} onPress={propose} />
              <P small muted>Proposing never submits anything. You (or a second approver) must approve the exact text with a passkey.</P>
            </>
          )}
        </>
      )}
      <Button kind="ghost" label="Close" onPress={onDone} />
    </Screen>
  );
}
