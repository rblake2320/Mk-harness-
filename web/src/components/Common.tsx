import { describeMessageState, explain } from '../../../packages/sdk/src/index.ts';

export { explain };

/**
 * Plain-language errors with a recovery step (contract: "plain-language errors and
 * recovery instructions"). The wording lives in the SDK (`errors.ts`) so web and
 * mobile say the same thing; the machine code and request id are always shown so a
 * kernel refusal is never swallowed.
 */
export function ErrorNote({ error, onDismiss }: { error: unknown; onDismiss?: () => void }) {
  if (!error) return null;
  const x = explain(error);
  return (
    <div className="error-note" role="alert">
      <strong>{x.what}</strong>
      <div>{x.next}</div>
      {(x.code || x.requestId) && <div className="muted small">{[x.code, x.requestId && `request ${x.requestId}`].filter(Boolean).join(' · ')}</div>}
      {onDismiss && <button className="btn ghost small" onClick={onDismiss}>Dismiss</button>}
    </div>
  );
}

/** Where human action remains necessary — disclosed on every automated workflow. */
export function HumanSteps({ steps }: { steps: string[] }) {
  if (!steps?.length) return null;
  return (
    <aside className="human-steps" aria-label="Human steps required">
      <strong>What still needs a person</strong>
      <ul>{steps.map((s, i) => <li key={i}>{s}</li>)}</ul>
    </aside>
  );
}

/**
 * The only way the web renders a message state (contract row C3): label and definition
 * come verbatim from the SDK vocabulary; unknown values say so. `showDefinition` prints
 * the definition next to the label; otherwise it is the accessible description.
 */
export function StateBadge({ state, showDefinition = false }: { state: unknown; showDefinition?: boolean }) {
  const d = describeMessageState(state);
  const cls = d.known ? `badge state-${d.id} tone-${d.tone}` : 'badge tone-problem';
  return (
    <span className="state">
      <span className="visually-hidden">Message state: </span>
      <span className={cls} title={d.definition}>{d.label}</span>
      {!d.known && d.raw && <code className="muted small"> {d.raw}</code>}
      <span className={showDefinition ? 'muted small' : 'visually-hidden'}> — {d.definition}</span>
    </span>
  );
}

export function fmtWhen(iso: string | null | undefined) {
  if (!iso) return '—';
  const t = Date.parse(iso);
  if (!Number.isFinite(t)) return 'unknown time';
  try { return new Date(t).toLocaleString(undefined, { dateStyle: 'medium', timeStyle: 'short' }); } catch { return iso; }
}
