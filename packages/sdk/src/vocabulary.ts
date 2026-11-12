/**
 * Contract row C3 — the customer-message lifecycle vocabulary, for every web and
 * mobile screen.
 *
 * The declared single source is `rust/crates/mk-contracts/src/message_state.rs`
 * (`MessageState::definition`), which the API also serves verbatim
 * (`backend/app/routes/outreach.py::MESSAGE_STATE_DEFINITIONS`) and the action
 * contract enumerates (`contracts/action/v1/action-result.schema.json`).
 * `packages/sdk/test/vocabulary.test.ts` fails if the identifiers, their order or
 * any definition here drift from any of those three.
 *
 * Rules this module enforces for the interface:
 *  - A label is the contract identifier in sentence case ("Provider accepted"),
 *    never a paraphrase ("Accepted by provider", "Sending…", "Delivered ✓").
 *  - A definition is quoted verbatim, never summarised.
 *  - Screens render message/delivery state ONLY through `describeMessageState`
 *    (enforced by `web/tests-unit/state-vocabulary.test.ts` over web and mobile).
 *  - Read status is separate from delivery and stays "unknown" unless a supported
 *    recipient-read signal exists.
 */

export const MESSAGE_STATE_IDS = [
  'proposed', 'awaiting_approval', 'approved', 'queued', 'dispatch_authorized', 'submission_started',
  'provider_accepted', 'sent', 'delivered', 'failed', 'delivery_unknown', 'submission_unknown',
  'cancelled', 'denied', 'expired',
] as const;
export type MessageState = typeof MESSAGE_STATE_IDS[number];

/** How a screen may colour a state. It never upgrades meaning: `evidence` only says
 *  the provider reported something; the label says exactly what. */
export type StateTone = 'pending' | 'progress' | 'evidence' | 'problem' | 'stopped';

export interface MessageStateEntry {
  id: MessageState;
  label: string;
  definition: string;
  tone: StateTone;
}

// Verbatim from mk-contracts::MessageState::definition (parity-tested).
const DEFINITIONS: Readonly<Record<MessageState, string>> = Object.freeze({
  proposed: 'Proposed by the AI or the consultant; nothing has been authorized.',
  awaiting_approval: 'Waiting for an explicit human approval gesture.',
  approved: 'Approved by a human; not yet queued for execution.',
  queued: 'Queued for execution; policy will be re-evaluated before any send.',
  dispatch_authorized: 'Dispatch authorization obtained; no provider request has been made.',
  submission_started: 'The provider request is in flight or its outcome is not yet recorded.',
  provider_accepted: 'Provider acknowledged submission.',
  sent: 'Provider reports outbound network submission.',
  delivered: 'Supported provider/carrier receipt reports delivery.',
  failed: 'Provider reported a terminal failure.',
  delivery_unknown: 'Evidence is insufficient to say whether the message was delivered.',
  submission_unknown: 'Evidence is insufficient to say whether the message was submitted; a human must resolve before any replacement.',
  cancelled: 'Cancelled before any provider submission.',
  denied: 'Refused by policy; nothing was sent.',
  expired: 'The authorization window elapsed before execution.',
});

const TONES: Readonly<Record<MessageState, StateTone>> = Object.freeze({
  proposed: 'pending', awaiting_approval: 'pending',
  approved: 'progress', queued: 'progress', dispatch_authorized: 'progress', submission_started: 'progress',
  provider_accepted: 'evidence', sent: 'evidence', delivered: 'evidence',
  failed: 'problem', delivery_unknown: 'problem', submission_unknown: 'problem',
  cancelled: 'stopped', denied: 'stopped', expired: 'stopped',
});

/** The contract identifier in sentence case: `provider_accepted` → "Provider accepted". */
export function labelFromIdentifier(id: string): string {
  const words = id.replace(/_/g, ' ');
  return words.charAt(0).toUpperCase() + words.slice(1);
}

export const MESSAGE_STATES: readonly MessageStateEntry[] = Object.freeze(
  MESSAGE_STATE_IDS.map(id => Object.freeze({ id, label: labelFromIdentifier(id), definition: DEFINITIONS[id], tone: TONES[id] })),
);

const BY_ID: ReadonlyMap<string, MessageStateEntry> = new Map(MESSAGE_STATES.map(e => [e.id, e]));

export function isMessageState(v: unknown): v is MessageState {
  return typeof v === 'string' && BY_ID.has(v);
}

export type StateDescription =
  | (MessageStateEntry & { known: true })
  | { known: false; id: null; raw: string; label: string; definition: string; tone: 'problem' };

/** Printable, bounded echo of an unexpected value (never trusted, never interpreted). */
function safeEcho(v: unknown): string {
  const s = typeof v === 'string' ? v : JSON.stringify(v) ?? String(v);
  // eslint-disable-next-line no-control-regex
  return s.replace(/[\u0000-\u001f\u007f-\u009f​-‏‪-‮⁦-⁩﻿]/g, '').slice(0, 64);
}

/**
 * The only way a screen turns a `message_state` into words. Unknown or missing values
 * are reported as such — never mapped to the nearest-sounding state, never treated
 * as sent. Lookup is by own key only, so `"constructor"` or `"__proto__"` cannot
 * resolve to an Object.prototype member.
 */
export function describeMessageState(raw: unknown): StateDescription {
  if (isMessageState(raw)) return { ...(BY_ID.get(raw) as MessageStateEntry), known: true };
  if (raw === null || raw === undefined || raw === '') {
    return { known: false, id: null, raw: '', label: 'Not reported', tone: 'problem',
      definition: 'The API did not report a message state for this action. Do not assume anything was sent.' };
  }
  return { known: false, id: null, raw: safeEcho(raw), label: 'Unrecognised state', tone: 'problem',
    definition: 'This interface does not recognise the reported state. Do not assume anything was sent; report it with the action id.' };
}

/** Kernel action states that are not the message vocabulary must never be shown as
 *  one. Screens pass `result.message_state` here, never `result.state`. */
export function messageStateOf(result: { message_state?: unknown } | null | undefined): StateDescription {
  return describeMessageState(result?.message_state);
}

// ---- Read status: separate from delivery (contract: "Store read status separately and
// leave it unknown unless a supported source actually supplies it"). Definitions are the
// contract's own wording ("Read: supported recipient-read signal exists." /
// "Unknown: evidence is insufficient."). ----
export const READ_STATUS_IDS = ['unknown', 'read'] as const;
export type ReadStatus = typeof READ_STATUS_IDS[number];
export const READ_STATUSES: Readonly<Record<ReadStatus, { label: string; definition: string }>> = Object.freeze({
  unknown: Object.freeze({ label: 'Unknown', definition: 'Evidence is insufficient.' }),
  read: Object.freeze({ label: 'Read', definition: 'Supported recipient-read signal exists.' }),
});

/** Anything other than an explicit `read` from the API is "Unknown" — never inferred
 *  from delivery or elapsed time. */
export function describeReadStatus(raw: unknown): { id: ReadStatus; label: string; definition: string } {
  const id: ReadStatus = raw === 'read' ? 'read' : 'unknown';
  return { id, ...READ_STATUSES[id] };
}
