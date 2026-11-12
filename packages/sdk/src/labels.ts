/**
 * Interface wording shared by web and mobile for vocabularies that are NOT the
 * message-state vocabulary (that one lives in `vocabulary.ts`). Keys are the exact
 * values the API returns (`backend/app/commitments.py`, `backend/app/inbound.py`,
 * `contracts/outcomes/v1`, the kernel's inbound gate); anything unknown is shown as
 * unknown, never guessed.
 */

function own<T>(table: Readonly<Record<string, T>>, key: unknown): T | undefined {
  return typeof key === 'string' && Object.prototype.hasOwnProperty.call(table, key) ? table[key] : undefined;
}

// ---- Daily brief (W2/W3): rank categories in the server's order, and rule tags ----
/** Server ranking (`commitments.py` RANK_*): safety → overdue → due today → unanswered → future. */
export const BRIEF_SECTIONS: readonly { rank: number; title: string; description: string }[] = Object.freeze([
  { rank: 0, title: 'Needs attention', description: 'Open exceptions: safety, opt-out or complaint items to review before any outreach.' },
  { rank: 1, title: 'Overdue', description: 'Confirmed promises past their date.' },
  { rank: 2, title: 'Due today', description: 'Confirmed promises and customer dates due today.' },
  { rank: 3, title: 'Unanswered requests', description: 'Customer requests and questions waiting for your answer.' },
  { rank: 4, title: 'Coming up', description: 'Windows that are open but end later.' },
]);

export const BRIEF_RULE_LABEL: Readonly<Record<string, string>> = Object.freeze({
  exception: 'Exception to review',
  commitment_due: 'Your promise',
  customer_date: 'Customer date',
  explicit_request: 'Customer request',
  unanswered_question: 'Unanswered question',
});

export function briefRuleLabel(rule: unknown): string {
  return own(BRIEF_RULE_LABEL, rule) ?? `Other (${String(rule ?? 'not reported').slice(0, 40)})`;
}

// ---- Exceptions (C7) ----
export const EXCEPTION_KIND_LABEL: Readonly<Record<string, string>> = Object.freeze({
  product_concern: 'Product or skin concern — sales follow-up stopped',
  complaint: 'Complaint',
  wrong_number: 'Wrong number — follow-up stopped',
  identity_ambiguity: 'Could not tell which customer this is',
  delivery_uncertain: 'Delivery or submission unknown — a person must check',
  missing_permission: 'Missing permission',
  ambiguous_reply: 'Ambiguous reply',
  ambiguous_opt_out: 'Possible opt-out — on hold until you decide',
  draft_review: 'Draft needs review',
});

export function exceptionKindLabel(kind: unknown): string {
  return own(EXCEPTION_KIND_LABEL, kind) ?? `Other exception (${String(kind ?? 'not reported').slice(0, 40)})`;
}

// ---- Business outcomes (X1, contracts/outcomes/v1): separate from transport state ----
export const OUTCOME_KINDS: readonly { id: string; label: string; note?: string }[] = Object.freeze([
  { id: 'resolved', label: 'Resolved' },
  { id: 'deferred', label: 'Deferred' },
  { id: 'opted_out', label: 'Customer opted out' },
  { id: 'no_response', label: 'No response' },
  { id: 'customer_reported_order', label: 'Customer reported an order', note: 'What the customer said; not a verified order.' },
  { id: 'consultant_confirmed_order', label: 'You confirmed an order', note: 'A consultant-confirmed order is not independently verified revenue.' },
  { id: 'exception_open', label: 'Exception open' },
  { id: 'cancelled', label: 'Commitment cancelled' },
]);

export function outcomeLabel(kind: unknown): string {
  return OUTCOME_KINDS.find(o => o.id === kind)?.label ?? `Other outcome (${String(kind ?? 'not reported').slice(0, 40)})`;
}

/** Contract X1 wording, shown wherever outcomes are recorded. */
export const OUTCOME_SEPARATION_NOTE =
  'Business outcomes are separate from message states. A delivered message is not a resolved commitment; a consultant-confirmed order is not verified revenue.';

// ---- Commitments (W1) ----
export const COMMITMENT_KINDS: readonly { id: string; label: string }[] = Object.freeze([
  { id: 'promise', label: 'Your promise' },
  { id: 'customer_request', label: 'Customer request' },
  { id: 'unanswered_question', label: 'Unanswered question' },
  { id: 'customer_date', label: 'Customer date' },
]);
export const RELATIVE_WINDOWS: readonly { id: string; label: string }[] = Object.freeze([
  { id: 'today', label: 'Today' }, { id: 'tomorrow', label: 'Tomorrow' }, { id: 'this_week', label: 'This week' },
  { id: 'next_week', label: 'Next week' }, { id: 'next_month', label: 'Next month' },
]);

// ---- Kernel inbound gate (C8): why outbound sending is paused ----
export const INBOUND_BLOCK_LABEL: Readonly<Record<string, string>> = Object.freeze({
  inbound_unverified: 'The reply path has never been confirmed working, so sending stays paused.',
  inbound_stale: 'The reply path failed and has not recovered within 60 seconds, so sending is paused.',
  inbound_paused: 'An admin paused sending because of the reply path.',
});

export function inboundBlockLabel(reason: unknown): string | null {
  if (reason === null || reason === undefined || reason === '') return null;
  return own(INBOUND_BLOCK_LABEL, reason) ?? `Sending is paused (${String(reason).slice(0, 40)}).`;
}

// ---- Permission observation shown on brief items and approvals (F4) ----
export const PERMISSION_STATE_LABEL: Readonly<Record<string, string>> = Object.freeze({
  active: 'Permission on record',
  none: 'No permission on record',
  suppressed: 'Do not contact (suppressed)',
});

export function permissionLabel(state: unknown): string {
  return own(PERMISSION_STATE_LABEL, state) ?? `Permission state not recognised (${String(state ?? 'not reported').slice(0, 40)})`;
}
