/**
 * What the approval screen shows (row H1), computed once for web and mobile so both
 * platforms present the same fields with the same wording:
 * destination, customer, sending business + number, exact text, purpose, supporting
 * commitment/request, permission state, scheduled time, approval expiry — and the
 * digest the approval binds to (H2).
 *
 * Missing data is never filled in with something plausible: every absent field says it
 * is absent and, where that matters for the decision, carries a warning.
 */
import type { PendingApproval } from './index';
import { permissionLabel } from './labels';

export type H1Key = 'to' | 'from' | 'purpose' | 'because' | 'permission' | 'when' | 'expiry' | 'digest';

export interface H1Row {
  key: H1Key;
  label: string;
  value: string;
  /** Something the approver must notice before deciding. */
  warning?: string;
}

export type WhenFormatter = (iso: string) => string;

/** Default human date-time; injectable so tests and screens control locale. */
export const defaultFormatWhen: WhenFormatter = (iso) => {
  const t = Date.parse(iso);
  if (!Number.isFinite(t)) return 'unknown time';
  try { return new Date(t).toLocaleString(undefined, { dateStyle: 'medium', timeStyle: 'short' }); } catch { return new Date(t).toISOString(); }
};

const DIGEST_RE = /^sha256:([0-9a-f]{64})$/;

/** First 16 hex digits of a `sha256:` digest, or null when malformed. */
export function digestShort(d: unknown): string | null {
  const m = typeof d === 'string' ? DIGEST_RE.exec(d) : null;
  return m ? m[1].slice(0, 16) : null;
}

// ---- Expiry -----------------------------------------------------------------------
export interface ExpiryDisplay {
  status: 'unknown' | 'expired' | 'soon' | 'open';
  /** "Expires in 14 min", "This request expired 3 min ago", "Expiry not reported". */
  text: string;
  remainingMs: number | null;
}

export function formatDuration(ms: number): string {
  const totalMin = Math.floor(Math.abs(ms) / 60_000);
  if (totalMin < 1) return 'less than a minute';
  const d = Math.floor(totalMin / 1440), h = Math.floor((totalMin % 1440) / 60), m = totalMin % 60;
  if (d > 0) return `${d} d ${h} h`;
  if (h > 0) return `${h} h ${m} min`;
  return `${m} min`;
}

/** Strict ISO-8601 instant with an explicit zone (`Z` or ±hh:mm). Anything else is "unknown". */
const ISO_INSTANT_RE = /^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}(:\d{2}(\.\d{1,9})?)?(Z|[+-]\d{2}:\d{2})$/;

export function expiryDisplay(iso: unknown, nowMs: number, soonMs = 5 * 60_000): ExpiryDisplay {
  if (typeof iso !== 'string' || !ISO_INSTANT_RE.test(iso)) return { status: 'unknown', text: 'Expiry not reported', remainingMs: null };
  const t = Date.parse(iso);
  if (!Number.isFinite(t)) return { status: 'unknown', text: 'Expiry not reported', remainingMs: null };
  const remaining = t - nowMs;
  if (remaining <= 0) return { status: 'expired', text: `This request expired ${formatDuration(remaining)} ago`, remainingMs: remaining };
  return { status: remaining <= soonMs ? 'soon' : 'open', text: `Expires in ${formatDuration(remaining)}`, remainingMs: remaining };
}

// ---- SMS segments (estimate shown with the exact text) ------------------------------
const GSM7_BASIC = '@£$¥èéùìòÇ\nØø\rÅåΔ_ΦΓΛΩΠΨΣΘΞÆæßÉ !"#¤%&\'()*+,-./0123456789:;<=>?¡ABCDEFGHIJKLMNOPQRSTUVWXYZÄÖÑÜ§¿abcdefghijklmnopqrstuvwxyzäöñüà';
const GSM7_EXTENDED = '\f^{}\\[~]|€';
const BASIC = new Set(GSM7_BASIC);
const EXTENDED = new Set(GSM7_EXTENDED);

export interface SegmentInfo {
  encoding: 'GSM-7' | 'UCS-2';
  /** GSM-7 septets, or UTF-16 code units for UCS-2. */
  units: number;
  segments: number;
  /** Units per segment at this length (160/153 or 70/67). */
  perSegment: number;
}

/** Estimated SMS segments for `text` under standard GSM-7 / UCS-2 rules. A GSM escape
 *  pair and a UTF-16 surrogate pair are never split across segments. */
export function smsSegments(text: string): SegmentInfo {
  const chars = Array.from(text);
  const gsm = chars.every(c => BASIC.has(c) || EXTENDED.has(c));
  if (gsm) {
    const sizes = chars.map(c => (EXTENDED.has(c) ? 2 : 1));
    const units = sizes.reduce((a, b) => a + b, 0);
    if (units === 0) return { encoding: 'GSM-7', units: 0, segments: 0, perSegment: 160 };
    if (units <= 160) return { encoding: 'GSM-7', units, segments: 1, perSegment: 160 };
    return { encoding: 'GSM-7', units, segments: pack(sizes, 153), perSegment: 153 };
  }
  const sizes = chars.map(c => c.length); // 1 or 2 UTF-16 units (astral → surrogate pair)
  const units = sizes.reduce((a, b) => a + b, 0);
  if (units <= 70) return { encoding: 'UCS-2', units, segments: 1, perSegment: 70 };
  return { encoding: 'UCS-2', units, segments: pack(sizes, 67), perSegment: 67 };
}

function pack(sizes: number[], cap: number): number {
  let segments = 1, used = 0;
  for (const s of sizes) {
    if (used + s > cap) { segments++; used = 0; }
    used += s;
  }
  return segments;
}

export function segmentText(info: SegmentInfo): string {
  if (info.segments === 0) return 'Empty message';
  return `Estimated ${info.segments} SMS segment${info.segments === 1 ? '' : 's'} (${info.encoding}, ${info.units} ${info.encoding === 'GSM-7' ? 'characters' : 'code units'})`;
}

// ---- Characters the approver cannot see --------------------------------------------
/** Reorder what is displayed: the approver could read something other than what is sent. */
const BIDI_REORDERING = new Map<number, string>([
  [0x202a, 'LEFT-TO-RIGHT EMBEDDING'], [0x202b, 'RIGHT-TO-LEFT EMBEDDING'], [0x202c, 'POP DIRECTIONAL FORMATTING'],
  [0x202d, 'LEFT-TO-RIGHT OVERRIDE'], [0x202e, 'RIGHT-TO-LEFT OVERRIDE'], [0x2066, 'LEFT-TO-RIGHT ISOLATE'],
  [0x2067, 'RIGHT-TO-LEFT ISOLATE'], [0x2068, 'FIRST STRONG ISOLATE'], [0x2069, 'POP DIRECTIONAL ISOLATE'],
]);
const INVISIBLE = new Map<number, string>([
  [0x200b, 'ZERO WIDTH SPACE'], [0x200c, 'ZERO WIDTH NON-JOINER'], [0x200d, 'ZERO WIDTH JOINER'], [0x2060, 'WORD JOINER'],
  [0xfeff, 'ZERO WIDTH NO-BREAK SPACE'], [0x00ad, 'SOFT HYPHEN'], [0x200e, 'LEFT-TO-RIGHT MARK'], [0x200f, 'RIGHT-TO-LEFT MARK'],
  [0x061c, 'ARABIC LETTER MARK'], [0x180e, 'MONGOLIAN VOWEL SEPARATOR'],
]);

export interface HiddenCharacters {
  found: { codePoint: string; name: string; count: number }[];
  /** True when a character can reorder the displayed text — approval must not be offered. */
  reorders: boolean;
}

const PICTOGRAPHIC = /\p{Extended_Pictographic}/u;

export function hiddenCharacters(text: string): HiddenCharacters {
  const counts = new Map<number, number>();
  let reorders = false;
  const cps = Array.from(text, c => c.codePointAt(0) as number);
  cps.forEach((cp, i) => {
    let flagged = BIDI_REORDERING.has(cp) || INVISIBLE.has(cp);
    // A zero-width joiner inside an emoji sequence (👩‍👧) is rendering, not hiding.
    if (cp === 0x200d && i > 0 && i < cps.length - 1
        && PICTOGRAPHIC.test(String.fromCodePoint(cps[i - 1] === 0xfe0f && i > 1 ? cps[i - 2] : cps[i - 1]))
        && PICTOGRAPHIC.test(String.fromCodePoint(cps[i + 1]))) flagged = false;
    // C0/C1 controls other than tab and line breaks.
    if ((cp < 0x20 && cp !== 0x09 && cp !== 0x0a && cp !== 0x0d) || (cp >= 0x7f && cp <= 0x9f)) flagged = true;
    if (!flagged) return;
    if (BIDI_REORDERING.has(cp)) reorders = true;
    counts.set(cp, (counts.get(cp) ?? 0) + 1);
  });
  const found = [...counts.entries()].map(([cp, count]) => ({
    codePoint: `U+${cp.toString(16).toUpperCase().padStart(4, '0')}`,
    name: BIDI_REORDERING.get(cp) ?? INVISIBLE.get(cp) ?? 'CONTROL CHARACTER',
    count,
  }));
  return { found, reorders };
}

export function hiddenCharacterWarning(h: HiddenCharacters): string | null {
  if (h.found.length === 0) return null;
  const list = h.found.map(f => `${f.name} (${f.codePoint})${f.count > 1 ? ` ×${f.count}` : ''}`).join(', ');
  return h.reorders
    ? `This text contains characters that change how it is displayed: ${list}. What you see may not be what is sent, so it cannot be approved here. Edit the draft to remove them.`
    : `This text contains characters you cannot see: ${list}. Check the draft before approving.`;
}

// ---- The H1 rows --------------------------------------------------------------------
export interface ApprovalView {
  rows: H1Row[];
  exactText: string;
  segments: SegmentInfo;
  hidden: HiddenCharacters;
  expiry: ExpiryDisplay;
  digest: string | null;
  /** False when the screen must not offer the approve gesture (and why). */
  approvable: boolean;
  blockedReason?: string;
}

export function approvalView(it: PendingApproval, opts: { nowMs: number; formatWhen?: WhenFormatter }): ApprovalView {
  const when = opts.formatWhen ?? defaultFormatWhen;
  const exactText = typeof it.exact_text === 'string' ? it.exact_text : '';
  const digest = digestShort(it.action_digest);
  const expiry = expiryDisplay(it.approval_expires_at, opts.nowMs);
  const hidden = hiddenCharacters(exactText);
  const rows: H1Row[] = [];

  const dest = it.destination_masked ? `${it.destination_masked}${it.channel ? ` (${it.channel})` : ''}` : 'destination not reported';
  rows.push({ key: 'to', label: 'To', value: `${it.customer?.name ?? 'Unknown customer'} · ${dest}`,
    warning: !it.customer ? 'The customer could not be identified. Do not approve unless you know who this is.'
      : !it.destination_masked ? 'The destination was not reported.' : undefined });

  const sb = it.sending_business;
  rows.push({ key: 'from', label: 'From', value: sb ? `${sb.display_name ?? 'Unnamed business'} · ${sb.from_number ?? 'number not reported'} (registration: ${sb.registration_status ?? 'not reported'})` : 'No registered sending number',
    warning: !sb ? 'No sending business is attached; the kernel will refuse to submit this message.'
      : sb.registration_status !== 'registered' ? 'This sending number is not registered; messages to real customers require a registered number.' : undefined });

  rows.push({ key: 'purpose', label: 'Purpose', value: [it.purpose ?? 'purpose not reported', it.workflow, it.risk ? `risk ${it.risk}` : null].filter(Boolean).join(' · ') });

  const c = it.supporting?.commitment;
  const ev = c ? digestShort(c.evidence_digest) : null;
  rows.push({ key: 'because', label: 'Because', value: c ? `“${c.text}” (${c.status}${ev ? `, evidence ${ev.slice(0, 12)}…` : ', no evidence digest'})` : 'No supporting commitment or request',
    warning: c ? undefined : 'Nothing the customer asked for or you promised is attached. Review carefully.' });

  const p = it.permission;
  rows.push({ key: 'permission', label: 'Permission', value: p ? `${permissionLabel(p.state)} (checked ${p.checked_at ? when(p.checked_at) : 'time not reported'}) — ${p.note}` : 'Not recorded on this item; the kernel checks consent and suppression at send time',
    warning: p && p.state !== 'active' ? 'Permission is not active on the last observation; the kernel will refuse unless it is.' : undefined });

  rows.push({ key: 'when', label: 'When', value: it.scheduled_for ? when(it.scheduled_for) : 'As soon as policy allows (inside the customer’s contact hours)' });

  const lifetime = Number.isInteger(it.approval_lifetime_minutes) && it.approval_lifetime_minutes > 0 ? it.approval_lifetime_minutes : 15;
  rows.push({ key: 'expiry', label: 'Expires', value: `${expiry.text}${expiry.status !== 'unknown' && typeof it.approval_expires_at === 'string' ? ` (${when(it.approval_expires_at)})` : ''} · once approved, the approval is single-use and lasts ${lifetime} minutes`,
    warning: expiry.status === 'expired' ? 'This request has expired and cannot be approved.' : expiry.status === 'unknown' ? 'The expiry was not reported.' : undefined });

  rows.push({ key: 'digest', label: 'Digest', value: digest ? `digest ${digest}…` : 'digest not reported',
    warning: digest ? undefined : 'The digest this approval binds to is missing or malformed, so it cannot be approved.' });

  let blockedReason: string | undefined;
  if (!digest) blockedReason = 'The digest is missing or malformed.';
  else if (expiry.status === 'expired') blockedReason = 'This request has expired.';
  else if (hidden.reorders) blockedReason = 'The text contains characters that change how it is displayed.';
  else if (!exactText) blockedReason = 'The exact text was not reported.';
  return { rows, exactText, segments: smsSegments(exactText), hidden, expiry, digest, approvable: !blockedReason, blockedReason };
}

/** Disclosed on every approval screen: the API does not say in advance whether the
 *  tenant allows self-approval, so the kernel's answer is the authority (row H8). */
export const SELF_APPROVAL_NOTE =
  'If your team requires a second person, the kernel refuses your approval of a message you proposed yourself — you will see that here, and nothing is approved.';
