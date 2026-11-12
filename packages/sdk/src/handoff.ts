/**
 * Mobile → web passkey hand-off for human approval (rows H4/H6 on mobile).
 *
 * React Native has no WebAuthn API, and approval must stay a passkey ceremony that
 * the kernel verifies. So the mobile app opens the web approval page in an auth
 * session; the consultant approves there with their passkey; the page then returns
 * to the app at `APPROVAL_RETURN_URL?action=<id>`. The app re-reads the action from
 * the API and shows what the kernel says. The return URL is navigation only — it is
 * never evidence that anything was approved.
 *
 * Security properties (tested in packages/sdk/test/handoff.test.ts):
 *  - The web page accepts `return_to` only when the WHOLE value equals
 *    APPROVAL_RETURN_URL, character for character (no prefix match, no case folding,
 *    no trimming, no decoding beyond the single URL-query decode, no query/fragment).
 *    It then builds the redirect itself; nothing caller-supplied is echoed except a
 *    validated action UUID.
 *  - Duplicate `return_to`/`action` parameters are ambiguous and therefore refused.
 *  - Parsing is regex-based and platform-independent (React Native's URL class is
 *    incomplete), with hard length limits before any work.
 */

export const APPROVAL_RETURN_URL = 'consultantstudio://approvals/done';
/** Queries longer than this are not parsed at all (bounded work on hostile input). */
export const MAX_QUERY_LENGTH = 16_384;
const UUID_RE = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/;

/** Canonical lower-case UUID, or null. No trimming: whitespace is a different value. */
export function normalizeActionId(v: unknown): string | null {
  if (typeof v !== 'string' || v.length !== 36) return null;
  const lower = v.toLowerCase();
  return UUID_RE.test(lower) ? lower : null;
}

/** The allowlist check. Returns APPROVAL_RETURN_URL or null. */
export function acceptReturnTo(v: unknown): string | null {
  return typeof v === 'string' && v.length === APPROVAL_RETURN_URL.length && v === APPROVAL_RETURN_URL ? APPROVAL_RETURN_URL : null;
}

/** Decode one application/x-www-form-urlencoded component; malformed → null. */
function decodeComponent(s: string): string | null {
  try { return decodeURIComponent(s.replace(/\+/g, ' ')); } catch { return null; }
}

/** Every value for `name` in a query string (one decode each). */
function paramValues(search: string, name: string): (string | null)[] {
  const q = search.startsWith('?') ? search.slice(1) : search;
  const out: (string | null)[] = [];
  if (!q) return out;
  for (const part of q.split('&')) {
    const eq = part.indexOf('=');
    const rawKey = eq === -1 ? part : part.slice(0, eq);
    if (decodeComponent(rawKey) !== name) continue;
    out.push(eq === -1 ? '' : decodeComponent(part.slice(eq + 1)));
  }
  return out;
}

export interface ApprovalPageParams {
  /** `approvals` when the query asks for the approval screen. */
  view: string | null;
  /** The action to focus, when a single well-formed UUID was supplied. */
  actionId: string | null;
  /** APPROVAL_RETURN_URL when exactly one allowlisted value was supplied. */
  returnTo: string | null;
  /** True when a `return_to` was present but refused (so the page can say it will not redirect). */
  returnToRefused: boolean;
}

/** Parse `window.location.search` for the approval hand-off. Pure. */
export function readApprovalPageParams(search: unknown): ApprovalPageParams {
  const none: ApprovalPageParams = { view: null, actionId: null, returnTo: null, returnToRefused: false };
  if (typeof search !== 'string' || search.length === 0) return none;
  if (search.length > MAX_QUERY_LENGTH) return { ...none, returnToRefused: true };
  const views = paramValues(search, 'view');
  const actions = paramValues(search, 'action');
  const returns = paramValues(search, 'return_to');
  const view = views.length === 1 && typeof views[0] === 'string' && /^[a-z]{1,20}$/.test(views[0]) ? views[0] : null;
  const actionId = actions.length === 1 ? normalizeActionId(actions[0]) : null;
  const returnTo = returns.length === 1 ? acceptReturnTo(returns[0]) : null;
  return { view, actionId, returnTo, returnToRefused: returns.length > 0 && returnTo === null };
}

/** Where the web page sends the person after a completed decision: the allowlisted
 *  return URL plus the validated action id, nothing else. */
export function buildApprovalReturnUrl(returnTo: unknown, actionId: unknown): string | null {
  const base = acceptReturnTo(returnTo);
  const id = normalizeActionId(actionId);
  return base && id ? `${base}?action=${id}` : null;
}

/**
 * Mobile side: is this deep link a well-formed approval return, and for which action?
 * Only `consultantstudio://approvals/done?action=<uuid>` with exactly one parameter is
 * accepted. A valid return still proves nothing — the caller re-fetches the action.
 */
export function parseApprovalReturn(url: unknown): { actionId: string } | null {
  if (typeof url !== 'string' || url.length > APPROVAL_RETURN_URL.length + 1 + 7 + 36) return null;
  const prefix = `${APPROVAL_RETURN_URL}?`;
  if (!url.startsWith(prefix)) return null;
  const query = url.slice(prefix.length);
  if (query.includes('#') || query.split('&').length !== 1) return null;
  const values = paramValues(query, 'action');
  if (values.length !== 1) return null;
  const id = normalizeActionId(values[0]);
  return id && query === `action=${id}` ? { actionId: id } : null;
}

const WEB_URL_RE = /^(https):\/\/([a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?(?:\.[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?)*)(:\d{1,5})?(\/[A-Za-z0-9._~\-/]*)?$/;
const DEV_WEB_URL_RE = /^(http):\/\/(localhost|127\.0\.0\.1|10\.0\.2\.2)(:\d{1,5})?(\/[A-Za-z0-9._~\-/]*)?$/;

/**
 * The web app origin (+ optional path) that hosts the approval page. HTTPS only, except
 * loopback/emulator hosts for development. No credentials, query, fragment, whitespace
 * or non-ASCII host. Returns the base without a trailing slash, or null.
 */
export function validateWebUrl(raw: unknown, opts: { allowDevHttp?: boolean } = {}): string | null {
  if (typeof raw !== 'string' || raw.length === 0 || raw.length > 2048) return null;
  const ok = WEB_URL_RE.test(raw) || (opts.allowDevHttp === true && DEV_WEB_URL_RE.test(raw));
  if (!ok) return null;
  const m = /^(\w+:\/\/[^/]+)(\/.*)?$/.exec(raw);
  if (!m) return null;
  const path = (m[2] ?? '').replace(/\/+$/, '');
  if (path.split('/').some(seg => seg === '..' || seg === '.')) return null;
  return m[1] + path;
}

/** The page the mobile app opens in an auth session to approve one action. */
export function buildApprovalHandoffUrl(webUrl: unknown, actionId: unknown, opts: { allowDevHttp?: boolean } = {}): string | null {
  const base = validateWebUrl(webUrl, opts);
  const id = normalizeActionId(actionId);
  if (!base || !id) return null;
  return `${base}/?view=approvals&action=${id}&return_to=${encodeURIComponent(APPROVAL_RETURN_URL)}`;
}
