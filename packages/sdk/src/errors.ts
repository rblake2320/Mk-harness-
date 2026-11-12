/**
 * API errors and their plain-language explanations (contract: "plain-language errors
 * and recovery instructions"), shared by web and mobile so both say the same thing.
 *
 * Three body shapes reach the client and all three must keep the machine code:
 *  1. RFC 9457 problem details, forwarded verbatim from the kernel by `/api/agent-ops/*`
 *     (`{type, title, status, code, request_id, detail?}` — `contracts/action/v1/error.schema.json`).
 *  2. FastAPI `HTTPException` with a dict detail: `{detail: {code, detail}}`, or a
 *     kernel problem wrapped by a FastAPI route: `{detail: {type, title, status, code, …}}`.
 *  3. FastAPI string details `{detail: "…"}` and pydantic validation lists `{detail: [{loc, msg}]}`.
 * Before this module, shape 1 lost its code (only `.detail` was read), so a kernel
 * 403 SELF_APPROVAL_FORBIDDEN or 409 APPROVAL_DIGEST_MISMATCH surfaced as "HTTP 403".
 */

export interface ProblemDetail {
  code?: string;
  message?: string;
  title?: string;
  detail?: unknown;
  request_id?: string;
  fields?: string[];
  [k: string]: unknown;
}

const CODE_RE = /^[A-Za-z][A-Za-z0-9_.-]{1,63}$/;

function normCode(v: unknown): string | undefined {
  return typeof v === 'string' && CODE_RE.test(v) ? v.toUpperCase() : undefined;
}

function isRecord(v: unknown): v is Record<string, unknown> {
  return typeof v === 'object' && v !== null && !Array.isArray(v);
}

function isProblem(v: unknown): v is Record<string, unknown> {
  return isRecord(v) && typeof v.code === 'string' && (typeof v.type === 'string' || typeof v.title === 'string');
}

function validationSummary(list: unknown[]): ProblemDetail {
  const fields = list.slice(0, 8).map(x => {
    if (!isRecord(x)) return String(x).slice(0, 120);
    const loc = Array.isArray(x.loc) ? x.loc.filter(p => p !== 'body').join('.') : '';
    const msg = typeof x.msg === 'string' ? x.msg : 'invalid';
    return (loc ? `${loc}: ${msg}` : msg).slice(0, 160);
  });
  return { code: 'VALIDATION_ERROR', message: fields.join('; ') || 'The request was not accepted.', fields };
}

/** Normalise any error body into the `detail` an ApiError carries: a string, or a
 *  ProblemDetail with an upper-case `code` when one exists. Pure; never throws. */
export function errorDetailFromBody(status: number, body: unknown): string | ProblemDetail {
  if (isProblem(body)) {
    return { ...body, code: normCode(body.code), title: typeof body.title === 'string' ? body.title : undefined,
      message: typeof body.detail === 'string' ? body.detail : (typeof body.title === 'string' ? body.title : undefined),
      request_id: typeof body.request_id === 'string' ? body.request_id : undefined };
  }
  if (isRecord(body) && 'detail' in body) {
    const d = body.detail;
    if (typeof d === 'string') return d;
    if (Array.isArray(d)) return validationSummary(d);
    if (isProblem(d)) return errorDetailFromBody(status, d);
    if (isRecord(d)) {
      const message = typeof d.message === 'string' ? d.message : (typeof d.detail === 'string' ? d.detail : undefined);
      const decision = isRecord(d.decision) ? d.decision : undefined;
      return { ...d, code: normCode(d.code) ?? normCode(decision?.code), message,
        request_id: typeof d.request_id === 'string' ? d.request_id : undefined };
    }
  }
  return `HTTP ${status}`;
}

/** Structured API error: `status` is the HTTP code; `detail` is a string or a
 *  ProblemDetail (see `errorDetailFromBody`). */
export class ApiError extends Error {
  status: number;
  detail: any;
  retryAfter?: number;
  constructor(status: number, detail: any, retryAfter?: number) {
    super(typeof detail === 'string' ? detail : (detail?.message ?? detail?.title ?? `HTTP ${status}`));
    this.status = status; this.detail = detail; this.name = 'ApiError';
    if (retryAfter !== undefined && Number.isFinite(retryAfter) && retryAfter >= 0) this.retryAfter = retryAfter;
  }
  get code(): string | undefined {
    return isRecord(this.detail) ? normCode(this.detail.code) : undefined;
  }
  get requestId(): string | undefined {
    return isRecord(this.detail) && typeof this.detail.request_id === 'string' ? this.detail.request_id : undefined;
  }
}

/** Build the ApiError for a non-2xx response. `retryAfterHeader` is the raw header. */
export function apiErrorFrom(status: number, body: unknown, retryAfterHeader?: string | null): ApiError {
  const ra = retryAfterHeader && /^\d{1,6}$/.test(retryAfterHeader.trim()) ? Number(retryAfterHeader.trim()) : undefined;
  return new ApiError(status, errorDetailFromBody(status, body), ra);
}

export interface Explanation { what: string; next: string; code?: string; requestId?: string }

/**
 * Every kernel/API code the interface can meet maps to what happened and what the
 * person can do next — never a raw code alone. Wording is platform-neutral: passkeys
 * are registered in the web app's Settings on every platform.
 */
export const EXPLANATIONS: Readonly<Record<string, { what: string; next: string }>> = Object.freeze({
  WEBAUTHN_REQUIRED: { what: 'Approving needs your passkey.', next: 'Register an approval passkey in Settings on the web app, then approve again.' },
  NO_APPROVAL_CREDENTIAL: { what: 'You have no passkey registered for approvals.', next: 'Open Settings → Approval passkeys on the web app and add one.' },
  WEBAUTHN_CREDENTIAL_MISMATCH: { what: 'That passkey is not registered to your account.', next: 'Use a passkey you registered here, or add this one in Settings.' },
  WEBAUTHN_BAD_SIGNATURE: { what: 'The passkey signature did not verify.', next: 'Try again. If it keeps failing, re-register the passkey.' },
  WEBAUTHN_CHALLENGE_MISMATCH: { what: 'The approval challenge expired or was already used.', next: 'Approve again — a fresh challenge is issued each time.' },
  APPROVAL_DIGEST_MISMATCH: { what: 'This message changed since it was displayed.', next: 'Nothing was approved. Review the current text and approve that version — it needs its own approval.' },
  ILLEGAL_TRANSITION: { what: 'This message is no longer waiting for that decision — it was already decided, withdrawn or expired.', next: 'Nothing was changed. Refresh to see its current state.' },
  AGENT_CANNOT_APPROVE: { what: 'Automated principals cannot approve messages.', next: 'Sign in as yourself to approve.' },
  SELF_APPROVAL_FORBIDDEN: { what: 'Your team requires a second person to approve this kind of message.', next: 'Nothing was approved. Ask another consultant or your admin to approve it.' },
  APPROVER_NOT_AUTHORIZED: { what: 'Your role cannot approve messages.', next: 'Ask a consultant or your admin to approve it.' },
  APPROVAL_EXPIRED: { what: 'The approval window for this message has passed.', next: 'Review it again; a fresh approval is needed.' },
  PRINCIPAL_REVOKED: { what: 'Your session was revoked.', next: 'Sign in again. If you did not revoke it, contact your admin.' },
  TIMEZONE_UNKNOWN: { what: "This customer's timezone is not set, so contact hours cannot be respected.", next: "Set it on the customer's page before proposing a message." },
  NO_SMS_DESTINATION: { what: 'This customer has no mobile number on file.', next: 'Add an SMS destination on the customer page.' },
  NO_SENDER_IDENTITY: { what: 'Your business has no registered sending number yet.', next: 'Ask your admin to register one in Settings → Sending number.' },
  SENDER_NOT_FOUND: { what: 'The requested sending number is not registered to your team.', next: 'Pick a registered sender or ask your admin.' },
  CONTACT_PERMISSION_MISSING: { what: 'This customer has not given permission for this kind of message.', next: 'Record their consent (with evidence) before proposing outreach.' },
  CONTACT_PERMISSION_DESTINATION_MISMATCH: { what: 'The customer gave permission for a different number or address than this message is addressed to.', next: 'Send to the destination their consent covers, or record consent (with evidence) for this one.' },
  SUPPRESSED: { what: 'This customer asked not to be contacted on this channel.', next: 'Nothing can be sent. Re-consent requires fresh, purpose-specific evidence from the customer.' },
  DISPATCH_DISABLED: { what: 'Sending is paused for your team right now.', next: 'Your admin or the platform operator controls the pause. Nothing was sent.' },
  OUTSIDE_CONTACT_HOURS: { what: "It is outside the customer's contact hours.", next: 'The message will not be submitted now. Propose it again inside allowed hours.' },
  FREQUENCY_EXCEEDED: { what: 'This customer has already reached the daily message limit.', next: 'Wait until tomorrow or record the follow-up as resolved.' },
  CONTRACT_VIOLATION: { what: 'The request did not match the required format.', next: 'Reload and try again. If it repeats, report it with the request id.' },
  VALIDATION_ERROR: { what: 'Some details were not accepted.', next: 'Correct them and try again.' },
  KERNEL_UNAVAILABLE: { what: 'The action kernel is unreachable, so nothing can be approved or sent.', next: 'Try again in a minute. Nothing was sent or recorded.' },
  KERNEL_UNREACHABLE: { what: 'The action kernel is unreachable, so nothing can be approved or sent.', next: 'Try again in a minute. Nothing was sent or recorded.' },
  KERNEL_NOT_CONFIGURED: { what: 'Governed actions are not enabled in this environment.', next: 'An operator must configure the kernel connection.' },
  OVER_CAPACITY: { what: 'The service is at capacity right now.', next: 'Wait a moment and try again. Nothing was recorded.' },
  TENANT_RATE_LIMITED: { what: 'Your team has made too many requests in a short time.', next: 'Wait a moment and try again.' },
  UNAPPROVED_CLAIM_LANGUAGE: { what: 'Your edit contains a product claim that is not in the approved list.', next: 'Keep product statements to the approved wording, or ask your admin to add the claim.' },
  CONTROL_LANGUAGE: { what: 'Your edit contains approval, permission or system language that does not belong in a customer message.', next: 'Remove it and save again.' },
  CONTEXT_LEAK: { what: 'Your edit references another customer or private notes.', next: 'Remove the reference and save again.' },
  // identity and roles (S2/S3/S9)
  STEP_UP_REQUIRED: { what: "This change needs you to confirm it's you.", next: 'Try again and confirm with your authenticator app or passkey. Nothing was changed.' },
  SECOND_FACTOR_INVALID: { what: 'That code or passkey was not accepted.', next: 'Try again with a fresh code. Repeated failures sign you out.' },
  SESSION_ENDED: { what: 'This sign-in has ended.', next: 'Sign in again.' },
  MFA_ENROLLMENT_REQUIRED: { what: 'Your account needs a second sign-in step first.', next: 'Sign out and back in to set it up.' },
  PERMISSION_DENIED: { what: 'Your role does not include this.', next: 'Nothing was changed. Ask an admin or owner if you need it.' },
  ROUTE_NOT_AUTHORIZED: { what: 'This is not available to your account.', next: 'Ask an admin or owner if you need it.' },
  BREAKGLASS_READ_ONLY: { what: 'Support access is read-only.', next: 'Changes must be made by the business itself.' },
  LAST_OWNER: { what: 'A business must keep at least one active owner.', next: 'Make someone else an owner first.' },
  LAST_FACTOR: { what: 'This is your only second factor, and your business requires one.', next: 'Add another factor before removing this one.' },
  OWNER_REQUIRED: { what: 'Only an owner can change an owner or admin.', next: 'Ask an owner to make this change.' },
  SELF_DEACTIVATION: { what: 'You cannot deactivate your own account here.', next: 'Ask another owner or admin.' },
  SELF_APPROVAL: { what: 'You cannot approve your own support-access request.', next: 'Another admin must decide it.' },
  NOT_PENDING: { what: 'That request was already decided.', next: 'Refresh to see its current state.' },
  NOT_APPROVED: { what: 'That access is not active.', next: 'Refresh to see its current state.' },
  WORKS_FOR_REQUIRED: { what: "Assistants and viewers must be assigned to a consultant's book.", next: 'Choose whose customer book they work in.' },
  NO_FACTOR: { what: 'Your account has no second factor to confirm with.', next: 'Add one in Settings → Sign-in security.' },
  INBOUND_PAUSED: { what: 'Sending is paused because replies cannot be received right now.', next: 'Messages stay queued and resume when the reply path is healthy.' },
});

function lookup(code: string | undefined) {
  return code && Object.prototype.hasOwnProperty.call(EXPLANATIONS, code) ? EXPLANATIONS[code] : undefined;
}

export function explain(e: unknown): Explanation {
  if (e instanceof ApiError) {
    const code = e.code;
    const requestId = e.requestId;
    const known = lookup(code);
    if (known) {
      const extra = code === 'VALIDATION_ERROR' && isRecord(e.detail) && typeof e.detail.message === 'string' ? ` (${e.detail.message})` : '';
      return { what: known.what + extra, next: known.next, code, requestId };
    }
    if (e.status === 401) return { what: 'Your sign-in expired.', next: 'Sign in again.', code: code ?? 'UNAUTHORIZED', requestId };
    if (e.status === 429) {
      return { what: 'Too many requests right now.', next: e.retryAfter !== undefined ? `Wait ${e.retryAfter} seconds and try again.` : 'Wait a moment and try again.', code: code ?? 'RATE_LIMITED', requestId };
    }
    if (e.status === 503) return { ...EXPLANATIONS.KERNEL_UNAVAILABLE, code: code ?? 'UNAVAILABLE', requestId };
    const serverMessage = typeof e.detail === 'string' && !/^HTTP \d{3}$/.test(e.detail) ? e.detail
      : (isRecord(e.detail) && typeof e.detail.message === 'string' ? e.detail.message : undefined);
    if (e.status === 403) {
      return { what: serverMessage ? `Not allowed: ${serverMessage}` : 'You do not have permission for that.', next: 'Nothing was changed. Ask your admin if you need this access.', code: code ?? 'FORBIDDEN', requestId };
    }
    if (e.status === 404) return { what: 'That item was not found.', next: 'It may belong to another consultant or have been removed. Refresh the page.', code, requestId };
    if (e.status === 409) {
      return { what: serverMessage ? `This item changed or is already closed: ${serverMessage}` : 'This item changed since it was shown to you.', next: 'Refresh and review it again.', code: code ?? 'CONFLICT', requestId };
    }
    return { what: serverMessage ?? `The request failed (HTTP ${e.status}).`, next: 'Try again. If it repeats, report it with the request id.', code, requestId };
  }
  const message = isRecord(e) && typeof e.message === 'string' && e.message ? e.message : 'Something went wrong.';
  return { what: message, next: 'Try again.' };
}
