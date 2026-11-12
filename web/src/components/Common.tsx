import { ApiError } from '../../../packages/sdk/src/index.ts';

/**
 * Plain-language errors with a recovery step (contract: "plain-language errors
 * and recovery instructions"). Every kernel/API code the interface can meet maps
 * to what happened and what the person can do next — never a raw code alone.
 */
const EXPLANATIONS: Record<string, { what: string; next: string }> = {
  WEBAUTHN_REQUIRED: { what: 'Approving needs your passkey.', next: 'Register a passkey in Settings, then approve again.' },
  NO_APPROVAL_CREDENTIAL: { what: 'You have no passkey registered for approvals.', next: 'Open Settings → Approval passkeys and add one.' },
  WEBAUTHN_CREDENTIAL_MISMATCH: { what: 'That passkey is not registered to your account.', next: 'Use a passkey you registered here, or add this one in Settings.' },
  WEBAUTHN_BAD_SIGNATURE: { what: 'The passkey signature did not verify.', next: 'Try again. If it keeps failing, re-register the passkey.' },
  WEBAUTHN_CHALLENGE_MISMATCH: { what: 'The approval challenge expired or was already used.', next: 'Approve again — a fresh challenge is issued each time.' },
  APPROVAL_DIGEST_MISMATCH: { what: 'This message changed since it was shown to you.', next: 'Review the current text and approve that version.' },
  AGENT_CANNOT_APPROVE: { what: 'Automated principals cannot approve messages.', next: 'Sign in as yourself to approve.' },
  SELF_APPROVAL_FORBIDDEN: { what: 'Your team requires a second person to approve this kind of message.', next: 'Ask another consultant or your admin to approve it.' },
  PRINCIPAL_REVOKED: { what: 'Your session was revoked.', next: 'Sign in again. If you did not revoke it, contact your admin.' },
  TIMEZONE_UNKNOWN: { what: "This customer's timezone is not set, so contact hours cannot be respected.", next: "Set it on the customer's page before sending." },
  NO_SMS_DESTINATION: { what: 'This customer has no mobile number on file.', next: 'Add an SMS destination on the customer page.' },
  NO_SENDER_IDENTITY: { what: 'Your business has no registered sending number yet.', next: 'Ask your admin to register one in Settings → Sending number.' },
  SENDER_NOT_FOUND: { what: 'The requested sending number is not registered to your team.', next: 'Pick a registered sender or ask your admin.' },
  CONTACT_PERMISSION_MISSING: { what: 'This customer has not given permission for this kind of message.', next: 'Record their consent (with evidence) before proposing outreach.' },
  CONTACT_PERMISSION_DESTINATION_MISMATCH: { what: 'The customer gave permission for a different number or address than this message is addressed to.', next: 'Send to the destination their consent covers, or record consent (with evidence) for this one.' },
  SUPPRESSED: { what: 'This customer asked not to be contacted on this channel.', next: 'Nothing can be sent. Re-consent requires fresh, purpose-specific evidence from the customer.' },
  DISPATCH_DISABLED: { what: 'Sending is paused for your team right now.', next: 'Your admin or the platform operator controls the pause. Nothing was sent.' },
  OUTSIDE_CONTACT_HOURS: { what: "It is outside the customer's contact hours.", next: 'The message will not be sent now. Propose it again inside allowed hours.' },
  FREQUENCY_EXCEEDED: { what: 'This customer has already received the daily limit of messages.', next: 'Wait until tomorrow or record the follow-up as resolved.' },
  CONTRACT_VIOLATION: { what: 'The request did not match the required format.', next: 'Reload and try again. If it repeats, report it with the request id.' },
  KERNEL_UNAVAILABLE: { what: 'The action kernel is unreachable, so nothing can be approved or sent.', next: 'Try again in a minute. Nothing was sent or recorded.' },
  KERNEL_NOT_CONFIGURED: { what: 'Governed actions are not enabled in this environment.', next: 'An operator must configure the kernel connection.' },
  UNAPPROVED_CLAIM_LANGUAGE: { what: 'Your edit contains a product claim that is not in the approved list.', next: 'Keep product statements to the approved wording, or ask your admin to add the claim.' },
  CONTEXT_LEAK: { what: 'Your edit references another customer or private notes.', next: 'Remove the reference and save again.' },
  STEP_UP_REQUIRED: { what: 'This change needs you to confirm it\'s you.', next: 'Try again and confirm with your authenticator app or passkey. Nothing was changed.' },
  MFA_ENROLLMENT_REQUIRED: { what: 'Your account needs a second sign-in step first.', next: 'Sign out and back in to set it up.' },
  PERMISSION_DENIED: { what: 'Your role does not include this.', next: 'Ask an admin or owner if you need it.' },
  ROUTE_NOT_AUTHORIZED: { what: 'This is not available to your account.', next: 'Ask an admin or owner if you need it.' },
  BREAKGLASS_READ_ONLY: { what: 'Support access is read-only.', next: 'Changes must be made by the business itself.' },
  LAST_OWNER: { what: 'A business must keep at least one active owner.', next: 'Make someone else an owner first.' },
  LAST_FACTOR: { what: 'This is your only second factor, and your business requires one.', next: 'Add another factor before removing this one.' },
  OWNER_REQUIRED: { what: 'Only an owner can change an owner or admin.', next: 'Ask an owner to make this change.' },
  SELF_DEACTIVATION: { what: 'You cannot deactivate your own account here.', next: 'Ask another owner or admin.' },
  SELF_APPROVAL: { what: 'You cannot approve your own support-access request.', next: 'Another admin must decide it.' },
  NOT_PENDING: { what: 'That request was already decided.', next: 'Refresh to see its current state.' },
  NOT_APPROVED: { what: 'That access is not active.', next: 'Refresh to see its current state.' },
  WORKS_FOR_REQUIRED: { what: 'Assistants and viewers must be assigned to a consultant\'s book.', next: 'Choose whose customer book they work in.' },
  NO_FACTOR: { what: 'Your account has no second factor to confirm with.', next: 'Add one in Settings → Sign-in security.' },
  INBOUND_PAUSED: { what: 'Sending is paused because inbound messages cannot be received right now.', next: 'Messages stay queued and resume when the inbound path is healthy.' },
};

export function explain(e: unknown): { what: string; next: string; code?: string; requestId?: string } {
  if (e instanceof ApiError) {
    const d = e.detail;
    const code: string | undefined = (typeof d === 'object' && d) ? (d.code ?? d.decision?.code ?? '').toString().toUpperCase() : undefined;
    const reqId = typeof d === 'object' && d ? d.request_id : undefined;
    if (code && EXPLANATIONS[code]) return { ...EXPLANATIONS[code], code, requestId: reqId };
    if (e.status === 503) return { ...EXPLANATIONS.KERNEL_UNAVAILABLE, code: code ?? 'UNAVAILABLE', requestId: reqId };
    if (e.status === 401) return { what: 'Your sign-in expired.', next: 'Sign in again.', code: 'UNAUTHORIZED' };
    if (e.status === 403) return { what: 'You do not have permission for that.', next: 'Ask your admin if you need this access.', code: code ?? 'FORBIDDEN' };
    if (e.status === 404) return { what: 'That item was not found.', next: 'It may belong to another consultant or have been removed. Refresh the page.' };
    const msg = typeof d === 'string' ? d : (d?.detail ?? d?.message ?? e.message);
    return { what: String(msg), next: 'Try again. If it repeats, report it with the request id.', code, requestId: reqId };
  }
  return { what: (e as any)?.message ?? 'Something went wrong.', next: 'Try again.' };
}

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

export const STATE_LABEL: Record<string, string> = {
  proposed: 'Proposed', awaiting_approval: 'Awaiting your approval', approved: 'Approved', queued: 'Queued',
  dispatch_authorized: 'Authorized to send', submission_started: 'Submitting', provider_accepted: 'Accepted by provider',
  sent: 'Sent', delivered: 'Delivered', failed: 'Failed', delivery_unknown: 'Delivery unknown', submission_unknown: 'Submission unknown — needs a person',
  cancelled: 'Cancelled', denied: 'Denied by policy', expired: 'Expired',
};

export function StateBadge({ state, definitions }: { state: string | null | undefined; definitions?: Record<string, string> }) {
  if (!state) return null;
  const title = definitions?.[state];
  return <span className={`badge state-${state}`} title={title}>{STATE_LABEL[state] ?? state}</span>;
}

export function fmtWhen(iso: string | null | undefined) {
  if (!iso) return '—';
  try { return new Date(iso).toLocaleString(undefined, { dateStyle: 'medium', timeStyle: 'short' }); } catch { return iso; }
}
