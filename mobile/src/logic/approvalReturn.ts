/**
 * What the app does after the web approval page closes (row H6 on mobile).
 *
 * The auth session can end because the page redirected to the app, because the person
 * closed it, or because another session was open. In EVERY case the app re-reads the
 * action it opened from the API and shows the kernel's state; nothing here reports an
 * approval. A redirect for a different action, or one that is malformed, never changes
 * which action is re-read.
 */
import { parseApprovalReturn } from '../../../packages/sdk/src/index';

/** The subset of expo-web-browser's WebBrowserAuthSessionResult this logic reads. */
export type AuthSessionResult = { type: 'success'; url: string } | { type: string; url?: undefined };

export interface ReturnDecision {
  /** Always the action the person opened — the only one the app re-reads. */
  refetchActionId: string;
  /** Shown while and after re-reading; never claims an approval. */
  note: string;
  /** For diagnostics only: what came back, if anything. */
  returned: 'matching' | 'other_action' | 'unrecognised' | 'closed' | 'busy' | 'none';
}

export function interpretAuthSessionResult(result: AuthSessionResult | null | undefined, requestedActionId: string): ReturnDecision {
  const checking = 'Checking what the kernel reports for this message…';
  if (!result || typeof result.type !== 'string') {
    return { refetchActionId: requestedActionId, returned: 'none', note: `The approval page did not report back. ${checking}` };
  }
  if (result.type === 'success') {
    const parsed = parseApprovalReturn(result.url);
    if (!parsed) return { refetchActionId: requestedActionId, returned: 'unrecognised', note: `The page returned an unrecognised link, which is ignored. ${checking}` };
    if (parsed.actionId !== requestedActionId) {
      return { refetchActionId: requestedActionId, returned: 'other_action', note: `The page returned for a different message, which is ignored. ${checking}` };
    }
    return { refetchActionId: requestedActionId, returned: 'matching', note: `Back from the approval page. ${checking}` };
  }
  if (result.type === 'locked') {
    return { refetchActionId: requestedActionId, returned: 'busy', note: `Another sign-in window is already open; finish or close it first. ${checking}` };
  }
  return { refetchActionId: requestedActionId, returned: 'closed', note: `The approval page was closed. If you approved there, the kernel has the result. ${checking}` };
}

/** Extra guidance under the kernel's state after a hand-off. The state itself is always
 *  shown verbatim from the vocabulary; this only adds what to do next. */
export function afterHandoffHint(messageState: unknown): string | null {
  if (messageState === 'awaiting_approval') return 'Not approved yet. If you approved on the web page a moment ago, pull down to refresh.';
  if (messageState === undefined || messageState === null) return 'The state was not reported. Do not assume the message was approved.';
  return null;
}
