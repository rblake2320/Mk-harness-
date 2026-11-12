/**
 * "Approve with passkey" on mobile. React Native has no WebAuthn API and approval must
 * stay a passkey ceremony that the kernel verifies, so the app opens the web approval page
 * for exactly one action in an auth session and, whatever happens there, re-reads the
 * action from the API. There is deliberately no other approval path in the mobile app
 * (`mobile/src/logic/a11y.test.ts` fails if one appears).
 */
import * as WebBrowser from 'expo-web-browser';
import { APPROVAL_RETURN_URL, buildApprovalHandoffUrl } from '../../packages/sdk/src/index';
import type { ActionStatus } from '../../packages/sdk/src/index';
import { WEB_URL, client } from './api';
import { interpretAuthSessionResult, type ReturnDecision } from './logic/approvalReturn';

export type HandoffOutcome =
  | { kind: 'unavailable'; note: string }
  | { kind: 'done'; decision: ReturnDecision; status: ActionStatus | null; error: unknown };

export async function approveOnWeb(actionId: string): Promise<HandoffOutcome> {
  const url = buildApprovalHandoffUrl(WEB_URL, actionId, { allowDevHttp: __DEV__ });
  if (!url) {
    return { kind: 'unavailable', note: 'The web approval page is not configured for this build, so approval is not possible from this app. Approve on the web app.' };
  }
  let result: Awaited<ReturnType<typeof WebBrowser.openAuthSessionAsync>> | null = null;
  try {
    result = await WebBrowser.openAuthSessionAsync(url, APPROVAL_RETURN_URL);
  } catch {
    result = null;
  }
  const decision = interpretAuthSessionResult(result, actionId);
  try {
    const status = await client.actionStatus(decision.refetchActionId);
    return { kind: 'done', decision, status, error: null };
  } catch (error) {
    return { kind: 'done', decision, status: null, error };
  }
}
