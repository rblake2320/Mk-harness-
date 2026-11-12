// CLEAN FIXTURE for web/tests-unit/state-vocabulary.test.ts — ordinary copy and code that
// mentions the same words without claiming a message state. The lint must report nothing.
import type { MessageState } from '../../../../packages/sdk/src/index';
type Local = 'sent' | 'delivered' | 'provider_accepted';
// Comments are not copy: "Delivered", "Message sent!", sent: 'Sent'.
export const TERMINAL: MessageState[] = ['sent', 'delivered', 'failed'];
export const OUTCOME_LABEL = { cancelled: 'Commitment cancelled', resolved: 'Resolved' };
export const COUNTS = { sent: 2, delivered: 1 };
export const IDS = { sent: 'sent', delivered: 'delivered' };
export function isDone(s: Local | string) { return s === 'delivered' || s === 'sent' || s === 'provider_accepted'; }
export function Copy({ state }: { state: string }) {
  switch (state) { case 'sent': return null; default: break; }
  return (
    <div className={`badge state-${state}`} data-state="delivered">
      <button>Send</button>
      <span>Nothing has been sent.</span>
      <span>Rejected. Nothing will be sent.</span>
      <span>What you approve is exactly what is submitted.</span>
      <span>Sending number</span>
      <span>No message sent yet</span>
      <span>The message was not delivered by the provider</span>
      <span>Proposing never submits anything.</span>
      <span>A delivered message is not a resolved commitment.</span>
      <span>Delivery or submission unknown — a person must check</span>
      <span>Consent recorded</span>
      <span>Resend later</span>
      <span>If a message was sent, the kernel records it.</span>
      <StateLike state="sent" />
    </div>
  );
}
function StateLike(_: { state: string }) { return null; }
