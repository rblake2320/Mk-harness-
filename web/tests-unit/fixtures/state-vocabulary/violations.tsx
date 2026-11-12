// NEGATIVE FIXTURE for web/tests-unit/state-vocabulary.test.ts — every marked line is a
// violation the lint must report. Not compiled into the app.
export const LOCAL_LABELS = {
  provider_accepted: 'Accepted by provider', // R2 (also R1 paraphrase)
  sent: 'Sent', // R2 + R1
  delivered: 'Delivered', // R2 + R1
};
export const ONE_LOCAL_LABEL = { delivery_unknown: 'Not sure yet' }; // R2

export function Toasts({ n, name }: { n: number; name: string }) {
  const a = 'Sent!'; // R1
  const b = "Message sent"; // R1
  const c = `Message sent to ${name}`; // R3
  const d = `${n} delivered`; // R1 (template part)
  const e = 'Your text was delivered successfully.'; // R3
  const f = 'SENT'; // R1 (case)
  return (
    <div title="Delivered ✓">
      <span>Delivered</span>
      <span>sent</span>
      <span>Provider accepted</span>
      <p>Great news — message delivered!</p>
      <img alt="Message sent" />
      {a}{b}{c}{d}{e}{f}
    </div>
  );
}
