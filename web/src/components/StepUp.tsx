import { useEffect, useRef, useState } from 'react';
import { client } from '../App.tsx';
import { explain } from './Common.tsx';

/**
 * Step-up prompt (S2). The SDK calls `client.onStepUpRequired(methods)` when the API
 * answers 403 STEP_UP_REQUIRED; this dialog collects a fresh second factor, and the
 * SDK retries the original request once on success. Cancelling leaves the change
 * undone — nothing is retried.
 */
type Pending = { methods: string[]; resolve: (ok: boolean) => void };

export function StepUpHost() {
  const [pending, setPending] = useState<Pending | null>(null);
  useEffect(() => {
    client.onStepUpRequired = methods => new Promise<boolean>(resolve => setPending({ methods, resolve }));
    return () => { client.onStepUpRequired = null; };
  }, []);
  if (!pending) return null;
  const done = (ok: boolean) => { pending.resolve(ok); setPending(null); };
  return <StepUpDialog methods={pending.methods} onDone={done} />;
}

function StepUpDialog({ methods, onDone }: { methods: string[]; onDone: (ok: boolean) => void }) {
  const [code, setCode] = useState('');
  const [pw, setPw] = useState('');
  const [err, setErr] = useState<unknown>(null);
  const [busy, setBusy] = useState(false);
  const first = useRef<HTMLInputElement>(null);
  useEffect(() => { first.current?.focus(); }, []);

  async function run(fn: () => Promise<unknown>) {
    setErr(null); setBusy(true);
    try { await fn(); onDone(true); } catch (e) { setErr(e); } finally { setBusy(false); }
  }
  const hasTotp = methods.includes('totp');
  const hasPasskey = methods.includes('webauthn');
  const passwordOnly = methods.length === 1 && methods[0] === 'password';

  return (
    <div className="modal-backdrop" role="dialog" aria-modal="true" aria-labelledby="stepup-title"
         onKeyDown={e => e.key === 'Escape' && onDone(false)}>
      <div className="card modal">
        <h3 id="stepup-title" style={{ marginTop: 0 }}>Confirm it's you</h3>
        <p className="muted" style={{ marginTop: 0 }}>
          This change needs a fresh check of your second factor. Nothing has been changed yet.
        </p>
        {hasTotp && (
          <>
            <label className="small" htmlFor="stepup-code">Code from your authenticator app</label>
            <input id="stepup-code" ref={first} inputMode="numeric" autoComplete="one-time-code" maxLength={8}
                   value={code} onChange={e => setCode(e.target.value.replace(/\D/g, ''))}
                   onKeyDown={e => e.key === 'Enter' && code.length === 6 && run(() => client.stepUp('totp', { code }))} />
            <button className="btn" disabled={busy || code.length !== 6} onClick={() => run(() => client.stepUp('totp', { code }))}>
              Confirm
            </button>
          </>
        )}
        {hasPasskey && (
          <button className={hasTotp ? 'btn ghost' : 'btn'} disabled={busy} onClick={() => run(() => client.stepUpWithPasskey())}>
            Use a passkey
          </button>
        )}
        {passwordOnly && (
          <>
            <label className="small" htmlFor="stepup-pw">Your password</label>
            <input id="stepup-pw" ref={first} type="password" autoComplete="current-password"
                   value={pw} onChange={e => setPw(e.target.value)}
                   onKeyDown={e => e.key === 'Enter' && run(() => client.stepUp('password', { password: pw }))} />
            <button className="btn" disabled={busy || !pw} onClick={() => run(() => client.stepUp('password', { password: pw }))}>
              Confirm
            </button>
          </>
        )}
        {!hasTotp && !hasPasskey && !passwordOnly && (
          <p className="error" role="alert">Your account has no second factor that can confirm this. Add one in Settings → Sign-in security.</p>
        )}
        {err ? <div className="error" role="alert">{explainFactor(err)}</div> : null}
        <button className="btn ghost" onClick={() => onDone(false)}>Cancel</button>
      </div>
    </div>
  );
}

export function explainFactor(e: unknown): string {
  const x = explain(e);
  const d: any = (e as any)?.detail;
  if (d?.code === 'SECOND_FACTOR_INVALID') {
    return `That was not accepted.${typeof d.attempts_left === 'number' ? ` ${d.attempts_left} attempt(s) left before you are signed out.` : ''}`;
  }
  if (d?.code === 'SESSION_ENDED') return 'Too many failed attempts — you have been signed out. Sign in again.';
  return `${x.what} ${x.next}`;
}
