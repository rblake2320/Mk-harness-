import { useEffect, useRef, useState } from 'react';
import { MKClient, MfaCompletion, SecondFactor, Tokens } from '../../../packages/sdk/src/index.ts';
import { ErrorNote } from './Common.tsx';

function FactorInput({ recovery, setRecovery, value, setValue }: {
  recovery: boolean; setRecovery: (x: boolean) => void; value: string; setValue: (x: string) => void;
}) {
  return <>
    <label>{recovery ? 'Recovery code' : 'Authenticator code'}
      <input autoComplete="one-time-code" inputMode={recovery ? 'text' : 'numeric'} value={value}
        required maxLength={recovery ? 64 : 6} pattern={recovery ? undefined : '[0-9]{6}'}
        onChange={e => setValue(e.target.value.trim())} />
    </label>
    <button type="button" className="btn ghost" onClick={() => { setRecovery(!recovery); setValue(''); }}>
      {recovery ? 'Use authenticator instead' : 'Use a recovery code'}
    </button>
  </>;
}
const factor = (recovery: boolean, value: string): SecondFactor => recovery ? { recovery_code: value } : { code: value };

export function MfaScreen({ client, tokens, onVerified, onSignOut }: {
  client: MKClient; tokens: Tokens; onVerified: (tokens: Tokens) => void; onSignOut: () => void;
}) {
  const enrollment = tokens.mfa_state === 'enrollment_required';
  const [secret, setSecret] = useState('');
  const [value, setValue] = useState('');
  const [recovery, setRecovery] = useState(false);
  const [result, setResult] = useState<MfaCompletion | null>(null);
  const [error, setError] = useState<unknown>(null);
  const [busy, setBusy] = useState(false);
  async function begin() {
    setError(null); setBusy(true);
    try { setSecret((await client.enrollMfa()).secret); } catch (e) { setError(e); } finally { setBusy(false); }
  }
  async function submit(event: React.FormEvent) {
    event.preventDefault(); setError(null); setBusy(true);
    try {
      const completed = enrollment ? await client.confirmMfa(value) : await client.verifyMfa(factor(recovery, value));
      // The old bearer has been revoked. Keep the replacement only in memory
      // until recovery codes are acknowledged; never persist the secrets.
      client.tokens = completed.tokens;
      setSecret(''); setValue('');
      if (completed.recovery_codes) setResult(completed); else onVerified(completed.tokens);
    } catch (e) { setError(e); } finally { setBusy(false); }
  }
  return <main className="auth-wrap"><div className="card auth-card">
    <h1>{result ? 'Save your recovery codes' : enrollment ? 'Protect your account' : 'Verify your sign-in'}</h1>
    {result ? <>
      <p>Store these eight one-use codes in your password manager. They are shown only now. Anyone with your password and a code can sign in.</p>
      <ul className="recovery-codes">{result.recovery_codes!.map(code => <li key={code}><code>{code}</code></li>)}</ul>
      <button className="btn" onClick={() => onVerified(result.tokens)}>I saved my recovery codes</button>
    </> : <>
      <p>Password alone cannot access your data. Use an authenticator app. Each code works once; wait for the next code if you just used one.</p>
      {enrollment && !secret && <button className="btn" disabled={busy} onClick={begin}>Set up authenticator</button>}
      {secret && <div><p>In your authenticator, add a time-based account named Consultant Studio and enter this setup key:</p>
        <code data-testid="mfa-setup-key" className="mfa-secret">{secret}</code>
        <p>Keep the key private. Enter the six-digit code from your authenticator below.</p></div>}
      {(!enrollment || secret) && <form onSubmit={submit} className="auth-form">
        {enrollment ? <label>Authenticator code<input autoComplete="one-time-code" inputMode="numeric" pattern="[0-9]{6}" maxLength={6}
          required value={value} onChange={e => setValue(e.target.value.trim())} /></label>
          : <FactorInput {...{ recovery, setRecovery, value, setValue }} />}
        <button className="btn" disabled={busy}>{busy ? 'Checking…' : 'Verify code'}</button>
      </form>}
    </>}
    <ErrorNote error={error} />
    <button className="btn ghost" disabled={busy} onClick={onSignOut}>Sign out</button>
  </div></main>;
}

export function StepUpDialog({ client, onClose }: { client: MKClient; onClose: (ok: boolean) => void }) {
  const dialog = useRef<HTMLDialogElement>(null);
  const [password, setPassword] = useState('');
  const [value, setValue] = useState('');
  const [recovery, setRecovery] = useState(false);
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<unknown>(null);
  useEffect(() => {
    const el = dialog.current!;
    const previous = document.activeElement as HTMLElement | null;
    el.showModal();
    return () => { el.close(); previous?.focus(); };
  }, []);
  return <dialog ref={dialog} className="card step-up-dialog" aria-labelledby="step-up-title"
    onCancel={e => { e.preventDefault(); if (!busy) onClose(false); }}>
    <h2 id="step-up-title">Confirm this sensitive action</h2>
    <p>Enter your password and a fresh authenticator or recovery code. This authorizes sensitive changes for five minutes in this session only.</p>
    <form className="auth-form" onSubmit={async e => {
      e.preventDefault(); setBusy(true); setError(null);
      try { await client.stepUp(password, factor(recovery, value)); onClose(true); }
      catch (err) { setError(err); } finally { setBusy(false); }
    }}>
      <label>Password<input autoFocus type="password" autoComplete="current-password" required value={password} onChange={e => setPassword(e.target.value)} /></label>
      <FactorInput {...{ recovery, setRecovery, value, setValue }} />
      <ErrorNote error={error} />
      <button className="btn" disabled={busy}>{busy ? 'Checking…' : 'Confirm identity'}</button>
      <button type="button" className="btn ghost" disabled={busy} onClick={() => onClose(false)}>Cancel</button>
    </form>
  </dialog>;
}
