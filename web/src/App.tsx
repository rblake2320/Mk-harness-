import { useEffect, useState } from 'react';
import { MKClient, Tokens, readApprovalPageParams } from '../../packages/sdk/src/index.ts';
import ChatView from './views/Chat.tsx';
import SkinView from './views/Skin.tsx';
import CustomersView from './views/Customers.tsx';
import BillingView from './views/Billing.tsx';
import SettingsView from './views/Settings.tsx';
import BriefView from './views/Brief.tsx';
import ApprovalsView from './views/Approvals.tsx';
import InboxView from './views/Inbox.tsx';
import CustomerDetail from './views/CustomerDetail.tsx';
import GovernanceSettings from './views/Governance.tsx';
import type { Customer } from '../../packages/sdk/src/index.ts';
import { AiNoticeModal } from './components/AiDisclosure.tsx';
import { StepUpHost, explainFactor } from './components/StepUp.tsx';
import SecurityView, { EnrollFactor } from './views/Security.tsx';
import { isMfaChallenge, type MfaChallenge } from '../../packages/sdk/src/index.ts';
import './styles.css';

export const client = new MKClient(import.meta.env.VITE_API_URL ?? '');

const TOKEN_KEY = 'mk_tokens';

function loadTokens(): Tokens | null {
  try { return JSON.parse(sessionStorage.getItem(TOKEN_KEY) ?? 'null'); } catch { return null; }
}

/** Capture a ?ref=CODE referral code from the URL so signup can attribute it. */
function refFromUrl(): string | undefined {
  try { return new URLSearchParams(window.location.search).get('ref') || undefined; }
  catch { return undefined; }
}

/** `?view=approvals&action=<id>&return_to=…` — the mobile passkey hand-off. Read once;
 *  `return_to` is kept only when it exactly matches the allowlist (SDK `handoff.ts`). */
const HANDOFF = (() => {
  try { return readApprovalPageParams(window.location.search); }
  catch { return { view: null, actionId: null, returnTo: null, returnToRefused: false }; }
})();

export default function App() {
  const [tokens, setTokens] = useState<Tokens | null>(loadTokens);
  const [view, setView] = useState<'brief' | 'approvals' | 'inbox' | 'customers' | 'chat' | 'skin' | 'billing' | 'settings'>(
    HANDOFF.view === 'approvals' ? 'approvals' : 'brief');
  const [openCustomer, setOpenCustomer] = useState<Customer | null>(null);
  const [me, setMe] = useState<{ id: string } | null>(null);
  useEffect(() => { if (tokens) client.me().then(setMe).catch(() => {}); }, [tokens]);
  function goCustomer(id: string) {
    client.listCustomers().then(list => { const c = list.find(x => x.id === id); if (c) { setOpenCustomer(c); setView('customers'); } }).catch(() => {});
  }

  useEffect(() => {
    client.tokens = tokens;
    if (tokens) sessionStorage.setItem(TOKEN_KEY, JSON.stringify(tokens));
    else sessionStorage.removeItem(TOKEN_KEY);
    client.onAuthExpired = () => setTokens(null);
    client.onTokensChanged = t => setTokens(prev => (prev ? { ...t, mfa_enrollment_required: prev.mfa_enrollment_required && t.mfa_enrollment_required } : prev));
  }, [tokens]);

  async function signOut() {
    try { await client.logout(); } catch { /* the session is dropped locally either way */ }
    setTokens(null);
  }

  if (!tokens) return <AuthScreen onAuthed={setTokens} />;
  // MFA is required and this account has no second factor: the session can only enroll.
  if (tokens.mfa_enrollment_required) return (
    <div className="auth-wrap">
      <div className="card auth-card">
        <h1 className="display" style={{ fontSize: 28 }}>Protect your account</h1>
        <p className="muted" style={{ margin: 0 }}>
          Your business requires a second step at sign-in. Set it up once; it takes a minute.
        </p>
        <EnrollFactor passkeysAvailable={typeof window !== 'undefined' && !!window.PublicKeyCredential}
                      onDone={() => setTokens({ ...tokens, mfa_enrollment_required: false })} />
        <button className="btn ghost" onClick={signOut}>Sign out</button>
      </div>
    </div>
  );

  return (
    <div className="shell">
      <a className="skip-link" href="#main">Skip to content</a>
      <AiNoticeModal />
      <StepUpHost />
      <nav className="rail" aria-label="Main">
        <div className="brand display">Consultant <em>Studio</em></div>
        {([['brief', "Today's brief"], ['approvals', 'Approvals'], ['inbox', 'Inbox & exceptions'],
           ['customers', 'My customers'], ['chat', 'Ask anything'], ['skin', 'Skin studio'],
           ['billing', 'Plan & billing'], ['settings', 'Settings']] as const).map(([k, label]) => (
          <button key={k} className={view === k ? 'active' : ''} aria-current={view === k ? 'page' : undefined}
                  onClick={() => { setView(k); if (k !== 'customers') setOpenCustomer(null); }}>
            {label}
          </button>
        ))}
        <div className="spacer" />
        <div className="who">
          {tokens.display_name} · {tokens.role}
          <div><button className="btn ghost" style={{ marginTop: 8, padding: '6px 12px' }}
            onClick={signOut}>Sign out</button></div>
        </div>
      </nav>
      <main className="main" id="main">
        {view === 'brief' && <BriefView onOpenCustomer={goCustomer} />}
        {view === 'approvals' && <ApprovalsView handoff={HANDOFF.view === 'approvals' ? HANDOFF : undefined} />}
        {view === 'inbox' && <InboxView onOpenCustomer={goCustomer} />}
        {view === 'chat' && <ChatView />}
        {view === 'skin' && <SkinView />}
        {view === 'customers' && (openCustomer
          ? <CustomerDetail customer={openCustomer} onBack={() => setOpenCustomer(null)} />
          : <CustomersView onOpen={c => setOpenCustomer(c)} />)}
        {view === 'billing' && <BillingView />}
        {view === 'settings' && (<>
          <SecurityView role={tokens.role} userId={me?.id ?? ''} />
          <SettingsView role={tokens.role} />
          <GovernanceSettings role={tokens.role} userId={me?.id ?? ''} />
        </>)}
      </main>
    </div>
  );
}

function AuthScreen({ onAuthed }: { onAuthed: (t: Tokens) => void }) {
  const ref = refFromUrl();
  const [mode, setMode] = useState<'login' | 'signup'>(ref ? 'signup' : 'login');
  const [org, setOrg] = useState('');
  const [email, setEmail] = useState('');
  const [pw, setPw] = useState('');
  const [err, setErr] = useState('');
  const [busy, setBusy] = useState(false);
  const [challenge, setChallenge] = useState<MfaChallenge | null>(null);

  async function submit() {
    setErr(''); setBusy(true);
    try {
      if (mode === 'login') {
        const r = await client.login(email, pw);
        if (isMfaChallenge(r)) { setChallenge(r); setPw(''); } else onAuthed(r);
      } else onAuthed(await client.signup(org, email, pw, { ref }));
    } catch (e: any) { setErr(e.message); } finally { setBusy(false); }
  }

  if (challenge) return <SecondStep challenge={challenge} onAuthed={onAuthed} onRestart={() => { setChallenge(null); setErr(''); }} />;

  return (
    <div className="auth-wrap">
      <div className="card auth-card">
        <h1 className="display">Consultant <em style={{ color: 'var(--rose)', fontStyle: 'normal' }}>Studio</em></h1>
        <p className="muted" style={{ margin: 0 }}>
          {mode === 'login' ? 'Welcome back.' : 'Set up your team in one minute.'}
        </p>
        {ref && mode === 'signup' && (
          <div className="invited" role="note">You were invited — your referrer gets credit when you join.</div>
        )}
        {HANDOFF.view === 'approvals' && HANDOFF.actionId && (
          <div className="invited" role="note">Sign in to review and approve the message you opened from the mobile app.</div>
        )}
        {mode === 'signup' && (
          <input placeholder="Team or unit name" value={org} onChange={e => setOrg(e.target.value)} />
        )}
        <input placeholder="Email" type="email" autoComplete="email"
               value={email} onChange={e => setEmail(e.target.value)} />
        <input placeholder="Password (10+ characters)" type="password"
               autoComplete={mode === 'login' ? 'current-password' : 'new-password'}
               value={pw} onChange={e => setPw(e.target.value)}
               onKeyDown={e => e.key === 'Enter' && submit()} />
        {err && <div className="error" role="alert">{err}</div>}
        <button className="btn" disabled={busy} onClick={submit}>
          {busy ? 'One moment…' : mode === 'login' ? 'Sign in' : 'Create team'}
        </button>
        <button className="btn ghost" onClick={() => { setMode(m => m === 'login' ? 'signup' : 'login'); setErr(''); }}>
          {mode === 'login' ? 'New team? Create one' : 'Have an account? Sign in'}
        </button>
      </div>
    </div>
  );
}

/** Second sign-in step: authenticator code, passkey, or a one-time recovery code. */
function SecondStep({ challenge, onAuthed, onRestart }:
                    { challenge: MfaChallenge; onAuthed: (t: Tokens) => void; onRestart: () => void }) {
  const [method, setMethod] = useState<'totp' | 'recovery'>(challenge.methods.includes('totp') ? 'totp' : 'recovery');
  const [code, setCode] = useState('');
  const [err, setErr] = useState('');
  const [busy, setBusy] = useState(false);
  async function run(fn: () => Promise<Tokens>) {
    setErr(''); setBusy(true);
    try { onAuthed(await fn()); }
    catch (e: any) {
      const d = e?.detail;
      if (d === 'Sign in again' || d?.code === 'SESSION_ENDED') { onRestart(); return; }
      setErr(explainFactor(e));
    } finally { setBusy(false); }
  }
  const verify = () => run(() => client.verifyMfa(challenge.mfa_token, method, { code: code.trim() }));
  return (
    <div className="auth-wrap">
      <div className="card auth-card">
        <h1 className="display" style={{ fontSize: 28 }}>Second step</h1>
        {challenge.methods.includes('webauthn') && (
          <button className="btn" disabled={busy} onClick={() => run(() => client.signInWithPasskey(challenge.mfa_token))}>
            Use your passkey
          </button>
        )}
        <label className="small" htmlFor="mfa-code">
          {method === 'totp' ? 'Code from your authenticator app' : 'One of your recovery codes'}
        </label>
        <input id="mfa-code" autoFocus inputMode={method === 'totp' ? 'numeric' : 'text'} autoComplete="one-time-code"
               maxLength={method === 'totp' ? 6 : 32} value={code}
               onChange={e => setCode(method === 'totp' ? e.target.value.replace(/\D/g, '') : e.target.value)}
               onKeyDown={e => e.key === 'Enter' && verify()} />
        {err && <div className="error" role="alert">{err}</div>}
        <button className={challenge.methods.includes('webauthn') ? 'btn ghost' : 'btn'} disabled={busy || !code} onClick={verify}>
          Verify
        </button>
        {challenge.methods.includes('recovery') && challenge.methods.includes('totp') && (
          <button className="btn ghost" onClick={() => { setMethod(m => m === 'totp' ? 'recovery' : 'totp'); setCode(''); setErr(''); }}>
            {method === 'totp' ? 'Use a recovery code instead' : 'Use my authenticator app'}
          </button>
        )}
        <button className="btn ghost" onClick={onRestart}>Start over</button>
      </div>
    </div>
  );
}
