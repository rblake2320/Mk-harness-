import { useEffect, useLayoutEffect, useState } from 'react';
import { MKClient, Tokens, ERASURE_STAGE_LABELS } from '../../packages/sdk/src/index.ts';
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
import type { Customer, ErasureReceipt } from '../../packages/sdk/src/index.ts';
import { AiNoticeModal } from './components/AiDisclosure.tsx';
import { MfaScreen, StepUpDialog } from './components/Mfa.tsx';
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

export default function App() {
  const [tokens, setTokens] = useState<Tokens | null>(loadTokens);
  const [authNotice, setAuthNotice] = useState('');
  const [erasureReceipt, setErasureReceipt] = useState<ErasureReceipt | null>(null);
  const [signingOut, setSigningOut] = useState(false);
  const [stepUp, setStepUp] = useState<{ finish: (ok: boolean) => void } | null>(null);
  const [view, setView] = useState<'brief' | 'approvals' | 'inbox' | 'customers' | 'chat' | 'skin' | 'billing' | 'settings'>('brief');
  const [openCustomer, setOpenCustomer] = useState<Customer | null>(null);
  const [me, setMe] = useState<{ id: string } | null>(null);
  function goCustomer(id: string) {
    client.listCustomers().then(list => { const c = list.find(x => x.id === id); if (c) { setOpenCustomer(c); setView('customers'); } }).catch(() => {});
  }

  useLayoutEffect(() => {
    client.tokens = tokens;
    if (tokens) sessionStorage.setItem(TOKEN_KEY, JSON.stringify(tokens));
    else sessionStorage.removeItem(TOKEN_KEY);
    client.onAuthExpired = () => setTokens(null);
    // Persist rotation synchronously: a reload must not reuse the old refresh.
    client.onTokensChanged = updated => {
      if (updated) sessionStorage.setItem(TOKEN_KEY, JSON.stringify(updated));
      else sessionStorage.removeItem(TOKEN_KEY);
      setTokens(updated);
    };
  }, [tokens]);
  useEffect(() => {
    client.onStepUpRequired = () => new Promise(resolve => setStepUp({ finish: resolve }));
    return () => { client.onStepUpRequired = null; };
  }, []);
  useEffect(() => {
    let active = true;
    if (tokens && (!tokens.mfa_state || tokens.mfa_state === 'verified')) client.me().then(me => { if (active) setMe(me); }).catch(() => {});
    else setMe(null);
    return () => { active = false; };
  }, [tokens]);
  useEffect(() => {
    if (!tokens || (tokens.mfa_state && tokens.mfa_state !== 'verified')) {
      setView('brief'); setOpenCustomer(null); setMe(null);
    }
  }, [tokens?.session_id, tokens?.mfa_state, !!tokens]);

  async function signOut() {
    stepUp?.finish(false); setStepUp(null);
    setSigningOut(true);
    try {
      const result = await client.logout();
      setAuthNotice(result.kernel_revocation === 'confirmed' ? 'Signed out. This session is revoked.'
        : 'Signed out. App access is revoked; cancellation of pending kernel approvals is awaiting delivery.');
    } catch {
      setAuthNotice('Local sign-out only: the server could not confirm revocation. Sign in again to revoke the old session in Settings.');
    } finally { setTokens(null); setSigningOut(false); }
  }

  if (!tokens) return <>
    {erasureReceipt && <section className="card" aria-label="Deletion receipt" style={{ maxWidth: 600, margin: '1rem auto' }}>
      <h2>Deletion request accepted</h2>
      <p role="status">{erasureReceipt.detail}</p>
      <p>Request {erasureReceipt.request_id}. Pending: {erasureReceipt.pending.map(stage => ERASURE_STAGE_LABELS[stage] ?? 'Processing review').join('; ')}.</p>
      <button className="btn" onClick={() => {
        const link = document.createElement('a');
        link.href = URL.createObjectURL(new Blob([JSON.stringify(erasureReceipt, null, 2)], { type: 'application/json' }));
        link.download = 'deletion-receipt.json'; link.click();
        setTimeout(() => URL.revokeObjectURL(link.href), 1000);
      }}>Save deletion receipt</button>
      <p className="small muted">Keep this receipt private. Its status token can check processing for 45 days without signing in.</p>
    </section>}
    <AuthScreen notice={authNotice} onAuthed={t => { setErasureReceipt(null); setAuthNotice(''); setTokens(t); }} />
  </>;
  if (tokens.mfa_state && tokens.mfa_state !== 'verified') return <MfaScreen key={tokens.session_id}
    client={client} tokens={tokens} onVerified={setTokens} onSignOut={signOut} />;
  const shownView = tokens.role === 'auditor' ? 'settings' : view;

  return (
    <div className="shell">
      <a className="skip-link" href="#main">Skip to content</a>
      {tokens.role !== 'auditor' && <AiNoticeModal />}
      {stepUp && <StepUpDialog client={client} onClose={ok => { stepUp.finish(ok); setStepUp(null); }} />}
      <nav className="rail" aria-label="Main">
        <div className="brand display">Consultant <em>Studio</em></div>
        {([['brief', "Today's brief"], ['approvals', 'Approvals'], ['inbox', 'Inbox & exceptions'],
           ['customers', 'My customers'], ['chat', 'Ask anything'], ['skin', 'Skin studio'],
           ['billing', 'Plan & billing'], ['settings', 'Settings']] as const).filter(([k]) => tokens.role !== 'auditor' || k === 'settings').map(([k, label]) => (
          <button key={k} className={shownView === k ? 'active' : ''} aria-current={shownView === k ? 'page' : undefined}
                  onClick={() => { setView(k); if (k !== 'customers') setOpenCustomer(null); }}>
            {label}
          </button>
        ))}
        <div className="spacer" />
        <div className="who">
          {tokens.display_name} · {tokens.role}
          <div><button className="btn ghost" style={{ marginTop: 8, padding: '6px 12px' }}
            disabled={signingOut} onClick={signOut}>{signingOut ? 'Signing out…' : 'Sign out'}</button></div>
        </div>
      </nav>
      <div className="mobile-session">
        <span>{tokens.display_name} · {tokens.role}</span>
        <button className="btn ghost" disabled={signingOut} onClick={signOut}>
          {signingOut ? 'Signing out…' : 'Sign out'}
        </button>
      </div>
      <main className="main" id="main">
        {shownView === 'brief' && <BriefView onOpenCustomer={goCustomer} />}
        {shownView === 'approvals' && <ApprovalsView />}
        {shownView === 'inbox' && <InboxView onOpenCustomer={goCustomer} />}
        {shownView === 'chat' && <ChatView />}
        {shownView === 'skin' && <SkinView />}
        {shownView === 'customers' && (openCustomer
          ? <CustomerDetail customer={openCustomer} onBack={() => setOpenCustomer(null)} />
          : <CustomersView onOpen={c => setOpenCustomer(c)} />)}
        {shownView === 'billing' && <BillingView />}
        {shownView === 'settings' && (<>
          <SettingsView role={tokens.role} />
          <GovernanceSettings role={tokens.role} userId={me?.id ?? ''} onDeleted={receipt => {
            setErasureReceipt(receipt); setAuthNotice('All app sessions have been revoked.');
            client.tokens = null; sessionStorage.removeItem(TOKEN_KEY); setTokens(null);
          }} />
        </>)}
      </main>
    </div>
  );
}

function AuthScreen({ onAuthed, notice }: { onAuthed: (t: Tokens) => void; notice: string }) {
  const ref = refFromUrl();
  const [mode, setMode] = useState<'login' | 'signup'>(ref ? 'signup' : 'login');
  const [org, setOrg] = useState('');
  const [email, setEmail] = useState('');
  const [pw, setPw] = useState('');
  const [err, setErr] = useState('');
  const [busy, setBusy] = useState(false);

  async function submit() {
    setErr(''); setBusy(true);
    try {
      const t = mode === 'login'
        ? await client.login(email, pw)
        : await client.signup(org, email, pw, { ref });
      onAuthed(t);
    } catch (e: any) { setErr(e.message); } finally { setBusy(false); }
  }

  return (
    <div className="auth-wrap">
      <div className="card auth-card">
        {notice && <p role="status">{notice}</p>}
        <h1 className="display">Consultant <em style={{ color: 'var(--rose)', fontStyle: 'normal' }}>Studio</em></h1>
        <p className="muted" style={{ margin: 0 }}>
          {mode === 'login' ? 'Welcome back.' : 'Set up your team in one minute.'}
        </p>
        {ref && mode === 'signup' && (
          <div className="invited" role="note">You were invited — your referrer gets credit when you join.</div>
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
