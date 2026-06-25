import { useEffect, useState } from 'react';
import { MKClient, Tokens } from '../../packages/sdk/src/index.ts';
import ChatView from './views/Chat.tsx';
import SkinView from './views/Skin.tsx';
import CustomersView from './views/Customers.tsx';
import BillingView from './views/Billing.tsx';
import SettingsView from './views/Settings.tsx';
import { AiNoticeModal } from './components/AiDisclosure.tsx';
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
  const [view, setView] = useState<'chat' | 'skin' | 'customers' | 'billing' | 'settings'>('chat');

  useEffect(() => {
    client.tokens = tokens;
    if (tokens) sessionStorage.setItem(TOKEN_KEY, JSON.stringify(tokens));
    else sessionStorage.removeItem(TOKEN_KEY);
    client.onAuthExpired = () => setTokens(null);
  }, [tokens]);

  if (!tokens) return <AuthScreen onAuthed={setTokens} />;

  return (
    <div className="shell">
      <AiNoticeModal />
      <nav className="rail" aria-label="Main">
        <div className="brand display">Consultant <em>Studio</em></div>
        {([['chat', 'Ask anything'], ['skin', 'Skin studio'],
           ['customers', 'My customers'], ['billing', 'Plan & billing'],
           ['settings', 'Settings']] as const).map(([k, label]) => (
          <button key={k} className={view === k ? 'active' : ''} onClick={() => setView(k)}>
            {label}
          </button>
        ))}
        <div className="spacer" />
        <div className="who">
          {tokens.display_name} · {tokens.role}
          <div><button className="btn ghost" style={{ marginTop: 8, padding: '6px 12px' }}
            onClick={() => setTokens(null)}>Sign out</button></div>
        </div>
      </nav>
      <main className="main">
        {view === 'chat' && <ChatView />}
        {view === 'skin' && <SkinView />}
        {view === 'customers' && <CustomersView />}
        {view === 'billing' && <BillingView />}
        {view === 'settings' && <SettingsView role={tokens.role} />}
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
