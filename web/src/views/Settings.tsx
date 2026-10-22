import { useEffect, useState } from 'react';
import { client } from '../App.tsx';
import type { AuthSession } from '../../../packages/sdk/src/index.ts';
import { MfaScreen } from '../components/Mfa.tsx';
import MemberAccess from '../components/MemberAccess.tsx';

const PROVIDERS = ['anthropic', 'openai', 'gemini', 'ollama'] as const;

export default function SettingsView({ role }: { role: string }) {
  const [status, setStatus] = useState<any>(null);
  const [provider, setProvider] = useState('anthropic');
  const [apiKey, setApiKey] = useState('');
  const [baseUrl, setBaseUrl] = useState('');
  const [scope, setScope] = useState<'mine' | 'tenant'>('mine');
  const [msg, setMsg] = useState('');
  const [err, setErr] = useState('');
  const [usage, setUsage] = useState<any[]>([]);
  const [teamUsage, setTeamUsage] = useState<any[]>([]);
  const [invite, setInvite] = useState({ email: '', password: '' });
  const [inviteRole, setInviteRole] = useState('consultant');
  const [sessions, setSessions] = useState<AuthSession[]>([]);
  const [revoking, setRevoking] = useState<string | null>(null);
  const [mfaStatus, setMfaStatus] = useState<{ enrolled: boolean; recovery_codes_remaining: number } | null>(null);
  const [recoveryCodes, setRecoveryCodes] = useState<string[]>([]);
  const [replacingFactor, setReplacingFactor] = useState(false);

  function refresh() {
    if (role !== 'auditor') {
      client.keyStatus().then(setStatus).catch(e => setErr(e.message));
      client.myUsage().then(setUsage).catch(() => {});
    }
    client.sessions().then(setSessions).catch(e => setErr(e.message));
    client.mfaStatus().then(setMfaStatus).catch(() => {});
    if (role === 'admin' || role === 'manager') client.tenantUsage().then(setTeamUsage).catch(() => {});
  }
  useEffect(refresh, []);

  async function saveKey() {
    setErr(''); setMsg('');
    try {
      if (scope === 'mine') await client.setMyKey(provider, apiKey, baseUrl);
      else await client.setTenantKey(provider, apiKey, baseUrl);
      setApiKey(''); setBaseUrl('');
      setMsg(`${provider} key saved (${scope === 'mine' ? 'personal' : 'team'}). Stored encrypted.`);
      refresh();
    } catch (e: any) { setErr(e.message); }
  }

  async function sendInvite() {
    setErr(''); setMsg('');
    try {
      await client.addMember(invite.email, invite.password, inviteRole);
      setMsg(`Added ${invite.email}. Share their starting password securely.`);
      setInvite({ email: '', password: '' });
    } catch (e: any) { setErr(e.message); }
  }

  if (replacingFactor && client.tokens) return <MfaScreen client={client} tokens={{ ...client.tokens, mfa_state: 'enrollment_required' }}
    onVerified={tokens => { client.tokens = tokens; client.onTokensChanged?.(tokens); setReplacingFactor(false); refresh(); }}
    onSignOut={async () => { try { await client.logout(); } catch { client.tokens = null; client.onTokensChanged?.(null); } }} />;

  return (
    <div>
      <h1>Settings</h1>
      {msg && <div style={{ color: 'var(--ok)', margin: '8px 0' }}>{msg}</div>}
      {err && <div className="error" role="alert" style={{ margin: '8px 0' }}>{err}</div>}

      <section className="card" aria-label="Second-factor security" style={{ maxWidth: 720, marginBottom: 18 }}>
        <h2>Second-factor security</h2>
        <p>{mfaStatus?.enrolled ? `Authenticator enrolled. ${mfaStatus.recovery_codes_remaining} recovery codes remain.` : 'Checking authenticator status…'}</p>
        <p>Replacing the authenticator revokes all old sessions and recovery codes. Keep this session open until you save the replacements.</p>
        <button className="btn ghost" onClick={() => setReplacingFactor(true)}>Replace authenticator</button>{' '}
        <button className="btn ghost" disabled={recoveryCodes.length > 0} onClick={async () => {
          try { setRecoveryCodes((await client.rotateRecoveryCodes()).recovery_codes); refresh(); }
          catch (e: any) { setErr(e.message); }
        }}>Replace recovery codes</button>
        {recoveryCodes.length > 0 && <div role="region" aria-label="New recovery codes">
          <p>Old recovery codes no longer work. Save these one-use codes now; they will not be shown again.</p>
          <ul className="recovery-codes">{recoveryCodes.map(code => <li key={code}><code>{code}</code></li>)}</ul>
          <button className="btn" onClick={() => setRecoveryCodes([])}>I saved the new codes</button>
        </div>}
      </section>

      <section className="card" aria-label="Signed-in sessions" style={{ maxWidth: 720, marginBottom: 18 }}>
        <h2>Signed-in sessions</h2>
        <p>Revoke a lost or unused session. Use Sign out for this session.</p>
        {sessions.map(session => <div key={session.id} className="row" style={{ marginBottom: 12 }}>
          <span>{session.current ? 'This session' : 'Other session'} · {new Date(session.created_at).toLocaleString()}
            {session.revoked_at ? ' · Revoked' : ''}</span>
          {!session.current && !session.revoked_at && <button className="btn ghost" disabled={revoking !== null}
            aria-label={`Revoke session started ${new Date(session.created_at).toLocaleString()}`}
            onClick={async () => {
              setRevoking(session.id); setErr(''); setMsg('');
              try {
                const result = await client.revokeSession(session.id);
                setMsg(result.kernel_revocation === 'confirmed' ? 'Session and pending approvals revoked.'
                  : 'App session revoked. Kernel approval revocation is pending delivery.');
                setSessions(await client.sessions());
              } catch (e: any) { setErr(e.message); } finally { setRevoking(null); }
            }}>Revoke</button>}
        </div>)}
      </section>

      {role !== 'auditor' && <>
      <div className="card" style={{ maxWidth: 720 }}>
        <h3 style={{ marginTop: 0 }}>AI engines</h3>
        <p className="muted">
          Team policy: <strong>{status?.key_policy ?? '…'}</strong>.
          Keys are encrypted at rest and never shown again after saving.
        </p>
        <table>
          <thead><tr><th>Engine</th><th>Your key</th><th>Team / company</th><th>Usable now</th></tr></thead>
          <tbody>
            {PROVIDERS.map(p => {
              const s = status?.providers?.[p];
              return (
                <tr key={p}>
                  <td>{p}</td>
                  <td>{s?.byo_key_set ? '✓ set' : '—'}</td>
                  <td>{s?.central_available ? '✓ available' : '—'}</td>
                  <td>{s?.usable ? <span style={{ color: 'var(--ok)' }}>yes</span> : 'no'}</td>
                </tr>
              );
            })}
          </tbody>
        </table>

        <div style={{ marginTop: 16, display: 'grid', gap: 10 }}>
          <div className="row">
            <select aria-label="Provider" value={provider} onChange={e => setProvider(e.target.value)} style={{ width: 160 }}>
              {PROVIDERS.map(p => <option key={p} value={p}>{p}</option>)}
            </select>
            {role === 'admin' && (
              <select aria-label="Key scope" value={scope} onChange={e => setScope(e.target.value as any)} style={{ width: 200 }}>
                <option value="mine">My personal key</option>
                <option value="tenant">Team key (everyone)</option>
              </select>
            )}
          </div>
          <input placeholder={provider === 'ollama' ? 'No key needed for Ollama' : 'API key'}
                 type="password" value={apiKey} onChange={e => setApiKey(e.target.value)}
                 disabled={provider === 'ollama'} />
          <input placeholder={provider === 'ollama'
                   ? 'Server URL, e.g. http://192.168.1.50:11434'
                   : 'Custom base URL (optional — Azure/vLLM/LM Studio)'}
                 value={baseUrl} onChange={e => setBaseUrl(e.target.value)} />
          <div className="row">
            <button className="btn" onClick={saveKey}
                    disabled={provider !== 'ollama' && !apiKey}>Save key</button>
            <button className="btn ghost"
                    onClick={async () => { await client.deleteMyKey(provider).catch(() => {}); refresh(); }}>
              Remove my {provider} key
            </button>
          </div>
        </div>
      </div>

      <div className="card" style={{ maxWidth: 720, marginTop: 18 }}>
        <h3 style={{ marginTop: 0 }}>My usage</h3>
        {usage.length === 0 ? <p className="muted">No AI calls yet.</p> : (
          <table>
            <thead><tr><th>Engine</th><th>Model</th><th>Calls</th><th>Tokens in/out</th><th>Cost</th></tr></thead>
            <tbody>
              {usage.map((u, i) => (
                <tr key={i}>
                  <td>{u.provider}</td><td>{u.model}</td><td>{u.calls}</td>
                  <td>{u.input_tokens.toLocaleString()} / {u.output_tokens.toLocaleString()}</td>
                  <td>${u.cost_usd.toFixed(4)}</td>
                </tr>
              ))}
            </tbody>
          </table>
        )}
      </div>

      {(role === 'admin' || role === 'manager') && (
        <>
          <div className="card" style={{ maxWidth: 720, marginTop: 18 }}>
            <h3 style={{ marginTop: 0 }}>Team usage</h3>
            {teamUsage.length === 0 ? <p className="muted">No team AI calls yet.</p> : (
              <table>
                <thead><tr><th>Member</th><th>Engine</th><th>Key</th><th>Calls</th><th>Cost</th></tr></thead>
                <tbody>
                  {teamUsage.map((u, i) => (
                    <tr key={i}>
                      <td>{u.email}</td><td>{u.provider}</td><td>{u.key_scope}</td>
                      <td>{u.calls}</td><td>${u.cost_usd.toFixed(4)}</td>
                    </tr>
                  ))}
                </tbody>
              </table>
            )}
          </div>

          {role === 'admin' && <div className="card" style={{ maxWidth: 720, marginTop: 18, display: 'grid', gap: 10 }}>
            <h3 style={{ margin: 0 }}>Add a team member</h3>
            <div className="row">
              <input placeholder="Email" style={{ flex: 1 }} value={invite.email}
                     onChange={e => setInvite({ ...invite, email: e.target.value })} />
              <input placeholder="Starting password (10+ chars)" type="password" style={{ flex: 1 }}
                     value={invite.password}
                     onChange={e => setInvite({ ...invite, password: e.target.value })} />
              <select aria-label="New member role" value={inviteRole} onChange={e => setInviteRole(e.target.value)} style={{ maxWidth: 160 }}>
                {['consultant', 'manager', 'auditor', 'admin'].map(role => <option key={role}>{role}</option>)}
              </select>
              <button className="btn" onClick={sendInvite}
                      disabled={!invite.email || invite.password.length < 10}>Add</button>
            </div>
          </div>}
          {role === 'admin' && <MemberAccess />}
        </>
      )}
      </>}
    </div>
  );
}
