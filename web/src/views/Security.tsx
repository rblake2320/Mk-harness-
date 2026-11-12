import { useEffect, useState } from 'react';
import { client } from '../App.tsx';
import type { AuthSessionInfo, BreakGlassGrant, Member, MfaStatus } from '../../../packages/sdk/src/index.ts';
import { ErrorNote, fmtWhen } from '../components/Common.tsx';
import { explainFactor } from '../components/StepUp.tsx';

export const isAdminRole = (role: string) => role === 'owner' || role === 'admin';

const ROLE_LABEL: Record<string, string> = {
  owner: 'Owner — everything, including billing and closing the business',
  admin: 'Admin — team, security, sending numbers, approvals',
  consultant: 'Consultant — own customer book, drafts, approvals',
  assistant: 'Assistant — prepares work in one consultant\'s book; cannot approve or send',
  viewer: 'Viewer — read-only access to one consultant\'s book',
};

/* ------------------------------------------------------------------ enrollment */

/** Adds a second factor. Used by the first-sign-in gate and by Settings. Shows the
 *  one-time recovery codes when the server returns them (first factor only). */
export function EnrollFactor({ onDone, passkeysAvailable }: { onDone: () => void; passkeysAvailable: boolean }) {
  const [totp, setTotp] = useState<{ factor_id: string; secret: string; otpauth_uri: string } | null>(null);
  const [code, setCode] = useState('');
  const [codes, setCodes] = useState<string[] | null>(null);
  const [err, setErr] = useState<string>('');
  const [busy, setBusy] = useState(false);

  async function run<T>(fn: () => Promise<T>, then: (r: T) => void) {
    setErr(''); setBusy(true);
    try { then(await fn()); } catch (e) { setErr(explainFactor(e)); } finally { setBusy(false); }
  }
  const finished = (r: { recovery_codes: string[] | null }) => (r.recovery_codes ? setCodes(r.recovery_codes) : onDone());

  if (codes) return <RecoveryCodes codes={codes} onDone={onDone} />;
  return (
    <div className="stack">
      {!totp && (
        <div className="row" style={{ gap: 8, flexWrap: 'wrap' }}>
          <button className="btn" disabled={busy} onClick={() => run(() => client.totpBegin(), setTotp)}>
            Use an authenticator app
          </button>
          {passkeysAvailable && (
            <button className="btn ghost" disabled={busy}
                    onClick={() => run(() => client.addSignInPasskey('Passkey'), finished)}>
              Use a passkey (this device)
            </button>
          )}
        </div>
      )}
      {totp && (
        <div className="stack">
          <ol className="small">
            <li>Open your authenticator app and add an account.</li>
            <li>On a phone, <a href={totp.otpauth_uri}>tap here to add it</a>; otherwise enter this key:</li>
          </ol>
          <code className="exact-text" aria-label="Setup key" style={{ letterSpacing: 2 }}>
            {totp.secret.match(/.{1,4}/g)?.join(' ')}
          </code>
          <label className="small" htmlFor="enroll-code">Enter the 6-digit code the app shows</label>
          <input id="enroll-code" inputMode="numeric" autoComplete="one-time-code" maxLength={6}
                 value={code} onChange={e => setCode(e.target.value.replace(/\D/g, ''))} />
          <div className="row" style={{ gap: 8 }}>
            <button className="btn" disabled={busy || code.length !== 6}
                    onClick={() => run(() => client.totpConfirm(totp.factor_id, code), finished)}>Finish</button>
            <button className="btn ghost" onClick={() => { setTotp(null); setCode(''); }}>Back</button>
          </div>
        </div>
      )}
      {err && <div className="error" role="alert">{err}</div>}
    </div>
  );
}

export function RecoveryCodes({ codes, onDone }: { codes: string[]; onDone: () => void }) {
  const [saved, setSaved] = useState(false);
  return (
    <div className="stack" role="region" aria-label="Recovery codes">
      <strong>Save these recovery codes now</strong>
      <p className="muted small" style={{ margin: 0 }}>
        Each code signs you in once if you lose your phone or passkey. They are shown only this time.
      </p>
      <pre className="exact-text" style={{ columns: 2 }}>{codes.join('\n')}</pre>
      <div className="row" style={{ gap: 8 }}>
        <button className="btn ghost" onClick={() => navigator.clipboard?.writeText(codes.join('\n'))}>Copy</button>
        <label className="small"><input type="checkbox" checked={saved} onChange={e => setSaved(e.target.checked)} /> I saved them</label>
      </div>
      <button className="btn" disabled={!saved} onClick={onDone}>Continue</button>
    </div>
  );
}

/* ------------------------------------------------------------------ settings */

export default function SecurityView({ role, userId }: { role: string; userId: string }) {
  const [mfa, setMfa] = useState<MfaStatus | null>(null);
  const [sessions, setSessions] = useState<AuthSessionInfo[]>([]);
  const [adding, setAdding] = useState(false);
  const [codes, setCodes] = useState<string[] | null>(null);
  const [err, setErr] = useState<unknown>(null);
  const [note, setNote] = useState('');

  function load() {
    client.mfaStatus().then(setMfa).catch(setErr);
    client.sessions().then(setSessions).catch(setErr);
  }
  useEffect(load, []);

  async function act(fn: () => Promise<unknown>, ok: string) {
    setErr(null); setNote('');
    try { await fn(); setNote(ok); load(); } catch (e) { setErr(e); }
  }

  return (
    <section className="card" aria-labelledby="sec-title">
      <h2 id="sec-title" className="display" style={{ marginTop: 0 }}>Sign-in security</h2>
      <ErrorNote error={err} onDismiss={() => setErr(null)} />
      {note && <div className="ok-note" role="status">{note}</div>}

      <h3>Second factors</h3>
      {mfa && mfa.factors.length === 0 && <p className="muted">No second factor yet{mfa.mfa_required ? ' — required for this business.' : '.'}</p>}
      <ul className="plain">
        {mfa?.factors.map(f => (
          <li key={f.id} className="row" style={{ justifyContent: 'space-between', gap: 8 }}>
            <span>{f.kind === 'totp' ? 'Authenticator app' : 'Passkey'} · {f.label}
              <span className="muted small"> · added {fmtWhen(f.created_at)}{f.last_used_at ? ` · last used ${fmtWhen(f.last_used_at)}` : ''}</span></span>
            <button className="btn ghost small" onClick={() => act(() => client.revokeFactor(f.id), 'Factor removed.')}>Remove</button>
          </li>
        ))}
      </ul>
      {codes && <RecoveryCodes codes={codes} onDone={() => setCodes(null)} />}
      {adding
        ? <EnrollFactor passkeysAvailable={!!mfa?.passkeys_available} onDone={() => { setAdding(false); load(); setNote('Factor added.'); }} />
        : <div className="row" style={{ gap: 8 }}>
            <button className="btn ghost" onClick={() => setAdding(true)}>Add a factor</button>
            {!!mfa?.factors.length && (
              <button className="btn ghost" onClick={() => act(async () => setCodes((await client.regenerateRecoveryCodes()).recovery_codes),
                                                               'New recovery codes issued; the old ones no longer work.')}>
                New recovery codes
              </button>
            )}
          </div>}

      <h3>Where you're signed in</h3>
      <ul className="plain">
        {sessions.filter(s => !s.revoked).map(s => (
          <li key={s.id} className="row" style={{ justifyContent: 'space-between', gap: 8 }}>
            <span>{s.client || 'Unknown device'}{s.current && <strong> · this device</strong>}
              <span className="muted small"> · signed in {fmtWhen(s.created_at)} · last active {fmtWhen(s.last_seen_at)}{s.second_factor ? '' : ' · no second factor yet'}</span></span>
            {!s.current && <button className="btn ghost small" onClick={() => act(() => client.revokeSession(s.id), 'Signed out that device.')}>Sign out</button>}
          </li>
        ))}
      </ul>
      {sessions.filter(s => !s.revoked && !s.current).length > 0 && (
        <button className="btn ghost" onClick={() => act(() => client.revokeOtherSessions(), 'Signed out everywhere else.')}>
          Sign out all other devices
        </button>
      )}

      {isAdminRole(role) && <TeamAdmin role={role} userId={userId} />}
    </section>
  );
}

/* ------------------------------------------------------------------ team + support access */

function TeamAdmin({ role, userId }: { role: string; userId: string }) {
  const [members, setMembers] = useState<Member[]>([]);
  const [grants, setGrants] = useState<BreakGlassGrant[]>([]);
  const [invite, setInvite] = useState({ email: '', password: '', role: 'consultant', works_for: '' });
  const [err, setErr] = useState<unknown>(null);
  const [note, setNote] = useState('');
  function load() {
    client.members().then(setMembers).catch(setErr);
    client.breakGlassGrants().then(setGrants).catch(() => setGrants([]));
  }
  useEffect(load, []);
  async function act(fn: () => Promise<unknown>, ok: string) {
    setErr(null); setNote('');
    try { await fn(); setNote(ok); load(); } catch (e) { setErr(e); }
  }
  const books = members.filter(m => m.active && ['owner', 'admin', 'consultant'].includes(m.role));
  const assignable = role === 'owner' ? Object.keys(ROLE_LABEL) : ['consultant', 'assistant', 'viewer'];
  const needsBook = (r: string) => r === 'assistant' || r === 'viewer';
  const name = (id: string | null) => members.find(m => m.id === id)?.display_name || members.find(m => m.id === id)?.email || '—';

  return (
    <>
      <h3>Team and roles</h3>
      <ErrorNote error={err} onDismiss={() => setErr(null)} />
      {note && <div className="ok-note" role="status">{note}</div>}
      <table className="facts" style={{ width: '100%' }}>
        <thead><tr><th>Person</th><th>Role</th><th>Second factor</th><th /></tr></thead>
        <tbody>
          {members.map(m => (
            <tr key={m.id}>
              <td>{m.display_name || m.email}{!m.active && <span className="muted"> · deactivated</span>}
                {m.works_for && <div className="muted small">works in {name(m.works_for)}'s book</div>}</td>
              <td>
                <select aria-label={`Role for ${m.email}`} value={m.role} disabled={!m.active || m.id === userId}
                        onChange={e => {
                          const r = e.target.value;
                          const wf = needsBook(r) ? (books.find(b => b.id !== m.id)?.id ?? null) : null;
                          act(() => client.setMemberRole(m.id, r, wf), `${m.email} is now ${r}. Their sessions were signed out.`);
                        }}>
                  {Array.from(new Set([m.role, ...assignable])).map(r => <option key={r} value={r}>{r}</option>)}
                </select>
              </td>
              <td>{m.second_factor ? 'Yes' : <span className="muted">Not yet</span>}</td>
              <td className="row" style={{ gap: 4 }}>
                {m.active && m.id !== userId && <>
                  <button className="btn ghost small" onClick={() => act(() => client.revokeMemberSessions(m.id), `Signed ${m.email} out everywhere.`)}>Sign out</button>
                  <button className="btn ghost small" onClick={() => act(() => client.deactivateMember(m.id), `${m.email} deactivated.`)}>Deactivate</button>
                </>}
              </td>
            </tr>
          ))}
        </tbody>
      </table>
      <details>
        <summary>Add a person</summary>
        <div className="stack">
          <input placeholder="Email" type="email" value={invite.email} onChange={e => setInvite({ ...invite, email: e.target.value })} />
          <input placeholder="Starting password (10+ characters)" type="password" value={invite.password}
                 onChange={e => setInvite({ ...invite, password: e.target.value })} />
          <select aria-label="Role" value={invite.role} onChange={e => setInvite({ ...invite, role: e.target.value })}>
            {assignable.map(r => <option key={r} value={r}>{ROLE_LABEL[r]}</option>)}
          </select>
          {needsBook(invite.role) && (
            <select aria-label="Whose book" value={invite.works_for} onChange={e => setInvite({ ...invite, works_for: e.target.value })}>
              <option value="">Choose whose customer book they work in…</option>
              {books.map(b => <option key={b.id} value={b.id}>{b.display_name || b.email}</option>)}
            </select>
          )}
          <button className="btn" disabled={!invite.email || invite.password.length < 10 || (needsBook(invite.role) && !invite.works_for)}
                  onClick={() => act(() => client.addMember(invite.email, invite.password, invite.role, invite.works_for || null),
                                     `Added ${invite.email}. They set up a second factor on first sign-in.`)}>
            Add
          </button>
        </div>
      </details>

      <h3>Support access requests</h3>
      <p className="muted small" style={{ marginTop: 0 }}>
        Platform support can see your data only if an admin approves a time-limited, read-only request. Every access is recorded in your audit log.
      </p>
      {grants.length === 0 && <p className="muted">No requests.</p>}
      <ul className="plain">
        {grants.map(g => (
          <li key={g.id} className="stack" style={{ borderBottom: '1px solid var(--line, #ddd)', paddingBottom: 8 }}>
            <span><strong>{g.status}</strong> · ticket {g.ticket_ref} · {g.duration_minutes} min · requested {fmtWhen(g.requested_at)}
              {g.expires_at && <> · ends {fmtWhen(g.expires_at)}</>} · {g.access_count} access(es)</span>
            <span className="small">{g.reason}</span>
            <span className="row" style={{ gap: 4 }}>
              {g.status === 'pending' && <>
                <button className="btn small" onClick={() => act(() => client.breakGlassDecide(g.id, 'approve'), 'Support access approved.')}>Approve</button>
                <button className="btn ghost small" onClick={() => act(() => client.breakGlassDecide(g.id, 'deny'), 'Request denied.')}>Deny</button>
              </>}
              {g.status === 'approved' && (
                <button className="btn ghost small" onClick={() => act(() => client.breakGlassDecide(g.id, 'revoke'), 'Support access ended.')}>End access now</button>
              )}
            </span>
          </li>
        ))}
      </ul>
    </>
  );
}
