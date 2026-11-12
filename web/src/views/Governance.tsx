import { useEffect, useState } from 'react';
import { client } from '../App.tsx';
import { isAdminRole } from './Security.tsx';
import { dispatchSummary, inboundBlockLabel } from '../../../packages/sdk/src/index.ts';
import type { GovernanceStatus, InboundHealth, PasskeyInfo, SenderIdentity } from '../../../packages/sdk/src/index.ts';
import { ErrorNote, HumanSteps, fmtWhen } from '../components/Common.tsx';

/**
 * Settings → Governance: sending status (kernel, kill switches, reply path), approval
 * passkeys, sending number status, inbound health, session revocation, data export,
 * audit export, account deletion.
 */
export default function GovernanceSettings({ role, userId }: { role: string; userId: string }) {
  const [passkeys, setPasskeys] = useState<PasskeyInfo[]>([]);
  const [senders, setSenders] = useState<SenderIdentity[]>([]);
  const [health, setHealth] = useState<InboundHealth | null>(null);
  const [status, setStatus] = useState<GovernanceStatus | null>(null);
  const [err, setErr] = useState<unknown>(null);
  const [msg, setMsg] = useState('');
  const [label, setLabel] = useState('');
  const [sender, setSender] = useState({ display_name: '', account_sid: '', auth_token: '', from_number: '' });
  const [del, setDel] = useState('');

  function load() {
    setErr(null);
    client.governanceStatus().then(setStatus).catch(e => { setStatus(null); setErr(e); });
    client.passkeys().then(setPasskeys).catch(() => setPasskeys([]));
    client.senders().then(setSenders).catch(() => setSenders([]));
    client.inboundHealth().then(setHealth).catch(() => setHealth(null));
  }
  const summary = status ? dispatchSummary(status, health) : null;
  useEffect(load, []);

  const run = (fn: () => Promise<unknown>, ok: string) => { setErr(null); setMsg(''); fn().then(() => { setMsg(ok); load(); }).catch(setErr); };

  function download(name: string, text: string, type = 'application/json') {
    const a = document.createElement('a'); a.href = URL.createObjectURL(new Blob([text], { type })); a.download = name; a.click();
    setTimeout(() => URL.revokeObjectURL(a.href), 1000);
  }

  return (
    <div>
      <h2>Governance</h2>
      <section className={`card small ${summary?.allowed ? '' : 'limitation'}`} role="status" aria-label="Sending status">
        <strong>{summary ? summary.headline : 'Checking sending status…'}</strong>
        {summary && (
          <dl className="facts">
            {summary.lines.map(l => (
              <div key={l.key} className="fact"><dt>{l.label}</dt><dd>{l.value}</dd></div>
            ))}
          </dl>
        )}
        {status && status.kernel !== 'connected' && <div>Nothing can be approved or sent until the kernel is connected. No local fallback exists.</div>}
      </section>
      <ErrorNote error={err} onDismiss={() => setErr(null)} />
      {msg && <div className="ok-note" role="status">{msg}</div>}

      <section className="card" style={{ marginTop: 16 }}>
        <h3 style={{ marginTop: 0 }}>Approval passkeys</h3>
        <p className="muted small">Approving a message requires a passkey registered here. The kernel verifies it; your sign-in alone can never approve.</p>
        <ul className="plain">
          {passkeys.map(k => <li key={k.credential_row_id}>{k.label || 'passkey'} · {k.alg} · added {fmtWhen(k.created_at)}{k.last_used_at && ` · last used ${fmtWhen(k.last_used_at)}`}
            {k.revoked_at ? <em className="muted"> · revoked</em> : <button className="link" onClick={() => run(() => client.revokePasskey(k.credential_row_id), 'Passkey revoked.')}>revoke</button>}</li>)}
          {passkeys.length === 0 && <li className="muted">No passkey yet — you cannot approve messages until you add one.</li>}
        </ul>
        <div className="row">
          <input aria-label="Passkey label" placeholder="Label (e.g. my phone)" value={label} onChange={e => setLabel(e.target.value)} style={{ maxWidth: 260 }} />
          <button className="btn" disabled={!label.trim()} onClick={() => run(() => client.registerPasskey(label.trim()), 'Passkey registered.')}>Add passkey</button>
        </div>
      </section>

      <section className="card" style={{ marginTop: 16 }}>
        <h3 style={{ marginTop: 0 }}>Sending number</h3>
        <p className="muted small">Each business sends from its own registered number. Registration status is recorded, not assumed: messages to real customers require <em>registered</em>.</p>
        <ul className="plain">
          {senders.map(s => <li key={s.sender_identity_id}>{s.display_name} · {s.from_number ?? s.messaging_service_sid} · <strong>{s.registration_status}</strong> · {s.status}</li>)}
          {senders.length === 0 && <li className="muted">No sending number registered for this team.</li>}
        </ul>
        {isAdminRole(role) && (
          <details>
            <summary>Register a sending number (admin)</summary>
            <p className="muted small">The provider token is passed once to the kernel, which seals it. It is never stored by this app.</p>
            <input aria-label="Business name" placeholder="Business display name" value={sender.display_name} onChange={e => setSender({ ...sender, display_name: e.target.value })} />
            <input aria-label="Account SID" placeholder="AC… account SID" value={sender.account_sid} onChange={e => setSender({ ...sender, account_sid: e.target.value })} />
            <input aria-label="Auth token" placeholder="Auth token" type="password" autoComplete="off" value={sender.auth_token} onChange={e => setSender({ ...sender, auth_token: e.target.value })} />
            <input aria-label="From number" placeholder="+15555550100" value={sender.from_number} onChange={e => setSender({ ...sender, from_number: e.target.value })} />
            <button className="btn ghost" onClick={() => run(() => client.registerSender({ owner_user_id: userId, ...sender }), 'Sender registered (unverified until registration evidence is recorded).')}>Register</button>
          </details>
        )}
      </section>

      <section className="card" style={{ marginTop: 16 }}>
        <h3 style={{ marginTop: 0 }}>Inbound health</h3>
        {health ? (
          <p className="small">{health.dispatch_blocked ? <strong>Sending paused: {inboundBlockLabel(health.dispatch_blocked)}</strong> : <strong>Healthy.</strong>} {health.pending_events} unprocessed replies.
            {health.health?.last_ok_at && <> Last successful check {fmtWhen(health.health.last_ok_at)}.</>}
            {health.health?.last_failure_at && <> Last failure {fmtWhen(health.health.last_failure_at)} ({health.health.last_failure_reason}).</>}
            <br /><span className="muted">If replies cannot be received for 60 s, outbound sending pauses automatically and resumes only after a successful check with no backlog.</span></p>
        ) : <p className="muted small">Not available (kernel unreachable or not configured).</p>}
      </section>

      <section className="card" style={{ marginTop: 16 }}>
        <h3 style={{ marginTop: 0 }}>Your data & evidence</h3>
        <HumanSteps steps={['Deleting your account is irreversible for your data; anonymised audit records are retained for legal hold.']} />
        <div className="row">
          <button className="btn ghost" onClick={() => client.exportAccount().then(d => download('my-data.json', JSON.stringify(d, null, 2))).catch(setErr)}>Export my data (JSON)</button>
          <button className="btn ghost" onClick={() => client.exportCustomersCsv().then(t => download('customers.csv', t, 'text/csv')).catch(setErr)}>Export customers (CSV)</button>
          {isAdminRole(role) && <button className="btn ghost" onClick={() => client.exportAudit().then(t => download('audit.jsonl', t, 'application/x-ndjson')).catch(setErr)}>Export audit log (admin)</button>}
          <button className="btn ghost" onClick={() => run(() => client.revokeMySession('user requested'), 'Session revoked. Pending approvals you made were cancelled. Sign in again to continue.')}>Revoke my kernel session</button>
        </div>
        <details style={{ marginTop: 10 }}>
          <summary>Delete my account</summary>
          <label className="muted small" htmlFor="del-pw">Confirm with your password</label>
          <input id="del-pw" type="password" autoComplete="current-password" value={del} onChange={e => setDel(e.target.value)} />
          <button className="btn ghost" disabled={!del} onClick={() => run(() => client.deleteAccount({ password: del }), 'Deletion requested.')}>Delete account</button>
        </details>
      </section>
    </div>
  );
}
