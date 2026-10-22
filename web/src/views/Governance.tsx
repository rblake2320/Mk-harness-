import { useEffect, useState } from 'react';
import { client } from '../App.tsx';
import { ErrorNote, HumanSteps, fmtWhen } from '../components/Common.tsx';
import type { ErasureReceipt } from '../../../packages/sdk/src/index.ts';

/**
 * Settings → Governance: approval passkeys, sending number status, inbound health,
 * session revocation, data export, audit export, account deletion.
 */
export default function GovernanceSettings({ role, userId, onDeleted }: { role: string; userId: string; onDeleted: (receipt: ErasureReceipt) => void }) {
  const [passkeys, setPasskeys] = useState<any[]>([]);
  const [senders, setSenders] = useState<any[]>([]);
  const [health, setHealth] = useState<any>(null);
  const [kernel, setKernel] = useState<'ok' | 'down' | 'unconfigured' | null>(null);
  const [err, setErr] = useState<unknown>(null);
  const [msg, setMsg] = useState('');
  const [label, setLabel] = useState('');
  const [sender, setSender] = useState({ display_name: '', account_sid: '', auth_token: '', from_number: '' });
  const [del, setDel] = useState('');

  function load() {
    setErr(null);
    if (role === 'auditor') return;
    client.kernelHealth().then(() => setKernel('ok')).catch(e => setKernel(e?.status === 503 ? 'down' : 'unconfigured'));
    client.passkeys().then(setPasskeys).catch(() => setPasskeys([]));
    client.senders().then(setSenders).catch(() => setSenders([]));
    client.inboundHealth().then(setHealth).catch(() => setHealth(null));
  }
  useEffect(load, []);

  const run = (fn: () => Promise<unknown>, ok: string) => { setErr(null); setMsg(''); fn().then(() => { setMsg(ok); load(); }).catch(setErr); };

  function download(name: string, text: string, type = 'application/json') {
    const a = document.createElement('a'); a.href = URL.createObjectURL(new Blob([text], { type })); a.download = name; a.click();
    setTimeout(() => URL.revokeObjectURL(a.href), 1000);
  }

  return (
    <div>
      <h2>Governance</h2>
      {role !== 'auditor' && <div className={`card small ${kernel === 'ok' ? '' : 'limitation'}`} role="status">
        Action kernel: <strong>{kernel === 'ok' ? 'connected' : kernel === 'down' ? 'unreachable — approvals and sending are unavailable' : 'not configured in this environment'}</strong>.
        {kernel !== 'ok' && ' Nothing can be approved or sent until it is. No local fallback exists.'}
      </div>}
      <ErrorNote error={err} onDismiss={() => setErr(null)} />
      {msg && <div className="ok-note" role="status">{msg}</div>}

      {role !== 'auditor' && <><section className="card" style={{ marginTop: 16 }}>
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
        {role === 'admin' && (
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
          <p className="small">{health.dispatch_blocked ? <strong>Sending paused: {health.dispatch_blocked}.</strong> : <strong>Healthy.</strong>} {health.pending_events} unprocessed replies.
            {health.health?.last_ok_at && <> Last successful check {fmtWhen(health.health.last_ok_at)}.</>}
            {health.health?.last_failure_at && <> Last failure {fmtWhen(health.health.last_failure_at)} ({health.health.last_failure_reason}).</>}
            <br /><span className="muted">If replies cannot be received for 60 s, outbound sending pauses automatically and resumes only after a successful check with no backlog.</span></p>
        ) : <p className="muted small">Not available (kernel unreachable or not configured).</p>}
      </section></>}

      <section className="card" style={{ marginTop: 16 }}>
        <h3 style={{ marginTop: 0 }}>Your data & evidence</h3>
        <HumanSteps steps={['Deletion removes active application data and signs out all sessions. Downstream provider processing and backup expiry are tracked separately. Minimal consent and content-free audit records are retained.']} />
        <div className="row">
          <button className="btn ghost" onClick={() => client.exportAccount().then(d => download('my-data.json', JSON.stringify(d, null, 2))).catch(setErr)}>Export my data (JSON)</button>
          {role !== 'auditor' && <button className="btn ghost" onClick={() => client.exportCustomersCsv().then(t => download('customers.csv', t, 'text/csv')).catch(setErr)}>Export customers (CSV)</button>}
          {(role === 'admin' || role === 'auditor') && <button className="btn ghost" onClick={() => client.exportAudit().then(t => download('audit.jsonl', t, 'application/x-ndjson')).catch(setErr)}>Export audit log ({role})</button>}
        </div>
        <p className="small">Use Sign out to revoke this app session and its pending kernel approvals. Other sessions can be revoked above.</p>
        <details style={{ marginTop: 10 }}>
          <summary>Delete my account</summary>
          <label className="muted small" htmlFor="del-pw">Confirm with your password</label>
          <input id="del-pw" type="password" autoComplete="current-password" value={del} onChange={e => setDel(e.target.value)} />
          <button className="btn ghost" disabled={!del} onClick={() => {
            setErr(null); client.deleteAccount({ password: del }).then(onDeleted).catch(setErr);
          }}>Delete account</button>
        </details>
      </section>
    </div>
  );
}
