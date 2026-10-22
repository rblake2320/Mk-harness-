import { useEffect, useState } from 'react';
import { AppRole, TeamMember } from '../../../packages/sdk/src/index.ts';
import { client } from '../App.tsx';
import { ErrorNote } from './Common.tsx';

export default function MemberAccess() {
  const [members, setMembers] = useState<TeamMember[]>([]);
  const [self, setSelf] = useState('');
  const [error, setError] = useState<unknown>(null);
  const [message, setMessage] = useState('');
  const [busy, setBusy] = useState(false);
  async function reload() { setMembers(await client.members()); }
  useEffect(() => { reload().catch(setError); client.me().then(me => setSelf(me.id)).catch(setError); }, []);
  async function change(member: TeamMember, changes: { role?: AppRole; is_active?: boolean }) {
    setBusy(true); setError(null); setMessage('');
    try {
      await client.changeMemberAccess(member.id, changes);
      setMessage('Access updated. Old app sessions are revoked; kernel approval revocation is queued for delivery.');
      await reload();
    } catch (e) { setError(e); } finally { setBusy(false); }
  }
  return <section className="card" aria-label="Team access" style={{ maxWidth: 720, marginTop: 18 }}>
    <h3>Team access</h3>
    <p>Admins manage access and senders. Managers review team approvals and usage. Consultants manage their own customer book. Auditors can export tenant audit evidence but cannot use customer or action workflows.</p>
    <p>Changing access revokes existing sessions. You cannot remove your own administrator access.</p>
    <ErrorNote error={error} />
    {message && <p role="status">{message}</p>}
    {members.map(member => <div key={member.id} style={{ borderTop: '1px solid var(--edge)', padding: '12px 0' }}>
      <p style={{ overflowWrap: 'anywhere' }}>{member.email}{self === member.id ? ' (you)' : ''} · {member.is_active ? 'Active' : 'Disabled'}</p>
      <div className="row">
        <label>Role for {member.display_name}<select aria-label={`Role for ${member.email}`} value={member.role}
          disabled={busy || !self || self === member.id} onChange={e => change(member, { role: e.target.value as AppRole })}>
          {(['consultant', 'manager', 'auditor', 'admin'] as const).map(role => <option key={role}>{role}</option>)}
        </select></label>
        <button className="btn ghost" disabled={busy || !self || self === member.id}
          onClick={() => change(member, { is_active: !member.is_active })}>{member.is_active ? 'Disable' : 'Enable'} {member.display_name}</button>
      </div>
    </div>)}
    <button className="btn ghost" disabled={busy} onClick={() => reload().catch(setError)}>Refresh members</button>
  </section>;
}
