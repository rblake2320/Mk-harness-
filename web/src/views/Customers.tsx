import { useEffect, useState } from 'react';
import { client } from '../App.tsx';
import { AiBadge } from '../components/AiDisclosure.tsx';
import type { Customer, Suggestion } from '../../../packages/sdk/src/index.ts';

const EMPTY = { name: '', phone: '', email: '', notes: '' };

export default function CustomersView() {
  const [list, setList] = useState<Customer[]>([]);
  const [suggestions, setSuggestions] = useState<Suggestion[]>([]);
  const [form, setForm] = useState<typeof EMPTY & { id?: string }>(EMPTY);
  const [editing, setEditing] = useState(false);
  const [err, setErr] = useState('');
  const [drafts, setDrafts] = useState<{ name: string; text: string } | null>(null);
  const [busyId, setBusyId] = useState('');

  function refresh() {
    client.listCustomers().then(setList).catch(e => setErr(e.message));
    client.suggestions().then(setSuggestions).catch(() => {});
  }
  useEffect(refresh, []);

  async function save() {
    setErr('');
    try {
      if (!form.name.trim()) { setErr('Name is required.'); return; }
      if (form.id) await client.updateCustomer(form.id, form);
      else await client.createCustomer(form);
      setForm(EMPTY); setEditing(false); refresh();
    } catch (e: any) { setErr(e.message); }
  }

  async function followUp(c: Customer) {
    setBusyId(c.id); setDrafts(null); setErr('');
    try {
      const r = await client.followUp(c.id, 'warm check-in and gentle reorder');
      setDrafts({ name: c.name, text: r.drafts });
      await client.updateCustomer(c.id, c); // no-op keep
    } catch (e: any) { setErr(e.message); } finally { setBusyId(''); }
  }

  return (
    <div>
      <div className="row" style={{ justifyContent: 'space-between' }}>
        <h1 style={{ margin: 0 }}>My customers</h1>
        <button className="btn" onClick={() => { setForm(EMPTY); setEditing(true); }}>
          Add customer
        </button>
      </div>
      {err && <div className="error" role="alert" style={{ margin: '10px 0' }}>{err}</div>}

      {suggestions.length > 0 && (
        <div className="card power-hour" style={{ margin: '16px 0', maxWidth: 760 }}>
          <h3 style={{ marginTop: 0 }}>Power Hour — reach out today</h3>
          <p className="muted" style={{ marginTop: 0, marginBottom: 12 }}>
            Your most overdue customers. One reorder can pay for months of the app.
          </p>
          {suggestions.map(s => (
            <div className="ph-row" key={s.id}>
              <div>
                <strong>{s.name}</strong>
                <div className="level">{s.urgency}</div>
              </div>
              <button className="btn ghost" disabled={busyId === s.id}
                      onClick={() => followUp(s)}>
                {busyId === s.id ? 'Writing…' : <><AiBadge /> Draft follow-up</>}
              </button>
            </div>
          ))}
        </div>
      )}

      {editing && (
        <div className="card" style={{ margin: '16px 0', maxWidth: 560, display: 'grid', gap: 10 }}>
          <input placeholder="Name" value={form.name}
                 onChange={e => setForm({ ...form, name: e.target.value })} />
          <div className="row">
            <input placeholder="Phone" value={form.phone} style={{ flex: 1 }}
                   onChange={e => setForm({ ...form, phone: e.target.value })} />
            <input placeholder="Email" value={form.email} style={{ flex: 1 }}
                   onChange={e => setForm({ ...form, email: e.target.value })} />
          </div>
          <textarea placeholder="Notes — shades, favorites, reorder cadence, family details…"
                    rows={3} value={form.notes}
                    onChange={e => setForm({ ...form, notes: e.target.value })} />
          <div className="row">
            <button className="btn" onClick={save}>{form.id ? 'Save changes' : 'Add customer'}</button>
            <button className="btn ghost" onClick={() => { setEditing(false); setForm(EMPTY); }}>Cancel</button>
          </div>
        </div>
      )}

      <table style={{ marginTop: 14 }}>
        <thead><tr><th>Name</th><th>Contact</th><th>Notes</th><th>Last contact</th><th></th></tr></thead>
        <tbody>
          {list.map(c => (
            <tr key={c.id}>
              <td><strong>{c.name}</strong></td>
              <td>{[c.phone, c.email].filter(Boolean).join(' · ') || '—'}</td>
              <td className="muted" style={{ maxWidth: 320 }}>{c.notes || '—'}</td>
              <td>{c.last_contact ? new Date(c.last_contact).toLocaleDateString() : 'never'}</td>
              <td>
                <div className="row" style={{ flexWrap: 'nowrap' }}>
                  <button className="btn ghost" disabled={busyId === c.id}
                          onClick={() => followUp(c)}>
                    {busyId === c.id ? 'Writing…' : 'Draft follow-up'}
                  </button>
                  <button className="btn ghost"
                          onClick={() => { setForm({ ...c }); setEditing(true); }}>Edit</button>
                  <button className="btn ghost"
                          onClick={async () => { await client.deleteCustomer(c.id); refresh(); }}>
                    Delete
                  </button>
                </div>
              </td>
            </tr>
          ))}
          {list.length === 0 && (
            <tr><td colSpan={5} className="muted">
              No customers yet. Add your first one — notes power the AI follow-ups.
            </td></tr>
          )}
        </tbody>
      </table>

      {drafts && (
        <div className="card" style={{ marginTop: 18, maxWidth: 720 }}>
          <h3 style={{ marginTop: 0 }}>Follow-up drafts for {drafts.name}</h3>
          <div style={{ whiteSpace: 'pre-wrap' }}>{drafts.text}</div>
          <div className="row" style={{ marginTop: 12 }}>
            <button className="btn ghost"
                    onClick={() => navigator.clipboard.writeText(drafts.text)}>Copy</button>
            <button className="btn ghost" onClick={() => setDrafts(null)}>Close</button>
          </div>
        </div>
      )}
    </div>
  );
}
