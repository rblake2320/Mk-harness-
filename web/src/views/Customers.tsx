import { useEffect, useState } from 'react';
import { client } from '../App.tsx';
import { AiBadge } from '../components/AiDisclosure.tsx';
import type { Customer } from '../../../packages/sdk/src/index.ts';

const EMPTY = { name: '', phone: '', email: '', notes: '' };

export default function CustomersView({ onOpen }: { onOpen: (c: Customer) => void }) {
  const [list, setList] = useState<Customer[]>([]);
  const [form, setForm] = useState<typeof EMPTY & { id?: string }>(EMPTY);
  const [editing, setEditing] = useState(false);
  const [err, setErr] = useState('');

  function refresh() {
    client.listCustomers().then(setList).catch(e => setErr(e.message));
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


  return (
    <div>
      <div className="row" style={{ justifyContent: 'space-between' }}>
        <h1 style={{ margin: 0 }}>My customers</h1>
        <button className="btn" onClick={() => { setForm(EMPTY); setEditing(true); }}>
          Add customer
        </button>
      </div>
      {err && <div className="error" role="alert" style={{ margin: '10px 0' }}>{err}</div>}

      <p className="muted small">Follow-ups come from your brief (confirmed promises, requests and customer dates) — never from guesses about purchase age.</p>

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

      {/* Explicit ARIA table roles keep the semantics when narrow screens restyle rows as cards. */}
      <table className="responsive" role="table" style={{ marginTop: 14 }}>
        <thead role="rowgroup"><tr role="row"><th role="columnheader">Name</th><th role="columnheader">Contact</th><th role="columnheader">Notes</th><th role="columnheader">Last contact</th><th role="columnheader"><span className="visually-hidden">Actions</span></th></tr></thead>
        <tbody role="rowgroup">
          {list.map(c => (
            <tr key={c.id} role="row">
              <td role="cell"><button className="link" onClick={() => onOpen(c)}><strong>{c.name}</strong></button></td>
              <td role="cell" data-label="Contact">{[c.phone, c.email].filter(Boolean).join(' · ') || '—'}</td>
              <td role="cell" data-label="Notes" className="muted" style={{ maxWidth: 320 }}>{c.notes || '—'}</td>
              <td role="cell" data-label="Last contact">{c.last_contact ? new Date(c.last_contact).toLocaleDateString() : 'never'}</td>
              <td role="cell">
                <div className="row actions">
                  <button className="btn ghost" onClick={() => onOpen(c)}>Open</button>
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
            <tr role="row"><td role="cell" colSpan={5} className="muted">
              No customers yet. Add your first one. Notes stay private to you; they are context, never quoted to a customer.
            </td></tr>
          )}
        </tbody>
      </table>

    </div>
  );
}
