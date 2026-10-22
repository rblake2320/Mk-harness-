import { useEffect, useRef, useState } from 'react';
import { client } from '../App.tsx';
import { AiBadge } from '../components/AiDisclosure.tsx';
import type { Customer } from '../../../packages/sdk/src/index.ts';

const EMPTY = { name: '', phone: '', email: '', notes: '' };

export default function CustomersView({ onOpen }: { onOpen: (c: Customer) => void }) {
  const [list, setList] = useState<Customer[]>([]);
  const [form, setForm] = useState<typeof EMPTY & { id?: string }>(EMPTY);
  const [editing, setEditing] = useState(false);
  const [err, setErr] = useState('');
  const [deletionNotice, setDeletionNotice] = useState('');
  const [query, setQuery] = useState('');
  const [activeQuery, setActiveQuery] = useState('');
  const [nextOffset, setNextOffset] = useState<number | null>(null);
  const [loading, setLoading] = useState(false);
  const requestId = useRef(0);

  async function refresh(term = activeQuery, offset = 0) {
    const request = ++requestId.current;
    setLoading(true); setErr('');
    try {
      const result = term ? await client.searchCustomers(term, offset) : { items: await client.listCustomers(), next_offset: null };
      if (request !== requestId.current) return;
      setList(previous => offset ? [...previous, ...result.items] : result.items);
      setActiveQuery(term); setNextOffset(result.next_offset);
    } catch (e: any) { if (request === requestId.current) setErr(e.message); }
    finally { if (request === requestId.current) setLoading(false); }
  }
  useEffect(() => { void refresh(''); }, []);

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
      {deletionNotice && <p role="status">{deletionNotice}</p>}

      <p className="muted small">Follow-ups come from your brief (confirmed promises, requests and customer dates) — never from guesses about purchase age.</p>

      <form role="search" onSubmit={e => { e.preventDefault(); void refresh(query.trim()); }}>
        <label htmlFor="customer-search">Find a customer by name, phone or email</label>
        <div className="row" style={{ flexWrap: 'wrap', marginTop: 6 }}>
          <input id="customer-search" type="search" maxLength={120} value={query}
                 onChange={e => setQuery(e.target.value)} style={{ flex: '1 1 200px', minWidth: 0 }} />
          <button className="btn" type="submit" disabled={loading}>Search</button>
          {activeQuery && <button className="btn ghost" type="button" onClick={() => { setQuery(''); void refresh(''); }}>Clear search</button>}
        </div>
        <p className="muted small" role="status">{loading ? 'Loading customers…' : `${list.length} customer${list.length === 1 ? '' : 's'} shown${activeQuery ? ' for your search' : ''}.`}</p>
      </form>

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

      <table className="customer-table" role="table" style={{ marginTop: 14 }}>
        <thead><tr><th>Name</th><th>Contact</th><th>Notes</th><th>Last contact</th><th></th></tr></thead>
        <tbody>
          {list.map(c => (
            <tr key={c.id}>
              <td><button className="link" onClick={() => onOpen(c)}><strong>{c.name}</strong></button></td>
              <td data-label="Contact">{[c.phone, c.email].filter(Boolean).join(' · ') || '—'}</td>
              <td data-label="Notes" className="muted" style={{ maxWidth: 320 }}>{c.notes || '—'}</td>
              <td data-label="Last contact">{c.last_contact ? new Date(c.last_contact).toLocaleDateString() : 'never'}</td>
              <td>
                <div className="row" style={{ flexWrap: 'nowrap' }}>
                  <button className="btn ghost" onClick={() => onOpen(c)}>Open</button>
                  <button className="btn ghost"
                          onClick={() => { setForm({ ...c }); setEditing(true); }}>Edit</button>
                  <button className="btn ghost"
                          onClick={async () => {
                            try { const receipt = await client.deleteCustomer(c.id); setDeletionNotice(receipt.detail); await refresh(); }
                            catch (e: any) { setErr(e.message); }
                          }}>
                    Delete
                  </button>
                </div>
              </td>
            </tr>
          ))}
          {list.length === 0 && (
            <tr><td colSpan={5} className="muted">
              {activeQuery ? 'No matching customers. Try another name, phone number or email.' : 'No customers yet. Add your first one. Notes stay private to you; they are context, never quoted to a customer.'}
            </td></tr>
          )}
        </tbody>
      </table>
      {nextOffset !== null && <button className="btn ghost" disabled={loading} onClick={() => void refresh(activeQuery, nextOffset)}>More results</button>}

    </div>
  );
}
