import { useEffect, useRef, useState } from 'react';
import { client } from '../App.tsx';
import type { SkinResult } from '../../../packages/sdk/src/index.ts';

export default function SkinView() {
  const [preview, setPreview] = useState<string | null>(null);
  const [file, setFile] = useState<File | null>(null);
  const [customers, setCustomers] = useState<any[]>([]);
  const [customerId, setCustomerId] = useState('');
  const [provider, setProvider] = useState('');
  const [busy, setBusy] = useState(false);
  const [err, setErr] = useState('');
  const [result, setResult] = useState<SkinResult | null>(null);
  const [resultMeta, setResultMeta] = useState('');
  const [history, setHistory] = useState<any[]>([]);
  const inputRef = useRef<HTMLInputElement>(null);

  useEffect(() => {
    client.listCustomers().then(setCustomers).catch(() => {});
    client.skinHistory().then(setHistory).catch(() => {});
  }, []);

  function pick(f: File | null) {
    setFile(f); setResult(null); setErr('');
    if (preview) URL.revokeObjectURL(preview);
    setPreview(f ? URL.createObjectURL(f) : null);
  }

  async function analyze() {
    if (!file || busy) return;
    setBusy(true); setErr(''); setResult(null);
    try {
      const r = await client.analyzeSkin(file, {
        customer_id: customerId || undefined, provider: provider || undefined });
      setResult(r.result);
      setResultMeta(`${r.provider} · ${r.model}`);
      client.skinHistory().then(setHistory).catch(() => {});
    } catch (e: any) { setErr(e.message); } finally { setBusy(false); }
  }

  return (
    <div>
      <h1>Skin studio</h1>
      <p className="muted" style={{ maxWidth: 640 }}>
        Upload a clear, well-lit face photo. You'll get cosmetic observations,
        care focus areas, and talking points you can use with your customer.
        This is never medical advice.
      </p>

      <div className="card" style={{ maxWidth: 720 }}>
        <div className="row">
          <input ref={inputRef} type="file" accept="image/jpeg,image/png,image/webp"
                 style={{ display: 'none' }}
                 onChange={e => pick(e.target.files?.[0] ?? null)} />
          <button className="btn ghost" onClick={() => inputRef.current?.click()}>
            {file ? 'Change photo' : 'Choose photo'}
          </button>
          <select value={customerId} onChange={e => setCustomerId(e.target.value)}
                  style={{ width: 220 }} aria-label="Link to customer">
            <option value="">No customer link</option>
            {customers.map(c => <option key={c.id} value={c.id}>{c.name}</option>)}
          </select>
          <select value={provider} onChange={e => setProvider(e.target.value)}
                  style={{ width: 170 }} aria-label="Provider">
            <option value="">Auto (failover)</option>
            {['anthropic', 'openai', 'gemini', 'ollama'].map(p =>
              <option key={p} value={p}>{p}</option>)}
          </select>
          <button className="btn" disabled={!file || busy} onClick={analyze}>
            {busy ? 'Analyzing…' : 'Analyze'}
          </button>
        </div>
        {preview && (
          <img src={preview} alt="Selected face photo"
               style={{ marginTop: 14, maxWidth: 260, borderRadius: 12,
                        border: '1px solid var(--edge-hi)' }} />
        )}
        {err && <div className="error" role="alert" style={{ marginTop: 10 }}>{err}</div>}
      </div>

      {result && (
        <div className="mirror" style={{ marginTop: 20 }}>
          <h3 className="display">Cosmetic observations</h3>
          <div className="muted" style={{ fontSize: 13, marginBottom: 8 }}>{resultMeta}</div>
          {result.observations.map((o, i) => (
            <div className="obs" key={i}>
              <strong>{o.category.replace(/_/g, ' ')}</strong>
              <span className="level">{o.level}</span>
              <span>{o.note}</span>
            </div>
          ))}
          <h3 className="display" style={{ marginTop: 16 }}>Care focus</h3>
          <div>{result.care_focus.map((c, i) => <span className="pill" key={i}>{c}</span>)}</div>
          <h3 className="display" style={{ marginTop: 16 }}>Suggested routine</h3>
          <div className="row" style={{ alignItems: 'start' }}>
            <div style={{ minWidth: 200 }}>
              <div className="level">Morning</div>
              {result.routine_suggestion.am.map((s, i) => <div key={i}>· {s}</div>)}
            </div>
            <div style={{ minWidth: 200 }}>
              <div className="level">Evening</div>
              {result.routine_suggestion.pm.map((s, i) => <div key={i}>· {s}</div>)}
            </div>
          </div>
          <h3 className="display" style={{ marginTop: 16 }}>Talking points</h3>
          {result.consultant_talking_points.map((t, i) => <p key={i} style={{ margin: '4px 0' }}>“{t}”</p>)}
          {result.see_professional && (
            <p style={{ color: 'var(--brass)' }}>
              Some areas may benefit from a dermatologist's opinion.
            </p>
          )}
          <div className="disclaimer">{result.disclaimer}</div>
        </div>
      )}

      {history.length > 0 && (
        <div style={{ marginTop: 28 }}>
          <h2>Recent analyses</h2>
          <table>
            <thead><tr><th>When</th><th>Customer</th><th>Engine</th><th>Top focus</th></tr></thead>
            <tbody>
              {history.slice(0, 10).map(h => (
                <tr key={h.id}>
                  <td>{new Date(h.created_at).toLocaleString()}</td>
                  <td>{customers.find(c => c.id === h.customer_id)?.name ?? '—'}</td>
                  <td>{h.provider}</td>
                  <td>{h.result?.care_focus?.[0] ?? '—'}</td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      )}
    </div>
  );
}
