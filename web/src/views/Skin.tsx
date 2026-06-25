import { useEffect, useRef, useState } from 'react';
import { client } from '../App.tsx';
import { AiStrip, AiBadge } from '../components/AiDisclosure.tsx';
import { ApiError } from '../../../packages/sdk/src/index.ts';
import type { SkinResult, ConsentStatus } from '../../../packages/sdk/src/index.ts';

export default function SkinView() {
  const [preview, setPreview] = useState<string | null>(null);
  const [file, setFile] = useState<File | null>(null);
  const [customers, setCustomers] = useState<any[]>([]);
  const [customerId, setCustomerId] = useState('');
  const [provider, setProvider] = useState('');
  const [busy, setBusy] = useState(false);
  const [err, setErr] = useState('');
  const [result, setResult] = useState<(SkinResult & { ai_disclosure?: string }) | null>(null);
  const [resultMeta, setResultMeta] = useState('');
  const [history, setHistory] = useState<any[]>([]);
  const [consentInfo, setConsentInfo] = useState<ConsentStatus | null>(null);
  const [consentModal, setConsentModal] = useState<null | 'operator' | 'customer'>(null);
  const [granting, setGranting] = useState(false);
  const inputRef = useRef<HTMLInputElement>(null);

  useEffect(() => {
    client.listCustomers().then(setCustomers).catch(() => {});
    client.skinHistory().then(setHistory).catch(() => {});
    client.getSkinConsent().then(setConsentInfo).catch(() => {});
  }, []);

  function pick(f: File | null) {
    setFile(f); setResult(null); setErr('');
    if (preview) URL.revokeObjectURL(preview);
    setPreview(f ? URL.createObjectURL(f) : null);
  }

  async function runAnalyze() {
    const r = await client.analyzeSkin(file!, {
      customer_id: customerId || undefined, provider: provider || undefined });
    setResult(r.result);
    setResultMeta(`${r.provider} · ${r.model}`);
    client.skinHistory().then(setHistory).catch(() => {});
  }

  async function analyze() {
    if (!file || busy) return;
    setBusy(true); setErr(''); setResult(null);
    try {
      await runAnalyze();
    } catch (e: any) {
      // Backend is the source of truth for the consent gate — raise the right modal.
      if (e instanceof ApiError && e.code === 'operator_consent_required') setConsentModal('operator');
      else if (e instanceof ApiError && e.code === 'customer_consent_required') setConsentModal('customer');
      else setErr(e.message);
    } finally { setBusy(false); }
  }

  async function grantAndRetry(subject: 'operator' | 'customer') {
    setGranting(true); setErr('');
    try {
      await client.grantSkinConsent(subject, subject === 'customer' ? customerId : undefined);
      client.getSkinConsent().then(setConsentInfo).catch(() => {});
      setConsentModal(null);
      setBusy(true);
      try { await runAnalyze(); }
      catch (e: any) {
        if (e instanceof ApiError && e.code === 'customer_consent_required') setConsentModal('customer');
        else setErr(e.message);
      } finally { setBusy(false); }
    } catch (e: any) { setErr(e.message); } finally { setGranting(false); }
  }

  return (
    <div>
      <h1>Skin studio</h1>
      <AiStrip />
      <p className="muted" style={{ maxWidth: 640 }}>
        Upload a clear, well-lit face photo. You'll get cosmetic observations,
        care focus areas, and talking points you can use with your customer.
        This is never medical advice. The photo is analyzed and not stored — only
        cosmetic notes are kept, and you can delete them anytime from Settings.
      </p>

      {consentModal && consentInfo && (
        <div className="modal-backdrop" role="dialog" aria-modal="true" aria-label="Consent required">
          <div className="card modal">
            <h3 style={{ marginTop: 0 }}>
              {consentModal === 'operator' ? 'Before you analyze a photo' : 'Confirm customer consent'}
            </h3>
            <p className="muted" style={{ whiteSpace: 'pre-wrap' }}>
              {consentModal === 'operator' ? consentInfo.operator_text : consentInfo.customer_text}
            </p>
            <div className="row">
              <button className="btn" disabled={granting} onClick={() => grantAndRetry(consentModal)}>
                {granting ? 'Saving…'
                  : consentModal === 'operator' ? 'I agree — continue' : 'My customer consented — continue'}
              </button>
              <button className="btn ghost" disabled={granting}
                      onClick={() => { setConsentModal(null); setBusy(false); }}>Cancel</button>
            </div>
          </div>
        </div>
      )}

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
          <h3 className="display"><AiBadge /> Cosmetic observations</h3>
          <div className="muted" style={{ fontSize: 13, marginBottom: 8 }}>{resultMeta}</div>
          {result.ai_disclosure && (
            <div className="disclaimer" style={{ marginTop: 0, marginBottom: 10, borderTop: 0,
                 borderBottom: '1px solid var(--edge-hi)', paddingBottom: 10 }}>
              {result.ai_disclosure}
            </div>
          )}
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
