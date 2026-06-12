import { useEffect, useRef, useState } from 'react';
import { client } from '../App.tsx';

interface Msg { role: 'user' | 'assistant'; content: string; provider?: string; model?: string }

export default function ChatView() {
  const [skills, setSkills] = useState<Record<string, { label: string }>>({});
  const [models, setModels] = useState<Record<string, { provider: string; vision: boolean }>>({});
  const [skill, setSkill] = useState('assistant');
  const [provider, setProvider] = useState('');   // '' = auto failover
  const [model, setModel] = useState('');
  const [convId, setConvId] = useState<string | null>(null);
  const [convs, setConvs] = useState<any[]>([]);
  const [msgs, setMsgs] = useState<Msg[]>([]);
  const [input, setInput] = useState('');
  const [busy, setBusy] = useState(false);
  const [err, setErr] = useState('');
  const logRef = useRef<HTMLDivElement>(null);

  useEffect(() => {
    client.listSkills().then(setSkills).catch(() => {});
    client.listModels().then(setModels).catch(() => {});
    refreshConvs();
  }, []);
  useEffect(() => { logRef.current?.scrollTo({ top: 1e9 }); }, [msgs]);

  function refreshConvs() { client.listConversations().then(setConvs).catch(() => {}); }

  async function openConv(id: string) {
    const c = await client.getConversation(id);
    setConvId(id); setSkill(c.skill);
    setMsgs(c.messages);
  }

  function newConv() { setConvId(null); setMsgs([]); setErr(''); }

  async function send() {
    const text = input.trim();
    if (!text || busy) return;
    setErr(''); setBusy(true); setInput('');
    setMsgs(m => [...m, { role: 'user', content: text }, { role: 'assistant', content: '' }]);
    let assistantText = '';
    await client.chatStream(
      { message: text, conversation_id: convId ?? undefined, skill,
        provider: provider || undefined, model: model || undefined },
      ev => {
        if (ev.type === 'meta') { setConvId(ev.conversation_id); }
        if (ev.type === 'delta') {
          assistantText += ev.text;
          setMsgs(m => {
            const copy = m.slice();
            copy[copy.length - 1] = { role: 'assistant', content: assistantText };
            return copy;
          });
        }
        if (ev.type === 'done') {
          setMsgs(m => {
            const copy = m.slice();
            copy[copy.length - 1] = { role: 'assistant', content: assistantText,
                                      provider: ev.provider, model: ev.model };
            return copy;
          });
          refreshConvs();
        }
        if (ev.type === 'error') { setErr(ev.message); setMsgs(m => m.slice(0, -1)); }
      },
    );
    setBusy(false);
  }

  const modelOptions = Object.entries(models)
    .filter(([, v]) => !provider || v.provider === provider);

  return (
    <div className="chat">
      <div className="row" style={{ marginBottom: 12 }}>
        <select value={skill} onChange={e => setSkill(e.target.value)} style={{ width: 200 }}
                aria-label="Skill">
          {Object.entries(skills).map(([k, v]) => <option key={k} value={k}>{v.label}</option>)}
        </select>
        <select value={provider} onChange={e => { setProvider(e.target.value); setModel(''); }}
                style={{ width: 170 }} aria-label="Provider">
          <option value="">Auto (failover)</option>
          {['anthropic', 'openai', 'gemini', 'ollama'].map(p => <option key={p} value={p}>{p}</option>)}
        </select>
        <select value={model} onChange={e => setModel(e.target.value)} style={{ width: 220 }}
                aria-label="Model">
          <option value="">Default model</option>
          {modelOptions.map(([m]) => <option key={m} value={m}>{m}</option>)}
        </select>
        <button className="btn ghost" onClick={newConv}>New chat</button>
        {convs.length > 0 && (
          <select value={convId ?? ''} onChange={e => e.target.value && openConv(e.target.value)}
                  style={{ width: 240 }} aria-label="Past conversations">
            <option value="">Past conversations…</option>
            {convs.map(c => <option key={c.id} value={c.id}>{c.title}</option>)}
          </select>
        )}
      </div>

      <div className="chat-log" ref={logRef}>
        {msgs.length === 0 && (
          <div className="card" style={{ maxWidth: 680 }}>
            <h3 style={{ marginTop: 0 }}>Ask anything about your business</h3>
            <p className="muted" style={{ marginBottom: 0 }}>
              Booking parties, handling objections, follow-up texts, social captions,
              product questions. Pick a skill above, or just type.
            </p>
          </div>
        )}
        {msgs.map((m, i) => (
          <div key={i} className={`msg ${m.role}`}>
            {m.content || <span className="muted">…</span>}
            {m.provider && <span className="meta">{m.provider} · {m.model}</span>}
          </div>
        ))}
      </div>

      {err && <div className="error" role="alert" style={{ padding: '6px 0' }}>{err}</div>}
      <div className="chat-input">
        <textarea value={input} onChange={e => setInput(e.target.value)}
                  placeholder="Type your question…" aria-label="Message"
                  onKeyDown={e => { if (e.key === 'Enter' && !e.shiftKey) { e.preventDefault(); send(); } }} />
        <button className="btn" disabled={busy || !input.trim()} onClick={send}>
          {busy ? 'Thinking…' : 'Send'}
        </button>
      </div>
    </div>
  );
}
