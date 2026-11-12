import { useEffect, useRef, useState } from 'react';
import { FlatList, KeyboardAvoidingView, Platform, StyleSheet, Text, View } from 'react-native';
import { client } from '../api';
import { AiStrip, Button, Choices, ErrorNote, Field } from '../components/ui';
import { rnChatStream } from '../stream';
import { C, GUTTER } from '../theme';

/** "Ask anything" — moved unchanged in behaviour from the old single-file app, plus the
 *  SB 243 AI disclosure strip and the shared accessible controls. */
export default function ChatScreen() {
  const [skill, setSkill] = useState('assistant');
  const [skills, setSkills] = useState<Record<string, { label: string }>>({});
  const [msgs, setMsgs] = useState<{ role: string; content: string }[]>([]);
  const [input, setInput] = useState('');
  const [busy, setBusy] = useState(false);
  const [err, setErr] = useState<unknown>(null);
  const convId = useRef<string | undefined>(undefined);
  const listRef = useRef<FlatList>(null);

  useEffect(() => { client.listSkills().then(setSkills).catch(() => {}); }, []);

  function send() {
    const text = input.trim();
    if (!text || busy) return;
    setBusy(true); setInput(''); setErr(null);
    setMsgs(m => [...m, { role: 'user', content: text }, { role: 'assistant', content: '' }]);
    let acc = '';
    rnChatStream(client, { message: text, conversation_id: convId.current, skill }, ev => {
      if (ev.type === 'meta') convId.current = ev.conversation_id;
      if (ev.type === 'delta') {
        acc += ev.text;
        setMsgs(m => { const c = m.slice(); c[c.length - 1] = { role: 'assistant', content: acc }; return c; });
      }
      if (ev.type === 'done') setBusy(false);
      if (ev.type === 'error') { setErr(new Error(ev.message)); setBusy(false); }
    });
  }

  return (
    <KeyboardAvoidingView style={{ flex: 1 }} behavior={Platform.OS === 'ios' ? 'padding' : undefined}>
      <View style={{ paddingHorizontal: GUTTER, paddingTop: 8, gap: 8 }}>
        <AiStrip />
        <Choices label="Assistant skill" options={Object.entries(skills).map(([id, v]) => ({ id, label: v.label }))} value={skill} onChange={setSkill} />
        <ErrorNote error={err} onDismiss={() => setErr(null)} />
      </View>
      <FlatList ref={listRef} data={msgs} keyExtractor={(_, i) => String(i)}
                contentContainerStyle={{ padding: GUTTER, gap: 10 }}
                onContentSizeChange={() => listRef.current?.scrollToEnd({ animated: true })}
                renderItem={({ item }) => (
                  <View style={[st.msg, item.role === 'user' ? st.msgUser : st.msgAi]}>
                    <Text style={{ color: C.text }}>{item.content || '…'}</Text>
                  </View>
                )} />
      <View style={st.composer}>
        <View style={{ flex: 1 }}><Field label="Ask anything" value={input} onChangeText={setInput} multiline /></View>
        <Button label="Send question" text="Ask" busy={busy} onPress={send} />
      </View>
    </KeyboardAvoidingView>
  );
}

const st = StyleSheet.create({
  msg: { borderRadius: 14, padding: 12, maxWidth: '85%' },
  msgUser: { backgroundColor: C.edge, alignSelf: 'flex-end' },
  msgAi: { backgroundColor: C.surface, borderWidth: 1, borderColor: C.edge, alignSelf: 'flex-start' },
  composer: { flexDirection: 'row', gap: 8, padding: 12, borderTopWidth: 1, borderColor: C.edge, alignItems: 'flex-end' },
});
