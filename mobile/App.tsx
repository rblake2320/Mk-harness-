/**
 * Consultant Studio — React Native client (Expo).
 * Shares the TypeScript SDK with the web app; streaming via src/stream.ts.
 */
import { useEffect, useRef, useState } from 'react';
import {
  ActivityIndicator, Alert, FlatList, Image, KeyboardAvoidingView, Platform,
  Pressable, ScrollView, StyleSheet, Text, TextInput, View,
} from 'react-native';
import { StatusBar } from 'expo-status-bar';
import * as ImagePicker from 'expo-image-picker';
import Constants from 'expo-constants';
import { MKClient, SkinResult, Tokens, Customer } from '../packages/sdk/src/index';
import { rnChatStream } from './src/stream';

const API_URL = (Constants.expoConfig?.extra as any)?.apiUrl ?? 'http://localhost:8000';
const client = new MKClient(API_URL);

const C = {
  bg: '#161216', surface: '#221b21', edge: '#2f262e', edgeHi: '#4a3a45',
  rose: '#e8a8b8', brass: '#d9b08c', text: '#f2e9ee', muted: '#a8929f', danger: '#e87a7a',
};

type Tab = 'chat' | 'skin' | 'customers';

export default function App() {
  const [tokens, setTokens] = useState<Tokens | null>(null);
  const [tab, setTab] = useState<Tab>('chat');

  useEffect(() => {
    client.tokens = tokens;
    client.onAuthExpired = () => setTokens(null);
  }, [tokens]);

  if (!tokens) return <Auth onAuthed={setTokens} />;
  return (
    <View style={s.app}>
      <StatusBar style="light" />
      <View style={s.header}>
        <Text style={s.brand}>Consultant <Text style={{ color: C.rose }}>Studio</Text></Text>
        <Pressable onPress={() => setTokens(null)}><Text style={s.muted}>Sign out</Text></Pressable>
      </View>
      <View style={{ flex: 1 }}>
        {tab === 'chat' && <Chat />}
        {tab === 'skin' && <Skin />}
        {tab === 'customers' && <Customers />}
      </View>
      <View style={s.tabbar}>
        {(['chat', 'skin', 'customers'] as Tab[]).map(t => (
          <Pressable key={t} style={s.tab} onPress={() => setTab(t)}>
            <Text style={[s.tabLabel, tab === t && { color: C.rose }]}>
              {t === 'chat' ? 'Ask' : t === 'skin' ? 'Skin' : 'Customers'}
            </Text>
          </Pressable>
        ))}
      </View>
    </View>
  );
}

function Auth({ onAuthed }: { onAuthed: (t: Tokens) => void }) {
  const [email, setEmail] = useState('');
  const [pw, setPw] = useState('');
  const [busy, setBusy] = useState(false);
  async function go() {
    setBusy(true);
    try { onAuthed(await client.login(email, pw)); }
    catch (e: any) { Alert.alert('Sign in failed', e.message); }
    finally { setBusy(false); }
  }
  return (
    <View style={[s.app, { justifyContent: 'center', padding: 24 }]}>
      <StatusBar style="light" />
      <Text style={[s.brand, { fontSize: 28, marginBottom: 18 }]}>
        Consultant <Text style={{ color: C.rose }}>Studio</Text>
      </Text>
      <TextInput style={s.input} placeholder="Email" placeholderTextColor={C.muted}
                 autoCapitalize="none" keyboardType="email-address"
                 value={email} onChangeText={setEmail} />
      <TextInput style={s.input} placeholder="Password" placeholderTextColor={C.muted}
                 secureTextEntry value={pw} onChangeText={setPw} />
      <Pressable style={s.btn} onPress={go} disabled={busy}>
        {busy ? <ActivityIndicator color="#2a1620" /> : <Text style={s.btnText}>Sign in</Text>}
      </Pressable>
      <Text style={[s.muted, { marginTop: 14, textAlign: 'center' }]}>
        New team? Create it on the web app first.
      </Text>
    </View>
  );
}

function Chat() {
  const [skill, setSkill] = useState('assistant');
  const [skills, setSkills] = useState<Record<string, { label: string }>>({});
  const [msgs, setMsgs] = useState<{ role: string; content: string }[]>([]);
  const [input, setInput] = useState('');
  const [busy, setBusy] = useState(false);
  const convId = useRef<string | undefined>(undefined);
  const listRef = useRef<FlatList>(null);

  useEffect(() => { client.listSkills().then(setSkills).catch(() => {}); }, []);

  function send() {
    const text = input.trim();
    if (!text || busy) return;
    setBusy(true); setInput('');
    setMsgs(m => [...m, { role: 'user', content: text }, { role: 'assistant', content: '' }]);
    let acc = '';
    rnChatStream(client, { message: text, conversation_id: convId.current, skill }, ev => {
      if (ev.type === 'meta') convId.current = ev.conversation_id;
      if (ev.type === 'delta') {
        acc += ev.text;
        setMsgs(m => { const c = m.slice(); c[c.length - 1] = { role: 'assistant', content: acc }; return c; });
      }
      if (ev.type === 'done') setBusy(false);
      if (ev.type === 'error') { Alert.alert('AI error', ev.message); setBusy(false); }
    });
  }

  return (
    <KeyboardAvoidingView style={{ flex: 1 }}
                          behavior={Platform.OS === 'ios' ? 'padding' : undefined}>
      <ScrollView horizontal showsHorizontalScrollIndicator={false}
                  style={{ flexGrow: 0, paddingHorizontal: 12 }}>
        {Object.entries(skills).map(([k, v]) => (
          <Pressable key={k} style={[s.chip, skill === k && s.chipOn]} onPress={() => setSkill(k)}>
            <Text style={{ color: skill === k ? '#2a1620' : C.text, fontSize: 13 }}>{v.label}</Text>
          </Pressable>
        ))}
      </ScrollView>
      <FlatList ref={listRef} data={msgs} keyExtractor={(_, i) => String(i)}
                contentContainerStyle={{ padding: 14, gap: 10 }}
                onContentSizeChange={() => listRef.current?.scrollToEnd({ animated: true })}
                renderItem={({ item }) => (
                  <View style={[s.msg, item.role === 'user' ? s.msgUser : s.msgAi]}>
                    <Text style={{ color: C.text }}>{item.content || '…'}</Text>
                  </View>
                )} />
      <View style={s.composer}>
        <TextInput style={[s.input, { flex: 1, marginBottom: 0 }]} placeholder="Ask anything…"
                   placeholderTextColor={C.muted} value={input} onChangeText={setInput} multiline />
        <Pressable style={[s.btn, { paddingHorizontal: 18 }]} onPress={send} disabled={busy}>
          <Text style={s.btnText}>{busy ? '…' : 'Send'}</Text>
        </Pressable>
      </View>
    </KeyboardAvoidingView>
  );
}

function Skin() {
  const [photo, setPhoto] = useState<{ uri: string } | null>(null);
  const [busy, setBusy] = useState(false);
  const [result, setResult] = useState<SkinResult | null>(null);

  async function pick(fromCamera: boolean) {
    const fn = fromCamera ? ImagePicker.launchCameraAsync : ImagePicker.launchImageLibraryAsync;
    if (fromCamera) {
      const p = await ImagePicker.requestCameraPermissionsAsync();
      if (!p.granted) { Alert.alert('Camera permission needed'); return; }
    }
    const r = await fn({ mediaTypes: ['images'], quality: 0.9 });
    if (!r.canceled && r.assets[0]) { setPhoto({ uri: r.assets[0].uri }); setResult(null); }
  }

  async function analyze() {
    if (!photo) return;
    setBusy(true); setResult(null);
    try {
      const r = await client.analyzeSkin(
        { uri: photo.uri, name: 'face.jpg', type: 'image/jpeg' });
      setResult(r.result);
    } catch (e: any) { Alert.alert('Analysis failed', e.message); }
    finally { setBusy(false); }
  }

  return (
    <ScrollView contentContainerStyle={{ padding: 16, gap: 12 }}>
      <Text style={s.h1}>Skin studio</Text>
      <Text style={s.muted}>
        Take a clear, well-lit face photo for cosmetic observations. Never medical advice.
      </Text>
      <View style={{ flexDirection: 'row', gap: 10 }}>
        <Pressable style={s.btnGhost} onPress={() => pick(true)}>
          <Text style={{ color: C.rose }}>Camera</Text>
        </Pressable>
        <Pressable style={s.btnGhost} onPress={() => pick(false)}>
          <Text style={{ color: C.rose }}>Photo library</Text>
        </Pressable>
        <Pressable style={[s.btn, { flex: 1 }]} onPress={analyze} disabled={!photo || busy}>
          {busy ? <ActivityIndicator color="#2a1620" />
                : <Text style={s.btnText}>Analyze</Text>}
        </Pressable>
      </View>
      {photo && <Image source={photo} style={{ width: 180, height: 180, borderRadius: 14 }} />}
      {result && (
        <View style={s.mirror}>
          <Text style={[s.h2, { color: C.rose }]}>Cosmetic observations</Text>
          {result.observations.map((o, i) => (
            <View key={i} style={{ paddingVertical: 6, borderBottomWidth: 1, borderColor: C.edge }}>
              <Text style={{ color: C.text, fontWeight: '600' }}>
                {o.category.replace(/_/g, ' ')}{'  '}
                <Text style={{ color: C.brass, fontSize: 11 }}>{o.level.toUpperCase()}</Text>
              </Text>
              <Text style={{ color: C.text }}>{o.note}</Text>
            </View>
          ))}
          <Text style={[s.h2, { color: C.rose, marginTop: 12 }]}>Care focus</Text>
          <Text style={{ color: C.text }}>{result.care_focus.join(' · ')}</Text>
          <Text style={[s.h2, { color: C.rose, marginTop: 12 }]}>Talking points</Text>
          {result.consultant_talking_points.map((t, i) => (
            <Text key={i} style={{ color: C.text, marginTop: 4 }}>“{t}”</Text>
          ))}
          {result.see_professional && (
            <Text style={{ color: C.brass, marginTop: 10 }}>
              Some areas may benefit from a dermatologist's opinion.
            </Text>
          )}
          <Text style={[s.muted, { marginTop: 12, fontSize: 12 }]}>{result.disclaimer}</Text>
        </View>
      )}
    </ScrollView>
  );
}

function Customers() {
  const [list, setList] = useState<Customer[]>([]);
  const [drafts, setDrafts] = useState('');
  const [busyId, setBusyId] = useState('');

  useEffect(() => { client.listCustomers().then(setList).catch(() => {}); }, []);

  async function followUp(c: Customer) {
    setBusyId(c.id); setDrafts('');
    try {
      const r = await client.followUp(c.id, 'warm check-in and gentle reorder');
      setDrafts(`For ${c.name}:\n\n${r.drafts}`);
    } catch (e: any) { Alert.alert('Draft failed', e.message); }
    finally { setBusyId(''); }
  }

  return (
    <ScrollView contentContainerStyle={{ padding: 16, gap: 10 }}>
      <Text style={s.h1}>My customers</Text>
      {list.length === 0 && (
        <Text style={s.muted}>Add customers on the web app — notes power the AI follow-ups.</Text>
      )}
      {list.map(c => (
        <View key={c.id} style={s.card}>
          <Text style={{ color: C.text, fontWeight: '600', fontSize: 16 }}>{c.name}</Text>
          {!!c.notes && <Text style={[s.muted, { marginTop: 4 }]}>{c.notes}</Text>}
          <Pressable style={[s.btnGhost, { marginTop: 10, alignSelf: 'flex-start' }]}
                     onPress={() => followUp(c)}>
            <Text style={{ color: C.rose }}>
              {busyId === c.id ? 'Writing…' : 'Draft follow-up'}
            </Text>
          </Pressable>
        </View>
      ))}
      {!!drafts && (
        <View style={s.card}>
          <Text style={{ color: C.text }}>{drafts}</Text>
        </View>
      )}
    </ScrollView>
  );
}

const s = StyleSheet.create({
  app: { flex: 1, backgroundColor: C.bg, paddingTop: Platform.OS === 'android' ? 36 : 54 },
  header: { flexDirection: 'row', justifyContent: 'space-between', alignItems: 'center',
            paddingHorizontal: 16, paddingBottom: 10 },
  brand: { color: C.text, fontSize: 19, fontWeight: '600' },
  h1: { color: C.text, fontSize: 22, fontWeight: '600' },
  h2: { fontSize: 16, fontWeight: '600' },
  muted: { color: C.muted },
  input: { backgroundColor: C.bg, borderWidth: 1, borderColor: C.edgeHi, borderRadius: 10,
           color: C.text, padding: 12, marginBottom: 10 },
  btn: { backgroundColor: C.rose, borderRadius: 10, padding: 12, alignItems: 'center',
         justifyContent: 'center' },
  btnText: { color: '#2a1620', fontWeight: '600' },
  btnGhost: { borderWidth: 1, borderColor: C.edgeHi, borderRadius: 10, paddingVertical: 10,
              paddingHorizontal: 14, alignItems: 'center' },
  card: { backgroundColor: C.surface, borderWidth: 1, borderColor: C.edge, borderRadius: 14,
          padding: 14 },
  mirror: { backgroundColor: '#241a20', borderWidth: 1, borderColor: C.edgeHi, borderRadius: 20,
            padding: 18 },
  chip: { borderWidth: 1, borderColor: C.edgeHi, borderRadius: 999, paddingVertical: 6,
          paddingHorizontal: 12, marginRight: 8, marginBottom: 8 },
  chipOn: { backgroundColor: C.rose, borderColor: C.rose },
  msg: { borderRadius: 14, padding: 12, maxWidth: '85%' },
  msgUser: { backgroundColor: C.edge, alignSelf: 'flex-end' },
  msgAi: { backgroundColor: C.surface, borderWidth: 1, borderColor: C.edge, alignSelf: 'flex-start' },
  tabbar: { flexDirection: 'row', borderTopWidth: 1, borderColor: C.edge,
            backgroundColor: C.surface, paddingBottom: Platform.OS === 'ios' ? 22 : 8 },
  tab: { flex: 1, alignItems: 'center', paddingVertical: 12 },
  tabLabel: { color: C.muted, fontWeight: '600' },
});
