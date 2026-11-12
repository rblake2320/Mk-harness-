import { useState } from 'react';
import { Text, View } from 'react-native';
import type { Tokens } from '../../../packages/sdk/src/index';
import { client } from '../api';
import { Button, ErrorNote, Field, Screen, s } from '../components/ui';
import { C } from '../theme';

export default function AuthScreen({ onAuthed }: { onAuthed: (t: Tokens) => void }) {
  const [email, setEmail] = useState('');
  const [pw, setPw] = useState('');
  const [busy, setBusy] = useState(false);
  const [err, setErr] = useState<unknown>(null);
  async function go() {
    setBusy(true); setErr(null);
    try { onAuthed(await client.login(email.trim(), pw)); }
    catch (e) { setErr(e); }
    finally { setBusy(false); }
  }
  return (
    <Screen>
      <View style={{ marginTop: 48, gap: 12 }}>
        <Text style={[s.h1, { fontSize: 28 }]} accessibilityRole="header">Consultant <Text style={{ color: C.rose }}>Studio</Text></Text>
        <Field label="Email" value={email} onChangeText={setEmail} autoCapitalize="none" keyboardType="email-address" />
        <Field label="Password" value={pw} onChangeText={setPw} secure />
        <ErrorNote error={err} />
        <Button label="Sign in" onPress={go} busy={busy} disabled={!email || !pw} />
        <Text style={[s.p, s.muted, { textAlign: 'center' }]}>New team? Create it on the web app first.</Text>
      </View>
    </Screen>
  );
}
