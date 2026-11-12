import { useState } from 'react';
import { Alert, Image, Text, View } from 'react-native';
import * as ImagePicker from 'expo-image-picker';
import type { SkinResult } from '../../../packages/sdk/src/index';
import { client } from '../api';
import { AiStrip, Button, ErrorNote, H1, P, Row, Screen } from '../components/ui';
import { C } from '../theme';

/** Skin studio — moved unchanged in behaviour from the old single-file app, plus the
 *  SB 243 AI disclosure strip and the shared accessible controls. */
export default function SkinScreen() {
  const [photo, setPhoto] = useState<{ uri: string } | null>(null);
  const [busy, setBusy] = useState(false);
  const [result, setResult] = useState<SkinResult | null>(null);
  const [err, setErr] = useState<unknown>(null);

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
    setBusy(true); setResult(null); setErr(null);
    try {
      const r = await client.analyzeSkin({ uri: photo.uri, name: 'face.jpg', type: 'image/jpeg' });
      setResult(r.result);
    } catch (e) { setErr(e); }
    finally { setBusy(false); }
  }

  return (
    <Screen>
      <H1>Skin studio</H1>
      <AiStrip />
      <P muted>Take a clear, well-lit face photo for cosmetic observations. Never medical advice.</P>
      <Row>
        <Button kind="ghost" label="Take a photo with the camera" text="Camera" onPress={() => pick(true)} />
        <Button kind="ghost" label="Choose a photo from the library" text="Photo library" onPress={() => pick(false)} />
        <Button label="Analyze photo" text="Analyze" disabled={!photo} busy={busy} onPress={analyze} />
      </Row>
      <ErrorNote error={err} onDismiss={() => setErr(null)} />
      {photo && <Image source={photo} style={{ width: 180, height: 180, borderRadius: 14 }} accessibilityLabel="Selected face photo" />}
      {result && (
        <View style={{ backgroundColor: '#241a20', borderWidth: 1, borderColor: C.edgeHi, borderRadius: 20, padding: 18, gap: 6 }}>
          <Text style={{ color: C.rose, fontSize: 16, fontWeight: '600' }} accessibilityRole="header">Cosmetic observations</Text>
          {result.observations.map((o, i) => (
            <View key={i} style={{ paddingVertical: 6, borderBottomWidth: 1, borderColor: C.edge }}>
              <Text style={{ color: C.text, fontWeight: '600' }}>
                {o.category.replace(/_/g, ' ')}{'  '}
                <Text style={{ color: C.brass, fontSize: 11 }}>{o.level.toUpperCase()}</Text>
              </Text>
              <Text style={{ color: C.text }}>{o.note}</Text>
            </View>
          ))}
          <Text style={{ color: C.rose, fontSize: 16, fontWeight: '600', marginTop: 12 }} accessibilityRole="header">Care focus</Text>
          <Text style={{ color: C.text }}>{result.care_focus.join(' · ')}</Text>
          <Text style={{ color: C.rose, fontSize: 16, fontWeight: '600', marginTop: 12 }} accessibilityRole="header">Talking points</Text>
          {result.consultant_talking_points.map((t, i) => <Text key={i} style={{ color: C.text, marginTop: 4 }}>“{t}”</Text>)}
          {result.see_professional && <Text style={{ color: C.brass, marginTop: 10 }}>Some areas may benefit from a dermatologist's opinion.</Text>}
          <Text style={{ color: C.muted, marginTop: 12, fontSize: 12 }}>{result.disclaimer}</Text>
        </View>
      )}
    </Screen>
  );
}
