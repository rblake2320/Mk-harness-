import { useState } from 'react';
import { Linking, Text, View } from 'react-native';
import { isMfaChallenge, type MfaChallenge, type Tokens } from '../../../packages/sdk/src/index';
import { client } from '../api';
import { Button, ErrorNote, Field, LinkButton, Screen, s } from '../components/ui';
import { C } from '../theme';

const digits = (t: string) => t.replace(/\D/g, '').slice(0, 6);

/** Password, then the second step (S2): authenticator code or a one-time recovery
 *  code. Passkey sign-in needs the platform passkey API, which this app does not
 *  embed; accounts that only have a passkey sign in on the web app. */
export default function AuthScreen({ onAuthed }: { onAuthed: (t: Tokens) => void }) {
  const [email, setEmail] = useState('');
  const [pw, setPw] = useState('');
  const [busy, setBusy] = useState(false);
  const [err, setErr] = useState<unknown>(null);
  const [challenge, setChallenge] = useState<MfaChallenge | null>(null);
  const [method, setMethod] = useState<'totp' | 'recovery'>('totp');
  const [code, setCode] = useState('');

  async function run(fn: () => Promise<void>) {
    setBusy(true); setErr(null);
    try { await fn(); } catch (e) { setErr(e); } finally { setBusy(false); }
  }
  const signIn = () => run(async () => {
    const r = await client.login(email.trim(), pw);
    if (isMfaChallenge(r)) {
      setChallenge(r); setPw('');
      setMethod(r.methods.includes('totp') ? 'totp' : 'recovery');
    } else onAuthed(r);
  });
  const verify = () => run(async () => {
    if (!challenge) return;
    try { onAuthed(await client.verifyMfa(challenge.mfa_token, method, { code: code.trim() })); }
    catch (e: any) {
      if (e?.status === 401 && e?.code !== 'SECOND_FACTOR_INVALID') { setChallenge(null); setCode(''); }
      throw e;
    }
  });

  if (challenge) {
    const usable = challenge.methods.filter(m => m === 'totp' || m === 'recovery');
    return (
      <Screen>
        <View style={{ marginTop: 48, gap: 12 }}>
          <Text style={[s.h1, { fontSize: 26 }]} accessibilityRole="header">Second step</Text>
          {usable.length === 0 ? (
            <>
              <Text style={s.p}>Your account signs in with a passkey. Sign in on the web app, or add an authenticator app there.</Text>
              <LinkButton label="Start over" onPress={() => setChallenge(null)} />
            </>
          ) : (
            <>
              <Field label={method === 'totp' ? 'Code from your authenticator app' : 'One of your recovery codes'}
                     value={code} onChangeText={t => setCode(method === 'totp' ? digits(t) : t)}
                     keyboardType={method === 'totp' ? 'number-pad' : 'default'} autoCapitalize="none" />
              <ErrorNote error={err} />
              <Button label="Verify" onPress={verify} busy={busy} disabled={method === 'totp' ? code.length !== 6 : !code.trim()} />
              {usable.length === 2 && (
                <LinkButton label={method === 'totp' ? 'Use a recovery code instead' : 'Use my authenticator app'}
                            onPress={() => { setMethod(m => (m === 'totp' ? 'recovery' : 'totp')); setCode(''); setErr(null); }} />
              )}
              <LinkButton label="Start over" onPress={() => { setChallenge(null); setCode(''); setErr(null); }} />
            </>
          )}
        </View>
      </Screen>
    );
  }
  return (
    <Screen>
      <View style={{ marginTop: 48, gap: 12 }}>
        <Text style={[s.h1, { fontSize: 28 }]} accessibilityRole="header">Consultant <Text style={{ color: C.rose }}>Studio</Text></Text>
        <Field label="Email" value={email} onChangeText={setEmail} autoCapitalize="none" keyboardType="email-address" />
        <Field label="Password" value={pw} onChangeText={setPw} secure />
        <ErrorNote error={err} />
        <Button label="Sign in" onPress={signIn} busy={busy} disabled={!email || !pw} />
        <Text style={[s.p, s.muted, { textAlign: 'center' }]}>New team? Create it on the web app first.</Text>
      </View>
    </Screen>
  );
}

/** First sign-in when the business requires a second step and the account has none:
 *  nothing else is reachable until an authenticator app is added. */
export function EnrollScreen({ onDone, onSignOut }: { onDone: () => void; onSignOut: () => void }) {
  const [setup, setSetup] = useState<{ factor_id: string; secret: string; otpauth_uri: string } | null>(null);
  const [code, setCode] = useState('');
  const [codes, setCodes] = useState<string[] | null>(null);
  const [busy, setBusy] = useState(false);
  const [err, setErr] = useState<unknown>(null);
  async function run(fn: () => Promise<void>) {
    setBusy(true); setErr(null);
    try { await fn(); } catch (e) { setErr(e); } finally { setBusy(false); }
  }
  if (codes) return (
    <Screen>
      <View style={{ marginTop: 32, gap: 12 }}>
        <Text style={s.h1} accessibilityRole="header">Save your recovery codes</Text>
        <Text style={s.p}>Each code signs you in once if you lose your phone. They are shown only now.</Text>
        <Text selectable style={[s.p, { fontFamily: 'monospace' }]} accessibilityLabel="Recovery codes">{codes.join('\n')}</Text>
        <Button label="I saved them" onPress={onDone} />
      </View>
    </Screen>
  );
  return (
    <Screen>
      <View style={{ marginTop: 32, gap: 12 }}>
        <Text style={s.h1} accessibilityRole="header">Protect your account</Text>
        <Text style={s.p}>Your business requires a second step at sign-in. Add an authenticator app once.</Text>
        {!setup ? (
          <Button label="Set up an authenticator app" busy={busy}
                  onPress={() => run(async () => setSetup(await client.totpBegin()))} />
        ) : (
          <>
            <LinkButton label="Open my authenticator app to add this account" onPress={() => { Linking.openURL(setup.otpauth_uri).catch(() => {}); }} />
            <Text style={[s.small, s.muted]}>Or enter this key in the app:</Text>
            <Text selectable style={[s.p, { fontFamily: 'monospace', letterSpacing: 2 }]} accessibilityLabel="Setup key">
              {setup.secret.match(/.{1,4}/g)?.join(' ')}
            </Text>
            <Field label="6-digit code from the app" value={code} onChangeText={t => setCode(digits(t))} keyboardType="number-pad" />
            <Button label="Finish" busy={busy} disabled={code.length !== 6}
                    onPress={() => run(async () => {
                      const r = await client.totpConfirm(setup.factor_id, code);
                      if (r.recovery_codes) setCodes(r.recovery_codes); else onDone();
                    })} />
          </>
        )}
        <ErrorNote error={err} />
        <LinkButton label="Sign out" onPress={onSignOut} />
      </View>
    </Screen>
  );
}

/** Step-up prompt (403 STEP_UP_REQUIRED): one fresh authenticator code, then the SDK
 *  retries the original request once. Cancel retries nothing. */
export function StepUpPrompt({ methods, onDone }: { methods: string[]; onDone: (ok: boolean) => void }) {
  const [code, setCode] = useState('');
  const [busy, setBusy] = useState(false);
  const [err, setErr] = useState<unknown>(null);
  return (
    <Screen>
      <View style={{ marginTop: 32, gap: 12 }} accessibilityViewIsModal>
        <Text style={s.h1} accessibilityRole="header">Confirm it's you</Text>
        <Text style={s.p}>This change needs a fresh code. Nothing has been changed yet.</Text>
        {methods.includes('totp') ? (
          <>
            <Field label="Code from your authenticator app" value={code} onChangeText={t => setCode(digits(t))} keyboardType="number-pad" />
            <ErrorNote error={err} />
            <Button label="Confirm" busy={busy} disabled={code.length !== 6} onPress={async () => {
              setBusy(true); setErr(null);
              try { await client.stepUp('totp', { code }); onDone(true); } catch (e) { setErr(e); } finally { setBusy(false); }
            }} />
          </>
        ) : (
          <Text style={s.p}>Confirm this change on the web app with your passkey.</Text>
        )}
        <LinkButton label="Cancel" onPress={() => onDone(false)} />
      </View>
    </Screen>
  );
}
