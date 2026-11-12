/**
 * Consultant Studio — React Native client (Expo).
 * The consultant workflow at parity with the web app: daily brief, draft editor, approvals
 * (passkey on the web approval page), inbox + exceptions, customer page with timeline,
 * commitments and outcomes, and a read-only status view. Every API call goes through the
 * shared SDK; screens live in src/screens, pure logic (tested) in src/logic.
 */
import { useCallback, useEffect, useReducer, useState } from 'react';
import { BackHandler, Linking, Platform, Pressable, StyleSheet, Text, View } from 'react-native';
import { StatusBar } from 'expo-status-bar';
import { parseApprovalReturn } from '../packages/sdk/src/index';
import type { Tokens } from '../packages/sdk/src/index';
import { client } from './src/api';
import { TABS, canGoBack, currentRoute, initialNav, navReducer } from './src/logic/navigation';
import type { Route } from './src/logic/navigation';
import ApprovalsScreen from './src/screens/ApprovalsScreen';
import AuthScreen, { EnrollScreen, StepUpPrompt } from './src/screens/AuthScreen';
import BriefScreen from './src/screens/BriefScreen';
import ChatScreen from './src/screens/ChatScreen';
import CustomerDetailScreen from './src/screens/CustomerDetailScreen';
import CustomersScreen from './src/screens/CustomersScreen';
import DraftEditorScreen from './src/screens/DraftEditorScreen';
import InboxScreen from './src/screens/InboxScreen';
import MoreScreen from './src/screens/MoreScreen';
import SkinScreen from './src/screens/SkinScreen';
import StatusScreen from './src/screens/StatusScreen';
import { C, MIN_TOUCH } from './src/theme';

export default function App() {
  const [tokens, setTokens] = useState<Tokens | null>(null);
  const [nav, dispatch] = useReducer(navReducer, undefined, initialNav);

  const [stepUp, setStepUp] = useState<{ methods: string[]; resolve: (ok: boolean) => void } | null>(null);
  useEffect(() => {
    client.tokens = tokens;
    client.onAuthExpired = () => setTokens(null);
    client.onTokensChanged = t => setTokens(prev => (prev ? t : prev));
    client.onStepUpRequired = methods => new Promise<boolean>(resolve => setStepUp({ methods, resolve }));
  }, [tokens]);
  const signOut = useCallback(() => { client.logout().catch(() => {}).finally(() => setTokens(null)); }, []);

  // consultantstudio://approvals/done?action=<id> — navigation only. The approvals screen
  // re-reads the action from the API; the link itself is never treated as an approval.
  useEffect(() => {
    const open = (url: string | null) => {
      const r = parseApprovalReturn(url);
      if (r) dispatch({ type: 'focusApproval', actionId: r.actionId });
    };
    Linking.getInitialURL().then(open).catch(() => {});
    const sub = Linking.addEventListener('url', e => open(e.url));
    return () => sub.remove();
  }, []);

  useEffect(() => {
    if (Platform.OS !== 'android') return;
    const sub = BackHandler.addEventListener('hardwareBackPress', () => {
      if (!canGoBack(nav)) return false;
      dispatch({ type: 'back' });
      return true;
    });
    return () => sub.remove();
  }, [nav]);

  const push = useCallback((route: Route) => dispatch({ type: 'push', route }), []);
  const back = useCallback(() => dispatch({ type: 'back' }), []);
  const clearFocus = useCallback(() => dispatch({ type: 'clearFocus' }), []);

  if (!tokens) return <View style={st.app}><StatusBar style="light" /><AuthScreen onAuthed={setTokens} /></View>;
  if (tokens.mfa_enrollment_required) return (
    <View style={st.app}><StatusBar style="light" />
      <EnrollScreen onDone={() => setTokens({ ...tokens, mfa_enrollment_required: false })} onSignOut={signOut} />
    </View>
  );
  if (stepUp) return (
    <View style={st.app}><StatusBar style="light" />
      <StepUpPrompt methods={stepUp.methods} onDone={ok => { stepUp.resolve(ok); setStepUp(null); }} />
    </View>
  );

  const route = currentRoute(nav);
  let body;
  if (route?.name === 'customer') body = <CustomerDetailScreen key={route.customerId} customerId={route.customerId} customerName={route.customerName} push={push} />;
  else if (route?.name === 'draft') body = <DraftEditorScreen key={`${route.customerId}:${route.briefItemId ?? ''}:${route.commitmentId ?? ''}`} {...route} onDone={back} />;
  else if (route?.name === 'status') body = <StatusScreen />;
  else if (route?.name === 'chat') body = <ChatScreen />;
  else if (route?.name === 'skin') body = <SkinScreen />;
  else if (nav.tab === 'brief') body = <BriefScreen push={push} />;
  else if (nav.tab === 'approvals') body = <ApprovalsScreen focusActionId={nav.focusActionId} onFocusHandled={clearFocus} />;
  else if (nav.tab === 'inbox') body = <InboxScreen push={push} />;
  else if (nav.tab === 'customers') body = <CustomersScreen push={push} />;
  else body = <MoreScreen push={push} who={`${tokens.display_name} · ${tokens.role}`} onSignOut={signOut} />;

  return (
    <View style={st.app}>
      <StatusBar style="light" />
      <View style={st.header}>
        {route ? (
          <Pressable accessibilityRole="button" accessibilityLabel="Back" onPress={back} hitSlop={6} style={st.back}>
            <Text style={st.backText}>‹ Back</Text>
          </Pressable>
        ) : (
          <Text style={st.brand} accessibilityRole="header">Consultant <Text style={{ color: C.rose }}>Studio</Text></Text>
        )}
      </View>
      <View style={{ flex: 1 }}>{body}</View>
      <View style={st.tabbar} accessibilityRole="tablist">
        {TABS.map(t => {
          const on = nav.tab === t.id;
          return (
            <Pressable key={t.id} accessibilityRole="tab" accessibilityLabel={t.label} accessibilityState={{ selected: on }}
                       onPress={() => dispatch({ type: 'tab', tab: t.id })} style={st.tab}>
              <Text style={[st.tabLabel, on && { color: C.rose }]} numberOfLines={1} adjustsFontSizeToFit minimumFontScale={0.8}>{t.label}</Text>
            </Pressable>
          );
        })}
      </View>
    </View>
  );
}

const st = StyleSheet.create({
  app: { flex: 1, backgroundColor: C.bg, paddingTop: Platform.OS === 'android' ? 36 : 54 },
  header: { flexDirection: 'row', alignItems: 'center', paddingHorizontal: 16, minHeight: MIN_TOUCH },
  brand: { color: C.text, fontSize: 19, fontWeight: '600' },
  back: { minHeight: MIN_TOUCH, minWidth: MIN_TOUCH, justifyContent: 'center' },
  backText: { color: C.rose, fontSize: 16 },
  tabbar: { flexDirection: 'row', borderTopWidth: 1, borderColor: C.edge, backgroundColor: C.surface, paddingBottom: Platform.OS === 'ios' ? 22 : 8 },
  tab: { flex: 1, alignItems: 'center', justifyContent: 'center', minHeight: MIN_TOUCH, paddingVertical: 8, paddingHorizontal: 2 },
  tabLabel: { color: C.muted, fontWeight: '600', fontSize: 13 },
});
