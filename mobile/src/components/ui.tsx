/**
 * The only place the mobile app creates touchable elements. Every control here has an
 * accessibility role and label, a touch target of at least MIN_TOUCH × MIN_TOUCH, and
 * text that scales with the system font size (no fixed heights, no allowFontScaling={false}).
 * `mobile/src/logic/a11y.test.ts` fails if a screen bypasses these components.
 */
import type { ReactNode } from 'react';
import { ActivityIndicator, Pressable, RefreshControl, ScrollView, StyleSheet, Text, TextInput, View } from 'react-native';
import { describeMessageState, explain } from '../../../packages/sdk/src/index';
import { C, GUTTER, MIN_TOUCH, TONE_COLOR } from '../theme';

const HIT = { top: 6, bottom: 6, left: 6, right: 6 };

export function Screen({ children, refreshing, onRefresh }: { children: ReactNode; refreshing?: boolean; onRefresh?: () => void }) {
  return (
    <ScrollView contentContainerStyle={s.screen} keyboardShouldPersistTaps="handled"
                refreshControl={onRefresh ? <RefreshControl refreshing={!!refreshing} onRefresh={onRefresh} tintColor={C.rose} /> : undefined}>
      {children}
    </ScrollView>
  );
}

export function H1({ children }: { children: ReactNode }) {
  return <Text style={s.h1} accessibilityRole="header">{children}</Text>;
}
export function H2({ children }: { children: ReactNode }) {
  return <Text style={s.h2} accessibilityRole="header">{children}</Text>;
}
export function P({ children, muted, small }: { children: ReactNode; muted?: boolean; small?: boolean }) {
  return <Text style={[s.p, muted && s.muted, small && s.small]}>{children}</Text>;
}
export function Card({ children, label }: { children: ReactNode; label?: string }) {
  return <View style={s.card} accessibilityLabel={label}>{children}</View>;
}

/** A button. `label` is what assistive technology announces; `hint` explains the effect. */
export function Button({ label, onPress, disabled, busy, kind = 'primary', hint, text }: {
  label: string; onPress: () => void; disabled?: boolean; busy?: boolean; kind?: 'primary' | 'ghost' | 'danger'; hint?: string; text?: string;
}) {
  const off = !!disabled || !!busy;
  return (
    <Pressable accessibilityRole="button" accessibilityLabel={label} accessibilityHint={hint}
               accessibilityState={{ disabled: off, busy: !!busy }} disabled={off} onPress={onPress} hitSlop={HIT}
               style={({ pressed }) => [s.btn, kind === 'ghost' && s.btnGhost, kind === 'danger' && s.btnDanger, off && s.btnOff, pressed && s.pressed]}>
      {busy ? <ActivityIndicator color={kind === 'primary' ? C.onRose : C.rose} />
            : <Text style={[s.btnText, kind !== 'primary' && s.btnTextGhost]}>{text ?? label}</Text>}
    </Pressable>
  );
}

/** A text-styled control (opens a customer, a screen). Still a 44 pt target. */
export function LinkButton({ label, onPress, text }: { label: string; onPress: () => void; text?: string }) {
  return (
    <Pressable accessibilityRole="link" accessibilityLabel={label} onPress={onPress} hitSlop={HIT}
               style={({ pressed }) => [s.link, pressed && s.pressed]}>
      <Text style={s.linkText}>{text ?? label}</Text>
    </Pressable>
  );
}

export function Row({ children }: { children: ReactNode }) {
  return <View style={s.row}>{children}</View>;
}

/** A set of mutually exclusive choices (tabs or a picker). */
export function Choices<T extends string>({ label, options, value, onChange, role = 'radio' }: {
  label: string; options: readonly { id: T; label: string }[]; value: T | null; onChange: (v: T) => void; role?: 'radio' | 'tab';
}) {
  return (
    <View accessibilityRole={role === 'tab' ? 'tablist' : 'radiogroup'} accessibilityLabel={label} style={s.choices}>
      {options.map(o => {
        const on = o.id === value;
        return (
          <Pressable key={o.id} accessibilityRole={role} accessibilityLabel={o.label} accessibilityState={{ selected: on, checked: role === 'radio' ? on : undefined }}
                     onPress={() => onChange(o.id)} hitSlop={HIT} style={({ pressed }) => [s.chip, on && s.chipOn, pressed && s.pressed]}>
            <Text style={[s.chipText, on && s.chipTextOn]}>{o.label}</Text>
          </Pressable>
        );
      })}
    </View>
  );
}

export function Field({ label, value, onChangeText, placeholder, multiline, secure, maxLength, readOnly, autoCapitalize, keyboardType }: {
  label: string; value: string; onChangeText?: (t: string) => void; placeholder?: string; multiline?: boolean; secure?: boolean; maxLength?: number;
  readOnly?: boolean; autoCapitalize?: 'none' | 'sentences'; keyboardType?: 'default' | 'email-address' | 'phone-pad';
}) {
  return (
    <View style={s.field}>
      <Text style={[s.small, s.muted]} accessibilityElementsHidden importantForAccessibility="no">{label}</Text>
      <TextInput accessibilityLabel={label} value={value} onChangeText={onChangeText} placeholder={placeholder} placeholderTextColor={C.muted}
                 multiline={multiline} secureTextEntry={secure} maxLength={maxLength} editable={!readOnly} autoCapitalize={autoCapitalize}
                 keyboardType={keyboardType} style={[s.input, multiline && s.inputMulti, readOnly && s.inputReadOnly]} />
    </View>
  );
}

/** The only way the app renders a message state (contract C3): label and verbatim definition. */
export function StateBadge({ state, showDefinition = true }: { state: unknown; showDefinition?: boolean }) {
  const d = describeMessageState(state);
  const color = TONE_COLOR[d.tone];
  return (
    <View style={s.state} accessible accessibilityLabel={`Message state: ${d.label}. ${d.definition}`}>
      <Text style={[s.badge, { borderColor: color, color }]}>{d.label}</Text>
      {!d.known && !!d.raw && <Text style={[s.small, s.muted]}>{d.raw}</Text>}
      {showDefinition && <Text style={[s.small, s.muted]}>{d.definition}</Text>}
    </View>
  );
}

export function ErrorNote({ error, onDismiss }: { error: unknown; onDismiss?: () => void }) {
  if (!error) return null;
  const x = explain(error);
  return (
    <View style={[s.note, s.noteErr]} accessibilityRole="alert" accessibilityLiveRegion="assertive">
      <Text style={s.noteTitle}>{x.what}</Text>
      <Text style={s.p}>{x.next}</Text>
      {(x.code || x.requestId) && <Text style={[s.small, s.muted]}>{[x.code, x.requestId && `request ${x.requestId}`].filter(Boolean).join(' · ')}</Text>}
      {onDismiss && <Button kind="ghost" label="Dismiss" onPress={onDismiss} />}
    </View>
  );
}

export function Notice({ children, tone = 'warn' }: { children: ReactNode; tone?: 'warn' | 'ok' | 'info' }) {
  return (
    <View style={[s.note, tone === 'warn' ? s.noteWarn : tone === 'ok' ? s.noteOk : s.noteInfo]} accessibilityLiveRegion="polite">
      {typeof children === 'string' ? <Text style={s.p}>{children}</Text> : children}
    </View>
  );
}

/** Where human action remains necessary (X3). */
export function HumanSteps({ steps }: { steps: string[] }) {
  if (!steps.length) return null;
  return (
    <View style={s.steps} accessibilityLabel="What still needs a person">
      <Text style={s.noteTitle}>What still needs a person</Text>
      {steps.map((t, i) => <Text key={i} style={[s.p, s.small]}>• {t}</Text>)}
    </View>
  );
}

/** A labelled value; `warning` is announced with it. */
export function Fact({ label, value, warning }: { label: string; value: string; warning?: string }) {
  return (
    <View style={s.fact} accessible accessibilityLabel={`${label}: ${value}${warning ? `. Warning: ${warning}` : ''}`}>
      <Text style={[s.small, s.muted]}>{label}</Text>
      <Text style={s.p}>{value}</Text>
      {!!warning && <Text style={[s.small, s.warn]}>{warning}</Text>}
    </View>
  );
}

export function AiBadge() {
  return <Text style={s.ai} accessibilityLabel="AI-generated">AI</Text>;
}

/** SB 243: a persistent, visible disclosure on every AI surface. */
export function AiStrip() {
  return (
    <View style={s.aiStrip} accessibilityRole="text">
      <AiBadge /><Text style={[s.small, s.muted, { flex: 1 }]}>You're interacting with an AI assistant — review its output before sharing.</Text>
    </View>
  );
}

export function Loading({ label }: { label: string }) {
  return <View style={s.loading} accessible accessibilityLabel={label}><ActivityIndicator color={C.rose} /></View>;
}

export const s = StyleSheet.create({
  screen: { padding: GUTTER, gap: 12, paddingBottom: 48 },
  h1: { color: C.text, fontSize: 24, fontWeight: '600' },
  h2: { color: C.text, fontSize: 18, fontWeight: '600', marginTop: 4 },
  p: { color: C.text, fontSize: 15, lineHeight: 21 },
  muted: { color: C.muted },
  small: { fontSize: 13, lineHeight: 18 },
  warn: { color: C.danger },
  card: { backgroundColor: C.surface, borderWidth: 1, borderColor: C.edge, borderRadius: 14, padding: 14, gap: 8 },
  row: { flexDirection: 'row', flexWrap: 'wrap', gap: 8, alignItems: 'center' },
  btn: { minHeight: MIN_TOUCH, minWidth: MIN_TOUCH, paddingHorizontal: 16, paddingVertical: 10, borderRadius: 10,
    backgroundColor: C.rose, alignItems: 'center', justifyContent: 'center', flexShrink: 1 },
  btnGhost: { backgroundColor: 'transparent', borderWidth: 1, borderColor: C.edgeHi },
  btnDanger: { backgroundColor: 'transparent', borderWidth: 1, borderColor: C.danger },
  btnOff: { opacity: 0.5 },
  btnText: { color: C.onRose, fontWeight: '600', fontSize: 15, textAlign: 'center' },
  btnTextGhost: { color: C.rose },
  pressed: { opacity: 0.75 },
  link: { minHeight: MIN_TOUCH, minWidth: MIN_TOUCH, justifyContent: 'center', alignSelf: 'flex-start' },
  linkText: { color: C.rose, fontSize: 15, textDecorationLine: 'underline' },
  choices: { flexDirection: 'row', flexWrap: 'wrap', gap: 8 },
  chip: { minHeight: MIN_TOUCH, minWidth: MIN_TOUCH, paddingHorizontal: 14, borderRadius: 999, borderWidth: 1, borderColor: C.edgeHi,
    alignItems: 'center', justifyContent: 'center' },
  chipOn: { backgroundColor: C.rose, borderColor: C.rose },
  chipText: { color: C.text, fontSize: 14 },
  chipTextOn: { color: C.onRose, fontWeight: '600' },
  field: { gap: 4 },
  input: { minHeight: MIN_TOUCH, backgroundColor: C.bg, borderWidth: 1, borderColor: C.edgeHi, borderRadius: 10, color: C.text,
    paddingHorizontal: 12, paddingVertical: 10, fontSize: 15 },
  inputMulti: { minHeight: 110, textAlignVertical: 'top' },
  inputReadOnly: { opacity: 0.7 },
  state: { gap: 4 },
  badge: { alignSelf: 'flex-start', borderWidth: 1, borderRadius: 6, paddingHorizontal: 8, paddingVertical: 2, fontSize: 13, fontWeight: '600' },
  note: { borderRadius: 10, borderWidth: 1, padding: 12, gap: 6 },
  noteErr: { backgroundColor: C.errBg, borderColor: C.danger },
  noteWarn: { backgroundColor: C.warnBg, borderColor: C.brass },
  noteOk: { backgroundColor: C.okBg, borderColor: C.ok },
  noteInfo: { backgroundColor: C.bg, borderColor: C.edgeHi },
  noteTitle: { color: C.text, fontWeight: '600', fontSize: 15 },
  steps: { borderWidth: 1, borderStyle: 'dashed', borderColor: C.edgeHi, borderRadius: 10, padding: 12, gap: 4 },
  fact: { gap: 2, paddingVertical: 4, borderBottomWidth: 1, borderColor: C.edge },
  ai: { color: C.onRose, backgroundColor: C.brass, fontSize: 11, fontWeight: '700', paddingHorizontal: 6, borderRadius: 5, overflow: 'hidden', alignSelf: 'flex-start' },
  aiStrip: { flexDirection: 'row', gap: 8, alignItems: 'center', padding: 10, borderRadius: 10, borderWidth: 1, borderColor: C.edge, backgroundColor: C.surface },
  loading: { padding: 24, alignItems: 'center' },
  exact: { backgroundColor: C.bg, borderWidth: 1, borderColor: C.edgeHi, borderRadius: 10, padding: 12, color: C.text, fontSize: 16, lineHeight: 23 },
});
