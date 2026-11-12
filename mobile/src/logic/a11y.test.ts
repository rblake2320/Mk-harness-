/**
 * Static guards over the mobile sources (TypeScript AST), each proven by a fixture:
 *  - Accessibility (X4 on mobile): every touchable has an accessibility role and label and
 *    a touch target of at least MIN_TOUCH (44 pt); every TextInput is labelled; text is
 *    never prevented from scaling; no fixed width that cannot fit a 360 dp screen.
 *  - Approval authority (H6 on mobile): no code path approves from the app. The only way
 *    is the web approval page opened in an auth session, where the passkey ceremony runs.
 */
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { existsSync, readdirSync, readFileSync, statSync } from 'node:fs';
import { dirname, join, resolve } from 'node:path';
import ts from 'typescript';
import { MIN_TOUCH } from '../theme';

const TOUCHABLES = new Set(['Pressable', 'TouchableOpacity', 'TouchableHighlight', 'TouchableWithoutFeedback', 'TouchableNativeFeedback']);
const SHARED_CONTROLS = new Set(['Button', 'LinkButton', 'Choices', 'Field']);
const FORBIDDEN_CALLS = new Set(['approve', 'approveWithPasskey', 'approvalChallenge']);

interface Finding { file: string; line: number; rule: string; detail: string }

function check(file: string, source: string): Finding[] {
  const sf = ts.createSourceFile(file, source, ts.ScriptTarget.Latest, true, file.endsWith('x') ? ts.ScriptKind.TSX : ts.ScriptKind.TS);
  const out: Finding[] = [];
  const add = (n: ts.Node, rule: string, detail: string) => out.push({ file, line: sf.getLineAndCharacterOfPosition(n.getStart(sf)).line + 1, rule, detail });

  // StyleSheet.create objects: "st.tab" → its properties.
  const styles = new Map<string, Map<string, ts.Expression>>();
  const visitStyles = (n: ts.Node) => {
    if (ts.isVariableDeclaration(n) && ts.isIdentifier(n.name) && n.initializer && ts.isCallExpression(n.initializer)
        && n.initializer.expression.getText(sf) === 'StyleSheet.create' && ts.isObjectLiteralExpression(n.initializer.arguments[0])) {
      for (const p of (n.initializer.arguments[0] as ts.ObjectLiteralExpression).properties) {
        if (!ts.isPropertyAssignment(p) || !ts.isObjectLiteralExpression(p.initializer)) continue;
        const props = new Map<string, ts.Expression>();
        for (const q of p.initializer.properties) if (ts.isPropertyAssignment(q)) props.set(q.name.getText(sf), q.initializer);
        styles.set(`${n.name.text}.${p.name.getText(sf)}`, props);
      }
    }
    ts.forEachChild(n, visitStyles);
  };
  visitStyles(sf);
  const atLeast44 = (e: ts.Expression | undefined) => !!e && (e.getText(sf) === 'MIN_TOUCH' || (ts.isNumericLiteral(e) && Number(e.text) >= 44));

  const attr = (el: ts.JsxOpeningLikeElement, name: string) =>
    el.attributes.properties.find((a): a is ts.JsxAttribute => ts.isJsxAttribute(a) && a.name.getText(sf) === name);

  const visit = (n: ts.Node) => {
    if (ts.isImportDeclaration(n) && n.moduleSpecifier.getText(sf).includes('react-native') && n.importClause?.namedBindings
        && ts.isNamedImports(n.importClause.namedBindings) && n.importClause.namedBindings.elements.some(e => e.name.text === 'Button')) {
      add(n, 'no-rn-button', 'use the shared Button (44 pt, labelled) instead of react-native Button');
    }
    if (ts.isJsxOpeningElement(n) || ts.isJsxSelfClosingElement(n)) {
      const tag = n.tagName.getText(sf);
      if (TOUCHABLES.has(tag)) {
        if (!attr(n, 'accessibilityRole')) add(n, 'touchable-role', `${tag} without accessibilityRole`);
        if (!attr(n, 'accessibilityLabel')) add(n, 'touchable-label', `${tag} without accessibilityLabel`);
        const style = attr(n, 'style');
        const keys: string[] = [];
        const collect = (e: ts.Node) => { if (ts.isPropertyAccessExpression(e) && styles.has(e.getText(sf))) keys.push(e.getText(sf)); ts.forEachChild(e, collect); };
        if (style?.initializer) collect(style.initializer);
        const props = keys.map(k => styles.get(k)!);
        const tallEnough = props.some(p => atLeast44(p.get('minHeight')) || atLeast44(p.get('height')));
        const wideEnough = props.some(p => atLeast44(p.get('minWidth')) || atLeast44(p.get('width')) || p.get('flex')?.getText(sf) === '1');
        if (!tallEnough || !wideEnough) add(n, 'touch-target', `${tag} style does not guarantee ${MIN_TOUCH}×${MIN_TOUCH} (styles: ${keys.join(', ') || 'none'})`);
      }
      if (tag === 'TextInput' && !attr(n, 'accessibilityLabel')) add(n, 'input-label', 'TextInput without accessibilityLabel');
      if (SHARED_CONTROLS.has(tag)) {
        const label = attr(n, 'label');
        const init = label?.initializer;
        if (!label || (init && ts.isStringLiteral(init) && !init.text.trim())) add(n, 'control-label', `${tag} without a non-empty label`);
      }
      const scaling = attr(n, 'allowFontScaling');
      if (scaling?.initializer && scaling.initializer.getText(sf).includes('false')) add(n, 'font-scaling', 'allowFontScaling={false} stops text from scaling');
      const mult = attr(n, 'maxFontSizeMultiplier');
      if (mult?.initializer && /\{\s*(0|1)(\.\d+)?\s*\}/.test(mult.initializer.getText(sf)) && Number(mult.initializer.getText(sf).replace(/[{}]/g, '')) < 1.5) add(n, 'font-scaling', 'maxFontSizeMultiplier below 1.5');
    }
    if (ts.isPropertyAssignment(n) && ['width', 'minWidth'].includes(n.name.getText(sf)) && ts.isNumericLiteral(n.initializer) && Number(n.initializer.text) > 320) {
      add(n, 'fixed-width', `${n.name.getText(sf)}: ${n.initializer.text} does not fit a 360 dp screen`);
    }
    // Approval authority: the app never calls the approve or challenge endpoints itself.
    if (ts.isCallExpression(n) && ts.isPropertyAccessExpression(n.expression) && FORBIDDEN_CALLS.has(n.expression.name.text)) {
      add(n, 'approval-path', `${n.expression.getText(sf)}(…) — approval must go through the web passkey page`);
    }
    const texts = ts.isStringLiteral(n) || ts.isNoSubstitutionTemplateLiteral(n) ? [n.text]
      : ts.isTemplateExpression(n) ? [n.head.text, ...n.templateSpans.map(sp => sp.literal.text)] : [];
    if (texts.some(t => /\/approve\b|approval-challenge/.test(t))) add(n, 'approval-path', `endpoint string ${JSON.stringify(texts.join('…'))}`);
    ts.forEachChild(n, visit);
  };
  visit(sf);
  return out;
}

function mobileRoot(): string {
  for (let dir = resolve(process.cwd()); ; dir = dirname(dir)) {
    if (existsSync(join(dir, 'app.json')) && existsSync(join(dir, 'App.tsx'))) return dir;
    if (existsSync(join(dir, 'mobile', 'App.tsx'))) return join(dir, 'mobile');
    if (dirname(dir) === dir) throw new Error('mobile root not found');
  }
}
const ROOT = mobileRoot();
function sources(rel: string): string[] {
  const abs = join(ROOT, rel);
  if (statSync(abs).isFile()) return [rel];
  return readdirSync(abs).flatMap(name => {
    const child = `${rel}/${name}`;
    if (statSync(join(ROOT, child)).isDirectory()) return sources(child);
    return /\.tsx?$/.test(name) && !/\.test\.tsx?$/.test(name) ? [child] : [];
  });
}
const FILES = [...sources('App.tsx'), ...sources('src')];

test('the touch-target constant is at least 44 pt', () => {
  assert.ok(MIN_TOUCH >= 44);
});

test('every mobile source passes the accessibility and approval-authority checks', () => {
  assert.ok(FILES.includes('src/screens/ApprovalsScreen.tsx') && FILES.includes('src/components/ui.tsx') && FILES.includes('App.tsx'));
  const findings = FILES.flatMap(f => check(f, readFileSync(join(ROOT, f), 'utf8')));
  assert.deepEqual(findings, [], findings.map(f => `${f.file}:${f.line} ${f.rule} — ${f.detail}`).join('\n'));
});

test('the only approval path opens the web approval page in an auth session that returns to the allowlisted URL', () => {
  const src = readFileSync(join(ROOT, 'src/approvalHandoff.ts'), 'utf8');
  assert.match(src, /WebBrowser\.openAuthSessionAsync\(url, APPROVAL_RETURN_URL\)/);
  assert.match(src, /client\.actionStatus\(decision\.refetchActionId\)/, 'the result is re-read from the API, not taken from the redirect');
  const importers = FILES.filter(f => /from '\.\.?\/(\.\.\/)?approvalHandoff'/.test(readFileSync(join(ROOT, f), 'utf8')));
  assert.deepEqual(importers, ['src/screens/ApprovalsScreen.tsx']);
});

test('fixture: each accessibility violation is caught', () => {
  const bad = `
import { Button, Pressable, StyleSheet, Text, TextInput } from 'react-native';
export function X() {
  return (<>
    <Pressable onPress={() => {}} style={st.small}><Text>Tap</Text></Pressable>
    <TextInput value="" />
    <Text allowFontScaling={false}>fixed</Text>
    <Text maxFontSizeMultiplier={1}>capped</Text>
  </>);
}
const st = StyleSheet.create({ small: { height: 30, width: 400 } });`;
  const rules = check('bad.tsx', bad).map(f => f.rule).sort();
  assert.deepEqual(rules, ['fixed-width', 'font-scaling', 'font-scaling', 'input-label', 'no-rn-button', 'touch-target', 'touchable-label', 'touchable-role'].sort());
});

test('fixture: a labelled 44 pt touchable, labelled input and shared controls pass', () => {
  const good = `
import { Pressable, StyleSheet, Text, TextInput } from 'react-native';
import { MIN_TOUCH } from '../theme';
export function X() {
  return (<>
    <Pressable accessibilityRole="button" accessibilityLabel="Open" onPress={() => {}} style={({ pressed }) => [st.btn, pressed && st.p]}><Text>Open</Text></Pressable>
    <Pressable accessibilityRole="tab" accessibilityLabel="Inbox" style={st.tab} onPress={() => {}}><Text>Inbox</Text></Pressable>
    <TextInput accessibilityLabel="Name" value="" />
    <Button label="Save" onPress={() => {}} />
  </>);
}
const st = StyleSheet.create({ btn: { minHeight: MIN_TOUCH, minWidth: MIN_TOUCH }, p: { opacity: 0.5 }, tab: { flex: 1, minHeight: 44 } });`;
  assert.deepEqual(check('good.tsx', good), []);
});

test('fixture: any direct approval call or endpoint is caught', () => {
  const bad = `
export async function sneaky(client: any, id: string, d: string) {
  await client.approve(id, d, {});
  await client.approveWithPasskey(id, d);
  await client.approvalChallenge(id);
  await fetch('/api/agent-ops/actions/' + id + '/approve');
  await fetch(\`/api/agent-ops/actions/\${id}/approval-challenge\`);
}`;
  const found = check('sneaky.ts', bad).filter(f => f.rule === 'approval-path');
  assert.equal(found.length, 5, JSON.stringify(found));
  const fine = `export const t = 'Approve with passkey'; export async function r(c: any) { await c.reject('a', 'b'); await c.pendingApprovals(); }`;
  assert.deepEqual(check('fine.ts', fine), []);
});

test('fixture: unlabelled shared controls are caught', () => {
  const bad = `export function X() { return (<><Button label="" onPress={() => {}} /><LinkButton onPress={() => {}} /></>); }`;
  assert.deepEqual(check('c.tsx', bad).map(f => f.rule), ['control-label', 'control-label']);
});
