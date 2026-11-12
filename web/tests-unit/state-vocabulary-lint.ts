/**
 * Contract row C3 guard: UI code must render message/delivery state only through the SDK
 * vocabulary (`describeMessageState`), never with its own words. This lint parses UI
 * sources with the TypeScript compiler and reports copy that names a message state outside
 * that helper. It looks only at user-visible text (string literals, template text, JSX
 * text and attribute strings) and at object literals that map state identifiers to words —
 * never at comments, identifiers or type positions — so ordinary words ("Send", "Nothing
 * was sent.", "Sending number") do not trip it.
 *
 * Rules:
 *  R1 whole-copy state label: the entire string/JSX text, ignoring case, spacing and
 *     punctuation/symbols ("Delivered ✓", "SENT!", "Provider accepted"), is a message-state
 *     label or a known paraphrase. The bare identifier in a string literal ('sent',
 *     'provider_accepted') is code, not copy, and is allowed; in JSX text it is rendered
 *     and is flagged.
 *  R2 local state map: an object literal that maps message-state identifiers to human
 *     words (`{ sent: 'Sent', delivered: 'Delivered' }`, `{ provider_accepted: 'Accepted' }`).
 *  R3 delivery claim inside longer copy: "message sent", "text delivered", "sent
 *     successfully", "successfully delivered", "Sent!", "read receipt" — unless negated
 *     ("No message sent", "not delivered").
 */
import ts from 'typescript';

export interface Violation { file: string; line: number; rule: 'R1' | 'R2' | 'R3'; text: string }

export const STATE_IDS = [
  'proposed', 'awaiting_approval', 'approved', 'queued', 'dispatch_authorized', 'submission_started',
  'provider_accepted', 'sent', 'delivered', 'failed', 'delivery_unknown', 'submission_unknown',
  'cancelled', 'denied', 'expired',
] as const;
/** States whose words only ever describe a message (as opposed to commitments or outcomes). */
const MESSAGE_ONLY = new Set(['awaiting_approval', 'dispatch_authorized', 'submission_started', 'provider_accepted', 'sent', 'delivered', 'delivery_unknown', 'submission_unknown']);
const PARAPHRASES = [
  'accepted by provider', 'accepted by the provider', 'authorized to send', 'authorised to send', 'submitting', 'sending',
  'awaiting your approval', 'denied by policy', 'message sent', 'messages sent', 'text sent', 'sms sent', 'message delivered',
  'text delivered', 'sms delivered', 'sent successfully', 'successfully sent', 'delivered successfully', 'successfully delivered',
  'message queued', 'delivery confirmed', 'delivered to customer', 'sent to customer', 'not delivered', 'undelivered',
];
const PHRASES = new Set<string>([...STATE_IDS.map(s => s.replace(/_/g, ' ')), ...PARAPHRASES]);
const IDS = new Set<string>(STATE_IDS);

export function normalize(s: string): string {
  return s.normalize('NFKC').replace(/[_\-\s]+/g, ' ').replace(/^[\s\p{P}\p{S}]+|[\s\p{P}\p{S}]+$/gu, '').replace(/\s+/g, ' ').toLowerCase();
}

const CLAIM = /\b(?:(?:message|messages|text|texts|sms)\s+(?:was\s+|were\s+|has\s+been\s+|have\s+been\s+|is\s+)?(?:sent|delivered)|(?:sent|delivered)\s+successfully|successfully\s+(?:sent|delivered)|read\s+receipts?)\b|\b(?:sent|delivered)\s*!/gi;
const NEGATION = /\b(?:no|not|nothing|never|without|before|until|unless|whether|if)\b[^.;:!?]{0,24}$/i;

function claimIn(text: string): string | null {
  for (const m of text.matchAll(CLAIM)) {
    const before = text.slice(0, m.index ?? 0);
    if (!NEGATION.test(before)) return m[0];
  }
  return null;
}

/** Human words (not an identifier): contains a capital, a space or punctuation. */
const isHuman = (v: string) => v !== v.toLowerCase() || /[\s\p{P}\p{S}]/u.test(v.replace(/_/g, ''));

/** JSX attributes whose string value people read or hear; other attributes carry code values
 *  (`state="sent"` passed to the vocabulary helper is fine). */
const COPY_ATTRIBUTES = new Set(['title', 'aria-label', 'aria-description', 'aria-roledescription', 'alt', 'placeholder', 'label',
  'accessibilityLabel', 'accessibilityHint', 'children']);

export function lintSource(file: string, source: string): Violation[] {
  const sf = ts.createSourceFile(file, source, ts.ScriptTarget.Latest, true, file.endsWith('x') ? ts.ScriptKind.TSX : ts.ScriptKind.TS);
  const out: Violation[] = [];
  const add = (node: ts.Node, rule: Violation['rule'], text: string) =>
    out.push({ file, line: sf.getLineAndCharacterOfPosition(node.getStart(sf)).line + 1, rule, text: text.slice(0, 80) });

  const checkCopy = (node: ts.Node, raw: string, rendered: boolean) => {
    const n = normalize(raw);
    if (n && PHRASES.has(n) && (rendered || !IDS.has(raw))) { add(node, 'R1', raw); return; }
    const claim = claimIn(raw);
    if (claim) add(node, 'R3', raw);
  };

  const inTypePosition = (node: ts.Node) => {
    for (let p = node.parent; p; p = p.parent) {
      if (ts.isTypeNode(p) && !ts.isTypeQueryNode(p)) return true;
      if (ts.isImportDeclaration(p) || ts.isExportDeclaration(p) || ts.isExternalModuleReference(p)) return true;
      if (ts.isStatement(p) || ts.isExpression(p) && !ts.isLiteralExpression(p)) break;
    }
    return false;
  };

  const visit = (node: ts.Node) => {
    if (ts.isObjectLiteralExpression(node)) {
      const stateProps = node.properties.filter((p): p is ts.PropertyAssignment => ts.isPropertyAssignment(p)
        && (ts.isIdentifier(p.name) || ts.isStringLiteral(p.name)) && IDS.has(p.name.text)
        && (ts.isStringLiteralLike(p.initializer)) && isHuman(p.initializer.text));
      const messageOnly = stateProps.some(p => MESSAGE_ONLY.has((p.name as ts.Identifier | ts.StringLiteral).text));
      if ((stateProps.length >= 2 && messageOnly) || stateProps.length >= 3 || (stateProps.length === 1 && messageOnly)) {
        for (const p of stateProps) add(p, 'R2', `${(p.name as ts.Identifier).text}: ${(p.initializer as ts.StringLiteralLike).text}`);
      }
    }
    if ((ts.isStringLiteral(node) || ts.isNoSubstitutionTemplateLiteral(node)) && !inTypePosition(node)) {
      // Property keys are handled by R2; module specifiers are not copy.
      const parent = node.parent;
      const isKey = parent && (ts.isPropertyAssignment(parent) || ts.isPropertySignature(parent) || ts.isMethodDeclaration(parent)) && parent.name === node;
      const isElementKey = parent && ts.isElementAccessExpression(parent) && parent.argumentExpression === node;
      const copyAttribute = parent !== undefined && ts.isJsxAttribute(parent) && COPY_ATTRIBUTES.has(parent.name.getText(sf));
      if (!isKey && !isElementKey) checkCopy(node, node.text, copyAttribute);
    }
    if (ts.isTemplateExpression(node)) {
      const parts = [node.head.text, ...node.templateSpans.map(s => s.literal.text)];
      for (const t of parts) {
        const n = normalize(t);
        if (n && PHRASES.has(n) && !IDS.has(t)) { add(node, 'R1', t); break; }
        if (claimIn(t)) { add(node, 'R3', t); break; }
      }
    }
    if (ts.isJsxText(node)) {
      const t = node.text.trim();
      if (t) checkCopy(node, t, true);
    }
    ts.forEachChild(node, visit);
  };
  visit(sf);
  return out;
}
