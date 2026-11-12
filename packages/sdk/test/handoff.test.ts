/**
 * The mobile → web passkey hand-off allowlist. `return_to` is accepted only when the whole
 * value equals `consultantstudio://approvals/done`; every bypass family below is refused.
 */
import { test } from 'node:test';
import assert from 'node:assert/strict';
import {
  APPROVAL_RETURN_URL, MAX_QUERY_LENGTH, acceptReturnTo, buildApprovalHandoffUrl, buildApprovalReturnUrl, normalizeActionId,
  parseApprovalReturn, readApprovalPageParams, validateWebUrl,
} from '../src/index';

const ID = '11111111-1111-4111-8111-111111111111';
/** Has hex letters, so its upper-case form is a different string (unlike ID). */
const HEX_ID = 'aaaaaaaa-bbbb-4ccc-8ddd-eeeeeeeeeeee';
const enc = encodeURIComponent;

/** Values a hostile page, link or app could put in `return_to` (after the one URL decode). */
const BYPASSES: Array<[string, unknown]> = [
  ['lookalike suffix', 'consultantstudio://approvals/done.evil'],
  ['lookalike prefix', 'consultantstudio://approvals/donee'],
  ['path traversal', 'consultantstudio://approvals/done/../x'],
  ['dot segment', 'consultantstudio://approvals/./done'],
  ['trailing slash', 'consultantstudio://approvals/done/'],
  ['query appended', 'consultantstudio://approvals/done?action=x'],
  ['fragment appended', 'consultantstudio://approvals/done#frag'],
  ['uppercase scheme', 'CONSULTANTSTUDIO://approvals/done'],
  ['mixed-case scheme', 'ConsultantStudio://approvals/done'],
  ['uppercase host', 'consultantstudio://APPROVALS/done'],
  ['percent-encoded slashes', 'consultantstudio:%2F%2Fapprovals%2Fdone'],
  ['percent-encoded separator', 'consultantstudio://approvals%2Fdone'],
  ['double-encoded', 'consultantstudio%253A%252F%252Fapprovals%252Fdone'],
  ['backslashes', 'consultantstudio:\\\\approvals\\done'],
  ['https URL', 'https://evil.example'],
  ['https lookalike', 'https://consultantstudio.example/approvals/done'],
  ['javascript:', 'javascript:alert(1)'],
  ['javascript: with scheme text', 'javascript://approvals/done%0aalert(1)'],
  ['data:', 'data:text/html,<script>alert(1)</script>'],
  ['other scheme', 'otherapp://approvals/done'],
  ['scheme-relative', '//approvals/done'],
  ['userinfo', 'consultantstudio://evil@approvals/done'],
  ['port', 'consultantstudio://approvals:443/done'],
  ['leading space', ' consultantstudio://approvals/done'],
  ['trailing space', 'consultantstudio://approvals/done '],
  ['trailing newline', 'consultantstudio://approvals/done\n'],
  ['embedded CRLF', 'consultantstudio://approvals/done\r\nLocation: https://evil.example'],
  ['tab inside', 'consultantstudio://approvals/\tdone'],
  ['NUL', 'consultantstudio://approvals/done\u0000'],
  ['zero-width space', 'consultantstudio://approvals/done\u200b'],
  ['Cyrillic homoglyph', 'consultantstudіo://approvals/done'],
  ['fullwidth colon', 'consultantstudio：//approvals/done'],
  ['very long', APPROVAL_RETURN_URL + 'a'.repeat(100_000)],
  ['empty', ''],
  ['null', null],
  ['undefined', undefined],
  ['number', 1],
  ['array', [APPROVAL_RETURN_URL]],
  ['object with toString', { toString: () => APPROVAL_RETURN_URL }],
];

test('acceptReturnTo accepts exactly the allowlisted value', () => {
  assert.equal(acceptReturnTo('consultantstudio://approvals/done'), APPROVAL_RETURN_URL);
});

for (const [name, value] of BYPASSES) {
  test(`acceptReturnTo refuses: ${name}`, () => {
    assert.equal(acceptReturnTo(value), null);
  });
}

test('readApprovalPageParams: the encoded allowlisted value (as the app sends it) is accepted', () => {
  const p = readApprovalPageParams(`?view=approvals&action=${ID}&return_to=${enc(APPROVAL_RETURN_URL)}`);
  assert.deepEqual(p, { view: 'approvals', actionId: ID, returnTo: APPROVAL_RETURN_URL, returnToRefused: false });
  // Unencoded reserved characters in a query value are also legal and decode to the same value.
  assert.equal(readApprovalPageParams(`?view=approvals&return_to=${APPROVAL_RETURN_URL}`).returnTo, APPROVAL_RETURN_URL);
});

test('readApprovalPageParams refuses every bypass after exactly one decode, and says so', () => {
  for (const [name, value] of BYPASSES) {
    if (typeof value !== 'string' || value === '' || value.length > 1000) continue; // over-long: see the next tests
    const p = readApprovalPageParams(`?view=approvals&action=${ID}&return_to=${enc(value)}`);
    assert.equal(p.returnTo, null, name);
    assert.equal(p.returnToRefused, true, name);
    assert.equal(p.view, 'approvals', name);
  }
});

test('readApprovalPageParams: "+" decodes to space and is refused; malformed percent-encoding is refused', () => {
  assert.equal(readApprovalPageParams(`?return_to=${enc(APPROVAL_RETURN_URL)}+`).returnTo, null);
  const bad = readApprovalPageParams('?view=approvals&return_to=%E0%A4%A');
  assert.equal(bad.returnTo, null);
  assert.equal(bad.returnToRefused, true);
});

test('readApprovalPageParams: duplicate parameters are ambiguous and refused', () => {
  const p = readApprovalPageParams(`?view=approvals&return_to=${enc(APPROVAL_RETURN_URL)}&return_to=${enc('https://evil.example')}`);
  assert.equal(p.returnTo, null);
  assert.equal(p.returnToRefused, true);
  const q = readApprovalPageParams(`?view=approvals&return_to=${enc(APPROVAL_RETURN_URL)}&return_to=${enc(APPROVAL_RETURN_URL)}`);
  assert.equal(q.returnTo, null, 'even two identical values are refused');
  assert.equal(readApprovalPageParams(`?action=${ID}&action=${ID}`).actionId, null);
  assert.equal(readApprovalPageParams('?view=approvals&view=brief').view, null);
});

test('readApprovalPageParams: encoded parameter names are decoded once like values', () => {
  const p = readApprovalPageParams(`?view=approvals&return%5Fto=${enc('https://evil.example')}`);
  assert.equal(p.returnTo, null);
  assert.equal(p.returnToRefused, true);
});

test('readApprovalPageParams: no return_to → nothing refused; missing or junk search → empty', () => {
  assert.deepEqual(readApprovalPageParams(`?view=approvals&action=${ID}`), { view: 'approvals', actionId: ID, returnTo: null, returnToRefused: false });
  for (const s of ['', '?', '?&&&', '?=', undefined, null, 42]) {
    assert.deepEqual(readApprovalPageParams(s), { view: null, actionId: null, returnTo: null, returnToRefused: false }, String(s));
  }
});

test('readApprovalPageParams: an over-long query is not parsed at all', () => {
  const p = readApprovalPageParams(`?view=approvals&action=${ID}&return_to=${enc(APPROVAL_RETURN_URL)}&pad=${'a'.repeat(MAX_QUERY_LENGTH)}`);
  assert.deepEqual(p, { view: null, actionId: null, returnTo: null, returnToRefused: true });
});

test('readApprovalPageParams: view must be a short lower-case word', () => {
  assert.equal(readApprovalPageParams('?view=Approvals').view, null);
  assert.equal(readApprovalPageParams(`?view=${enc('approvals<script>')}`).view, null);
});

test('normalizeActionId accepts canonical UUIDs (any case) and nothing else', () => {
  assert.equal(normalizeActionId(ID), ID);
  assert.equal(normalizeActionId(HEX_ID.toUpperCase()), HEX_ID);
  for (const bad of [`${ID} `, ` ${ID}`, `${ID}\n`, ID.replace(/-/g, ''), `{${ID}}`, `${ID}&x=1`, '11111111-1111-4111-8111-11111111111g',
    '../../../../etc/passwd', '', null, undefined, 7, [ID]]) {
    assert.equal(normalizeActionId(bad), null, String(bad));
  }
});

test('buildApprovalReturnUrl: only the allowlisted base plus a validated id', () => {
  assert.equal(buildApprovalReturnUrl(APPROVAL_RETURN_URL, ID), `${APPROVAL_RETURN_URL}?action=${ID}`);
  assert.equal(buildApprovalReturnUrl(APPROVAL_RETURN_URL, HEX_ID.toUpperCase()), `${APPROVAL_RETURN_URL}?action=${HEX_ID}`);
  assert.equal(buildApprovalReturnUrl('https://evil.example', ID), null);
  assert.equal(buildApprovalReturnUrl(APPROVAL_RETURN_URL, `${ID}&next=https://evil.example`), null);
  assert.equal(buildApprovalReturnUrl(APPROVAL_RETURN_URL, null), null);
});

test('parseApprovalReturn (mobile): only the exact return shape yields an action id', () => {
  assert.deepEqual(parseApprovalReturn(`${APPROVAL_RETURN_URL}?action=${ID}`), { actionId: ID });
  const refused = [
    APPROVAL_RETURN_URL, `${APPROVAL_RETURN_URL}?`, `${APPROVAL_RETURN_URL}?action=`, `${APPROVAL_RETURN_URL}?action=${HEX_ID.toUpperCase()}`,
    `${APPROVAL_RETURN_URL}?action=${ID}&approved=true`, `${APPROVAL_RETURN_URL}?approved=true&action=${ID}`, `${APPROVAL_RETURN_URL}?action=${ID}#x`,
    `${APPROVAL_RETURN_URL}?action=${enc(ID)}x`, `${APPROVAL_RETURN_URL}/?action=${ID}`, `${APPROVAL_RETURN_URL}.evil?action=${ID}`,
    `CONSULTANTSTUDIO://approvals/done?action=${ID}`, `https://evil.example/?action=${ID}`, `${APPROVAL_RETURN_URL}?action=${ID}\n`,
    `${APPROVAL_RETURN_URL}?action=${ID}${'a'.repeat(10_000)}`, `${APPROVAL_RETURN_URL}?action=${ID.replace(/-/g, '%2D')}`, '', null, undefined, {},
  ];
  for (const url of refused) assert.equal(parseApprovalReturn(url), null, String(url));
});

test('validateWebUrl: HTTPS hosts only (dev loopback opt-in), no credentials, query, fragment or dot segments', () => {
  assert.equal(validateWebUrl('https://app.example.com'), 'https://app.example.com');
  assert.equal(validateWebUrl('https://app.example.com/'), 'https://app.example.com');
  assert.equal(validateWebUrl('https://app.example.com:8443/studio/'), 'https://app.example.com:8443/studio');
  assert.equal(validateWebUrl('http://localhost:5173'), null, 'dev http needs the explicit opt-in');
  assert.equal(validateWebUrl('http://localhost:5173', { allowDevHttp: true }), 'http://localhost:5173');
  assert.equal(validateWebUrl('http://10.0.2.2:5173', { allowDevHttp: true }), 'http://10.0.2.2:5173');
  for (const bad of ['http://app.example.com', 'https://user:pw@app.example.com', 'https://app.example.com/?x=1', 'https://app.example.com/#x',
    'https://app.example.com/../x', 'javascript:alert(1)', 'https://APP.example.com', 'https://app.example.com /x', ' https://app.example.com',
    'https://exämple.com', 'https://-bad.example.com', 'https://app.example.com/a b', 'ftp://app.example.com', 'https://', '', null, 5,
    'http://evil.example', 'http://localhost.evil.example']) {
    assert.equal(validateWebUrl(bad, { allowDevHttp: true }), null, String(bad));
  }
});

test('buildApprovalHandoffUrl produces the page the web app parses back to the same action and allowlisted return', () => {
  const url = buildApprovalHandoffUrl('https://app.example.com/studio', HEX_ID.toUpperCase());
  assert.equal(url, `https://app.example.com/studio/?view=approvals&action=${HEX_ID}&return_to=consultantstudio%3A%2F%2Fapprovals%2Fdone`);
  const p = readApprovalPageParams(url!.slice(url!.indexOf('?')));
  assert.deepEqual(p, { view: 'approvals', actionId: HEX_ID, returnTo: APPROVAL_RETURN_URL, returnToRefused: false });
  assert.equal(buildApprovalHandoffUrl('http://evil.example', ID), null);
  assert.equal(buildApprovalHandoffUrl('https://app.example.com', 'not-an-id'), null);
});
