import { test, expect, type Page } from '@playwright/test';
import AxeBuilder from '@axe-core/playwright';
import { ACTION_ID, DIGEST, challenge, fakePasskey, json, mockApi, openApprovals, problem } from './fixtures';

/** WCAG 2.2 AA automated checks on every supported screen (contract WP08). Manual
 *  keyboard / screen-reader assessment is a separate, human-run acceptance step. */
const TAGS = ['wcag2a', 'wcag2aa', 'wcag21a', 'wcag21aa', 'wcag22aa'];
const SCREENS: Array<[string, RegExp]> = [
  ["Today's brief", /Today's brief/], ['Approvals', /Approvals/], ['Inbox & exceptions', /Inbox & exceptions/],
  ['My customers', /My customers/], ['Settings', /Governance/], ['Settings', /Sign-in security/],
];

async function expectNoViolations(page: Page) {
  const results = await new AxeBuilder({ page }).withTags(TAGS).analyze();
  expect(results.violations, JSON.stringify(results.violations.map(v => ({ id: v.id, impact: v.impact, nodes: v.nodes.map(n => n.target) })), null, 2)).toEqual([]);
}

for (const [nav, heading] of SCREENS) {
  test(`${nav} (${heading.source}) has no WCAG 2.2 A/AA violations`, async ({ page }) => {
    await mockApi(page);
    await page.goto('/');
    await page.getByRole('navigation', { name: 'Main' }).getByRole('button', { name: nav }).click();
    await expect(page.getByText(heading).first()).toBeVisible();
    await expectNoViolations(page);
  });
}

test('customer page has no WCAG 2.2 A/AA violations', async ({ page }) => {
  await mockApi(page);
  await page.goto('/');
  await page.getByRole('navigation', { name: 'Main' }).getByRole('button', { name: 'My customers' }).click();
  await page.getByRole('button', { name: 'Brenda Lee' }).click();
  await expect(page.getByText('Permission & suppression')).toBeVisible();
  await expectNoViolations(page);
});

test('mobile hand-off approval page (focused message, refused return link) has no WCAG 2.2 A/AA violations', async ({ page }) => {
  await mockApi(page);
  await page.goto(`/?view=approvals&action=${ACTION_ID}&return_to=${encodeURIComponent('https://evil.example')}`);
  await expect(page.getByRole('note', { name: 'Approval requested from the mobile app' })).toBeVisible();
  await expect(page.getByText('The return link in this address was not recognised')).toBeVisible();
  await expectNoViolations(page);
});

test('approvals after a kernel refusal (error with code, second-person note) have no WCAG 2.2 A/AA violations', async ({ page }) => {
  await mockApi(page);
  await fakePasskey(page);
  await page.route('**/api/agent-ops/actions/*/approval-challenge', r => json(r, challenge(DIGEST)));
  await page.route('**/api/agent-ops/actions/*/approve', r => r.fulfill(problem(403, 'SELF_APPROVAL_FORBIDDEN', 'Policy denied the action')));
  await openApprovals(page);
  await page.getByRole('button', { name: 'Approve this message with passkey' }).click();
  await expect(page.getByRole('alert')).toContainText('second person');
  await expectNoViolations(page);
});

/** X4: at 360 CSS px every main screen keeps its essential controls on screen without
 *  horizontal scrolling. (Automated layout check; the manual review is separate.) */
const NARROW: Array<[string, string[]]> = [
  ["Today's brief", ['Draft a message', 'Defer to tomorrow', 'Mark resolved', 'Skip']],
  ['Approvals', ['Approve this message with passkey', 'Reject']],
  ['Inbox & exceptions', ['Process new replies', 'Resolved', 'Dismiss']],
  ['My customers', ['Add customer', 'Open', 'Edit', 'Delete']],
  ['Settings', ['Add passkey', 'Export my data (JSON)']],
];
for (const [nav, controls] of NARROW) {
  test(`${nav} at 360 CSS px: no horizontal scroll, essential controls visible`, async ({ page }) => {
    await page.setViewportSize({ width: 360, height: 740 });
    await mockApi(page);
    await page.goto('/');
    await page.getByRole('navigation', { name: 'Main' }).getByRole('button', { name: nav }).click();
    for (const control of controls) {
      const btn = page.getByRole('button', { name: control, exact: true }).first();
      await btn.scrollIntoViewIfNeeded();
      await expect(btn).toBeVisible();
      const box = await btn.boundingBox();
      expect(box && box.x >= 0 && box.x + box.width <= 360, `${control} lies outside the 360 px viewport: ${JSON.stringify(box)}`).toBe(true);
    }
    const overflow = await page.evaluate(() => {
      const main = document.querySelector('main');
      return { doc: document.documentElement.scrollWidth, main: main ? main.scrollWidth - main.clientWidth : 0 };
    });
    expect(overflow.doc, 'page scrolls horizontally').toBeLessThanOrEqual(360);
    expect(overflow.main, 'main content scrolls horizontally').toBeLessThanOrEqual(0);
  });
}
