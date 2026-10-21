import { test, expect } from '@playwright/test';
import AxeBuilder from '@axe-core/playwright';
import { mockApi } from './fixtures';

/** WCAG 2.2 AA automated checks on every supported screen (contract WP08). Manual
 *  keyboard / screen-reader assessment is a separate, human-run acceptance step. */
const SCREENS: Array<[string, RegExp]> = [
  ["Today's brief", /Today's brief/], ['Approvals', /Approvals/], ['Inbox & exceptions', /Inbox & exceptions/],
  ['My customers', /My customers/], ['Settings', /Governance/],
];

for (const [nav, heading] of SCREENS) {
  test(`${nav} has no WCAG 2.2 A/AA violations`, async ({ page }) => {
    await mockApi(page);
    await page.goto('/');
    await page.getByRole('navigation', { name: 'Main' }).getByRole('button', { name: nav }).click();
    await expect(page.getByText(heading).first()).toBeVisible();
    const results = await new AxeBuilder({ page }).withTags(['wcag2a', 'wcag2aa', 'wcag21a', 'wcag21aa', 'wcag22aa']).analyze();
    expect(results.violations, JSON.stringify(results.violations.map(v => ({ id: v.id, impact: v.impact, nodes: v.nodes.map(n => n.target) })), null, 2)).toEqual([]);
  });
}

test('customer page has no WCAG 2.2 A/AA violations', async ({ page }) => {
  await mockApi(page);
  await page.goto('/');
  await page.getByRole('navigation', { name: 'Main' }).getByRole('button', { name: 'My customers' }).click();
  await page.getByRole('button', { name: 'Brenda Lee' }).click();
  await expect(page.getByText('Permission & suppression')).toBeVisible();
  const results = await new AxeBuilder({ page }).withTags(['wcag2a', 'wcag2aa', 'wcag21a', 'wcag21aa', 'wcag22aa']).analyze();
  expect(results.violations, JSON.stringify(results.violations, null, 2)).toEqual([]);
});
