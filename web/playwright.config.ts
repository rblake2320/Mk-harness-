import { defineConfig } from '@playwright/test';

/** Accessibility + usability acceptance (contract: WCAG 2.2 AA automated checks).
 *  Runs against the production build served statically; the API is mocked at the
 *  network layer so every screen renders with realistic data and no backend. */
export default defineConfig({
  testDir: './tests',
  timeout: 60_000,
  retries: 0,
  use: {
    baseURL: 'http://127.0.0.1:4173', headless: true,
    // CI installs browsers with `npx playwright install chromium`; a pre-provisioned
    // container may pin a different build via PW_CHROMIUM_PATH.
    launchOptions: process.env.PW_CHROMIUM_PATH ? { executablePath: process.env.PW_CHROMIUM_PATH } : {},
  },
  webServer: { command: 'npx vite preview --port 4173 --strictPort', port: 4173, reuseExistingServer: true, timeout: 60_000 },
  reporter: [['list'], ['json', { outputFile: 'test-results/a11y.json' }]],
});
