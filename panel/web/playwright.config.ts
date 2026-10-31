import { defineConfig } from '@playwright/test'

const baseURL = process.env.PANEL_E2E_BASE_URL
if (!baseURL || !['127.0.0.1', 'localhost', '[::1]'].includes(new URL(baseURL).hostname)) {
  throw new Error('PANEL_E2E_BASE_URL must explicitly select the local synthetic test installation')
}
if (new URL(baseURL).protocol !== 'https:') throw new Error('The browser acceptance installation must use HTTPS')

export default defineConfig({
  testDir: './tests/e2e', workers: 1, retries: 0, timeout: 120_000,
  expect: { timeout: 10_000 }, reporter: 'line',
  outputDir: process.env.PANEL_E2E_OUTPUT_DIR ?? '../artifacts/b1-20261013/web/browser-results',
  use: {
    baseURL, channel: 'chrome', headless: true, viewport: { width: 1440, height: 1000 },
    // Only this guarded loopback lab may use a self-signed test certificate.
    ignoreHTTPSErrors: true, trace: 'off', video: 'off', screenshot: 'off',
  },
})
