import { defineConfig, devices } from '@playwright/test'

// The preview port can be moved with E2E_PORT, so two checkouts on one
// machine do not reuse each other's server and test the wrong build.
const PORT = Number(process.env.E2E_PORT) || 5173
const BASE_URL = `http://127.0.0.1:${PORT}`

export default defineConfig({
  testDir: './tests/browser',
  fullyParallel: true,
  timeout: 60000,
  expect: { timeout: 15000 },
  use: { baseURL: BASE_URL, trace: 'retain-on-failure' },
  projects: [
    { name: 'desktop', use: { ...devices['Desktop Chrome'] } },
    { name: 'mobile', use: { ...devices['Pixel 7'] } },
  ],
  webServer: {
    command: `npm run build && npm run preview -- --host 127.0.0.1 --port ${PORT} --strictPort`,
    url: BASE_URL,
    reuseExistingServer: !process.env.CI,
  },
})
