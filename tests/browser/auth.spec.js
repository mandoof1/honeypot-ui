import { test, expect } from '@playwright/test'

// The API has enforced TOTP since it was added, but the console could neither
// send a code at sign-in nor enrol an authenticator, so turning MFA on locked
// the user out of the dashboard. These cover both halves against a mocked API.

const ME = { id: 1, email: 'admin@example.com', role: 'admin', name: 'Admin', totp_enabled: false }

function mockDashboard(page, overrides = {}) {
  return page.route('**/api/v1/**', async (route) => {
    const url = new URL(route.request().url())
    for (const [suffix, handler] of Object.entries(overrides)) {
      if (url.pathname.endsWith(suffix)) return handler(route)
    }
    let body = {}
    if (url.pathname.endsWith('/auth/me')) body = ME
    else if (url.pathname.endsWith('/sessions/')) body = { sessions: [], total: 0 }
    else if (url.pathname.endsWith('/honeypot/status')) body = { reachable: true, running: true, protocols: ['ssh'] }
    else if (url.pathname.endsWith('/settings/thresholds')) body = []
    else if (url.pathname.endsWith('/settings/system')) body = { honeypot_mode: 'active', active_nodes: 1, protocols: ['multi'] }
    else if (url.pathname.endsWith('/nodes/') || url.pathname.endsWith('/live-events')) body = []
    await route.fulfill({ json: body })
  })
}

test('sign-in asks for the authenticator code when the account requires it', async ({ page }) => {
  const attempts = []
  await mockDashboard(page, {
    '/auth/login': async (route) => {
      const sent = route.request().postDataJSON()
      attempts.push(sent)
      if (!sent.totp_code) {
        return route.fulfill({
          status: 401,
          json: { detail: 'Authenticator code required' },
          // Cross-origin in this build, as on Vercel: unexposed, the browser
          // would hide the header and the form could not know to ask.
          headers: { 'X-MFA-Required': 'totp', 'Access-Control-Expose-Headers': 'X-MFA-Required' },
        })
      }
      if (sent.totp_code !== '123456') {
        return route.fulfill({ status: 401, json: { detail: 'Invalid authenticator code' } })
      }
      return route.fulfill({ json: { access_token: 'a', refresh_token: 'r', token_type: 'bearer' } })
    },
  })

  await page.goto('/login')
  await page.getByLabel('Email').fill('admin@example.com')
  await page.getByLabel('Password', { exact: true }).fill('correct horse')
  await page.getByRole('button', { name: 'Sign in' }).click()

  const code = page.getByLabel('Authenticator code')
  await expect(code).toBeVisible()
  await expect(page.getByRole('button', { name: 'Verify and sign in' })).toBeVisible()

  await code.fill('000 000')
  await page.getByRole('button', { name: 'Verify and sign in' }).click()
  await expect(page.getByText('Invalid authenticator code')).toBeVisible()

  await code.fill('123 456')
  await page.getByRole('button', { name: 'Verify and sign in' }).click()
  await expect(page).toHaveURL(/\/$/)
  // Whitespace is stripped and the password resent with the code.
  expect(attempts.at(-1)).toEqual({ email: 'admin@example.com', password: 'correct horse', totp_code: '123456' })
})

test('an authenticator can be enrolled from Settings, and recovery codes are shown once', async ({ page }) => {
  await page.addInitScript(() => localStorage.setItem('access_token', 'test-token'))
  let enabled = false
  await mockDashboard(page, {
    '/auth/me': (route) => route.fulfill({ json: { ...ME, totp_enabled: enabled } }),
    '/auth/mfa/enroll': (route) => route.fulfill({
      json: { secret: 'JBSWY3DPEHPK3PXP', otpauth_uri: 'otpauth://totp/HoneySentinel:admin%40example.com?secret=JBSWY3DPEHPK3PXP&issuer=HoneySentinel' },
    }),
    '/auth/mfa/confirm': (route) => {
      expect(route.request().postDataJSON()).toEqual({ code: '654321' })
      enabled = true
      return route.fulfill({ json: { enabled: true, recovery_codes: ['aaaa-bbbb', 'cccc-dddd'] } })
    },
  })

  await page.goto('/settings')
  await page.getByRole('button', { name: 'Set up an authenticator' }).click()
  await expect(page.getByAltText('Authenticator enrolment QR code')).toBeVisible()
  await expect(page.getByText('JBSWY3DPEHPK3PXP')).toBeVisible()

  await page.getByPlaceholder('123 456').fill('654 321')
  await page.getByRole('button', { name: 'Turn on' }).click()
  await expect(page.getByText('aaaa-bbbb')).toBeVisible()
  await expect(page.getByText(/shown once/)).toBeVisible()
})
