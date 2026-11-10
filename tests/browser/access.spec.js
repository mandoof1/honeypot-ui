import { test, expect } from '@playwright/test'
import { ADMIN, mockApi, signIn } from './support.js'

// Getting in and getting out: what the first screen offers, signing out in
// every tab at once, and the settings that depend on what the deployment can do.

const withMail = { email_delivery: true, self_registration: true, password_reset: true, mfa: true }

test('the sign-in page does not offer flows that cannot finish here', async ({ page }) => {
  await mockApi(page, {
    handlers: { 'GET /auth/me$': (route) => route.fulfill({ status: 401, json: { detail: 'Invalid or expired token' } }) },
  })
  await page.goto('/login')
  await expect(page).toHaveTitle('Sign in · HoneySentinel')
  await expect(page.getByRole('button', { name: 'Sign in' })).toBeVisible()
  await expect(page.getByTestId('signup-unavailable')).toHaveText('No account yet? Ask an administrator to create one.')
  await expect(page.getByTestId('reset-unavailable')).toContainText('An administrator can set a new one.')
  await expect(page.getByRole('link', { name: 'Request access' })).toHaveCount(0)
  await expect(page.getByRole('link', { name: 'Forgot your password?' })).toHaveCount(0)

  // The pages themselves explain, for anyone arriving by an old link.
  await page.goto('/signup')
  await expect(page.getByText('Not available on this deployment')).toBeVisible()
  await expect(page.getByRole('button', { name: 'Create account' })).toHaveCount(0)
  await page.goto('/forgot-password')
  await expect(page.getByText('Not available on this deployment')).toBeVisible()
  await expect(page.getByRole('button', { name: 'Send reset code' })).toHaveCount(0)
  await page.getByRole('link', { name: 'Back to sign in' }).click()
  await expect(page).toHaveURL(/\/login$/)
})

test('with a mail provider the same flows are offered', async ({ page }) => {
  await mockApi(page, {
    handlers: {
      'GET /auth/me$': (route) => route.fulfill({ status: 401, json: { detail: 'Invalid or expired token' } }),
      'GET /auth/capabilities$': (route) => route.fulfill({ json: withMail }),
    },
  })
  await page.goto('/login')
  await expect(page.getByRole('link', { name: 'Request access' })).toBeVisible()
  await page.getByRole('link', { name: 'Forgot your password?' }).click()
  await expect(page.getByRole('button', { name: 'Send reset code' })).toBeVisible()
  await page.goto('/signup')
  await expect(page.getByRole('button', { name: 'Create account' })).toBeVisible()
})

test('if the deployment cannot be asked, nothing is offered on a guess', async ({ page }) => {
  await mockApi(page, {
    handlers: {
      'GET /auth/me$': (route) => route.fulfill({ status: 401, json: { detail: 'Invalid or expired token' } }),
      'GET /auth/capabilities$': (route) => route.fulfill({ status: 404, json: { detail: 'Not Found' } }),
    },
  })
  await page.goto('/login')
  await expect(page.getByTestId('signup-unavailable')).toBeVisible()
  await page.goto('/signup')
  await expect(page.getByText(/did not confirm that it can send one/)).toBeVisible()
})

test('signing out in one tab signs the other tab out', async ({ context }) => {
  const first = await context.newPage()
  const second = await context.newPage()
  for (const tab of [first, second]) {
    await mockApi(tab, { me: ADMIN })
  }
  // Signed in once, as a real session is: storage is shared by both tabs.
  await first.goto('/login')
  await first.evaluate(() => {
    localStorage.setItem('access_token', 'test-token')
    localStorage.setItem('refresh_token', 'test-refresh')
  })
  await first.goto('/alerts')
  await second.goto('/sessions')
  await expect(first.getByRole('heading', { name: 'Alerts', level: 1 })).toBeVisible()
  await expect(second.getByRole('heading', { name: 'Sessions', level: 1 })).toBeVisible()

  await first.setViewportSize({ width: 1400, height: 900 })
  await first.getByRole('button', { name: /admin@example.com/ }).click()
  await first.getByRole('menuitem', { name: 'Sign out' }).click()
  await expect(first).toHaveURL(/\/login/)

  // The other tab did nothing, and is on the sign-in page with the reason.
  await expect(second).toHaveURL(/\/login\?next=%2Fsessions/)
  await expect(second.getByRole('status')).toContainText('You signed out in another tab.')
  expect(await second.evaluate(() => localStorage.getItem('refresh_token'))).toBeNull()
})

test('an expired session returns to sign-in with the reason', async ({ page }) => {
  await signIn(page)
  let expired = false
  await mockApi(page, {
    handlers: {
      'GET /alerts/$': (route) => (expired
        ? route.fulfill({ status: 401, json: { detail: 'Invalid or expired token' } })
        : route.fulfill({ json: { alerts: [], total: 0 } })),
    },
  })
  await page.goto('/alerts')
  await expect(page.getByText('Nothing waiting')).toBeVisible()
  expired = true
  await page.getByRole('button', { name: 'Refresh' }).click()
  await expect(page).toHaveURL(/\/login/)
  await expect(page.getByRole('status')).toContainText('Your session has expired')
})

test('settings offer e-mail delivery only where mail can be sent, and a threshold can be paused', async ({ page }) => {
  await signIn(page)
  const threshold = {
    id: 7, name: 'Critical only', min_severity: 'critical', anomaly_score_threshold: 0.6,
    email_enabled: true, webhook_enabled: false, is_active: true, created_at: '2026-01-01T00:00:00Z', updated_at: null,
  }
  let active = true
  const api = await mockApi(page, {
    handlers: {
      'GET /settings/thresholds$': (route) => route.fulfill({ json: [{ ...threshold, is_active: active }] }),
      'PATCH /settings/thresholds/7$': (route, _url, request) => {
        active = request.postDataJSON().is_active
        return route.fulfill({ json: { ...threshold, is_active: active } })
      },
    },
  })
  await page.goto('/settings')
  await expect(page.getByTestId('delivery-channels')).toContainText('E-mail not available (no mail provider configured)')
  await expect(page.getByText('E-mail is selected but cannot be sent')).toBeVisible()
  await page.getByRole('button', { name: 'New threshold' }).click()
  await expect(page.getByRole('checkbox', { name: 'Email' })).toBeDisabled()
  await expect(page.getByTestId('email-unavailable')).toBeVisible()

  // "Paused" used to be a label with nothing to press.
  await page.getByRole('button', { name: 'Pause Critical only' }).click()
  await expect(page.getByText('Paused', { exact: true })).toBeVisible()
  expect(api.calls.find((c) => c.method === 'PATCH' && c.path === '/settings/thresholds/7').body).toEqual({ is_active: false })
  await page.getByRole('button', { name: 'Resume Critical only' }).click()
  await expect(page.getByRole('button', { name: 'Pause Critical only' })).toBeVisible()
  await expect(page.getByText('Paused', { exact: true })).toHaveCount(0)
})

test('the engines link in the rail scrolls to the engines panel', async ({ page }) => {
  await signIn(page)
  await mockApi(page)
  await page.setViewportSize({ width: 1400, height: 600 })
  await page.goto('/')
  await page.getByTestId('engines-chip').click()
  await expect(page).toHaveURL(/\/settings#engines$/)
  await expect(page.getByRole('heading', { name: 'Engines' })).toBeInViewport()
  await expect(page.locator('#engines')).toBeFocused()
})

test('moving between views renames the tab and moves focus to the new view', async ({ page }) => {
  await signIn(page)
  await mockApi(page)
  await page.setViewportSize({ width: 1400, height: 900 })
  await page.goto('/')
  await expect(page).toHaveTitle('Overview · HoneySentinel')
  await page.getByRole('link', { name: 'Indicators' }).click()
  await expect(page).toHaveTitle('Indicators · HoneySentinel')
  await expect(page.locator('#main-content')).toBeFocused()
  await expect(page.locator('#main-content')).toHaveAttribute('aria-label', 'Indicators')
})

test('an authenticator key and recovery codes are masked in presentation mode', async ({ page }) => {
  await signIn(page)
  let enabled = false
  await mockApi(page, {
    handlers: {
      'GET /auth/me$': (route) => route.fulfill({ json: { ...ADMIN, totp_enabled: enabled } }),
      'POST /auth/mfa/enroll$': (route) => route.fulfill({
        json: { secret: 'JBSWY3DPEHPK3PXP', otpauth_uri: 'otpauth://totp/HoneySentinel:admin%40example.com?secret=JBSWY3DPEHPK3PXP&issuer=HoneySentinel' },
      }),
      'POST /auth/mfa/confirm$': (route) => {
        enabled = true
        return route.fulfill({ json: { enabled: true, recovery_codes: ['aaaa-bbbb-cccc', 'dddd-eeee-ffff'] } })
      },
    },
  })
  await page.setViewportSize({ width: 1400, height: 900 })
  await page.goto('/settings')
  await page.getByLabel('Presentation mode').check()
  await page.getByRole('button', { name: 'Set up an authenticator' }).click()
  await expect(page.getByTestId('qr-masked')).toBeVisible()
  await expect(page.getByAltText('Authenticator enrolment QR code')).toHaveCount(0)
  await expect(page.getByText('JBSWY3DPEHPK3PXP')).toHaveCount(0)
  await expect(page.getByText('masked in presentation mode')).toBeVisible()

  await page.getByPlaceholder('123 456').fill('654321')
  await page.getByRole('button', { name: 'Turn on' }).click()
  await expect(page.getByTestId('recovery-masked')).toContainText('The 2 codes are masked')
  await expect(page.getByText('aaaa-bbbb-cccc')).toHaveCount(0)

  await page.getByLabel('Presentation mode').uncheck()
  await expect(page.getByText('aaaa-bbbb-cccc')).toBeVisible()
})
