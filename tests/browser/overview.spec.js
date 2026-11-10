import { test, expect } from '@playwright/test'
import { STATS, mockApi, setDisplay, signIn } from './support.js'

// The Overview: what it shows when the API answers, and what it must not
// claim when the API does not.

test.use({ timezoneId: 'Asia/Dubai' })

test.beforeEach(async ({ page }) => {
  await signIn(page)
})

test('the overview shows its readings, names the view and can be refreshed', async ({ page }) => {
  const api = await mockApi(page)
  await page.goto('/')
  await expect(page.getByRole('heading', { name: 'Overview', level: 1 })).toBeVisible()
  await expect(page).toHaveTitle('Overview · HoneySentinel')
  await expect(page.getByTestId('needs-review')).toHaveText('3')
  await expect(page.getByTestId('updated-ago')).toContainText(/updated (just now|\d+ s ago)/)

  // Only addresses seen more than once are "repeat visitors".
  const repeats = page.locator('section', { has: page.getByRole('heading', { name: 'Repeat visitors' }) })
  await expect(repeats.getByRole('link', { name: '203.0.113.7' })).toBeVisible()
  await expect(repeats.getByText('198.51.100.20')).toHaveCount(0)

  const before = api.calls.filter((c) => c.path === '/dashboard/stats').length
  await page.getByRole('button', { name: 'Refresh' }).click()
  await expect.poll(() => api.calls.filter((c) => c.path === '/dashboard/stats').length).toBe(before + 1)
})

test('a failed first load is shown as a failure, not as zero alerts', async ({ page }) => {
  let fail = true
  await mockApi(page, {
    handlers: {
      'GET /dashboard/stats$': (route) => (fail
        ? route.fulfill({ status: 503, json: { detail: 'Database is unavailable' } })
        : route.fulfill({ json: STATS })),
    },
  })
  await page.goto('/')
  await expect(page.getByRole('alert').filter({ hasText: 'Could not load the overview' })).toContainText('Database is unavailable')
  await expect(page.getByTestId('needs-review')).toHaveCount(0)
  await expect(page.getByText('No unacknowledged high-severity alerts.')).toHaveCount(0)
  await expect(page.getByText('Nothing caught yet')).toHaveCount(0)

  fail = false
  await page.getByRole('button', { name: 'Try again' }).click()
  await expect(page.getByTestId('needs-review')).toHaveText('3')
})

test('when a refresh fails the last good readings stay, marked as stale', async ({ page }) => {
  let fail = false
  await mockApi(page, {
    handlers: {
      'GET /dashboard/stats$': (route) => (fail
        ? route.fulfill({ status: 500, json: { detail: 'Internal Server Error' } })
        : route.fulfill({ json: STATS })),
    },
  })
  await page.goto('/')
  await expect(page.getByTestId('needs-review')).toHaveText('3')
  fail = true
  await page.getByRole('button', { name: 'Refresh' }).click()
  const stale = page.getByTestId('stale-notice')
  await expect(stale).toContainText('This overview may be out of date')
  await expect(stale).toContainText('Internal Server Error')
  await expect(page.getByTestId('needs-review')).toHaveText('3')
})

test('the rail tells an unreachable API from an unreachable engine', async ({ page }) => {
  await mockApi(page, {
    handlers: {
      'GET /honeypot/status$': (route) => route.fulfill({ status: 502, json: { detail: 'Bad gateway' } }),
      'GET /alerts/stats$': (route) => route.fulfill({ status: 502, json: { detail: 'Bad gateway' } }),
    },
  })
  await page.setViewportSize({ width: 1400, height: 900 })
  await page.goto('/')
  await expect(page.getByTestId('engine-state')).toHaveText('Console API unreachable')
  await page.getByRole('button', { name: /admin@example.com/ }).click()
  await expect(page.getByRole('menuitem', { name: 'Unread count unavailable' })).toBeVisible()
  await expect(page.getByText('No unread alerts')).toHaveCount(0)
})

test('hour buckets follow the chosen zone and their values can be read without hovering', async ({ page }) => {
  await mockApi(page)
  await page.setViewportSize({ width: 1400, height: 900 })
  await page.goto('/')
  // Local by default: the server's 06:00 UTC bucket is 10:00 in Dubai.
  await expect(page.getByTestId('hour-zone')).toContainText('Hours in UTC+4')
  await expect(page.getByTestId('hour-zone')).toContainText('Busiest hour 10:00 with 9')
  await page.getByText('Sessions by hour as a table').click()
  await expect(page.getByTestId('hour-table').getByRole('row', { name: '10:00 9' })).toBeVisible()

  await page.getByRole('group', { name: 'Times' }).getByRole('button', { name: 'UTC' }).click()
  await expect(page.getByTestId('hour-zone')).toContainText('Hours in UTC.')
  await expect(page.getByTestId('hour-zone')).toContainText('Busiest hour 06:00 with 9')
  // The choice is kept for the next visit.
  await page.reload()
  await expect(page.getByTestId('hour-zone')).toContainText('Busiest hour 06:00 with 9')
})

test('the daily trend has a window selector and a text alternative', async ({ page }) => {
  const api = await mockApi(page)
  await page.goto('/')
  const panel = page.getByTestId('trends-panel')
  await expect(panel.getByTestId('trend-chart')).toBeVisible()
  // 29 days of 2 plus one day of 10.
  await expect(panel.getByTestId('trend-summary')).toContainText('68 sessions in the last 30 days (UTC days)')
  await expect(panel.getByTestId('trend-summary')).toContainText('The busiest day was Jan 31 with 10.')
  await expect(panel.getByRole('list', { name: 'Categories' })).toContainText('Exploitation')

  await page.getByRole('group', { name: 'Trend window' }).getByRole('button', { name: '7 days' }).click()
  await expect(panel.getByTestId('trend-summary')).toContainText('22 sessions in the last 7 days')
  expect(api.calls.some((c) => c.path === '/dashboard/trends' && c.params.get('days') === '7')).toBe(true)

  await panel.getByText('Daily figures as a table').click()
  await expect(panel.getByRole('row', { name: /2026-01-31 10/ })).toBeVisible()
})

test('a failing trend does not take the overview down with it', async ({ page }) => {
  await mockApi(page, {
    handlers: { 'GET /dashboard/trends$': (route) => route.fulfill({ status: 500, json: { detail: 'trend query failed' } }) },
  })
  await page.goto('/')
  await expect(page.getByTestId('needs-review')).toHaveText('3')
  await expect(page.getByTestId('trends-panel').getByRole('alert')).toContainText('Could not load the daily trend')
})

test('the light theme is applied and remembered', async ({ page }) => {
  await mockApi(page)
  await page.setViewportSize({ width: 1400, height: 900 })
  await page.goto('/')
  await expect(page.locator('html')).toHaveAttribute('data-theme', 'dark')
  await page.getByRole('group', { name: 'Theme' }).getByRole('button', { name: 'Light' }).click()
  await expect(page.locator('html')).toHaveAttribute('data-theme', 'light')
  const background = await page.evaluate(() => getComputedStyle(document.body).backgroundColor)
  expect(background).toBe('rgb(255, 255, 255)')
  await page.reload()
  await expect(page.locator('html')).toHaveAttribute('data-theme', 'light')
})

test('nothing on the overview is smaller than 12 pixels', async ({ page }) => {
  await mockApi(page)
  await setDisplay(page, { theme: 'light', zone: 'utc', presentation: false })
  await page.setViewportSize({ width: 1400, height: 900 })
  await page.goto('/')
  await expect(page.getByTestId('needs-review')).toBeVisible()
  const smallest = await page.evaluate(() => {
    let min = Infinity
    for (const node of document.querySelectorAll('body *')) {
      const hasText = [...node.childNodes].some((child) => child.nodeType === 3 && child.textContent.trim())
      if (!hasText || node.closest('svg')) continue
      min = Math.min(min, parseFloat(getComputedStyle(node).fontSize))
    }
    return min
  })
  expect(smallest).toBeGreaterThanOrEqual(12)
})
