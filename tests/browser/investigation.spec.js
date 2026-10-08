import { test, expect } from '@playwright/test'

const session = {
  id: 1, session_uuid: 'test-session-1', attacker_ip: '192.0.2.10',
  protocol: 'ssh', status: 'completed', started_at: '2026-01-01T10:00:00Z',
  attack_category: 'reconnaissance', is_anomalous: true, geo: { country: 'AE' },
  detected_tools: [], detected_intents: [], mitre_techniques: [], mitre_tactics: [],
}

test.beforeEach(async ({ page }) => {
  await page.addInitScript(() => localStorage.setItem('access_token', 'test-token'))
  await page.route('**/api/v1/**', async (route) => {
    const url = new URL(route.request().url())
    let body = {}
    if (url.pathname.endsWith('/auth/me')) body = { email: 'analyst@example.com', role: 'analyst' }
    else if (url.pathname.endsWith('/sessions/')) body = { sessions: [session], total: 1 }
    else if (url.pathname.endsWith('/sessions/1')) body = session
    else if (url.pathname.endsWith('/nodes/')) body = []
    else if (url.pathname.endsWith('/honeypot/status')) body = { reachable: true, running: true, protocols: ['ssh'] }
    else if (url.pathname.endsWith('/alerts/stats')) body = { new: 3 }
    else if (url.pathname.endsWith('/export/')) {
      return route.fulfill({ body: 'Session ID,Protocol\ntest-session-1,ssh\n', headers: { 'Access-Control-Expose-Headers': 'Content-Disposition, X-Export-Count, X-Export-Truncated', 'Content-Type': 'text/csv', 'Content-Disposition': 'attachment; filename="sessions.csv"', 'X-Export-Count': '1', 'X-Export-Truncated': 'false' } })
    }
    await route.fulfill({ json: body })
  })
})

test('restores filters from links and exports the same investigation', async ({ page }) => {
  await page.goto('/sessions?protocol=ssh&exclude_scanners=true')
  await expect(page.getByRole('heading', { name: 'Sessions', exact: true })).toBeVisible()
  await expect(page.getByText('1 matching session', { exact: true })).toBeVisible()
  await expect(page.getByRole('combobox', { name: 'Protocol', exact: true })).toHaveValue('ssh')
  const request = page.waitForRequest((req) => req.url().includes('/export/'))
  const download = page.waitForEvent('download')
  await page.getByRole('button', { name: 'CSV', exact: true }).click()
  expect(new URL((await request).url()).searchParams.get('exclude_scanners')).toBe('true')
  expect((await download).suggestedFilename()).toBe('sessions.csv')
  await expect(page.getByRole('status')).toContainText('Exported 1 matching session.')
  await page.getByRole('button', { name: 'Remove protocol filter' }).click()
  await expect(page).not.toHaveURL(/protocol=/)
  await page.reload()
  await expect(page.getByRole('combobox', { name: 'Protocol', exact: true })).toHaveValue('')
})

test('session browsing stays usable on narrow screens', async ({ page }, testInfo) => {
  await page.goto('/sessions')
  await expect(page.getByText('1 matching session', { exact: true })).toBeVisible()
  await expect(page.getByRole('dialog')).toHaveCount(0)
  expect(await page.evaluate(() => document.documentElement.scrollWidth <= innerWidth)).toBe(true)
  await page.getByRole('button', { name: /192\.0\.2\.10/ }).click()
  if (testInfo.project.name === 'mobile') {
    await expect(page.getByRole('dialog')).toBeVisible()
    await page.keyboard.press('Escape')
    await expect(page.getByRole('dialog')).toHaveCount(0)
  }
  await expect(page).toHaveURL(/session=1/)
  await page.screenshot({ path: testInfo.outputPath('sessions.png'), fullPage: true })
})

test('latest search wins even when an older request completes later', async ({ page }) => {
  await page.route('**/sessions/?**', async (route) => {
    const search = new URL(route.request().url()).searchParams.get('search')
    if (search === 'old') await new Promise((resolve) => setTimeout(resolve, 700))
    await route.fulfill({ json: { sessions: [{ ...session, attacker_ip: search === 'old' ? '192.0.2.99' : '192.0.2.10' }], total: 1 } })
  })
  await page.goto('/sessions')
  const input = page.getByRole('searchbox')
  const oldRequest = page.waitForRequest((req) => new URL(req.url()).searchParams.get('search') === 'old')
  await input.fill('old')
  await oldRequest
  await input.fill('new')
  await expect(page.getByRole('button', { name: /192\.0\.2\.10/ })).toBeVisible()
  await page.waitForTimeout(850)
  await expect(page.getByRole('button', { name: /192\.0\.2\.99/ })).toHaveCount(0)
})

test('a missing linked session preserves the filtered list and exports', async ({ page }) => {
  await page.route('**/sessions/999', (route) => route.fulfill({ status: 404, json: { detail: 'Session not found' } }))
  await page.goto('/sessions?protocol=ssh&session=999')
  await expect(page.getByRole('status')).toContainText('Unable to open the linked session')
  await expect(page.getByText('1 matching session', { exact: true })).toBeVisible()
  await expect(page.getByRole('button', { name: /192\.0\.2\.10/ })).toBeVisible()
  const download = page.waitForEvent('download')
  await page.getByRole('button', { name: 'CSV', exact: true }).click()
  await download
  await page.getByRole('button', { name: /192\.0\.2\.10/ }).click()
  await expect(page).toHaveURL(/session=1/)
  await expect(page.getByText(/Unable to open the linked session/)).toHaveCount(0)
})

test('selection and browser history reuse the list without additional requests', async ({ page }) => {
  const second = { ...session, id: 2, session_uuid: 'test-session-2', attacker_ip: '192.0.2.20' }
  let lists = 0
  let details = 0
  await page.route('**/sessions/?**', (route) => {
    lists += 1
    return route.fulfill({ json: { sessions: [session, second], total: 2 } })
  })
  page.on('request', (req) => { if (/\/sessions\/\d+$/.test(new URL(req.url()).pathname)) details += 1 })
  await page.goto('/sessions')
  await expect(page.getByText('2 matching sessions', { exact: true })).toBeVisible()
  const initialLists = lists
  await page.getByRole('button', { name: /192\.0\.2\.20/ }).click()
  await expect(page).toHaveURL(/session=2/)
  await page.keyboard.press('Escape')
  await expect(page.getByRole('button', { name: /192\.0\.2\.20/ })).toHaveAttribute('aria-current', 'true')
  await page.getByRole('button', { name: /192\.0\.2\.10/ }).click()
  await page.keyboard.press('Escape')
  // A navigation that changes only selection must also restore locally.
  await page.evaluate(() => { history.pushState(null, '', '?session=2'); dispatchEvent(new PopStateEvent('popstate')) })
  await expect(page.getByRole('button', { name: /192\.0\.2\.20/ })).toHaveAttribute('aria-current', 'true')
  await page.goBack()
  await expect(page.getByRole('button', { name: /192\.0\.2\.10/ })).toHaveAttribute('aria-current', 'true')
  await page.waitForTimeout(250)
  expect(lists).toBe(initialLists)
  expect(details).toBe(0)
  await expect(page.getByText('2 matching sessions', { exact: true })).toBeVisible()
  await page.getByRole('button', { name: 'Refresh', exact: true }).click()
  await expect.poll(() => lists).toBe(initialLists + 1)
})

test('slow linked details do not delay the list or overwrite a later selection', async ({ page }) => {
  let releaseDetail
  const gate = new Promise((resolve) => { releaseDetail = resolve })
  await page.route('**/sessions/99', async (route) => {
    await gate
    await route.fulfill({ json: { ...session, id: 99, session_uuid: 'late-session' } })
  })
  const requested = page.waitForRequest('**/sessions/99')
  await page.goto('/sessions?session=99')
  await requested
  try {
    await expect(page.getByText('1 matching session', { exact: true })).toBeVisible()
    await page.getByRole('button', { name: /192\.0\.2\.10/ }).click()
    await expect(page).toHaveURL(/session=1/)
  } finally {
    releaseDetail()
  }
  await page.keyboard.press('Escape')
  await page.waitForTimeout(250)
  await expect(page.getByRole('button', { name: /192\.0\.2\.10/ })).toHaveAttribute('aria-current', 'true')
  await expect(page.getByText('late-session', { exact: true })).toHaveCount(0)
})

test('a linked session outside the current page loads independently', async ({ page }) => {
  await page.route('**/sessions/99', (route) => route.fulfill({ json: { ...session, id: 99, session_uuid: 'outside-page' } }))
  await page.goto('/sessions?protocol=ssh&session=99')
  await expect(page.getByText('1 matching session', { exact: true })).toBeVisible()
  await expect(page.getByText('outside-page', { exact: true }).last()).toBeVisible()
})

test('widening an open mobile sheet releases the document', async ({ page }) => {
  await page.setViewportSize({ width: 412, height: 915 })
  await page.goto('/sessions')
  await page.getByRole('button', { name: /192\.0\.2\.10/ }).click()
  await expect(page.getByRole('dialog')).toBeVisible()
  await page.setViewportSize({ width: 1280, height: 900 })
  await expect(page.getByRole('dialog')).toHaveCount(0)
  await page.getByRole('button', { name: 'Refresh', exact: true }).click()
  await expect(page.getByText('1 matching session', { exact: true })).toBeVisible()
  await page.setViewportSize({ width: 412, height: 915 })
  await expect(page.getByRole('dialog')).toHaveCount(0)
  await page.getByRole('button', { name: /192\.0\.2\.10/ }).click()
  await expect(page.getByRole('dialog')).toBeVisible()
})

// Regression: the debounce decided what was sent, never whether to send. Typing
// four characters issued five list requests, four carrying a stale search term.
test('typing a search term issues one list request, not one per keystroke', async ({ page }) => {
  const searches = []
  await page.route('**/api/v1/sessions/?*', async (route) => {
    searches.push(new URL(route.request().url()).searchParams.get('search') ?? '')
    await route.fulfill({ json: { sessions: [session], total: 1 } })
  })
  await page.goto('/sessions')
  await expect(page.getByText('1 matching session', { exact: true })).toBeVisible()
  searches.length = 0
  await page.getByLabel('Search sessions by address or session ID').pressSequentially('root', { delay: 120 })
  await expect.poll(() => searches).toEqual(['root'])
})

// Regression: free-text filters pushed one history entry per character, so Back
// walked "AE" back to "A" instead of leaving the view. They now replace, as the
// search box always has: a typed refinement is not a navigation step.
test('typing a filter adds no per-character history entries', async ({ page }) => {
  await page.goto('/sessions')
  await expect(page.getByText('1 matching session', { exact: true })).toBeVisible()
  await page.getByRole('button', { name: /filters/i }).click()
  const before = await page.evaluate(() => history.length)
  const country = page.getByPlaceholder('NL')
  await country.click()
  await country.pressSequentially('AE', { delay: 120 })
  await expect(page).toHaveURL(/country=AE/)
  expect(await page.evaluate(() => history.length)).toBe(before)
})

// A select is one decision, so it still earns an entry Back can undo.
test('a dropdown filter remains undoable with back', async ({ page }) => {
  await page.goto('/sessions')
  await expect(page.getByText('1 matching session', { exact: true })).toBeVisible()
  await page.getByRole('button', { name: /filters/i }).click()
  await page.getByRole('combobox', { name: 'Protocol', exact: true }).selectOption('ssh')
  await expect(page).toHaveURL(/protocol=ssh/)
  await page.goBack()
  await expect(page).not.toHaveURL(/protocol=/)
})

test('triage shows its distribution, its route and the technique check', async ({ page }) => {
  await page.route('**/sessions/77', (route) => route.fulfill({
    json: {
      ...session,
      id: 77,
      session_uuid: 'triaged-session',
      mitre_techniques: [
        { id: 'T1105', name: 'Ingress Tool Transfer', source: 'chimera', support: 0.94, unconfirmed: false },
        { id: 'T1486', name: 'Data Encrypted for Impact', source: 'chimera', support: 0.04, unconfirmed: true },
      ],
      triage_status: 'complete',
      triage: {
        model: 'kev-4b',
        category: 'exploitation',
        category_probabilities: { benign: 0.02, reconnaissance: 0.08, exploitation: 0.85, exfiltration: 0.05 },
        severity: 2.21,
        operator: 'automated',
        operator_probability: 0.8,
        agrees_with_rules: false,
        route: 'pending',
        route_reason: 'the rules flagged it and triage did not rule it out',
        ms: 7100,
        triaged_at: '2026-10-08T12:00:00Z',
      },
      enrichment_status: 'complete',
      enrichment: { intent: 'Fetch a payload', objectives: [], model: 'wolfram', checked_by: 'kev-4b', analysed_at: '2026-10-08T12:02:00Z' },
    },
  }))
  await page.goto('/sessions?session=77')
  // The mobile layout renders the detail in a sheet as well; read the one in view.
  const triage = page.getByTestId('triage-block').last()
  await expect(triage).toContainText('kev-4b')
  await expect(triage.getByRole('list', { name: 'Category probabilities' })).toContainText('85%')
  await expect(triage).toContainText('Disagrees with the verdict above')
  await expect(triage).toContainText('Attempted compromise')
  await expect(triage).toContainText('Sent to the language model')
  await expect(page.getByText('checked 94%').last()).toBeVisible()
  await expect(page.getByText('unconfirmed 4%').last()).toBeVisible()
  await expect(page.getByTestId('enrichment-block').last()).toContainText('techniques checked by kev-4b')
})
