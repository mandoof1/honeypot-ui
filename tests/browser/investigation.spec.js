import { test, expect } from '@playwright/test'

const session = {
  id: 1, session_uuid: 'test-session-1', attacker_ip: '192.0.2.10',
  protocol: 'ssh', status: 'completed', started_at: '2026-01-01T10:00:00Z',
  duration_seconds: 60,
  attack_category: 'reconnaissance', is_anomalous: true, geo: { country: 'AE' },
  detected_tools: [], detected_intents: [], mitre_techniques: [], mitre_tactics: [],
}

const relatedSession = { ...session, id: 22, session_uuid: 'related-session-22', attacker_ip: '192.0.2.22', protocol: 'http' }

const relatedActivity = {
  session_id: 1, truncated: false, indicators_truncated: false,
  matches: [{ session: relatedSession, same_source_ip: false,
    shared_indicators: [{ type: 'url', value: 'http://payload.example/stage.sh' }], shared_indicator_count: 1 }],
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

test('related activity explains evidence and preserves filters through pivots and Back', async ({ page }, testInfo) => {
  let lists = 0
  page.on('request', (request) => { if (new URL(request.url()).pathname.endsWith('/sessions/')) lists += 1 })
  await page.route('**/sessions/1/related?**', (route) => route.fulfill({ json: relatedActivity }))
  await page.route('**/sessions/22', (route) => route.fulfill({ json: relatedSession }))
  await page.goto('/sessions?protocol=ssh&session=1')
  await page.getByRole('button', { name: 'Find related activity' }).click()
  const region = page.getByRole('region', { name: 'Related activity' })
  await expect(region.getByText('http://payload.example/stage.sh')).toBeVisible()
  await expect(region.getByText(/does not establish a common attacker/)).toBeVisible()
  const initialLists = lists
  await region.getByRole('link', { name: /192\.0\.2\.22/ }).scrollIntoViewIfNeeded()
  await page.screenshot({ path: testInfo.outputPath('related-activity.png'), fullPage: true })
  await region.getByRole('link', { name: /192\.0\.2\.22/ }).click()
  await expect(page).toHaveURL(/protocol=ssh&session=22/)
  await expect(page.getByRole('heading', { name: '192.0.2.22', exact: true })).toBeVisible()
  expect(lists).toBe(initialLists)
  await page.goBack()
  await expect(page).toHaveURL(/protocol=ssh&session=1/)
  await expect(page.getByRole('heading', { name: '192.0.2.10', exact: true })).toBeVisible()
  expect(lists).toBe(initialLists)
})

test('related search cancels stale windows and supports scanner filtering', async ({ page }) => {
  let release
  const gate = new Promise((resolve) => { release = resolve })
  await page.route('**/sessions/1/related?**', async (route) => {
    const params = new URL(route.request().url()).searchParams
    if (params.get('window_days') === '7') await gate
    await route.fulfill({ json: params.get('window_days') === '7' ? relatedActivity : { ...relatedActivity, matches: [] } })
  })
  await page.goto('/sessions?session=1')
  const started = page.waitForRequest('**/sessions/1/related?**')
  await page.getByRole('button', { name: 'Find related activity' }).click()
  await started
  try {
    await page.getByRole('combobox', { name: 'Related activity time window' }).selectOption('1')
    await expect(page.getByText('No related sessions in this time window.')).toBeVisible()
  } finally { release() }
  const filtered = page.waitForRequest((request) => request.url().includes('/related?') && new URL(request.url()).searchParams.get('exclude_scanners') === 'true')
  await page.getByRole('checkbox', { name: 'Hide research scanners', exact: true }).check()
  await filtered
  await expect(page.getByText('No related sessions in this time window.')).toBeVisible()
  await expect(page.getByRole('region', { name: 'Related activity' }).getByRole('link')).toHaveCount(0)
})

test('related failures can be retried without losing session evidence', async ({ page }) => {
  let calls = 0
  await page.route('**/sessions/1/related?**', (route) => {
    calls += 1
    return route.fulfill(calls === 1 ? { status: 503, json: { detail: 'Temporarily unavailable' } } : { json: { ...relatedActivity, truncated: true, indicators_truncated: true } })
  })
  await page.goto('/sessions?session=1')
  await page.getByRole('button', { name: 'Find related activity' }).click()
  await expect(page.getByRole('alert')).toContainText('Temporarily unavailable')
  await expect(page.getByRole('heading', { name: '192.0.2.10', exact: true })).toBeVisible()
  await page.getByRole('button', { name: 'Retry related activity' }).click()
  await expect(page.getByRole('link', { name: /192\.0\.2\.22/ })).toBeVisible()
  await expect(page.getByText(/Showing the newest 20 matches/)).toBeVisible()
  await expect(page.getByText(/first 100 distinct URL/)).toBeVisible()
})

test('capture omissions and delivery backlog remain visible', async ({ page }, testInfo) => {
  await page.route('**/sessions/?**', (route) => route.fulfill({ json: {
    sessions: [{ ...session, capture_dropped: { commands: 14, credentials: 2 } }], total: 1,
  } }))
  await page.route('**/honeypot/status', (route) => route.fulfill({ json: {
    reachable: true, running: true, protocols: ['ssh'],
    delivery: { pending: 3, retrying: 2, capture_errors: 1, last_error: 'Ingest HTTP 503' },
  } }))
  await page.goto('/sessions?session=1')
  await expect(page.getByRole('heading', { name: 'Capture limits reached' })).toBeVisible()
  await expect(page.getByText('Retained evidence is incomplete.', { exact: false }).last()).toBeVisible()
  if (testInfo.project.name === 'mobile') {
    await page.keyboard.press('Escape')
    await page.getByRole('button', { name: 'Open menu' }).click()
  }
  await expect(page.getByText('3 captures awaiting delivery')).toBeVisible()
  await expect(page.getByText('2 awaiting retry')).toBeVisible()
  await expect(page.getByText('Capture storage errors — check engine logs')).toBeVisible()
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
