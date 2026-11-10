import { test, expect } from '@playwright/test'
import {
  ADMIN, ANALYST, VIEWER, makeSession, mockApi, signIn,
} from './support.js'

// Indicators, the ATT&CK matrix, the audit log, blocking, alerts paging and
// the origin map's fallback.

test.use({ timezoneId: 'Asia/Dubai' })

test.beforeEach(async ({ page }) => {
  await signIn(page)
  await page.setViewportSize({ width: 1400, height: 900 })
})

const INDICATORS = [
  { type: 'ip', value: '203.0.113.7', sessions: 4, confidence: 0.95, first_seen: '2026-01-01T09:00:00Z', last_seen: '2026-01-02T10:00:00Z' },
  { type: 'referenced_ip', value: '8.8.8.8', sessions: 1, confidence: 0.7, first_seen: '2026-01-01T09:00:00Z', last_seen: '2026-01-01T09:00:00Z' },
  { type: 'url', value: 'http://198.51.100.9/x.sh\nrm -rf /', sessions: 2, confidence: 0.8, first_seen: '2026-01-01T09:00:00Z', last_seen: '2026-01-01T09:00:00Z' },
  { type: 'tool', value: 'nmap', sessions: 1, confidence: 0.85, first_seen: '2026-01-01T09:00:00Z', last_seen: '2026-01-01T09:00:00Z' },
]

function indicatorHandlers() {
  return {
    'GET /iocs/$': (route, url) => {
      const min = Number(url.searchParams.get('min_sessions') || 1)
      const type = url.searchParams.get('ioc_type')
      const rows = INDICATORS.filter((row) => row.sessions >= min && (!type || row.type === type))
      return route.fulfill({ json: { indicators: rows, total: rows.length, page: 1, page_size: 50 } })
    },
    'GET /iocs/feed$': (route) => route.fulfill({
      body: '# HoneySentinel indicator feed\n203.0.113.7\n',
      headers: {
        'Content-Type': 'text/plain',
        'Content-Disposition': 'attachment; filename="honeysentinel-ip-2026-01-02.txt"',
        'Access-Control-Expose-Headers': 'Content-Disposition',
      },
    }),
  }
}

test('indicators open on everything seen once, and only a source address links to a profile', async ({ page }) => {
  const api = await mockApi(page, { handlers: indicatorHandlers() })
  await page.goto('/indicators')
  await expect(page.getByRole('heading', { name: 'Indicators', level: 1 })).toBeVisible()
  // The default view asks for one session, so thin data is not an empty page.
  await expect(page.getByRole('row')).toHaveCount(INDICATORS.length + 1)
  expect(api.calls.find((c) => c.path === '/iocs/').params.get('min_sessions')).toBe('1')

  const source = page.getByRole('row').filter({ hasText: '203.0.113.7' })
  await expect(source.getByRole('link', { name: '203.0.113.7', exact: true })).toHaveAttribute('href', '/attackers/203.0.113.7')

  const referenced = page.getByRole('row').filter({ hasText: '8.8.8.8' })
  await expect(referenced.getByRole('link', { name: '8.8.8.8', exact: true })).toHaveCount(0)
  await expect(referenced).toContainText('Named in a command; it did not connect to the honeypot.')
  await expect(referenced.getByRole('link', { name: 'Sessions mentioning 8.8.8.8' })).toHaveAttribute('href', '/sessions?search=8.8.8.8')

  // A tool name cannot be searched for in sessions, so no link is offered.
  await expect(page.getByRole('row').filter({ hasText: 'nmap' }).getByRole('link')).toHaveCount(0)
})

test('a copied indicator cannot carry a second line', async ({ page, context }) => {
  await context.grantPermissions(['clipboard-read', 'clipboard-write'])
  await mockApi(page, { handlers: indicatorHandlers() })
  await page.goto('/indicators')
  const marker = String.fromCodePoint(0x2370)
  const row = page.getByRole('row').filter({ hasText: 'x.sh' })
  await row.getByRole('button', { name: /^Copy / }).click()
  const copied = await page.evaluate(() => navigator.clipboard.readText())
  expect(copied).toBe(`http://198.51.100.9/x.sh${marker}rm -rf /`)
  expect(copied).not.toContain('\n')
})

test('the blocklist is source addresses seen at least twice, and never referenced ones', async ({ page }) => {
  const api = await mockApi(page, { handlers: indicatorHandlers() })
  await page.goto('/indicators')
  await expect(page.getByTestId('blocklist-note')).toContainText('seen in at least 2 sessions')
  const download = page.waitForEvent('download')
  await page.getByRole('button', { name: 'Blocklist · source addresses' }).click()
  expect((await download).suggestedFilename()).toBe('honeysentinel-ip-2026-01-02.txt')
  const feed = api.calls.find((c) => c.path === '/iocs/feed')
  expect(feed.params.get('ioc_type')).toBe('ip')
  expect(feed.params.get('min_sessions')).toBe('2')

  await page.getByLabel('Type').selectOption('referenced_ip')
  await expect(page).toHaveURL(/type=referenced_ip/)
  await expect(page.getByRole('button', { name: /Blocklist/ })).toHaveCount(0)
  await expect(page.getByTestId('blocklist-note')).toContainText('never offered as a blocklist')

  // The view is in the address bar, so it survives a reload and can be shared.
  await page.reload()
  await expect(page.getByLabel('Type')).toHaveValue('referenced_ip')
  await expect(page.getByRole('row')).toHaveCount(2)
})

test('a failed indicator load is not shown as "no indicators"', async ({ page }) => {
  await mockApi(page, {
    handlers: { 'GET /iocs/$': (route) => route.fulfill({ status: 500, json: { detail: 'Internal Server Error' } }) },
  })
  await page.goto('/indicators')
  await expect(page.getByRole('alert').filter({ hasText: 'Could not load indicators' })).toBeVisible()
  await expect(page.getByText(/No indicators/)).toHaveCount(0)
})

const MATRIX = {
  sessions: 12,
  attack_version: '17.1',
  domain: 'enterprise-attack',
  tactics: [
    { id: 'TA0043', name: 'Reconnaissance', techniques: [] },
    { id: 'TA0002', name: 'Execution', techniques: [{ id: 'T1059.004', name: 'Unix Shell', count: 9 }, { id: 'T1059', name: 'Command and Scripting Interpreter', count: 3 }] },
    { id: 'TA0011', name: 'Command and Control', techniques: [{ id: 'T1105', name: 'Ingress Tool Transfer', count: 2 }] },
    { id: 'TA0010', name: 'Exfiltration', techniques: [] },
  ],
}

test('the ATT&CK matrix shades techniques by count and opens the sessions behind a cell', async ({ page }) => {
  const sessions = [
    makeSession({ id: 1 }),
    makeSession({ id: 2, attacker_ip: '198.51.100.20', mitre_techniques: [{ id: 'T1105', name: 'Ingress Tool Transfer' }] }),
  ]
  const api = await mockApi(page, {
    sessions,
    handlers: { 'GET /attack/matrix$': (route) => route.fulfill({ json: MATRIX }) },
  })
  await page.goto('/attack?protocol=ssh')
  await expect(page.getByRole('heading', { name: 'ATT&CK matrix', level: 1 })).toBeVisible()

  // Columns in the API's kill-chain order.
  await expect(page.getByTestId('matrix-tactic').getByRole('heading')).toHaveText(
    ['Reconnaissance', 'Execution', 'Command and Control', 'Exfiltration'],
  )
  // The filter in the address is the filter the matrix was asked for.
  expect(api.calls.find((c) => c.path === '/attack/matrix').params.get('protocol')).toBe('ssh')
  await expect(page.getByTestId('matrix-scope')).toContainText('12 sessions in scope · 3 techniques observed · ATT&CK 17.1')
  await expect(page.getByTestId('matrix-scope').getByRole('link')).toHaveAttribute('href', '/sessions?protocol=ssh')

  const strong = page.getByRole('button', { name: /T1059\.004/ })
  const weak = page.getByRole('button', { name: /T1105/ })
  await expect(strong).toHaveClass(/heat-4/)
  await expect(weak).toHaveClass(/heat-1/)
  await expect(strong).toContainText('9')

  await strong.click()
  const dialog = page.getByRole('dialog')
  await expect(dialog).toContainText('The matrix counts 9 sessions')
  await expect(dialog).toContainText('Found 1 in the newest 2 of 2 matching sessions.')
  await expect(dialog.getByRole('link', { name: /203\.0\.113\.7/ })).toHaveAttribute('href', '/sessions?protocol=ssh&session=1')
  await expect(dialog.getByRole('link', { name: /198\.51\.100\.20/ })).toHaveCount(0)
  await dialog.getByRole('link', { name: /203\.0\.113\.7/ }).click()
  await expect(page).toHaveURL(/\/sessions\?protocol=ssh&session=1$/)
})

test('the Navigator layer downloads for an analyst and is explained to a viewer', async ({ page }) => {
  const api = await mockApi(page, {
    me: ANALYST,
    handlers: {
      'GET /attack/matrix$': (route) => route.fulfill({ json: MATRIX }),
      'GET /attack/navigator-layer$': (route) => route.fulfill({
        body: '{"name":"HoneySentinel observed techniques"}',
        headers: {
          'Content-Type': 'application/json',
          'Content-Disposition': 'attachment; filename="honeysentinel_attack_layer.json"',
          'Access-Control-Expose-Headers': 'Content-Disposition',
        },
      }),
    },
  })
  await page.goto('/attack?exclude_scanners=true')
  const download = page.waitForEvent('download')
  await page.getByRole('button', { name: 'Download Navigator layer' }).click()
  expect((await download).suggestedFilename()).toBe('honeysentinel_attack_layer.json')
  expect(api.calls.find((c) => c.path === '/attack/navigator-layer').params.get('exclude_scanners')).toBe('true')

  await page.route('**/api/v1/auth/me', (route) => route.fulfill({ json: VIEWER }))
  await page.reload()
  await expect(page.getByRole('button', { name: 'Download Navigator layer' })).toHaveCount(0)
  await expect(page.getByText('Downloading the Navigator layer needs an analyst account.')).toBeVisible()
})

test('a matrix with nothing observed, or that failed to load, says which', async ({ page }) => {
  let fail = false
  await mockApi(page, {
    handlers: {
      'GET /attack/matrix$': (route) => (fail
        ? route.fulfill({ status: 500, json: { detail: 'matrix query failed' } })
        : route.fulfill({ json: { ...MATRIX, tactics: MATRIX.tactics.map((t) => ({ ...t, techniques: [] })) } })),
    },
  })
  await page.goto('/attack')
  await expect(page.getByText('No technique observed')).toBeVisible()
  fail = true
  await page.reload()
  await expect(page.getByRole('alert').filter({ hasText: 'Could not load the ATT&CK matrix' })).toContainText('matrix query failed')
  await expect(page.getByText('No technique observed')).toHaveCount(0)
})

const AUDIT = Array.from({ length: 120 }, (_, i) => ({
  id: 500 - i,
  user_id: i % 2 ? 1 : null,
  user_email: i % 2 ? 'admin@example.com' : null,
  action: i % 3 === 0 ? 'credentials_viewed' : 'session_ingested_honeypot',
  resource_type: 'session',
  resource_id: 40 + i,
  details: i % 3 === 0 ? null : { category: 'exploitation', uploads: 0 },
  ip_address: i % 2 ? '100.64.0.5' : null,
  created_at: '2026-01-02T10:00:00Z',
}))

function auditHandler(route, url) {
  const limit = Number(url.searchParams.get('limit') || 50)
  const offset = Number(url.searchParams.get('offset') || 0)
  const action = url.searchParams.get('action')
  const rows = AUDIT.filter((row) => !action || row.action === action)
  return route.fulfill({ json: { items: rows.slice(offset, offset + limit), total: rows.length } })
}

test('an administrator can read, filter and page the audit log', async ({ page }) => {
  const api = await mockApi(page, { me: ADMIN, handlers: { 'GET /audit-logs$': auditHandler } })
  await page.goto('/settings')
  const log = page.getByTestId('audit-log')
  await expect(log.getByTestId('audit-row')).toHaveCount(50)
  await expect(log).toContainText('120 entries')
  await expect(log.getByTestId('audit-row').first()).toContainText('2026-01-02 14:00:00 UTC+4')
  await expect(log.getByTestId('audit-row').nth(1)).toContainText('category: exploitation')
  await expect(log.getByText('1–50 of 120')).toBeVisible()

  await log.getByRole('button', { name: 'Older' }).click()
  await expect(log.getByText('51–100 of 120')).toBeVisible()
  expect(api.calls.some((c) => c.path === '/audit-logs' && c.params.get('offset') === '50')).toBe(true)

  // Filtering starts again from the newest row.
  await log.getByLabel('Action').fill('credentials_viewed')
  await expect(log).toContainText('40 entries')
  await expect(log.getByTestId('audit-row')).toHaveCount(40)
  const filtered = api.calls.filter((c) => c.path === '/audit-logs' && c.params.get('action') === 'credentials_viewed')
  expect(filtered.at(-1).params.get('offset')).toBe('0')

  await log.getByLabel(/^Since/).fill('2026-01-02T12:00')
  await expect.poll(() => api.calls.filter((c) => c.path === '/audit-logs').at(-1).params.get('since')).toBe('2026-01-02T08:00:00.000Z')
})

test('the audit log is not offered to an analyst, and a refusal is shown as one', async ({ page }) => {
  await mockApi(page, { me: ANALYST })
  await page.goto('/settings')
  await expect(page.getByRole('heading', { name: 'Settings', level: 1 })).toBeVisible()
  await expect(page.getByTestId('audit-log')).toHaveCount(0)

  await page.route('**/api/v1/auth/me', (route) => route.fulfill({ json: ADMIN }))
  await page.route('**/api/v1/audit-logs**', (route) => route.fulfill({ status: 500, json: { detail: 'audit store unavailable' } }))
  await page.reload()
  await expect(page.getByTestId('audit-log').getByRole('alert')).toContainText('audit store unavailable')
  await expect(page.getByTestId('audit-log').getByText(/No entries/)).toHaveCount(0)
})

const PROFILE = {
  ip: '203.0.113.7', scanner_operator: null, geo: { country: 'NL', country_name: 'Netherlands', city: 'Amsterdam' },
  first_seen: '2026-01-01T09:00:00Z', last_seen: '2026-01-02T10:00:00Z', session_count: 2, aggregated_sessions: 2,
  alert_count: 1, open_alert_count: 1, protocols: { ssh: 2 }, categories: { exploitation: 2 },
  nodes: ['honeysentinel-debian'], tools: [], intents: [], techniques: [{ id: 'T1059.004', name: 'Unix Shell', count: 2 }],
  credential_attempts: 3, top_usernames: [{ username: 'root', count: 3 }], upload_count: 0, diverted: false,
  sessions: [
    makeSession({ id: 1, fingerprints: { hassh: 'aaaa1111bbbb2222cccc3333dddd4444' }, signals: { ai_agent: { score: 1, canary: true, basis: 'canary', reasons: [] } } }),
    makeSession({ id: 2, fingerprints: { hassh: 'aaaa1111bbbb2222cccc3333dddd4444' }, signals: { honeytoken: { token_ids: ['aws-key-7'] } } }),
  ],
}

test('an address can be blocked after confirmation and unblocked by an administrator', async ({ page }) => {
  let blocked = []
  const api = await mockApi(page, {
    me: ADMIN,
    handlers: {
      'GET /sessions/attacker/': (route) => route.fulfill({ json: PROFILE }),
      'GET /honeypot/blocked-ips$': (route) => route.fulfill({ json: { blocked_ips: blocked } }),
      'POST /honeypot/block-ip$': (route, _url, request) => { blocked = [request.postDataJSON().ip]; return route.fulfill({ json: { status: 'blocked' } }) },
      'POST /honeypot/unblock-ip$': (route) => { blocked = []; return route.fulfill({ json: { status: 'unblocked' } }) },
    },
  })
  await page.goto('/attackers/203.0.113.7')
  await expect(page).toHaveTitle('Address 203.0.113.7 · HoneySentinel')
  // Fingerprints and signals across its sessions.
  const tooling = page.getByTestId('profile-tooling')
  await expect(tooling).toContainText('aaaa1111bbbb2222cccc3333dddd4444')
  await expect(tooling).toContainText('×2')
  await expect(tooling).toContainText('Likely automated AI agent in 1 session')
  await expect(tooling).toContainText('Honeytoken used in 1 session')

  await page.getByRole('button', { name: 'Block address…' }).click()
  const dialog = page.getByRole('dialog')
  await expect(dialog).toContainText('Block 203.0.113.7?')
  await expect(dialog).toContainText('records nothing more')
  // Nothing is sent until it is confirmed.
  expect(api.calls.some((c) => c.path === '/honeypot/block-ip')).toBe(false)
  await dialog.getByRole('button', { name: 'Cancel' }).click()
  await expect(page.getByRole('dialog')).toHaveCount(0)
  expect(api.calls.some((c) => c.path === '/honeypot/block-ip')).toBe(false)

  await page.getByRole('button', { name: 'Block address…' }).click()
  await page.getByRole('dialog').getByRole('button', { name: 'Block address' }).click()
  await expect(page.getByTestId('blocked-tag')).toBeVisible()
  expect(api.calls.find((c) => c.path === '/honeypot/block-ip').body).toEqual({ ip: '203.0.113.7' })

  // It is listed under Settings, and can be released from there.
  await page.goto('/settings#blocked')
  const row = page.getByTestId('blocked-row')
  await expect(row).toContainText('203.0.113.7')
  await row.getByRole('button', { name: 'Unblock…' }).click()
  await page.getByRole('dialog').getByRole('button', { name: 'Unblock address' }).click()
  await expect(page.getByText('No address is blocked')).toBeVisible()
})

test('a failed block is reported in the dialog, and a viewer is not offered the control', async ({ page }) => {
  await mockApi(page, {
    me: ANALYST,
    handlers: {
      'GET /sessions/attacker/': (route) => route.fulfill({ json: PROFILE }),
      'POST /honeypot/block-ip$': (route) => route.fulfill({ status: 503, json: { detail: 'Honeypot engine is unreachable' } }),
    },
  })
  await page.goto('/attackers/203.0.113.7')
  await page.getByRole('button', { name: 'Block address…' }).click()
  await page.getByRole('dialog').getByRole('button', { name: 'Block address' }).click()
  await expect(page.getByRole('dialog').getByRole('alert')).toContainText('Honeypot engine is unreachable')
  await expect(page.getByTestId('blocked-tag')).toHaveCount(0)

  await page.route('**/api/v1/auth/me', (route) => route.fulfill({ json: VIEWER }))
  await page.reload()
  await expect(page.getByRole('heading', { name: '203.0.113.7' })).toBeVisible()
  await expect(page.getByTestId('block-control')).toHaveCount(0)
})

test('an address that never connected gets an explanation, not an error', async ({ page }) => {
  await mockApi(page, {
    handlers: { 'GET /sessions/attacker/': (route) => route.fulfill({ status: 404, json: { detail: 'No sessions from this address' } }) },
  })
  await page.goto('/attackers/8.8.8.8')
  await expect(page.getByTestId('profile-empty')).toContainText('It has not connected to a decoy')
  await expect(page.getByRole('link', { name: 'Search sessions that mention it' })).toHaveAttribute('href', '/sessions?search=8.8.8.8')
})

function alertRows(count, offset = 0) {
  return Array.from({ length: count }, (_, i) => ({
    id: offset + i + 1, kind: 'session', session_id: 100 + i, session_ids: i === 0 ? [100, 205, 310] : [100 + i],
    attacker_ip: '203.0.113.7', severity: 'high', title: `Alert ${offset + i + 1}`, description: null, status: 'new',
    assigned_to_id: null, auto_generated: true, mitre_tactics: [], mitre_techniques: [],
    created_at: '2026-01-02T10:00:00Z', updated_at: null, notes: null, occurrences: 1,
  }))
}

test('alerts page from the address bar, link every session, and keep a selection to what is on screen', async ({ page }) => {
  let total = 26
  const api = await mockApi(page, {
    me: ANALYST,
    handlers: {
      'GET /alerts/$': (route, url) => {
        const number = Number(url.searchParams.get('page') || 1)
        const rows = number === 1 ? alertRows(Math.min(25, total)) : alertRows(Math.max(0, total - 25), 25)
        return route.fulfill({ json: { alerts: rows, total, page: number, page_size: 25 } })
      },
      'POST /alerts/bulk$': (route) => { total = 25; return route.fulfill({ json: { alerts: [], total: 1, page: 1, page_size: 1 } }) },
    },
  })
  await page.goto('/alerts?severity=high')
  await expect(page.getByLabel('Severity')).toHaveValue('high')
  await expect(page.getByRole('article')).toHaveCount(25)
  expect(api.calls.find((c) => c.path === '/alerts/').params.get('severity')).toBe('high')

  // The first alert was raised by three sessions; each is linked.
  const first = page.getByRole('article').filter({ hasText: 'Alert 1' }).first()
  await expect(first.getByTestId('alert-sessions')).toContainText('3 sessions:')
  await expect(first.getByRole('link', { name: 'Session 205' })).toHaveAttribute('href', '/sessions?session=205')

  await page.getByRole('button', { name: 'Select open on this page' }).click()
  await expect(page.getByText('25 selected')).toBeVisible()
  // Moving to another page drops the selection: it was made on page 1.
  await page.getByRole('button', { name: 'Next' }).click()
  await expect(page).toHaveURL(/page=2/)
  await expect(page.getByRole('article')).toHaveCount(1)
  await expect(page.getByText(/\d+ selected/)).toHaveCount(0)

  // Resolve the only alert on the last page: the list falls back to page 1.
  await page.getByRole('button', { name: 'Select open on this page' }).click()
  await expect(page.getByText('1 selected')).toBeVisible()
  await page.getByRole('button', { name: 'Resolve selected' }).click()
  await expect.poll(() => api.calls.find((c) => c.path === '/alerts/bulk')?.body).toEqual({ ids: [26], status: 'resolved' })
  await expect(page).not.toHaveURL(/page=2/)
  await expect(page.getByRole('article')).toHaveCount(25)
  await expect(page.getByText('No alerts match')).toHaveCount(0)
})

test('the origin map says so when its background tiles cannot be fetched', async ({ page }) => {
  await mockApi(page)
  await page.route('https://tile.openstreetmap.org/**', (route) => route.abort('connectionrefused'))
  await page.goto('/map')
  await expect(page.getByTestId('tiles-fallback')).toContainText('The background map did not load')
  // The markers and the counts do not depend on the tiles.
  await expect(page.getByRole('button', { name: /All/ })).toContainText('1')
})

test('the origin map shows no fallback when tiles load', async ({ page }) => {
  await mockApi(page)
  const pixel = Buffer.from('iVBORw0KGgoAAAANSUhEUgAAAAEAAAABCAQAAAC1HAwCAAAAC0lEQVR42mNkYAAAAAYAAjCB0C8AAAAASUVORK5CYII=', 'base64')
  await page.route('https://tile.openstreetmap.org/**', (route) => route.fulfill({ body: pixel, contentType: 'image/png' }))
  await page.goto('/map')
  await expect(page.locator('.leaflet-tile-loaded').first()).toBeVisible()
  await expect(page.getByTestId('tiles-fallback')).toHaveCount(0)
})

test('a filter set can be saved in this browser, reopened and deleted', async ({ page }) => {
  await mockApi(page, { me: ANALYST })
  await page.goto('/sessions?protocol=ssh&page=3&session=1')
  await page.getByRole('button', { name: 'Saved searches' }).click()
  const panel = page.getByRole('dialog', { name: 'Saved searches' })
  await expect(panel).toContainText('Nothing saved yet')
  await expect(panel).toContainText('Kept in this browser only')
  await panel.getByLabel('Save the current filters as').fill('SSH only')
  await panel.getByRole('button', { name: 'Save' }).click()
  // The page number and the open row are not part of the question.
  await expect(panel.getByRole('link', { name: /SSH only/ })).toHaveAttribute('href', '/sessions?protocol=ssh')

  await page.goto('/sessions')
  await page.getByRole('button', { name: 'Saved searches' }).click()
  await page.getByRole('link', { name: /SSH only/ }).click()
  await expect(page).toHaveURL(/\/sessions\?protocol=ssh$/)
  await expect(page.getByRole('button', { name: 'Remove protocol filter' })).toContainText('protocol: ssh')

  await page.getByRole('button', { name: 'Saved searches' }).click()
  await page.getByRole('button', { name: 'Delete saved search SSH only' }).click()
  await expect(page.getByRole('dialog', { name: 'Saved searches' })).toContainText('Nothing saved yet')
})
