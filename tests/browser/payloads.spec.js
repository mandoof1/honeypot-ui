import { test, expect } from '@playwright/test'

const SAMPLE = {
  sha256: 'a'.repeat(64), sha1: 'b'.repeat(40), md5: 'c'.repeat(32),
  size: 1234, file_kind: 'elf', file_type: '64-bit x86-64 ELF',
  family: 'Mirai', analysis_status: 'complete',
  summary: '64-bit x86-64 ELF executable, statically linked, stripped — likely Mirai',
  notable: ['Fetches multiple CPU architectures (IoT botnet loader)'],
  indicator_count: 3, sessions_seen: 2,
  first_seen: '2026-02-01T00:00:00Z', last_seen: '2026-02-02T00:00:00Z',
  analysed_at: '2026-02-02T00:00:00Z',
}

const DETAIL = {
  ...SAMPLE, content_available: true, analysis_error: null,
  analysis: {
    entropy: 6.1, indicator_count: 3,
    file_type: { kind: 'elf', basis: 'magic' },
    notable: ['Fetches multiple CPU architectures (IoT botnet loader)'],
    family: { family: 'Mirai', kind: 'botnet', confidence: 0.7, evidence: ['/bin/busybox', 'mirai'] },
    elf: {
      architecture: 'x86-64', bits: 64, linking: 'static', stripped: true,
      capabilities: ['network', 'process'], libraries: [], build: {},
      sections: [{ name: '.text', size: 900, entropy: 6.2 }],
    },
    indicators: {
      ips: [{ value: '203.0.113.44', port: 4444, scope: 'public', origin: 'strings' }],
      domains: [], urls: [], mining_pools: [], wallets: [], c2_channels: [],
      ssh_keys: [], emails: [], user_agents: [], irc: [],
    },
  },
  sessions: [
    { session_id: 7, session_uuid: 'u7', attacker_ip: '198.51.100.9',
      filename: 'x86', remote_path: '/tmp/.x86', source: 'ssh_shell', methods: ['echo'],
      captured_at: '2026-02-02T00:00:00Z' },
  ],
}

test.beforeEach(async ({ page }) => {
  await page.addInitScript(() => localStorage.setItem('access_token', 'test-token'))
  await page.route('**/api/v1/**', async (route) => {
    const url = new URL(route.request().url())
    const p = url.pathname
    let body = {}
    if (p.endsWith('/auth/me')) body = { email: 'admin@example.com', role: 'admin' }
    else if (p.endsWith('/payloads/stats')) body = { total: 1, pending_analysis: 0, by_kind: { elf: 1 }, top_families: [{ family: 'Mirai', count: 1 }] }
    else if (p.endsWith('/payloads/')) body = { payloads: [SAMPLE], total: 1, page: 1, page_size: 30 }
    else if (p.includes('/payloads/' + 'a'.repeat(64))) body = DETAIL
    else if (p.endsWith('/alerts/stats')) body = { new: 0 }
    else if (p.endsWith('/honeypot/status')) body = { reachable: true, running: true }
    await route.fulfill({ json: body })
  })
})

test('lists samples and opens the full analysis', async ({ page }) => {
  await page.goto('/payloads')
  await expect(page.getByRole('heading', { name: 'Payloads', exact: true })).toBeVisible()
  await expect(page.getByText('Unique samples')).toBeVisible()
  await expect(page.getByText(/likely Mirai/)).toBeVisible()

  await page.getByRole('button', { name: /likely Mirai/ }).click()
  await expect(page).toHaveURL(/sha=aaaa/)
  // The report renders: the ELF section, the notable line, the recovered C2,
  // and the session it arrived in — content the list row does not carry.
  await expect(page.getByRole('heading', { name: 'ELF binary' })).toBeVisible()
  await expect(page.getByText(/Fetches multiple CPU architectures/)).toBeVisible()
  await expect(page.getByText('203.0.113.44:4444')).toBeVisible()
  await expect(page.getByText('198.51.100.9')).toBeVisible()
})

test('the family hint is shown as a hedge, not a verdict', async ({ page }) => {
  await page.goto('/payloads?sha=' + 'a'.repeat(64))
  await expect(page.getByText(/heuristic match on 2 marker/)).toBeVisible()
})

test('an analyst cannot download the raw sample', async ({ page }) => {
  await page.route('**/api/v1/auth/me', (route) => route.fulfill({ json: { email: 'a@example.com', role: 'analyst' } }))
  await page.goto('/payloads?sha=' + 'a'.repeat(64))
  await expect(page.getByRole('heading', { name: 'ELF binary' })).toBeVisible()
  await expect(page.getByRole('button', { name: /Download sample/ })).toHaveCount(0)
})

test('an admin is offered the download, marked as malware', async ({ page }) => {
  await page.goto('/payloads?sha=' + 'a'.repeat(64))
  const button = page.getByRole('button', { name: /Download sample/ })
  await expect(button).toBeVisible()
  await expect(button).toHaveAttribute('title', /live malware/)
})
