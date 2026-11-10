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

test('downloading a sample asks first and says what the file is', async ({ page }) => {
  let downloads = 0
  await page.route('**/api/v1/payloads/*/download', (route) => {
    downloads += 1
    return route.fulfill({
      body: 'MZ-not-really',
      headers: {
        'Content-Type': 'application/octet-stream',
        'Content-Disposition': `attachment; filename="${'a'.repeat(64)}.bin"`,
        'Access-Control-Expose-Headers': 'Content-Disposition',
      },
    })
  })
  await page.goto('/payloads?sha=' + 'a'.repeat(64))
  await page.getByRole('button', { name: /Download sample/ }).click()
  const dialog = page.getByRole('dialog', { name: 'Download a live malware sample?' })
  await expect(dialog).toContainText('exactly as the attacker uploaded it')
  await expect(dialog).toContainText('64-bit x86-64 ELF')
  await expect(dialog).toContainText('a'.repeat(64))
  await expect(dialog).toContainText('recorded in the audit log')
  // One click is not enough: it has to be acknowledged.
  const confirm = dialog.getByRole('button', { name: 'Download sample' })
  await expect(confirm).toBeDisabled()
  expect(downloads).toBe(0)

  await dialog.getByRole('button', { name: 'Cancel' }).click()
  await expect(page.getByRole('dialog', { name: 'Download a live malware sample?' })).toHaveCount(0)
  expect(downloads).toBe(0)

  await page.getByRole('button', { name: /Download sample/ }).click()
  await page.getByLabel(/I understand this file is live malware/).check()
  const download = page.waitForEvent('download')
  await page.getByRole('dialog', { name: 'Download a live malware sample?' }).getByRole('button', { name: 'Download sample' }).click()
  expect((await download).suggestedFilename()).toBe(`${'a'.repeat(64)}.bin`)
  expect(downloads).toBe(1)
})

test('a failed payload list is not shown as "no payloads", and the linked sample can be retried', async ({ page }) => {
  let detailFails = true
  let detailReads = 0
  await page.route('**/api/v1/payloads/?**', (route) => route.fulfill({ status: 500, json: { detail: 'Internal Server Error' } }))
  await page.route('**/api/v1/payloads/' + 'a'.repeat(64), (route) => {
    detailReads += 1
    return detailFails
      ? route.fulfill({ status: 502, json: { detail: 'Bad gateway' } })
      : route.fulfill({ json: DETAIL })
  })
  await page.goto('/payloads?sha=' + 'a'.repeat(64))
  await expect(page.getByRole('alert').filter({ hasText: 'Could not load payloads' })).toBeVisible()
  await expect(page.getByText(/No payloads/)).toHaveCount(0)

  const banner = page.getByRole('alert').filter({ hasText: 'Could not open the linked sample' })
  await expect(banner).toContainText('Bad gateway')
  const before = detailReads
  detailFails = false
  // "Try again" used to set the address to what it already was.
  await banner.getByRole('button', { name: 'Try again' }).click()
  await expect.poll(() => detailReads).toBeGreaterThan(before)
  await expect(page.getByRole('heading', { name: 'ELF binary' })).toBeVisible()
})

test('on a narrow screen the sample opens in a dialog that Escape closes', async ({ page }) => {
  await page.setViewportSize({ width: 412, height: 915 })
  await page.goto('/payloads')
  await page.getByRole('button', { name: /likely Mirai/ }).click()
  const sheet = page.getByRole('dialog', { name: 'Sample analysis' })
  await expect(sheet.getByRole('heading', { name: 'ELF binary' })).toBeVisible()
  await page.keyboard.press('Escape')
  await expect(page.getByRole('dialog')).toHaveCount(0)
  await expect(page).not.toHaveURL(/sha=/)
})
