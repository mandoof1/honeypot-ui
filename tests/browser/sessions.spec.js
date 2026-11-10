import { test, expect } from '@playwright/test'
import {
  ADMIN, ANALYST, TRANSCRIPT, VIEWER, makeSession, mockApi, signIn,
} from './support.js'

// The session list and the detail panel: staying current, paging, the
// transcript and its replay, credentials, roles, and the new evidence fields.

test.use({ timezoneId: 'Asia/Dubai' })

test.beforeEach(async ({ page }) => {
  await signIn(page)
  await page.setViewportSize({ width: 1400, height: 900 })
})

const detail = (page) => page.getByTestId('session-detail')

test('the open session follows the server without another row being clicked', async ({ page }) => {
  // Still in progress when first seen; finished by the time it is read again.
  let reads = 0
  const active = makeSession({ status: 'active', duration_seconds: null, ended_at: null })
  await mockApi(page, {
    sessions: [active],
    handlers: {
      'GET /sessions/1$': (route) => {
        reads += 1
        // The first read still finds it running; it ends before the next.
        return route.fulfill({ json: reads < 2 ? active : makeSession({ status: 'completed', duration_seconds: 124.2 }) })
      },
    },
  })
  await page.clock.install()
  await page.goto('/sessions')
  await expect(detail(page).getByTestId('session-status')).toHaveText('active')
  await expect(detail(page).getByTestId('session-duration')).toHaveText('In progress')
  await page.clock.runFor(6000)
  await expect(detail(page).getByTestId('session-status')).toHaveText('completed')
  await expect(detail(page).getByTestId('session-duration')).toHaveText('2m 4s')
  expect(reads).toBeGreaterThanOrEqual(2)
})

test('a queued analysis shows its result when the model finishes', async ({ page }) => {
  let stage = 'idle'
  const base = makeSession({ enrichment_status: 'complete', enrichment: { intent: 'First reading.', objectives: [], model: 'wolfram', confidence: 0.82, analysed_at: '2026-01-01T10:05:00Z' } })
  await mockApi(page, {
    me: ANALYST,
    sessions: [base],
    handlers: {
      'POST /sessions/1/enrich$': (route) => { stage = 'pending'; return route.fulfill({ status: 202, json: { session_id: 1, enrichment_status: 'pending' } }) },
      'GET /sessions/1$': (route) => {
        if (stage === 'pending') return route.fulfill({ json: { ...base, enrichment_status: 'pending' } })
        if (stage === 'done') {
          return route.fulfill({ json: { ...base, enrichment: { ...base.enrichment, intent: 'Second reading.', analysed_at: '2026-01-01T10:09:00Z' } } })
        }
        return route.fulfill({ json: base })
      },
    },
  })
  await page.clock.install()
  await page.goto('/sessions')
  const block = detail(page).getByTestId('enrichment-block')
  await expect(block).toContainText('First reading.')
  // The model's own figure is a score, never a percentage.
  await expect(block).toContainText('Self-reported confidence')
  await expect(block).toContainText('0.82')
  await expect(block).not.toContainText('82%')
  await block.getByRole('button', { name: 'Analyse again' }).click()
  await expect(block.getByTestId('enrichment-status')).toHaveText('queued')
  stage = 'done'
  await page.clock.runFor(6000)
  await expect(block).toContainText('Second reading.')
  await expect(block.getByTestId('enrichment-status')).toHaveText('complete')
})

test('a poll that started before a page change cannot put old rows under the new pager', async ({ page }) => {
  const pageOne = Array.from({ length: 25 }, (_, i) => makeSession({ id: i + 1, attacker_ip: `198.51.100.${i + 1}` }))
  const pageTwo = [makeSession({ id: 99, attacker_ip: '192.0.2.99' })]
  let holdNextPageOne = false
  let release
  const gate = new Promise((resolve) => { release = resolve })
  await mockApi(page, {
    handlers: {
      'GET /sessions/$': async (route, url) => {
        const second = url.searchParams.get('page') === '2'
        if (!second && holdNextPageOne) {
          holdNextPageOne = false
          await gate
        }
        return route.fulfill({ json: { sessions: second ? pageTwo : pageOne, total: 26, page: second ? 2 : 1, page_size: 25 } })
      },
    },
  })
  await page.clock.install()
  await page.goto('/sessions')
  await expect(page.getByText('26 matching sessions', { exact: true })).toBeVisible()
  await expect(page.getByText('1–25 of 26')).toBeVisible()

  // The background refresh for page 1 goes out and is held in the air.
  holdNextPageOne = true
  await page.clock.runFor(15_500)
  await page.getByRole('button', { name: 'Next page' }).click()
  await expect(page).toHaveURL(/page=2/)
  await expect(page.getByRole('button', { name: /192\.0\.2\.99/ })).toBeVisible()
  await expect(page.getByText('26–26 of 26')).toBeVisible()

  release()
  await page.clock.runFor(500)
  await expect(page.getByRole('button', { name: /192\.0\.2\.99/ })).toBeVisible()
  await expect(page.getByRole('link', { name: 'Profile of 198.51.100.1', exact: true })).toHaveCount(0)

  await page.getByRole('button', { name: 'Previous page' }).click()
  await expect(page.getByText('1–25 of 26')).toBeVisible()
})

test('a list that fails to load says so, and keeps its rows when a refresh fails', async ({ page }) => {
  let mode = 'fail'
  await mockApi(page, {
    handlers: {
      'GET /sessions/$': (route) => (mode === 'fail'
        ? route.fulfill({ status: 500, json: { detail: 'Internal Server Error' } })
        : route.fulfill({ json: { sessions: [makeSession()], total: 1 } })),
    },
  })
  await page.goto('/sessions')
  await expect(page.getByRole('alert').filter({ hasText: 'Could not load sessions' })).toContainText('Internal Server Error')
  await expect(page.getByText('No sessions match')).toHaveCount(0)
  await expect(page.getByText('Not loaded', { exact: true })).toBeVisible()

  mode = 'ok'
  await page.getByRole('button', { name: 'Try again' }).click()
  await expect(page.getByText('1 matching session', { exact: true })).toBeVisible()

  mode = 'fail'
  await page.getByRole('button', { name: 'Refresh', exact: true }).click()
  await expect(page.getByTestId('stale-notice')).toContainText('The session list may be out of date')
  await expect(page.getByRole('button', { name: /203\.0\.113\.7/ })).toBeVisible()
})

test('the row link is not nested in the row button, and timestamps name their zone', async ({ page }) => {
  await mockApi(page)
  await page.goto('/sessions')
  const row = page.getByRole('listitem').filter({ has: page.getByRole('button', { name: /203\.0\.113\.7/ }) })
  await expect(row.locator('button a')).toHaveCount(0)
  await expect(row.getByRole('link', { name: 'Profile of 203.0.113.7' })).toBeVisible()
  await expect(row).toContainText('Jan 1, 14:00 UTC+4')
  await expect(detail(page)).toContainText('2026-01-01 14:00:00 UTC+4')
  await expect(page.getByPlaceholder('Address, session UUID or command text')).toBeVisible()

  // A date filter is shown in the same zone as everything else.
  await page.goto('/sessions?date_from=2026-01-01T10%3A00%3A00.000Z')
  await expect(page.getByRole('button', { name: 'Remove date from filter' })).toContainText('2026-01-01 14:00 UTC+4')
  await expect(page.getByLabel('From (UTC+4)')).toHaveValue('2026-01-01T14:00')
})

test('each verdict number is named for its source and tactics are named in kill-chain order', async ({ page }) => {
  await mockApi(page, {
    sessions: [makeSession({
      signals: {
        anomaly: { calibrated: false },
        verdict: { flow: { role: 'advisory', category: 'reconnaissance', confidence: 0.71, disagrees: false } },
        disagreement: { rules: 'exploitation', llm: { category: 'exfiltration' } },
      },
      is_anomalous: true,
      enrichment_status: 'complete',
      enrichment: {
        intent: 'Fetch and run a dropper.', objectives: [], model: 'wolfram',
        unverified_techniques: [{ id: 'T9999', name: 'Made Up', reason: 'not in the ATT&CK catalog' }],
      },
      mitre_techniques: [
        { id: 'T1059.004', name: 'Unix Shell', source: 'rules' },
        { id: 'T1105', name: 'Ingress Tool Transfer', source: 'chimera', verified: false },
      ],
    })],
  })
  await page.goto('/sessions')
  const block = detail(page).getByTestId('classification-block')
  await expect(block).toContainText('Category chosen by')
  await expect(block).toContainText('Signature rules')
  await expect(block).toContainText('Rule score')
  await expect(block).toContainText('0.90')
  await expect(block).not.toContainText('%')
  await expect(block.getByTestId('anomaly-not-calibrated')).toHaveText('Not calibrated')
  await expect(block.getByTestId('flow-advisory')).toContainText('advisory only: reconnaissance (score 0.71)')
  await expect(block).toContainText('The language model read this session as exfiltration')
  // No anomaly marker while the detector is uncalibrated.
  await expect(detail(page).getByText('Anomalous', { exact: true })).toHaveCount(0)
  await expect(detail(page).getByText('Anomaly: not calibrated')).toBeVisible()

  const attack = detail(page).getByTestId('attack-block')
  const tactics = attack.getByRole('list', { name: 'Tactics, in kill-chain order' }).getByRole('listitem')
  await expect(tactics).toHaveText([/Execution/, /Command and Control/])
  await expect(attack.getByRole('link', { name: /T1059\.004/ })).toHaveAttribute('href', 'https://attack.mitre.org/techniques/T1059/004/')
  // Unverified: shown, labelled, never a link.
  await expect(attack.getByRole('link', { name: /T1105/ })).toHaveCount(0)
  await expect(attack.getByText('unverified')).toBeVisible()
  const claims = detail(page).getByTestId('unverified-techniques')
  await expect(claims).toContainText('T9999')
  await expect(claims.getByRole('link')).toHaveCount(0)
  await expect(detail(page).getByTestId('enrichment-block')).toContainText('Written by the language model wolfram')
})

test('fingerprints can be copied and signals are badged by their strength', async ({ page, context }) => {
  await context.grantPermissions(['clipboard-read', 'clipboard-write'])
  const canary = makeSession({
    id: 1,
    fingerprints: { ssh_client_version: 'SSH-2.0-Go', hassh: 'a1b2c3d4e5f60718293a4b5c6d7e8f90', hassh_algorithms: 'curve25519-sha256;aes128-ctr' },
    signals: {
      ai_agent: { score: 1, canary: true, basis: 'canary', reasons: ['canary triggered: motd-note via shell'] },
      honeytoken: { token_ids: ['aws-key-7'], kinds: ['api_key'] },
    },
    network_events: [
      { event_type: 'ai_canary_triggered', canary: 'motd-note', channel: 'shell' },
      { event_type: 'direct_tcpip', dest_host: '10.0.0.5', dest_port: 3306, orig_host: '127.0.0.1', orig_port: 40000 },
    ],
  })
  const timing = makeSession({
    id: 2, attacker_ip: '198.51.100.20',
    signals: { ai_agent: { score: 0.45, canary: false, basis: 'timing', reasons: ['timing (suggestive only): median gap of 4.0 s between commands'] } },
  })
  await mockApi(page, { sessions: [canary, timing] })
  await page.goto('/sessions?session=1')
  await expect(detail(page).getByTestId('ai-agent-badge')).toHaveText('Likely automated AI agent')
  await expect(detail(page).getByTestId('honeytoken-badge')).toHaveText('Honeytoken used')
  const signals = detail(page).getByTestId('signals-block')
  await expect(signals).toContainText('canary triggered: motd-note via shell')
  await expect(signals).toContainText('aws-key-7')
  await expect(signals).toContainText('to 10.0.0.5:3306, from 127.0.0.1:40000')

  const prints = detail(page).getByTestId('fingerprints-block')
  await expect(prints).toContainText('SSH-2.0-Go')
  await prints.getByRole('button', { name: 'Copy HASSH' }).click()
  expect(await page.evaluate(() => navigator.clipboard.readText())).toBe('a1b2c3d4e5f60718293a4b5c6d7e8f90')

  // Timing alone is a note, never the badge.
  await page.getByRole('button', { name: /198\.51\.100\.20/ }).click()
  await expect(detail(page).getByTestId('ai-agent-badge')).toHaveCount(0)
  await expect(detail(page).getByTestId('ai-agent-note')).toContainText('Possibly automated')
  await expect(detail(page).getByTestId('ai-agent-note')).toContainText('not a detection')
})

test('a refused connection is listed as one, not as a session', async ({ page }) => {
  await mockApi(page, {
    sessions: [makeSession({
      attacker_port: 0, command_count: 0, has_transcript: false, has_credentials: false,
      signals: { refusal: true },
      network_events: [{ event_type: 'connection_refused', count: 40, first_seen: 1767261600 }],
    })],
  })
  await page.goto('/sessions')
  await expect(page.getByRole('button', { name: /203\.0\.113\.7/ })).toContainText('refused connection')
  await expect(page.getByRole('button', { name: /203\.0\.113\.7/ })).toContainText('40 connections refused')
  const panel = page.getByTestId('refused-connection')
  await expect(panel).toContainText('This is not a session')
  await expect(panel).toContainText('refused 40 connections')
  await expect(page.getByTestId('classification-block')).toHaveCount(0)
})

test('the transcript shows exit codes, isolates direction, and windows long output', async ({ page }) => {
  const long = Array.from({ length: 400 }, (_, i) => `row ${i}`).join('\n')
  const entries = [
    { command: `cat ${String.fromCodePoint(0x202e)}txt.exe`, output: 'cat: Permission denied\n', exit_code: 1, timestamp: 1767261600 },
    ...Array.from({ length: 9 }, (_, i) => ({ command: `dump ${i}`, output: long, exit_code: 0, timestamp: 1767261601 + i })),
  ]
  await mockApi(page, {
    handlers: { 'GET /sessions/1/transcript$': (route) => route.fulfill({ json: { ...TRANSCRIPT, entries } }) },
  })
  await page.goto('/sessions')
  await detail(page).getByRole('button', { name: /Transcript/ }).click()
  const first = detail(page).getByTestId('transcript-entry').first()
  await expect(first).toContainText(`cat ${String.fromCodePoint(0x2370)}txt.exe`)
  await expect(first.getByText('exit 1')).toBeVisible()
  expect(await first.locator('.bidi-isolate').first().evaluate((node) => getComputedStyle(node).unicodeBidi)).toBe('isolate')

  // 3,600 lines of output arrive; far fewer are drawn until asked for.
  const shown = await detail(page).getByTestId('transcript-entry').count()
  expect(shown).toBeLessThan(entries.length)
  const drawn = await detail(page).getByTestId('transcript-block').locator('.bidi-isolate').count()
  expect(drawn).toBeLessThan(1000)
  await expect(detail(page).getByRole('button', { name: /Show more commands/ })).toBeVisible()
  await detail(page).getByRole('button', { name: /Show more of this output/ }).first().click()
  await expect(detail(page).getByText('row 300', { exact: true }).first()).toBeVisible()
})

test('a shell session can be replayed on its own clock', async ({ page }) => {
  await mockApi(page)
  await page.clock.install()
  await page.goto('/sessions')
  await detail(page).getByRole('button', { name: /Transcript/ }).click()
  await detail(page).getByRole('group', { name: 'Transcript view' }).getByRole('button', { name: 'Replay' }).click()
  const replay = detail(page).getByTestId('session-replay')
  await expect(replay.getByTestId('replay-progress')).toContainText('1 of 3 commands')
  await expect(replay.getByTestId('replay-clock')).toHaveText('0:00 / 0:05')
  await expect(replay).toContainText('4 min of idle time is skipped')
  await expect(replay).toContainText('uname -a')
  await expect(replay).not.toContainText('cat /etc/shadow')

  await replay.getByRole('button', { name: 'Play replay' }).click()
  await page.clock.runFor(2300)
  await expect(replay.getByTestId('replay-progress')).toContainText('2 of 3 commands')
  await expect(replay).toContainText('cat /etc/shadow')
  await expect(replay.getByText('exit 1')).toBeVisible()

  await replay.getByRole('button', { name: 'Pause replay' }).click()
  await page.clock.runFor(5000)
  await expect(replay.getByTestId('replay-progress')).toContainText('2 of 3 commands')

  // Twice the speed: the remaining three seconds take a second and a half.
  await replay.getByLabel('Replay speed').selectOption('2')
  await replay.getByRole('button', { name: 'Play replay' }).click()
  await page.clock.runFor(1800)
  await expect(replay.getByTestId('replay-progress')).toContainText('3 of 3 commands')
  await expect(replay.getByTestId('replay-gap')).toContainText('idle, skipped')
  await expect(replay.getByRole('button', { name: 'Replay from the start' })).toBeVisible()

  // Scrub back, then turn compression off: the real five-minute gap returns.
  await replay.getByLabel('Replay position').fill('0')
  await expect(replay.getByTestId('replay-progress')).toContainText('1 of 3 commands')
  await replay.getByLabel(/Skip idle time/).uncheck()
  await expect(replay.getByTestId('replay-clock')).toHaveText('0:00 / 5:02')
  await replay.getByRole('button', { name: 'Next command' }).click()
  await expect(replay.getByTestId('replay-clock')).toHaveText('0:02 / 5:02')
})

test('a web session has no replay, and its transcript shows request headers', async ({ page }) => {
  await mockApi(page, {
    sessions: [makeSession({ protocol: 'http' })],
    handlers: {
      'GET /sessions/1/transcript$': (route) => route.fulfill({
        json: { ...TRANSCRIPT, entries: [{ command: 'GET /wp-login.php', output: '', exit_code: 0, headers: { 'User-Agent': 'curl/8.0', Accept: '*/*' } }] },
      }),
    },
  })
  await page.goto('/sessions')
  await detail(page).getByRole('button', { name: /Transcript/ }).click()
  await expect(detail(page).getByRole('group', { name: 'Transcript view' })).toHaveCount(0)
  await detail(page).getByText('2 request headers').click()
  await expect(detail(page).getByText('curl/8.0')).toBeVisible()
})

test('credentials are revealed on request and masked in presentation mode', async ({ page }) => {
  const api = await mockApi(page, {
    handlers: {
      'GET /sessions/1/credentials$': (route) => route.fulfill({
        json: { session_id: 1, available: true, credentials: [{ username: 'root', password: 'hunter2-secret', success: true }] },
      }),
    },
  })
  await page.goto('/sessions')
  const block = detail(page).getByTestId('credentials-block')
  await expect(block).not.toContainText('hunter2-secret')
  expect(api.calls.some((c) => c.path.endsWith('/credentials'))).toBe(false)
  await block.getByRole('button', { name: 'Reveal' }).click()
  await expect(block).toContainText('hunter2-secret')
  await expect(block).toContainText('accepted')

  await page.getByLabel('Presentation mode').check()
  await expect(block).not.toContainText('hunter2-secret')
  await expect(block).toContainText('root')
  await expect(block).toContainText('Passwords are masked while presentation mode is on.')
  await page.getByLabel('Presentation mode').uncheck()
  await expect(block).toContainText('hunter2-secret')
})

test('a viewer reads sessions but is told why transcripts, credentials and exports are not theirs', async ({ page }) => {
  const api = await mockApi(page, { me: VIEWER })
  await page.goto('/sessions')
  await expect(page.getByText('1 matching session', { exact: true })).toBeVisible()
  await expect(detail(page).getByTestId('classification-block')).toBeVisible()
  await expect(page.getByRole('button', { name: 'CSV', exact: true })).toHaveCount(0)
  await expect(detail(page).getByTestId('session-report-controls')).toHaveCount(0)
  await expect(detail(page).getByTestId('credentials-block')).toHaveCount(0)
  await detail(page).getByRole('button', { name: /Transcript/ }).click()
  await expect(detail(page).getByTestId('transcript-forbidden')).toContainText('needs an analyst or administrator account')
  expect(api.calls.some((c) => c.path.endsWith('/transcript'))).toBe(false)
})

test('a report is a job with progress, and original credentials are an explicit choice', async ({ page }) => {
  let polls = 0
  const api = await mockApi(page, {
    me: ADMIN,
    handlers: {
      'POST /export/reports$': (route) => route.fulfill({ status: 202, json: { id: 'job-1', status: 'queued', message: 'Waiting for the local analysis model.', session_count: 1 } }),
      'GET /export/reports/job-1$': (route) => {
        polls += 1
        return route.fulfill({ json: polls < 2
          ? { id: 'job-1', status: 'analysing', message: 'Our local model is writing findings from the selected evidence.', session_count: 1 }
          : { id: 'job-1', status: 'failed', message: 'The analysis model is not reachable.', session_count: 1 } })
      },
    },
  })
  await page.clock.install()
  await page.goto('/sessions')
  const controls = detail(page).getByTestId('session-report-controls')
  const sensitive = controls.getByLabel(/Include original credentials/)
  await expect(sensitive).not.toBeChecked()
  await controls.getByRole('button', { name: 'Export PDF report' }).click()

  const job = page.getByTestId('report-job')
  await expect(job).toHaveAttribute('data-status', 'working')
  await expect(job).toContainText('Waiting for the local analysis model.')
  const request = api.calls.find((c) => c.method === 'POST' && c.path === '/export/reports')
  expect(request.params.get('include_sensitive')).toBe('false')
  expect(request.params.get('session_ids')).toBe('1')
  // The rest of the page is not held up by it.
  await expect(page.getByRole('button', { name: 'CSV', exact: true })).toBeEnabled()

  await page.clock.runFor(4100)
  await expect(job).toContainText('writing findings')
  await page.clock.runFor(4100)
  await expect(job).toHaveAttribute('data-status', 'failed')
  await expect(job.getByRole('alert')).toContainText('The analysis model is not reachable.')

  // Ticked: the request says so, and the tray says so.
  await sensitive.check()
  await controls.getByRole('button', { name: 'Export Word report' }).click()
  await expect.poll(() => api.calls.filter((c) => c.method === 'POST' && c.path === '/export/reports').length).toBe(2)
  expect(api.calls.filter((c) => c.method === 'POST' && c.path === '/export/reports')[1].params.get('include_sensitive')).toBe('true')
  await expect(page.getByTestId('report-job').last()).toContainText('includes original credentials')

  // Leaving the page stops the status poll.
  const before = api.calls.filter((c) => c.path.startsWith('/export/reports/')).length
  await page.getByRole('link', { name: 'Overview' }).click()
  await page.clock.runFor(20_000)
  expect(api.calls.filter((c) => c.path.startsWith('/export/reports/')).length).toBe(before)
})

test('an analyst has no credential option and their reports never ask for originals', async ({ page }) => {
  const api = await mockApi(page, {
    me: ANALYST,
    handlers: {
      'POST /export/reports$': (route) => route.fulfill({ status: 202, json: { id: 'job-2', status: 'queued', message: 'Waiting.', session_count: 1 } }),
      'GET /export/reports/job-2$': (route) => route.fulfill({ json: { id: 'job-2', status: 'analysing', message: 'Writing.', session_count: 1 } }),
    },
  })
  await page.goto('/sessions')
  await expect(page.getByLabel(/Include original credentials/)).toHaveCount(0)
  await page.getByRole('button', { name: 'PDF report', exact: true }).click()
  await expect(page.getByTestId('report-job')).toContainText('PDF report on 1 matching session')
  // The job is listed as soon as it is asked for; wait for the request itself.
  await expect.poll(() => api.calls.find((c) => c.method === 'POST' && c.path === '/export/reports')
    ?.params.get('include_sensitive')).toBe('false')
  await page.getByRole('button', { name: 'Stop waiting' }).click()
  await expect(page.getByTestId('report-job')).toHaveAttribute('data-status', 'cancelled')
})
