import { test, beforeEach, afterEach } from 'node:test'
import assert from 'node:assert/strict'
import {
  api, applyExternalTokenChange, clearTokens, getAccessToken, onTokenChange, setTokens, setUnauthorizedHandler,
} from '../src/services/api.js'

const storage = new Map()
globalThis.localStorage = {
  getItem: (key) => storage.get(key) ?? null,
  setItem: (key, value) => storage.set(key, value),
  removeItem: (key) => storage.delete(key),
}
const originalFetch = globalThis.fetch
const json = (body, status = 200) => new Response(JSON.stringify(body), { status, headers: { 'Content-Type': 'application/json' } })
beforeEach(() => { storage.clear(); setTokens({ access_token: 'old', refresh_token: 'refresh' }); setUnauthorizedHandler(() => {}) })
afterEach(async () => { globalThis.fetch = originalFetch; await new Promise((resolve) => setTimeout(resolve, 5)) })

test('concurrent protected requests share one token refresh', async () => {
  let refreshes = 0
  globalThis.fetch = async (url, options) => {
    if (url.endsWith('/auth/refresh')) { refreshes++; await new Promise((resolve) => setTimeout(resolve, 10)); return json({ access_token: 'new' }) }
    return options.headers.Authorization === 'Bearer new' ? json({ total: 0 }) : json({}, 401)
  }
  await Promise.all([api.sessions.list(), api.alerts.stats(), api.dashboard.stats()])
  assert.equal(refreshes, 1)
  assert.equal(getAccessToken(), 'new')
})

test('exports recover an expired token and preserve download metadata', async () => {
  globalThis.fetch = async (url, options) => {
    if (url.endsWith('/auth/refresh')) return json({ access_token: 'new' })
    if (options.headers.Authorization !== 'Bearer new') return json({}, 401)
    assert.match(url, /protocol=ssh/)
    return new Response('data', { headers: { 'Content-Disposition': 'attachment; filename="sessions.csv"', 'X-Export-Count': '5000', 'X-Export-Truncated': 'true' } })
  }
  const result = await api.export.sessions({ format: 'csv', protocol: 'ssh' })
  assert.equal(result.filename, 'sessions.csv')
  assert.equal(result.count, 5000)
  assert.equal(result.truncated, true)
  assert.equal(await result.blob.text(), 'data')
})

test('invalid login preserves server error without attempting refresh', async () => {
  let calls = 0
  globalThis.fetch = async () => { calls++; return json({ detail: 'Incorrect email or password' }, 401) }
  await assert.rejects(api.auth.login('a@example.com', 'wrong'), /Incorrect email or password/)
  assert.equal(calls, 1)
  assert.equal(getAccessToken(), 'old')
})

test('logout during refresh cannot restore a signed-out session', async () => {
  globalThis.fetch = async (url) => {
    if (url.endsWith('/auth/refresh')) { clearTokens(); return json({ access_token: 'new' }) }
    return json({}, 401)
  }
  await assert.rejects(api.sessions.list(), /session has expired/)
  assert.equal(getAccessToken(), null)
})

test('a rejected refreshed token signs the user out', async () => {
  let unauthorized = 0
  setUnauthorizedHandler(() => unauthorized++)
  globalThis.fetch = async (url) => url.endsWith('/auth/refresh') ? json({ access_token: 'new' }) : json({}, 401)
  await assert.rejects(api.sessions.list(), /session has expired/)
  assert.equal(getAccessToken(), null)
  assert.equal(unauthorized, 1)
})

test('cancellation remains distinguishable from connection failure', async () => {
  globalThis.fetch = async () => { throw new DOMException('Cancelled', 'AbortError') }
  await assert.rejects(api.sessions.list(), { name: 'AbortError' })
})

test('download network failures produce an actionable error', async () => {
  globalThis.fetch = async () => { throw new TypeError('Failed to fetch') }
  await assert.rejects(api.export.sessions(), /Cannot reach the API/)
})

// The whole /auth/ prefix except /auth/me used to skip refresh-and-retry, so
// the first click after the access token expired failed with a raw 401.
test('signed-in account routes refresh an expired token and retry', async () => {
  let refreshes = 0
  globalThis.fetch = async (url, options) => {
    if (url.endsWith('/auth/refresh')) { refreshes++; return json({ access_token: 'new', refresh_token: 'refresh2' }) }
    if (options.headers.Authorization !== 'Bearer new') return json({ detail: 'Invalid or expired token' }, 401)
    return json(url.endsWith('/auth/users') ? [{ id: 1 }] : { message: 'ok' })
  }
  // Each expiry is its own event; the pause lets the shared refresh settle.
  const expire = async () => { await new Promise((resolve) => setTimeout(resolve, 5)); setTokens({ access_token: 'old' }) }
  assert.deepEqual(await api.auth.users.list(), [{ id: 1 }])
  await expire()
  assert.deepEqual(await api.auth.changePassword('current-password', 'a-new-long-password'), { message: 'ok' })
  await expire()
  assert.deepEqual(await api.auth.mfa.enroll(), { message: 'ok' })
  assert.equal(refreshes, 3)
})

test('a wrong current password is reported, not treated as an expired session', async () => {
  let unauthorized = 0
  let refreshes = 0
  setUnauthorizedHandler(() => unauthorized++)
  globalThis.fetch = async (url) => {
    if (url.endsWith('/auth/refresh')) { refreshes++; return json({ access_token: 'new' }) }
    return json({ detail: url.endsWith('/change-password') ? 'Current password is incorrect' : 'That code did not match' }, 401)
  }
  await assert.rejects(api.auth.changePassword('wrong', 'a-new-long-password'), /Current password is incorrect/)
  await assert.rejects(api.auth.mfa.disable('000000'), /That code did not match/)
  assert.equal(refreshes, 0)
  assert.equal(unauthorized, 0)
  assert.equal(getAccessToken(), 'old')
})

test('public auth routes never trigger a refresh', async () => {
  let calls = 0
  globalThis.fetch = async () => { calls++; return json({ detail: 'nope' }, 401) }
  await assert.rejects(api.auth.capabilities(), /nope/)
  await assert.rejects(api.auth.resetPassword({ email: 'a@example.com' }), /nope/)
  assert.equal(calls, 2)
  assert.equal(getAccessToken(), 'old')
})

test('a sign-out in another tab is announced, and other storage keys are ignored', () => {
  const seen = []
  const stop = onTokenChange((change) => seen.push(change))
  applyExternalTokenChange({ key: 'hs_display', newValue: '{}' })
  assert.deepEqual(seen, [])
  storage.clear()
  applyExternalTokenChange({ key: 'access_token', newValue: null })
  assert.deepEqual(seen, [{ signedIn: false }])
  storage.set('access_token', 'from-other-tab')
  applyExternalTokenChange({ key: null })
  assert.deepEqual(seen.at(-1), { signedIn: true })
  stop()
  applyExternalTokenChange({ key: 'access_token', newValue: null })
  assert.equal(seen.length, 2)
})

test('a request that failed before another tab rotated the token retries with the new one', async () => {
  let refreshes = 0
  globalThis.fetch = async (url, options) => {
    if (url.endsWith('/auth/refresh')) { refreshes++; return json({ access_token: 'unused' }) }
    if (options.headers.Authorization === 'Bearer rotated-elsewhere') return json({ total: 3 })
    // The other tab finishes its refresh while this request is in the air.
    storage.set('access_token', 'rotated-elsewhere')
    applyExternalTokenChange({ key: 'access_token', newValue: 'rotated-elsewhere' })
    return json({ detail: 'Invalid or expired token' }, 401)
  }
  assert.deepEqual(await api.sessions.list(), { total: 3 })
  assert.equal(refreshes, 0)
})

test('a report is polled until ready, reports its progress, and stops when aborted', async () => {
  const progress = []
  let polls = 0
  globalThis.fetch = async (url, options) => {
    if (url.includes('/export/reports?')) {
      assert.equal(options.method, 'POST')
      assert.match(url, /include_sensitive=false/)
      return json({ id: 'job-1', status: 'queued', message: 'Waiting for the local analysis model.', session_count: 2 }, 202)
    }
    if (url.endsWith('/export/reports/job-1')) {
      polls++
      return json(polls < 2
        ? { id: 'job-1', status: 'analysing', message: 'Writing findings.', session_count: 2 }
        : { id: 'job-1', status: 'complete', message: 'Ready.', session_count: 2 })
    }
    assert.match(url, /\/export\/reports\/job-1\/download\?format=pdf$/)
    return new Response('pdf', { headers: { 'Content-Disposition': 'attachment; filename="report.pdf"', 'X-Export-Count': '2' } })
  }
  const result = await api.export.sessions(
    { format: 'pdf', session_ids: [1, 2], include_sensitive: false },
    { onProgress: (state) => progress.push(state.status), pollMs: 1 },
  )
  assert.equal(result.filename, 'report.pdf')
  assert.equal(result.count, 2)
  assert.deepEqual(progress, ['queued', 'analysing', 'complete'])

  // Aborting while waiting rejects at once and leaves no timer behind.
  polls = -1000
  const controller = new AbortController()
  const waiting = api.export.sessions(
    { format: 'docx', include_sensitive: false },
    { signal: controller.signal, pollMs: 60_000 },
  )
  await new Promise((resolve) => setTimeout(resolve, 5))
  controller.abort()
  await assert.rejects(waiting, { name: 'AbortError' })
})

test('a failed report surfaces the reason the server gave', async () => {
  globalThis.fetch = async () => json({ id: 'job-2', status: 'failed', message: 'The analysis model is not reachable.' }, 202)
  await assert.rejects(api.export.sessions({ format: 'pdf' }), /analysis model is not reachable/)
})
