const API_BASE = import.meta.env?.VITE_API_URL || 'http://localhost:8000/api/v1'

/*
 * Where the tokens live, and why.
 *
 * The right place for a refresh token is an HttpOnly cookie, out of reach of
 * any script on the page. This API cannot do that: /auth/login returns both
 * tokens in the response body, and /auth/refresh and /auth/logout read the
 * refresh token from the request body. So both are kept in localStorage,
 * which is also what lets a second tab stay signed in.
 *
 * What is done instead, to shorten the time a stored token is of use:
 *
 *  - Signing out in one tab signs every tab out. Other tabs learn of it from
 *    the `storage` event and drop their user at once, instead of carrying on
 *    with a token they still hold in memory.
 *  - A rotated pair written by another tab is adopted, never replayed. The
 *    server treats a second use of a refresh token as theft and revokes the
 *    whole family, so two tabs refreshing on their own would sign each
 *    other out. The refresh is serialised across tabs with a Web Lock.
 *  - Both tokens are removed the moment the server rejects the refresh, and
 *    sign-out revokes the refresh token on the server before discarding it.
 *  - The refresh token is read from storage only at the instant it is sent.
 *
 * If the API gains cookie-based refresh, this block is the only place that
 * has to change.
 */
const ACCESS_TOKEN_KEY = 'access_token'
const REFRESH_TOKEN_KEY = 'refresh_token'
const REFRESH_LOCK = 'honeysentinel-token-refresh'

// Bumped whenever the stored pair changes, in this tab or another. A request
// that started under an older version knows its 401 may already be stale.
let tokenVersion = 0

export function getAccessToken() {
  return localStorage.getItem(ACCESS_TOKEN_KEY)
}

export function setTokens({ access_token, refresh_token }) {
  tokenVersion++
  if (access_token) localStorage.setItem(ACCESS_TOKEN_KEY, access_token)
  if (refresh_token) localStorage.setItem(REFRESH_TOKEN_KEY, refresh_token)
}

export function clearTokens() {
  tokenVersion++
  localStorage.removeItem(ACCESS_TOKEN_KEY)
  localStorage.removeItem(REFRESH_TOKEN_KEY)
}

const tokenListeners = new Set()

/**
 * Be told when another tab signs in, signs out or rotates the tokens.
 * The listener receives `{ signedIn }`. Returns an unsubscribe function.
 */
export function onTokenChange(listener) {
  tokenListeners.add(listener)
  return () => tokenListeners.delete(listener)
}

/**
 * Handle a `storage` event. Exported so the behaviour can be tested without a
 * second browser tab; the page wires it to `window` below.
 */
export function applyExternalTokenChange(event) {
  // `key` is null when the other tab cleared storage wholesale.
  if (event?.key !== null && event?.key !== undefined && event.key !== ACCESS_TOKEN_KEY) return
  tokenVersion++
  const signedIn = Boolean(getAccessToken())
  tokenListeners.forEach((listener) => listener({ signedIn }))
}

if (typeof window !== 'undefined' && typeof window.addEventListener === 'function') {
  window.addEventListener('storage', applyExternalTokenChange)
}

/** Raised for any non-2xx response, carrying the HTTP status. */
export class ApiError extends Error {
  constructor(message, status) {
    super(message)
    this.name = 'ApiError'
    this.status = status
  }
}

let onUnauthorized = () => {}
export function setUnauthorizedHandler(handler) {
  onUnauthorized = handler
}

/*
 * Routes under /auth/ that are called without a session. A 401 from one of
 * these is its own answer (wrong password, bad code) and must never trigger
 * a token refresh. Everything else under /auth/ — the signed-in user, their
 * password, their authenticator, account administration — is an ordinary
 * authenticated route. The old rule skipped refresh for the whole prefix
 * except /auth/me, so those failed with a raw 401 on the first click after
 * the access token expired.
 */
const PUBLIC_AUTH_ROUTES = new Set([
  '/auth/login',
  '/auth/register',
  '/auth/verify-otp',
  '/auth/resend-otp',
  '/auth/request-password-reset',
  '/auth/reset-password',
  '/auth/refresh',
  '/auth/logout',
  '/auth/capabilities',
])

/*
 * Authenticated routes that also answer 401 for a reason of their own: a
 * wrong current password, an authenticator code that did not match. That is
 * not an expired session, and signing the user out for mistyping a code
 * would be wrong.
 */
const ROUTES_WITH_OWN_401 = new Set([
  '/auth/change-password',
  '/auth/mfa/confirm',
  '/auth/mfa/disable',
])

/** The detail the API sends when it is the token that was refused. */
const TOKEN_REFUSED = 'Invalid or expired token'

/** True when the stored access token's own expiry has passed. Unknown formats count as not expired. */
function accessTokenExpired() {
  try {
    const payload = getAccessToken().split('.')[1]
    const claims = JSON.parse(atob(payload.replace(/-/g, '+').replace(/_/g, '/')))
    return typeof claims.exp === 'number' && claims.exp * 1000 <= Date.now()
  } catch {
    return false
  }
}

/** Run `task` while holding the cross-tab refresh lock, where the browser has one. */
function withRefreshLock(task) {
  const locks = globalThis.navigator?.locks
  if (!locks || typeof locks.request !== 'function') return task()
  return locks.request(REFRESH_LOCK, task)
}

// A single in-flight refresh shared by every concurrent 401, so a page with
// four parallel requests does not fire four refreshes and invalidate itself.
let refreshInFlight = null

async function refreshAccessToken() {
  if (!localStorage.getItem(REFRESH_TOKEN_KEY)) return false

  if (!refreshInFlight) {
    const staleAccess = getAccessToken()
    refreshInFlight = withRefreshLock(async () => {
      try {
        // Another tab may have rotated the pair while this one waited for
        // the lock. Its tokens are current; the one read earlier is spent.
        const current = getAccessToken()
        if (!current) return false
        if (current !== staleAccess) return true

        const refreshToken = localStorage.getItem(REFRESH_TOKEN_KEY)
        if (!refreshToken) return false
        const version = tokenVersion
        const res = await fetch(`${API_BASE}/auth/refresh`, {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({ refresh_token: refreshToken }),
        })
        if (!res.ok) return false
        const tokens = await res.json()
        // A sign-out that happened while the refresh was in the air wins.
        if (version !== tokenVersion || !tokens.access_token) return false
        setTokens(tokens)
        return true
      } catch {
        return false
      } finally {
        // Cleared on the next tick so concurrent callers all observe the
        // same settled promise.
        setTimeout(() => { refreshInFlight = null }, 0)
      }
    })
  }
  return refreshInFlight
}

function buildHeaders(extra) {
  const headers = {
    'Content-Type': 'application/json',
    'ngrok-skip-browser-warning': '69420',
    ...extra,
  }
  const token = getAccessToken()
  if (token) headers.Authorization = `Bearer ${token}`
  return headers
}

async function readError(res) {
  try {
    const body = await res.json()
    if (typeof body.detail === 'string') return body.detail
    // FastAPI validation errors arrive as a list of objects; rendering that
    // object directly produced "[object Object]" in the UI.
    if (Array.isArray(body.detail)) {
      return body.detail.map((d) => d.msg || JSON.stringify(d)).join('; ')
    }
    return res.statusText || 'Request failed'
  } catch {
    return res.statusText || 'Request failed'
  }
}

async function requestResponse(path, options = {}, { retry = true } = {}) {
  const version = tokenVersion
  const route = path.split('?')[0]
  const authenticated = !PUBLIC_AUTH_ROUTES.has(route)
  let res
  try {
    res = await fetch(`${API_BASE}${path}`, {
      ...options,
      headers: buildHeaders(options.headers),
    })
  } catch (error) {
    if (error.name === 'AbortError') throw error
    throw new ApiError('Cannot reach the API. Check your connection.', 0)
  }

  if (res.status === 401 && authenticated) {
    if (ROUTES_WITH_OWN_401.has(route)) {
      const detail = await readError(res)
      const tokenProblem = detail === TOKEN_REFUSED || accessTokenExpired()
      // After a retry the token is known to be fresh, so whatever this says
      // is the route's own verdict unless it names the token again.
      const ownVerdict = retry ? !tokenProblem : detail !== TOKEN_REFUSED
      if (ownVerdict) throw new ApiError(detail, 401)
    }
    // Another request may already have rotated the token while this one ran.
    if (retry && getAccessToken() && (version !== tokenVersion || await refreshAccessToken())) {
      return requestResponse(path, options, { retry: false })
    }
    if (version === tokenVersion) {
      clearTokens()
      onUnauthorized()
    }
    throw new ApiError('Your session has expired. Please sign in again.', 401)
  }

  if (!res.ok) {
    const error = new ApiError(await readError(res), res.status)
    // The password was right and the account wants its second factor.
    error.mfaRequired = res.headers.get('X-MFA-Required') === 'totp'
    throw error
  }
  return res
}

async function request(path, options = {}) {
  const res = await requestResponse(path, options)
  if (res.status === 204) return null

  const contentType = res.headers.get('content-type') || ''
  if (contentType.includes('application/json')) return res.json()
  return res.text()
}

/** A request that returns the raw body plus its filename, for file downloads. */
async function download(path, options = {}, fallbackName = 'export') {
  const res = await requestResponse(path, options)

  const disposition = res.headers.get('content-disposition') || ''
  const match = disposition.match(/filename="([^"]+)"|filename=([^;]+)/)
  return {
    blob: await res.blob(),
    filename: match ? (match[1] || match[2]).trim() : fallbackName,
    count: Number(res.headers.get('x-export-count') || 0),
    truncated: res.headers.get('x-export-truncated') === 'true',
  }
}

function toQuery(params = {}) {
  const qs = new URLSearchParams()
  Object.entries(params).forEach(([key, value]) => {
    if (value === undefined || value === null || value === '') return
    if (Array.isArray(value)) value.forEach((item) => qs.append(key, item))
    else qs.append(key, value)
  })
  return qs.toString()
}

function abortError() {
  return new DOMException('The request was cancelled.', 'AbortError')
}

/** A timer that an AbortSignal can cut short, so no poll outlives its page. */
function wait(ms, signal) {
  return new Promise((resolve, reject) => {
    if (signal?.aborted) {
      reject(abortError())
      return
    }
    const onAbort = () => {
      clearTimeout(timer)
      reject(abortError())
    }
    const timer = setTimeout(() => {
      signal?.removeEventListener('abort', onAbort)
      resolve()
    }, ms)
    signal?.addEventListener('abort', onAbort, { once: true })
  })
}

/** How often a report job is asked for its status. */
export const REPORT_POLL_MS = 4000
/** How long the console waits for a report before saying so. The job itself carries on. */
export const REPORT_WAIT_MS = 20 * 60 * 1000

/**
 * Ask for an investigation report, wait for the model to write it, and
 * download it. `onProgress({ status, message, sessionCount })` is called for
 * every state the job reports. Aborting `signal` stops the waiting and clears
 * the timer; the job on the server is unaffected and can be asked for again.
 */
async function investigationReport(params, { onProgress, signal, pollMs = REPORT_POLL_MS } = {}) {
  const { format, ...filters } = params
  const report = (job) => onProgress?.({
    status: job.status,
    message: job.message || '',
    sessionCount: typeof job.session_count === 'number' ? job.session_count : null,
  })

  let job = await request(`/export/reports?${toQuery(filters)}`, { method: 'POST', signal })
  const deadline = Date.now() + REPORT_WAIT_MS
  while (job.status !== 'complete') {
    if (job.status === 'failed') {
      throw new ApiError(job.message || 'The report could not be prepared.', 503)
    }
    if (Date.now() > deadline) {
      throw new ApiError(
        'The report is taking longer than expected. It is still being written; ask for it again shortly to collect the same report.',
        504,
      )
    }
    report(job)
    await wait(pollMs, signal)
    job = await request(`/export/reports/${encodeURIComponent(job.id)}`, { signal })
  }
  report({ ...job, message: 'The findings are ready. Preparing the file.' })
  return download(
    `/export/reports/${encodeURIComponent(job.id)}/download?format=${format}`,
    { signal },
    `investigation.${format}`,
  )
}

export const api = {
  auth: {
    login: (email, password, totpCode) =>
      request('/auth/login', {
        method: 'POST',
        body: JSON.stringify(
          totpCode ? { email, password, totp_code: totpCode } : { email, password },
        ),
      }),
    // What this deployment can actually do: send mail, accept sign-ups,
    // reset a password by mail. Public, so the sign-in page can ask.
    capabilities: (options = {}) => request('/auth/capabilities', options),
    mfa: {
      enroll: () => request('/auth/mfa/enroll', { method: 'POST' }),
      confirm: (code) =>
        request('/auth/mfa/confirm', { method: 'POST', body: JSON.stringify({ code }) }),
      disable: (code) =>
        request('/auth/mfa/disable', { method: 'POST', body: JSON.stringify({ code }) }),
    },
    register: (data) =>
      request('/auth/register', { method: 'POST', body: JSON.stringify(data) }),
    verifyOtp: (data) =>
      request('/auth/verify-otp', { method: 'POST', body: JSON.stringify(data) }),
    resendOtp: (data) =>
      request('/auth/resend-otp', { method: 'POST', body: JSON.stringify(data) }),
    requestPasswordReset: (email) =>
      request('/auth/request-password-reset', {
        method: 'POST',
        body: JSON.stringify({ email }),
      }),
    resetPassword: (data) =>
      request('/auth/reset-password', {
        method: 'POST',
        body: JSON.stringify(data),
      }),
    me: () => request('/auth/me'),
    // Revokes the refresh token on the server; best effort, never blocks sign-out.
    logout: () => {
      const refresh_token = localStorage.getItem(REFRESH_TOKEN_KEY)
      if (!refresh_token) return Promise.resolve()
      return fetch(`${API_BASE}/auth/logout`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ refresh_token }),
        keepalive: true,
      }).catch(() => {})
    },
    changePassword: (current_password, new_password) =>
      request('/auth/change-password', {
        method: 'POST',
        body: JSON.stringify({ current_password, new_password }),
      }),
    users: {
      list: () => request('/auth/users'),
      create: (data) =>
        request('/auth/users', { method: 'POST', body: JSON.stringify(data) }),
      setRole: (id, role) =>
        request(`/auth/users/${id}/role`, { method: 'PATCH', body: JSON.stringify({ role }) }),
      update: (id, data) =>
        request(`/auth/users/${id}`, { method: 'PATCH', body: JSON.stringify(data) }),
      resetMfa: (id) => request(`/auth/users/${id}/reset-mfa`, { method: 'POST' }),
      resetPassword: (id, new_password) =>
        request(`/auth/users/${id}/reset-password`, {
          method: 'POST',
          body: JSON.stringify({ new_password }),
        }),
    },
  },

  dashboard: {
    stats: (options = {}) => request('/dashboard/stats', options),
    liveEvents: (limit = 50, options = {}) => request(`/dashboard/live-events?limit=${limit}`, options),
    // Sessions per UTC day, split by category.
    trends: (days = 30, options = {}) => request(`/dashboard/trends?days=${days}`, options),
  },

  sessions: {
    list: (params = {}, options = {}) => request(`/sessions/?${toQuery(params)}`, options),
    get: (id, options = {}) => request(`/sessions/${id}`, options),
    getByUuid: (uuid) => request(`/sessions/uuid/${uuid}`),
    transcript: (id, options = {}) => request(`/sessions/${id}/transcript`, options),
    // Admin only, and the read is audit-logged server side.
    credentials: (id) => request(`/sessions/${id}/credentials`),
    // Queue the language-model analysis stage for one session.
    enrich: (id) => request(`/sessions/${id}/enrich`, { method: 'POST' }),
    // Everything one source address has done, aggregated.
    attacker: (ip, options = {}) => request(`/sessions/attacker/${encodeURIComponent(ip)}`, options),
  },

  alerts: {
    list: (params = {}, options = {}) => request(`/alerts/?${toQuery(params)}`, options),
    get: (id) => request(`/alerts/${id}`),
    update: (id, data) =>
      request(`/alerts/${id}`, { method: 'PATCH', body: JSON.stringify(data) }),
    bulk: (ids, status) =>
      request('/alerts/bulk', { method: 'POST', body: JSON.stringify({ ids, status }) }),
    stats: (options = {}) => request('/alerts/stats', options),
  },

  iocs: {
    list: (params = {}, options = {}) => request(`/iocs/?${toQuery(params)}`, options),
    forSession: (id) => request(`/iocs/session/${id}`),
    // Plain text, one value per line — downloaded rather than rendered.
    feed: (params = {}) => download(`/iocs/feed?${toQuery(params)}`, {}, 'indicators.txt'),
  },

  payloads: {
    list: (params = {}, options = {}) => request(`/payloads/?${toQuery(params)}`, options),
    get: (sha256, options = {}) => request(`/payloads/${sha256}`, options),
    stats: (options = {}) => request('/payloads/stats', options),
    // Raw sample bytes, admin only and audit-logged server side.
    download: (sha256) => download(`/payloads/${sha256}/download`, {}, `${sha256}.bin`),
  },

  attack: {
    // Technique counts per tactic, over the same filters as the session list.
    matrix: (params = {}, options = {}) => request(`/attack/matrix?${toQuery(params)}`, options),
    // The same counts as an ATT&CK Navigator layer file.
    navigatorLayer: (params = {}) =>
      download(`/attack/navigator-layer?${toQuery(params)}`, {}, 'honeysentinel-attack-layer.json'),
  },

  // Admin only.
  auditLogs: {
    list: (params = {}, options = {}) => request(`/audit-logs?${toQuery(params)}`, options),
  },

  nodes: {
    list: (activeOnly = false, options = {}) => request(`/nodes/?active_only=${activeOnly}`, options),
    get: (id) => request(`/nodes/${id}`),
    create: (data) =>
      request('/nodes/', { method: 'POST', body: JSON.stringify(data) }),
    update: (id, data) =>
      request(`/nodes/${id}`, { method: 'PATCH', body: JSON.stringify(data) }),
    delete: (id) => request(`/nodes/${id}`, { method: 'DELETE' }),
  },

  settings: {
    thresholds: () => request('/settings/thresholds'),
    createThreshold: (data) =>
      request('/settings/thresholds', {
        method: 'POST',
        body: JSON.stringify(data),
      }),
    updateThreshold: (id, data) =>
      request(`/settings/thresholds/${id}`, {
        method: 'PATCH',
        body: JSON.stringify(data),
      }),
    deleteThreshold: (id) =>
      request(`/settings/thresholds/${id}`, { method: 'DELETE' }),
    systemConfig: () => request('/settings/system'),
    updateSystemConfig: (data) =>
      request('/settings/system', {
        method: 'PATCH',
        body: JSON.stringify(data),
      }),
  },

  export: {
    /**
     * Export the sessions matching `params`. CSV, JSON, CEF and STIX come
     * straight back as a file. PDF and Word reports are written by the model
     * as a background job; see investigationReport for `onProgress` and
     * `signal`.
     */
    sessions: (params = {}, { onProgress, signal, pollMs } = {}) => {
      if (!['pdf', 'docx'].includes(params.format)) {
        // The backend route is POST; this used to issue a GET and always 405'd.
        return download(`/export/?${toQuery(params)}`, { method: 'POST', signal })
      }
      return investigationReport(params, { onProgress, signal, pollMs })
    },
  },

  honeypot: {
    status: (options = {}) => request('/honeypot/status', options),
    securityStatus: () => request('/honeypot/security-status'),
    updateMode: (mode) =>
      request('/honeypot/mode', {
        method: 'PATCH',
        body: JSON.stringify({ mode }),
      }),
    blockIP: (ip) =>
      request('/honeypot/block-ip', {
        method: 'POST',
        body: JSON.stringify({ ip }),
      }),
    unblockIP: (ip) =>
      request('/honeypot/unblock-ip', {
        method: 'POST',
        body: JSON.stringify({ ip }),
      }),
    blockedIPs: (options = {}) => request('/honeypot/blocked-ips', options),
    threatActors: () => request('/honeypot/threat-actors'),
    activeSessions: () => request('/honeypot/sessions/active'),
  },
}
