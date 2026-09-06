const API_BASE = import.meta.env?.VITE_API_URL || 'http://localhost:8000/api/v1'

const ACCESS_TOKEN_KEY = 'access_token'
const REFRESH_TOKEN_KEY = 'refresh_token'
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

// A single in-flight refresh shared by every concurrent 401, so a page with
// four parallel requests does not fire four refreshes and invalidate itself.
let refreshInFlight = null

async function refreshAccessToken() {
  const refreshToken = localStorage.getItem(REFRESH_TOKEN_KEY)
  if (!refreshToken) return false

  if (!refreshInFlight) {
    const version = tokenVersion
    refreshInFlight = (async () => {
      try {
        const res = await fetch(`${API_BASE}/auth/refresh`, {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({ refresh_token: refreshToken }),
        })
        if (!res.ok) return false
        const tokens = await res.json()
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
    })()
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
  const authenticated = !path.startsWith('/auth/') || path === '/auth/me'
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

  if (!res.ok) throw new ApiError(await readError(res), res.status)
  return res
}

async function request(path, options = {}) {
  const res = await requestResponse(path, options)
  if (res.status === 204) return null

  const contentType = res.headers.get('content-type') || ''
  if (contentType.includes('application/json')) return res.json()
  return res.text()
}

/** POST that returns the raw body plus its filename, for file downloads. */
async function download(path, options = {}) {
  const res = await requestResponse(path, options)

  const disposition = res.headers.get('content-disposition') || ''
  const match = disposition.match(/filename="([^"]+)"|filename=([^;]+)/)
  return {
    blob: await res.blob(),
    filename: match ? (match[1] || match[2]).trim() : 'export',
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

export const api = {
  auth: {
    login: (email, password) =>
      request('/auth/login', {
        method: 'POST',
        body: JSON.stringify({ email, password }),
      }),
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
  },

  dashboard: {
    stats: () => request('/dashboard/stats'),
    liveEvents: (limit = 50) => request(`/dashboard/live-events?limit=${limit}`),
  },

  sessions: {
    list: (params = {}, options = {}) => request(`/sessions/?${toQuery(params)}`, options),
    get: (id, options = {}) => request(`/sessions/${id}`, options),
    related: (id, params = {}, options = {}) => request(`/sessions/${id}/related?${toQuery(params)}`, options),
    getByUuid: (uuid) => request(`/sessions/uuid/${uuid}`),
    transcript: (id) => request(`/sessions/${id}/transcript`),
    // Admin only, and the read is audit-logged server side.
    credentials: (id) => request(`/sessions/${id}/credentials`),
  },

  alerts: {
    list: (params = {}) => request(`/alerts/?${toQuery(params)}`),
    get: (id) => request(`/alerts/${id}`),
    update: (id, data) =>
      request(`/alerts/${id}`, { method: 'PATCH', body: JSON.stringify(data) }),
    stats: () => request('/alerts/stats'),
  },

  iocs: {
    list: (params = {}) => request(`/iocs/?${toQuery(params)}`),
    forSession: (id) => request(`/iocs/session/${id}`),
    // Plain text, one value per line — downloaded rather than rendered.
    feed: (params = {}) => download(`/iocs/feed?${toQuery(params)}`),
  },

  nodes: {
    list: (activeOnly = false) => request(`/nodes/?active_only=${activeOnly}`),
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
    // The backend route is POST; this used to issue a GET and always 405'd.
    sessions: (params = {}) =>
      download(`/export/?${toQuery(params)}`, { method: 'POST' }),
  },

  honeypot: {
    status: () => request('/honeypot/status'),
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
    blockedIPs: () => request('/honeypot/blocked-ips'),
    threatActors: () => request('/honeypot/threat-actors'),
    activeSessions: () => request('/honeypot/sessions/active'),
  },
}
