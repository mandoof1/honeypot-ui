import { useCallback, useEffect, useMemo, useRef, useState } from 'react'
import { AuthContext } from './authContext.js'
import {
  api,
  clearTokens,
  getAccessToken,
  onTokenChange,
  setTokens,
  setUnauthorizedHandler,
} from '../services/api'

const ROLE_RANK = { viewer: 0, analyst: 1, admin: 2 }

/** The fields the interface reads; a refetch that changes none of them keeps the same object. */
function sameUser(a, b) {
  if (!a || !b) return a === b
  return a.id === b.id && a.email === b.email && a.role === b.role
    && a.name === b.name && Boolean(a.totp_enabled) === Boolean(b.totp_enabled)
}

export function AuthProvider({ children }) {
  const [user, setUser] = useState(null)
  const [loading, setLoading] = useState(true)
  // Why the sign-in page is showing, when the user did not choose to be there.
  const [notice, setNotice] = useState(null)
  const mounted = useRef(true)

  const logout = useCallback((reason = null) => {
    // Tell the server first (it reads the token from storage), then clear.
    // Clearing storage is also what signs the other tabs out.
    api.auth.logout?.()
    clearTokens()
    setNotice(typeof reason === 'string' ? reason : null)
    setUser(null)
  }, [])

  /**
   * Leave a session the server has already ended, such as after a password
   * change, which revokes every token. Nothing is sent: presenting a revoked
   * refresh token would be recorded as a reuse attempt.
   */
  const endSession = useCallback((reason = null) => {
    clearTokens()
    setNotice(reason)
    setUser(null)
  }, [])

  const fetchUser = useCallback(async () => {
    if (!getAccessToken()) {
      if (mounted.current) {
        setUser(null)
        setLoading(false)
      }
      return
    }
    try {
      const me = await api.auth.me()
      if (mounted.current) setUser((current) => (sameUser(current, me) ? current : me))
    } catch (err) {
      // Only a rejected token ends the session. A network blip at startup
      // used to clear both tokens and send the user back to the login page,
      // which signed them out for the API being briefly unreachable.
      if (err?.status === 401 || err?.status === 403) clearTokens()
      if (mounted.current) setUser(null)
    } finally {
      if (mounted.current) setLoading(false)
    }
  }, [])

  useEffect(() => {
    mounted.current = true
    // Let the API layer return us to the login screen through React state
    // rather than a full-page window.location reload.
    setUnauthorizedHandler(() => {
      if (!mounted.current) return
      setNotice('Your session has expired. Sign in again.')
      setUser(null)
    })
    // Another tab signed out, signed in, or rotated the tokens.
    const unsubscribe = onTokenChange(({ signedIn }) => {
      if (!mounted.current) return
      if (signedIn) {
        fetchUser()
        return
      }
      setNotice('You signed out in another tab.')
      setUser(null)
    })
    const timer = setTimeout(fetchUser, 0)

    return () => {
      mounted.current = false
      clearTimeout(timer)
      unsubscribe()
      setUnauthorizedHandler(() => {})
    }
  }, [fetchUser])

  const login = useCallback(
    async (email, password, totpCode) => {
      const data = await api.auth.login(email, password, totpCode)
      setTokens(data)
      setNotice(null)
      await fetchUser()
      return data
    },
    [fetchUser],
  )

  const value = useMemo(
    () => ({
      user,
      loading,
      notice,
      login,
      logout,
      endSession,
      register: api.auth.register,
      /** Re-read the signed-in user, e.g. after enrolling an authenticator. */
      refreshUser: fetchUser,
      /** True when the signed-in user meets or exceeds `role`. */
      hasRole: (role) =>
        (ROLE_RANK[user?.role] ?? -1) >= (ROLE_RANK[role] ?? Infinity),
    }),
    [user, loading, notice, login, logout, endSession, fetchUser],
  )

  return <AuthContext.Provider value={value}>{children}</AuthContext.Provider>
}
