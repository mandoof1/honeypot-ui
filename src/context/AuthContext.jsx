import { useCallback, useEffect, useMemo, useRef, useState } from 'react'
import { AuthContext } from './authContext.js'
import {
  api,
  clearTokens,
  getAccessToken,
  setTokens,
  setUnauthorizedHandler,
} from '../services/api'

const ROLE_RANK = { viewer: 0, analyst: 1, admin: 2 }

export function AuthProvider({ children }) {
  const [user, setUser] = useState(null)
  const [loading, setLoading] = useState(true)
  const mounted = useRef(true)

  const logout = useCallback(() => {
    // Tell the server first (it reads the token from storage), then clear.
    api.auth.logout?.()
    clearTokens()
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
      if (mounted.current) setUser(me)
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
      if (mounted.current) setUser(null)
    })
    const timer = setTimeout(fetchUser, 0)

    return () => {
      mounted.current = false
      clearTimeout(timer)
      setUnauthorizedHandler(() => {})
    }
  }, [fetchUser])

  const login = useCallback(
    async (email, password, totpCode) => {
      const data = await api.auth.login(email, password, totpCode)
      setTokens(data)
      await fetchUser()
      return data
    },
    [fetchUser],
  )

  const value = useMemo(
    () => ({
      user,
      loading,
      login,
      logout,
      register: api.auth.register,
      /** Re-read the signed-in user, e.g. after enrolling an authenticator. */
      refreshUser: fetchUser,
      /** True when the signed-in user meets or exceeds `role`. */
      hasRole: (role) =>
        (ROLE_RANK[user?.role] ?? -1) >= (ROLE_RANK[role] ?? Infinity),
    }),
    [user, loading, login, logout, fetchUser],
  )

  return <AuthContext.Provider value={value}>{children}</AuthContext.Provider>
}
