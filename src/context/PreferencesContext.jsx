import { useCallback, useEffect, useMemo, useState } from 'react'
import { PreferencesContext } from './preferencesContext.js'
import { PREFS_KEY, normalisePrefs, readPrefs, writePrefs } from '../lib/prefs'
import { applyTheme } from '../lib/theme'
import { formatTimestamp, zoneDescription, zoneLabel } from '../lib/time'

function storage() {
  try {
    return window.localStorage
  } catch {
    return null
  }
}

export function PreferencesProvider({ children }) {
  const [prefs, setPrefs] = useState(() => readPrefs(storage()))

  useEffect(() => {
    applyTheme(prefs.theme)
  }, [prefs.theme])

  // A change made in another tab applies here too, so two windows on one
  // projector never disagree about the theme or about masking secrets.
  useEffect(() => {
    const onStorage = (event) => {
      if (event.key !== PREFS_KEY) return
      setPrefs(readPrefs(storage()))
    }
    window.addEventListener('storage', onStorage)
    return () => window.removeEventListener('storage', onStorage)
  }, [])

  const setPreference = useCallback((key, value) => {
    setPrefs((current) => {
      const next = normalisePrefs({ ...current, [key]: value })
      writePrefs(storage(), next)
      return next
    })
  }, [])

  const value = useMemo(() => ({
    ...prefs,
    setPreference,
    /** A timestamp in the chosen zone, with the zone named. */
    formatTime: (input, style = 'full', withZone = true) =>
      formatTimestamp(input, { zone: prefs.zone, style, withZone }),
    /** "UTC" or "UTC+4". */
    zoneLabel: (date) => zoneLabel(prefs.zone, date),
    /** "UTC" or "local time (UTC+4)". */
    zoneDescription: (date) => zoneDescription(prefs.zone, date),
  }), [prefs, setPreference])

  return <PreferencesContext.Provider value={value}>{children}</PreferencesContext.Provider>
}
