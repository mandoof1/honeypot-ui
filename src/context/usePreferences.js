import { useContext } from 'react'
import { PreferencesContext } from './preferencesContext.js'

/** The display preferences and the setter for them. */
export function usePreferences() {
  const ctx = useContext(PreferencesContext)
  if (!ctx) throw new Error('usePreferences must be used within PreferencesProvider')
  return ctx
}
