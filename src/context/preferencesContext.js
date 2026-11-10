import { createContext } from 'react'

/**
 * Display preferences shared across the app: theme, time zone, presentation
 * mode. In its own module so PreferencesContext.jsx exports only a component,
 * which is what React Fast Refresh requires.
 */
export const PreferencesContext = createContext(null)
