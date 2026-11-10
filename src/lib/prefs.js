/*
 * Display preferences: theme, time zone and presentation mode.
 *
 * Kept per browser in localStorage. They are view settings, not account
 * settings, and the console has no endpoint to store them on the server.
 * Reading tolerates anything that might be in the key, because a value
 * written by an older build must not break the first render.
 */

export const PREFS_KEY = 'hs_display'

export const THEMES = ['dark', 'light']

export const DEFAULT_PREFS = Object.freeze({
  // Dark is the design the console was drawn in; light is the high-contrast
  // one for a projector or a bright room.
  theme: 'dark',
  // Timestamps were always printed in the browser's zone; that stays the
  // default, now with the zone named beside every one of them.
  zone: 'local',
  // Presentation mode masks secrets even after they have been revealed.
  presentation: false,
})

/** Coerce anything into a complete, valid preference object. */
export function normalisePrefs(raw) {
  const source = raw && typeof raw === 'object' ? raw : {}
  return {
    theme: THEMES.includes(source.theme) ? source.theme : DEFAULT_PREFS.theme,
    zone: source.zone === 'utc' || source.zone === 'local' ? source.zone : DEFAULT_PREFS.zone,
    presentation: source.presentation === true,
  }
}

export function readPrefs(storage) {
  try {
    return normalisePrefs(JSON.parse(storage?.getItem(PREFS_KEY) || 'null'))
  } catch {
    return { ...DEFAULT_PREFS }
  }
}

export function writePrefs(storage, prefs) {
  try {
    storage?.setItem(PREFS_KEY, JSON.stringify(normalisePrefs(prefs)))
  } catch {
    // Storage can be full or disabled; the preference then lasts for the tab.
  }
}
