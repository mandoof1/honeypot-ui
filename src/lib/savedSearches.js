/*
 * Saved searches.
 *
 * A filter set an analyst returns to — "exploitation over SSH this week",
 * "critical alerts assigned to me" — kept by name. They live in this
 * browser's localStorage only: the API has no per-user store for them, so
 * they do not follow the account to another machine, and the control says so.
 *
 * A saved search is the view's query string with the parts that are not part
 * of the question removed: the page number and whichever row was open.
 */

export const SAVED_KEY = 'hs_saved_searches'
export const MAX_SAVED = 20
export const MAX_NAME_LENGTH = 60

/** Parameters that describe where the reader was, not what they asked for. */
const VOLATILE = new Set(['page', 'session', 'sha'])

/** A canonical query string for a view: volatile and empty parameters dropped, keys sorted. */
export function canonicalQuery(search) {
  const input = new URLSearchParams(typeof search === 'string' ? search : String(search || ''))
  const kept = [...input.entries()].filter(([key, value]) => !VOLATILE.has(key) && value !== '')
  kept.sort((a, b) => a[0].localeCompare(b[0]) || a[1].localeCompare(b[1]))
  return new URLSearchParams(kept).toString()
}

/** "protocol: ssh · status: active": a saved query in words, for the list. */
export function describeQuery(query) {
  const entries = [...new URLSearchParams(String(query || '')).entries()]
  if (!entries.length) return 'no filters'
  return entries.map(([key, value]) => `${key.replace(/_/g, ' ')}: ${value}`).join(' · ')
}

function readAll(storage) {
  try {
    const parsed = JSON.parse(storage?.getItem(SAVED_KEY) || '{}')
    return parsed && typeof parsed === 'object' && !Array.isArray(parsed) ? parsed : {}
  } catch {
    return {}
  }
}

function valid(entry) {
  return entry && typeof entry === 'object' && typeof entry.name === 'string' && typeof entry.query === 'string'
}

/** Saved searches for one view ("sessions", "alerts", "indicators"), newest first. */
export function listSaved(storage, scope) {
  const rows = readAll(storage)[scope]
  return Array.isArray(rows) ? rows.filter(valid) : []
}

/**
 * Save the current query under a name. A search with the same name is
 * replaced, so re-saving updates it instead of piling up duplicates.
 * Returns the new list, or null when the name is empty.
 */
export function saveSearch(storage, scope, name, search, now = Date.now()) {
  const trimmed = String(name || '').trim().slice(0, MAX_NAME_LENGTH)
  if (!trimmed) return null
  const all = readAll(storage)
  const others = listSaved(storage, scope).filter((entry) => entry.name.toLowerCase() !== trimmed.toLowerCase())
  const next = [{ name: trimmed, query: canonicalQuery(search), savedAt: now }, ...others].slice(0, MAX_SAVED)
  all[scope] = next
  try {
    storage?.setItem(SAVED_KEY, JSON.stringify(all))
  } catch {
    return null
  }
  return next
}

/** Remove a saved search by name. Returns the new list. */
export function removeSaved(storage, scope, name) {
  const all = readAll(storage)
  const next = listSaved(storage, scope).filter((entry) => entry.name !== name)
  all[scope] = next
  try {
    storage?.setItem(SAVED_KEY, JSON.stringify(all))
  } catch {
    // Nothing to do: the list on screen is still updated for this visit.
  }
  return next
}
