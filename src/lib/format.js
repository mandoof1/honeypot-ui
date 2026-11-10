/*
 * Small, pure formatting helpers shared across pages. Kept free of JSX so
 * they can be unit-tested under node directly.
 *
 * Every duration is rounded to its smallest shown unit first and bucketed
 * afterwards. Bucketing first is what produced "60 s", "1m 60s" and
 * "60 min ago": the value was just under a boundary when the unit was chosen
 * and rounded up across it when printed.
 */

/** "3 min ago", "2 h ago", "just now"; null for a missing timestamp. */
export function relativeTime(iso, now = Date.now()) {
  if (!iso) return null
  const then = typeof iso === 'number' ? iso : new Date(iso).getTime()
  if (Number.isNaN(then)) return null
  const seconds = Math.max(0, (now - then) / 1000)
  if (seconds < 45) return 'just now'
  const minutes = Math.max(1, Math.round(seconds / 60))
  if (minutes < 60) return `${minutes} min ago`
  const hours = Math.round(seconds / 3600)
  if (hours < 24) return `${hours} h ago`
  return `${Math.round(seconds / 86400)} d ago`
}

/**
 * How long ago a view was last loaded: "updated just now", "updated 12 s ago",
 * "updated 3 min ago". Finer than relativeTime because it sits beside a
 * refresh control, where "just now" for 44 seconds would hide a stalled poll.
 */
export function updatedAgo(loadedAt, now = Date.now()) {
  if (typeof loadedAt !== 'number' || Number.isNaN(loadedAt)) return 'not loaded yet'
  const seconds = Math.max(0, Math.round((now - loadedAt) / 1000))
  if (seconds < 3) return 'updated just now'
  if (seconds < 60) return `updated ${seconds} s ago`
  const minutes = Math.round(seconds / 60)
  if (minutes < 60) return `updated ${minutes} min ago`
  return `updated ${Math.round(minutes / 60)} h ago`
}

/** Seconds → "42 s", "3 min", "2 h 5 min", "4 d 1 h". */
export function formatDuration(seconds) {
  if (typeof seconds !== 'number' || !Number.isFinite(seconds) || seconds < 0) return '—'
  const total = Math.round(seconds)
  if (total < 60) return `${total} s`
  const minutes = Math.floor(total / 60)
  if (minutes < 60) return `${minutes} min`
  const hours = Math.floor(minutes / 60)
  if (hours < 48) return `${hours} h ${minutes % 60} min`
  const days = Math.floor(hours / 24)
  return `${days} d ${hours % 24} h`
}

/** Bytes → "512 B", "3.4 MB", "1.2 GB". */
export function formatBytes(bytes) {
  if (typeof bytes !== 'number' || !Number.isFinite(bytes) || bytes < 0) return '—'
  const units = ['B', 'KB', 'MB', 'GB', 'TB']
  let value = bytes
  let i = 0
  while (value >= 1000 && i < units.length - 1) {
    value /= 1000
    i += 1
  }
  const text = i === 0 ? String(value) : value.toFixed(value >= 100 ? 0 : 1).replace(/\.0$/, '')
  return `${text} ${units[i]}`
}

/**
 * Engine liveness from a node record. Tolerates the old API that has neither
 * `online` nor `heartbeat_age_seconds`: then only `last_heartbeat` is used.
 */
export function nodeLiveness(node, now = Date.now(), staleAfterSeconds = 180) {
  if (!node) return { state: 'unknown', ageSeconds: null }
  let age = typeof node.heartbeat_age_seconds === 'number' ? node.heartbeat_age_seconds : null
  if (age === null && node.last_heartbeat) {
    const then = new Date(node.last_heartbeat).getTime()
    if (!Number.isNaN(then)) age = Math.max(0, (now - then) / 1000)
  }
  if (typeof node.online === 'boolean') {
    return { state: node.online ? 'online' : 'stale', ageSeconds: age }
  }
  if (age === null) return { state: 'unknown', ageSeconds: null }
  return { state: age <= staleAfterSeconds ? 'online' : 'stale', ageSeconds: age }
}

/** Free-space ratio for a node status disk block; null when absent. */
export function diskFreeRatio(disk) {
  if (!disk || typeof disk.total_bytes !== 'number' || typeof disk.free_bytes !== 'number' || disk.total_bytes <= 0) {
    return null
  }
  return disk.free_bytes / disk.total_bytes
}

/** "1 command", "8 commands": a count with its noun in the right number. */
export function plural(count, singular, pluralForm = `${singular}s`) {
  const n = Number(count) || 0
  return `${n.toLocaleString()} ${n === 1 ? singular : pluralForm}`
}

/**
 * A session's length: "52 ms", "4.2 s", "2m 4s", "2h 5m". Scripted sessions
 * often finish in a few hundredths of a second, which one decimal place
 * showed as "0.0s", as though nothing happened.
 */
export function formatSessionDuration(seconds) {
  if (typeof seconds !== 'number' || !Number.isFinite(seconds)) return 'In progress'
  if (seconds < 0) return '—'
  if (seconds < 0.9995) return `${Math.max(1, Math.round(seconds * 1000))} ms`
  if (seconds < 59.95) return `${seconds.toFixed(1)} s`
  const total = Math.round(seconds)
  const hours = Math.floor(total / 3600)
  const minutes = Math.floor((total % 3600) / 60)
  if (hours > 0) return `${hours}h ${minutes}m`
  return `${minutes}m ${total % 60}s`
}

/** "12s", "4m", "3h", "2d": the compact age used in dense rows. */
export function compactAge(iso, now = Date.now()) {
  const then = new Date(iso).getTime()
  if (Number.isNaN(then)) return '—'
  const seconds = Math.max(0, Math.floor((now - then) / 1000))
  if (seconds < 60) return `${seconds}s`
  if (seconds < 3600) return `${Math.floor(seconds / 60)}m`
  if (seconds < 86400) return `${Math.floor(seconds / 3600)}h`
  return `${Math.floor(seconds / 86400)}d`
}
