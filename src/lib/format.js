/*
 * Small, pure formatting helpers shared across pages. Kept free of JSX so
 * they can be unit-tested under node directly.
 */

/** "3 min ago", "2 h ago", "just now"; null for a missing timestamp. */
export function relativeTime(iso, now = Date.now()) {
  if (!iso) return null
  const then = typeof iso === 'number' ? iso : new Date(iso).getTime()
  if (Number.isNaN(then)) return null
  const seconds = Math.max(0, (now - then) / 1000)
  if (seconds < 45) return 'just now'
  if (seconds < 3600) return `${Math.max(1, Math.round(seconds / 60))} min ago`
  if (seconds < 86400) return `${Math.round(seconds / 3600)} h ago`
  return `${Math.round(seconds / 86400)} d ago`
}

/** Seconds → "3 min", "2 h 5 min", "4 d 1 h". */
export function formatDuration(seconds) {
  if (typeof seconds !== 'number' || !Number.isFinite(seconds) || seconds < 0) return '—'
  if (seconds < 60) return `${Math.round(seconds)} s`
  const minutes = Math.floor(seconds / 60)
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
