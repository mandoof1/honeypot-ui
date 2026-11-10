/*
 * Indicator semantics.
 *
 * Two kinds of address reach the indicator table and they are not the same
 * thing. A source address connected to the honeypot. A referenced address was
 * only typed in a command — a DNS resolver in a ping, a victim in a scan
 * list — and has done nothing. Linking a referenced address to an attacker
 * profile leads to a 404, and putting one on a blocklist blocks a bystander.
 *
 *   ioc_type "ip"             a source address (tagged attacker_ip)
 *   ioc_type "referenced_ip"  an address named in a command
 *
 * Older rows may still carry a referenced address as type "ip"; when a row
 * has tags, the tag decides.
 */

export const INDICATOR_TYPES = [
  { id: '', label: 'All' },
  { id: 'ip', label: 'Source addresses' },
  { id: 'referenced_ip', label: 'Referenced addresses' },
  { id: 'domain', label: 'Domains' },
  { id: 'url', label: 'URLs' },
  { id: 'filename', label: 'Payload names' },
  { id: 'file_hash', label: 'Hashes' },
  { id: 'tool', label: 'Tools' },
]

const TYPE_LABEL = {
  ip: 'source address',
  referenced_ip: 'referenced address',
  domain: 'domain',
  url: 'URL',
  filename: 'payload name',
  file_hash: 'hash',
  tool: 'tool',
  host: 'host',
  file: 'file',
  wallet: 'wallet',
  ssh_key: 'SSH key',
  c2_channel: 'operator channel',
}

/** A short human name for an indicator type; unknown types keep their own text. */
export function indicatorTypeLabel(type) {
  return TYPE_LABEL[type] || String(type || 'unknown').replace(/_/g, ' ')
}

/** True when the row is an address that actually connected to the honeypot. */
export function isAttackerSource(row) {
  if (!row || row.type !== 'ip') return false
  if (Array.isArray(row.tags) && row.tags.length > 0) return row.tags.includes('attacker_ip')
  return true
}

/** True for an address that was only mentioned, whichever way the row says so. */
export function isReferencedAddress(row) {
  if (!row) return false
  if (row.type === 'referenced_ip') return true
  return row.type === 'ip' && !isAttackerSource(row)
}

/** The fewest sessions a value must be seen in before it may go on a blocklist. */
export const BLOCKLIST_MIN_SESSIONS = 2

const BLOCKABLE = new Set(['ip', 'domain', 'url', 'file_hash'])

/**
 * What the feed download may offer for the type the view is filtered to.
 * An unfiltered view offers source addresses. Returns `{iocType, minSessions,
 * label}` or `{reason}` when nothing may be offered.
 *
 * One sighting may be a passing scan or a shared exit node, so the floor is
 * two sessions however low the view's own filter is set.
 */
export function blocklistOffer(viewType, viewMinSessions = 1) {
  const iocType = viewType || 'ip'
  if (iocType === 'referenced_ip') {
    return { reason: 'Referenced addresses were only typed in a command. They are not attacker sources and are never offered as a blocklist.' }
  }
  if (!BLOCKABLE.has(iocType)) {
    return { reason: `A list of ${indicatorTypeLabel(iocType)}s is not something a firewall or proxy can block on.` }
  }
  const minSessions = Math.max(BLOCKLIST_MIN_SESSIONS, Number(viewMinSessions) || 0)
  const noun = iocType === 'ip' ? 'source addresses' : `${indicatorTypeLabel(iocType)}s`
  return { iocType, minSessions, label: `Blocklist · ${noun}` }
}

const SHA256 = /^[0-9a-f]{64}$/i

/**
 * Where an indicator row leads.
 *
 *   profile   the attacker profile, for a source address only
 *   sessions  the session list searched for the value. The list API searches
 *             source address, session id and command text, so this finds an
 *             address that connected or a value that was typed; it cannot
 *             find a tool name or a hash, and those get no session link.
 *   payload   the captured sample, for a SHA-256
 */
export function indicatorLinks(row) {
  const value = String(row?.value ?? '')
  if (!value) return {}
  const links = {}
  if (isAttackerSource(row)) links.profile = `/attackers/${encodeURIComponent(value)}`
  if (row.type === 'file_hash') {
    if (SHA256.test(value)) links.payload = `/payloads?sha=${value.toLowerCase()}`
    return links
  }
  if (row.type !== 'tool') links.sessions = `/sessions?search=${encodeURIComponent(value)}`
  return links
}
