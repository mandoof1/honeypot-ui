/*
 * Names the kind of address a session came from when it has no location.
 * Tailnet, LAN, container and loopback addresses have no place on a map, so
 * geolocation correctly leaves them blank, and showing "Unknown origin" for
 * them read as a failed lookup. This only classifies the address range; it
 * never guesses a country.
 */

function ipv4ToNumber(ip) {
  const parts = ip.split('.')
  if (parts.length !== 4) return null
  let n = 0
  for (const part of parts) {
    if (!/^\d{1,3}$/.test(part) || Number(part) > 255) return null
    n = n * 256 + Number(part)
  }
  return n
}

const IPV4_RANGES = [
  // RFC 6598 shared space; Tailscale hands out its addresses from here.
  ['100.64.0.0', 10, 'Tailnet'],
  ['10.0.0.0', 8, 'Private network'],
  // Also where Docker puts its bridge networks, e.g. the controlled-test engine.
  ['172.16.0.0', 12, 'Private network'],
  ['192.168.0.0', 16, 'Private network'],
  ['127.0.0.0', 8, 'Loopback'],
  ['169.254.0.0', 16, 'Link-local'],
].map(([base, bits, label]) => ({ start: ipv4ToNumber(base), size: 2 ** (32 - bits), label }))

/** "Tailnet", "Private network", "Loopback" or "Link-local"; null for a public address. */
export function networkLabel(ip) {
  if (!ip) return null
  let addr = String(ip).trim().toLowerCase()
  if (addr.startsWith('::ffff:')) addr = addr.slice(7)

  const n = ipv4ToNumber(addr)
  if (n !== null) {
    const range = IPV4_RANGES.find((r) => n >= r.start && n < r.start + r.size)
    return range ? range.label : null
  }

  if (addr === '::1') return 'Loopback'
  if (addr.startsWith('fd7a:115c:a1e0:')) return 'Tailnet'
  if (/^f[cd]/.test(addr)) return 'Private network'
  if (/^fe[89ab]/.test(addr)) return 'Link-local'
  return null
}
