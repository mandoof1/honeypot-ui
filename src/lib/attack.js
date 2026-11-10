/*
 * MITRE ATT&CK vocabulary for display.
 *
 * Sessions carry tactic ids (TA0002) and the console printed them bare, in
 * whatever order the pipeline emitted them. A reader should see "Execution",
 * and should see tactics in the order an intrusion moves through them, so the
 * progression of a session reads left to right.
 *
 * The table is the Enterprise matrix's own column order. It names tactics
 * only; technique names always come from the API, and a technique the API
 * marks `verified: false` (its id was not found in the ATT&CK catalog) is
 * never turned into a link to attack.mitre.org.
 */

/** Enterprise tactics in kill-chain (matrix column) order. */
export const TACTICS = [
  { id: 'TA0043', name: 'Reconnaissance' },
  { id: 'TA0042', name: 'Resource Development' },
  { id: 'TA0001', name: 'Initial Access' },
  { id: 'TA0002', name: 'Execution' },
  { id: 'TA0003', name: 'Persistence' },
  { id: 'TA0004', name: 'Privilege Escalation' },
  { id: 'TA0005', name: 'Defense Evasion' },
  { id: 'TA0006', name: 'Credential Access' },
  { id: 'TA0007', name: 'Discovery' },
  { id: 'TA0008', name: 'Lateral Movement' },
  { id: 'TA0009', name: 'Collection' },
  { id: 'TA0011', name: 'Command and Control' },
  { id: 'TA0010', name: 'Exfiltration' },
  { id: 'TA0040', name: 'Impact' },
]

const BY_ID = new Map(TACTICS.map((tactic, order) => [tactic.id, { ...tactic, order }]))
const BY_NAME = new Map(TACTICS.map((tactic, order) => [tactic.name.toLowerCase(), { ...tactic, order }]))

const TECHNIQUE_ID = /^T\d{4}(?:\.\d{3})?$/

/**
 * Resolve whatever the API sent for a tactic — an id, a name, or an object
 * with either — to `{id, name, order, known}`. Unknown values keep their own
 * text and sort after the known ones.
 */
export function describeTactic(value) {
  const raw = value && typeof value === 'object' ? (value.id || value.name || '') : (value ?? '')
  const text = String(raw).trim()
  const found = BY_ID.get(text.toUpperCase()) || BY_NAME.get(text.toLowerCase())
  if (found) return { ...found, known: true }
  const name = value && typeof value === 'object' && value.name ? String(value.name) : text
  return { id: text, name: name || 'Unnamed tactic', order: TACTICS.length, known: false }
}

/** Tactics de-duplicated and put in kill-chain order. */
export function orderTactics(list) {
  const seen = new Map()
  for (const item of list || []) {
    const tactic = describeTactic(item)
    const key = tactic.known ? tactic.id : `?${tactic.id}`
    if (tactic.id && !seen.has(key)) seen.set(key, tactic)
  }
  return [...seen.values()].sort((a, b) => a.order - b.order || a.name.localeCompare(b.name))
}

/** False only when the API said the id is not in the ATT&CK catalog. */
export function isVerifiedTechnique(technique) {
  return technique?.verified !== false
}

/**
 * The attack.mitre.org page for a technique, or null when there must not be
 * a link: the API marked it unverified, or the id is not shaped like one.
 */
export function techniqueUrl(technique) {
  const id = String(technique?.id || '').trim().toUpperCase()
  if (!isVerifiedTechnique(technique) || !TECHNIQUE_ID.test(id)) return null
  return `https://attack.mitre.org/techniques/${id.replace('.', '/')}/`
}

/**
 * The matrix response, made safe to draw: techniques by count, counts
 * coerced to numbers, and the largest count for the shading scale. The
 * tactics are kept in the order the API sends them, which is the kill-chain
 * order of its own ATT&CK catalog. Tolerates an empty or partial payload.
 */
export function normaliseMatrix(payload) {
  const columns = (payload?.tactics || []).map((tactic) => {
    const described = describeTactic(tactic)
    const techniques = (tactic?.techniques || [])
      .filter((technique) => technique && technique.id)
      .map((technique) => ({
        id: String(technique.id),
        name: technique.name ? String(technique.name) : '',
        count: Math.max(0, Number(technique.count) || 0),
        verified: isVerifiedTechnique(technique),
      }))
      .sort((a, b) => b.count - a.count || a.id.localeCompare(b.id))
    const name = tactic?.name ? String(tactic.name) : described.name
    return { ...described, name, techniques }
  })
  const max = columns.reduce(
    (peak, column) => column.techniques.reduce((inner, technique) => Math.max(inner, technique.count), peak),
    0,
  )
  const techniqueCount = columns.reduce((sum, column) => sum + column.techniques.length, 0)
  return {
    columns,
    max,
    techniqueCount,
    sessions: typeof payload?.sessions === 'number' ? payload.sessions : null,
    version: payload?.attack_version ? String(payload.attack_version) : null,
  }
}

/** Shade step 0–4 for a count on a scale topping out at `max`. Zero is its own step. */
export function heatStep(count, max) {
  if (!count || !max) return 0
  return Math.min(4, Math.max(1, Math.ceil((count / max) * 4)))
}
