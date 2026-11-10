/*
 * What produced a verdict, in plain words.
 *
 * A session passes through up to four stages, and the detail panel used to
 * print their numbers side by side under one heading: "Confidence 85.0%"
 * beneath "Model verdict" was, for most sessions, a constant written by the
 * rule layer and not a model's probability at all.
 *
 * These helpers decide the wording. The rule they enforce: a number is only
 * called a probability when the stage that produced it outputs one. Anything
 * else is a score, shown as a plain decimal and named for its source.
 *
 * Pure, so the wording is unit-tested.
 */

const SOURCES = {
  // Current pipeline: the rule layer always chooses the category. The flow
  // classifier's reading is advisory and is reported beside it.
  rules: {
    label: 'Signature rules',
    scoreLabel: 'Rule score',
    note: 'A value the rule layer assigns from the evidence it matched; 0 means it matched none. It is not a probability.',
  },
  // Sessions analysed by earlier versions, where a classifier could decide.
  cicids2017: {
    label: 'Flow classifier',
    detail: 'trained on the CIC-IDS2017 dataset',
    scoreLabel: 'Classifier score',
    note: 'The classifier’s own output for the chosen category. The API reports no calibration for it, so it is shown as a score, not as a probability.',
  },
  pretrained: {
    label: 'Flow classifier',
    detail: 'pre-trained',
    scoreLabel: 'Classifier score',
    note: 'The classifier’s own output for the chosen category. The API reports no calibration for it, so it is shown as a score, not as a probability.',
  },
  synthetic: {
    label: 'Bootstrap classifier',
    detail: 'trained on synthetic traffic only',
    scoreLabel: 'Placeholder score',
    note: 'This classifier has never seen captured traffic. The score is a placeholder, not a measurement.',
  },
  unloaded: {
    label: 'No classifier loaded',
    scoreLabel: 'Score',
    note: 'No classifier was loaded when this session was analysed.',
  },
}

const UNKNOWN_SOURCE = {
  label: 'Source not recorded',
  scoreLabel: 'Score',
  note: 'This session does not say which stage chose its category.',
}

/** Which stage chose the session's category, and how to label its number. */
export function verdictSource(session) {
  const key = session?.model_source
  const source = SOURCES[key] || UNKNOWN_SOURCE
  return { key: key || null, ...source }
}

/** A score as a plain decimal: "0.85". Never a percentage. */
export function scoreText(value, digits = 2) {
  return typeof value === 'number' && Number.isFinite(value) ? value.toFixed(digits) : '—'
}

/** A genuine probability as a percentage: "85%". */
export function probabilityText(value) {
  return typeof value === 'number' && Number.isFinite(value) ? `${Math.round(value * 100)}%` : '—'
}

/**
 * How to show the anomaly reading.
 *
 *   not_calibrated  the detector has no fitted threshold; its flag means nothing yet
 *   flagged         calibrated (or not stated) and above the threshold
 *   normal          calibrated (or not stated) and below it
 */
export function anomalyReading(session) {
  const score = typeof session?.anomaly_score === 'number' ? session.anomaly_score : null
  if (session?.signals?.anomaly?.calibrated === false) return { state: 'not_calibrated', score }
  return { state: session?.is_anomalous ? 'flagged' : 'normal', score }
}

/**
 * The automated-agent signal.
 *
 *   likely    a planted canary was acted on: a detection
 *   possible  no canary; the gaps between commands look like a model's
 *             think-then-act loop. The engine caps this score well below 1
 *             and labels it suggestive, and so does the console.
 *   null      nothing worth showing
 */
export function aiAgentReading(session) {
  const signal = session?.signals?.ai_agent
  if (!signal || typeof signal !== 'object') return null
  const score = typeof signal.score === 'number' && Number.isFinite(signal.score) ? signal.score : null
  const reasons = Array.isArray(signal.reasons) ? signal.reasons.filter((r) => typeof r === 'string' && r) : []
  if (signal.canary === true) return { level: 'likely', score, reasons }
  const timingOnly = signal.basis ? signal.basis === 'timing' : true
  if (timingOnly && score !== null && score > 0) return { level: 'possible', score, reasons }
  return null
}

/** Ids of the planted credentials or files this session used; empty when none. */
export function honeytokenIds(session) {
  const ids = session?.signals?.honeytoken?.token_ids
  if (!Array.isArray(ids)) return []
  return ids.filter((id) => id !== null && id !== undefined && id !== '').map(String)
}

const EVENT_TEXT = {
  ai_canary_triggered: 'AI-agent canary triggered',
  honeytoken_used: 'Honeytoken used',
  connection_refused: 'Connection refused by the engine',
  direct_tcpip: 'Asked the decoy to forward a connection',
}

function endpoint(host, port) {
  if (!host) return ''
  return port ? `${host}:${port}` : String(host)
}

function eventDetail(event) {
  if (event.event_type === 'ai_canary_triggered') {
    return [event.canary, event.channel && `via ${event.channel}`].filter(Boolean).join(' ')
  }
  if (event.event_type === 'honeytoken_used') {
    return [event.kind, event.token_id, event.detail].filter(Boolean).join(' · ')
  }
  if (event.event_type === 'direct_tcpip') {
    const to = endpoint(event.dest_host || event.host, event.dest_port || event.port)
    const from = endpoint(event.orig_host, event.orig_port)
    return [to && `to ${to}`, from && `from ${from}`].filter(Boolean).join(', ')
  }
  if (event.event_type === 'connection_refused') {
    const count = typeof event.count === 'number' && event.count > 1 ? `${event.count} connections` : ''
    return [count, event.reason || event.detail].filter(Boolean).join(' · ')
  }
  return ''
}

/**
 * The engine events worth a line of their own in the detail panel. Reads
 * `network_events` (and `events`, where an API sends that instead), and
 * ignores every other type.
 */
export function notableEvents(session) {
  const all = [...(session?.network_events || []), ...(session?.events || [])]
  const seen = new Set()
  const rows = []
  for (const event of all) {
    if (!event || typeof event !== 'object' || !EVENT_TEXT[event.event_type]) continue
    const detail = eventDetail(event)
    const at = [event.at, event.first_seen, event.timestamp].find((value) => typeof value === 'number')
    const key = `${event.event_type}|${detail}|${at ?? ''}`
    if (seen.has(key)) continue
    seen.add(key)
    rows.push({ type: event.event_type, text: EVENT_TEXT[event.event_type], detail, at: at ?? null })
  }
  return rows
}

/**
 * True for a row that is not a session at all: a connection the engine's
 * rate limit refused. It has no commands and no port, and counting it among
 * sessions would misstate what was captured.
 */
export function isRefusal(session) {
  return session?.signals?.refusal === true
}

/** How many connections a refusal row stands for; null when not recorded. */
export function refusalCount(session) {
  const event = (session?.network_events || []).find((item) => item?.event_type === 'connection_refused')
  return typeof event?.count === 'number' ? event.count : null
}

/**
 * The flow classifier's advisory reading. It no longer decides the category;
 * it is shown so a reader can see when it leans another way.
 */
export function flowAdvisory(session) {
  const flow = session?.signals?.verdict?.flow
  if (!flow || typeof flow !== 'object' || !flow.category) return null
  return {
    category: String(flow.category),
    score: typeof flow.confidence === 'number' ? flow.confidence : null,
    modelSource: flow.model_source ? String(flow.model_source) : null,
    disagrees: flow.disagrees === true,
  }
}

const STAGE_NAME = { llm: 'language model', chimera: 'language model', decider: 'decision model', triage: 'decision model' }

/**
 * Where a model stage read the session differently from the rules. The
 * stored category stays the rules'; the difference is what a reader needs.
 */
export function stageDisagreements(session) {
  const record = session?.signals?.disagreement
  if (!record || typeof record !== 'object') return []
  return Object.entries(record)
    .filter(([stage, value]) => stage !== 'rules' && value && typeof value === 'object' && value.category)
    .map(([stage, value]) => ({
      stage,
      name: STAGE_NAME[stage] || stage.replace(/_/g, ' '),
      category: String(value.category),
      rules: record.rules ? String(record.rules) : null,
    }))
}

/** True when the rules read only part of a session too long for their budget. */
export function rulesTruncated(session) {
  return session?.signals?.verdict?.rules_truncated === true
}

const FINGERPRINT_FIELDS = [
  ['ssh_client_version', 'SSH client', 'The version banner the client sent'],
  ['hassh', 'HASSH', 'Hash of the SSH algorithms the client offered; the same tool gives the same hash from any address'],
  ['hassh_server', 'HASSH server', 'Hash of the algorithms this decoy offered'],
  ['ja3', 'JA3', 'Hash of the TLS ClientHello'],
  ['ja4', 'JA4', 'TLS client fingerprint, successor to JA3'],
]

const FINGERPRINT_DETAILS = [
  ['hassh_algorithms', 'HASSH algorithms'],
  ['ja3_string', 'JA3 string'],
  ['telnet_options', 'Telnet options'],
  ['http_header_order', 'HTTP header order'],
]

function fingerprintValue(value) {
  if (value === null || value === undefined || value === '') return ''
  if (Array.isArray(value)) return value.map(String).join(', ')
  if (typeof value === 'object') return JSON.stringify(value)
  return String(value)
}

/**
 * Fingerprints present on a session, as rows to draw. `primary` are the short
 * hashes an analyst pivots on; `details` are the long strings behind them.
 */
export function fingerprintRows(session) {
  const source = session?.fingerprints
  if (!source || typeof source !== 'object') return { primary: [], details: [] }
  const primary = FINGERPRINT_FIELDS
    .map(([key, label, hint]) => ({ key, label, hint, value: fingerprintValue(source[key]) }))
    .filter((row) => row.value)
  const details = FINGERPRINT_DETAILS
    .map(([key, label]) => ({ key, label, value: fingerprintValue(source[key]) }))
    .filter((row) => row.value)
  return { primary, details }
}

/**
 * Fingerprints across several sessions of one address: each distinct value
 * with the number of sessions that carried it, most common first. Only the
 * short, comparable fingerprints are counted.
 */
export function aggregateFingerprints(sessions) {
  const counts = new Map()
  for (const session of sessions || []) {
    for (const row of fingerprintRows(session).primary) {
      const id = `${row.key}|${row.value}`
      const entry = counts.get(id) || { ...row, count: 0 }
      entry.count += 1
      counts.set(id, entry)
    }
  }
  return [...counts.values()].sort((a, b) => b.count - a.count || a.label.localeCompare(b.label))
}

/** How many of the given sessions carry each signal worth a badge. */
export function aggregateSignals(sessions) {
  const totals = { likelyAgent: 0, possibleAgent: 0, honeytoken: 0 }
  for (const session of sessions || []) {
    const agent = aiAgentReading(session)
    if (agent?.level === 'likely') totals.likelyAgent += 1
    if (agent?.level === 'possible') totals.possibleAgent += 1
    if (honeytokenIds(session).length > 0) totals.honeytoken += 1
  }
  return totals
}
