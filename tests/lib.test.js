import { test } from 'node:test'
import assert from 'node:assert/strict'
import { sanitizeForDisplay, sanitizeLine, MARKER } from '../src/lib/text.js'
import { formatDuration, formatSessionDuration, relativeTime, updatedAgo } from '../src/lib/format.js'
import {
  formatTimestamp, formatUtcDay, fromInputValue, offsetLabel, shiftHourBuckets, toInputValue,
} from '../src/lib/time.js'
import {
  TACTICS, describeTactic, heatStep, normaliseMatrix, orderTactics, techniqueUrl,
} from '../src/lib/attack.js'
import { advance, buildTimeline, formatClock, positionOf, visibleCount } from '../src/lib/replay.js'
import { ENTRY_LINE_CAP, headerPairs, windowTranscript } from '../src/lib/transcript.js'
import { canonicalQuery, describeQuery, listSaved, removeSaved, saveSearch } from '../src/lib/savedSearches.js'
import { DEFAULT_PREFS, normalisePrefs, readPrefs, writePrefs } from '../src/lib/prefs.js'
import {
  blocklistOffer, indicatorLinks, isAttackerSource, isReferencedAddress,
} from '../src/lib/indicators.js'

const cp = (n) => String.fromCodePoint(n)

function memoryStorage() {
  const data = new Map()
  return {
    getItem: (key) => data.get(key) ?? null,
    setItem: (key, value) => data.set(key, String(value)),
    removeItem: (key) => data.delete(key),
  }
}

// ---- text -----------------------------------------------------------------

test('a single-line value cannot carry a second line or a tab', () => {
  assert.equal(sanitizeLine('203.0.113.7\nrm -rf /'), `203.0.113.7${MARKER}rm -rf /`)
  assert.equal(sanitizeLine('a\tb'), `a${MARKER}b`)
  // The multi-line form keeps both: they are the structure of a transcript.
  assert.equal(sanitizeForDisplay('a\tb\nc'), 'a\tb\nc')
  assert.equal(sanitizeLine(42), 42)
})

test('invisible characters outside the basic plane and the newer blanks are marked', () => {
  const hidden = [
    0x061c, // Arabic letter mark
    0x00ad, // soft hyphen
    0x180e, // Mongolian vowel separator
    0x3164, // Hangul filler
    0xfe0f, // variation selector 16
    0xe0001, // language tag
    0xe0041, // tag latin capital A
    0xe0100, // variation selector 17
  ]
  for (const code of hidden) {
    assert.equal(sanitizeForDisplay(`a${cp(code)}b`), `a${MARKER}b`, `U+${code.toString(16)}`)
  }
  // One marker per character, not one per UTF-16 code unit.
  assert.equal(sanitizeForDisplay(cp(0xe0041)).length, 1)
})

// ---- format ---------------------------------------------------------------

test('durations never print a unit at its own limit', () => {
  assert.equal(formatDuration(59.6), '1 min')
  assert.equal(formatDuration(59.4), '59 s')
  assert.equal(formatSessionDuration(59.96), '1m 0s')
  assert.equal(formatSessionDuration(119.6), '2m 0s')
  assert.equal(formatSessionDuration(7500), '2h 5m')
  assert.equal(formatSessionDuration(0.9996), '1.0 s')
  assert.equal(formatSessionDuration(0.5), '500 ms')
  const now = 1_700_000_000_000
  assert.equal(relativeTime(now - 3570_000, now), '1 h ago')
  assert.equal(relativeTime(now - 23.8 * 3600_000, now), '1 d ago')
})

test('updatedAgo counts seconds, then minutes', () => {
  const now = 1_700_000_000_000
  assert.equal(updatedAgo(now - 1000, now), 'updated just now')
  assert.equal(updatedAgo(now - 12_000, now), 'updated 12 s ago')
  assert.equal(updatedAgo(now - 59_600, now), 'updated 1 min ago')
  assert.equal(updatedAgo(now - 5 * 60_000, now), 'updated 5 min ago')
  assert.equal(updatedAgo(null, now), 'not loaded yet')
})

// ---- time -----------------------------------------------------------------

test('timestamps are printed in UTC with the zone named', () => {
  const iso = '2026-01-01T10:00:05Z'
  assert.equal(formatTimestamp(iso, { zone: 'utc' }), '2026-01-01 10:00:05 UTC')
  assert.equal(formatTimestamp(iso, { zone: 'utc', style: 'minute' }), '2026-01-01 10:00 UTC')
  assert.equal(formatTimestamp(iso, { zone: 'utc', style: 'short' }), 'Jan 1, 10:00 UTC')
  assert.equal(formatTimestamp(iso, { zone: 'utc', style: 'date' }), '2026-01-01')
  assert.equal(formatTimestamp(iso, { zone: 'utc', style: 'time', withZone: false }), '10:00:05')
  assert.equal(formatTimestamp(null), '—')
  assert.equal(formatTimestamp('not a date'), '—')
  assert.equal(formatUtcDay('2026-03-09T00:00:00Z'), 'Mar 9')
})

test('offsets are labelled the way they are spoken', () => {
  assert.equal(offsetLabel(0), 'UTC')
  assert.equal(offsetLabel(240), 'UTC+4')
  assert.equal(offsetLabel(330), 'UTC+5:30')
  assert.equal(offsetLabel(-180), 'UTC−3')
})

test('date inputs round-trip through the display zone', () => {
  const iso = '2026-01-01T10:00:00.000Z'
  assert.equal(toInputValue(iso, 'utc'), '2026-01-01T10:00')
  assert.equal(fromInputValue('2026-01-01T10:00', 'utc'), iso)
  assert.equal(fromInputValue(toInputValue(iso, 'local'), 'local'), iso)
  assert.equal(fromInputValue('', 'utc'), '')
  assert.equal(toInputValue('nonsense', 'utc'), '')
})

test('UTC hour buckets shift to the display zone and say when the shift is inexact', () => {
  const dubai = shiftHourBuckets({ '00': 5, 23: 2 }, 240)
  assert.equal(dubai.values[4], 5)
  assert.equal(dubai.values[3], 2)
  assert.equal(dubai.exact, true)
  assert.equal(dubai.values.reduce((a, b) => a + b, 0), 7)
  const west = shiftHourBuckets({ '01': 3 }, -180)
  assert.equal(west.values[22], 3)
  assert.equal(shiftHourBuckets({ '00': 1 }, 330).exact, false)
  assert.deepEqual(shiftHourBuckets(undefined, 0).values, new Array(24).fill(0))
})

// ---- ATT&CK ---------------------------------------------------------------

test('tactics are named and put in kill-chain order', () => {
  assert.equal(describeTactic('TA0002').name, 'Execution')
  assert.equal(describeTactic({ id: 'ta0010' }).name, 'Exfiltration')
  assert.equal(describeTactic('Persistence').id, 'TA0003')
  const ordered = orderTactics(['TA0010', 'TA0002', 'TA0043', 'TA0002', 'TA9999'])
  assert.deepEqual(ordered.map((t) => t.name), ['Reconnaissance', 'Execution', 'Exfiltration', 'TA9999'])
  assert.equal(ordered.at(-1).known, false)
  // Command and Control comes before Exfiltration in the matrix, despite its id.
  const ids = TACTICS.map((t) => t.id)
  assert.ok(ids.indexOf('TA0011') < ids.indexOf('TA0010'))
})

test('an unverified or malformed technique is never linked', () => {
  assert.equal(techniqueUrl({ id: 'T1059.004' }), 'https://attack.mitre.org/techniques/T1059/004/')
  assert.equal(techniqueUrl({ id: 'T1105', verified: true }), 'https://attack.mitre.org/techniques/T1105/')
  assert.equal(techniqueUrl({ id: 'T1059.004', verified: false }), null)
  assert.equal(techniqueUrl({ id: 'T9999/../../x' }), null)
  assert.equal(techniqueUrl({}), null)
})

test('the matrix is sorted, counted and tolerant of a partial payload', () => {
  const matrix = normaliseMatrix({
    sessions: 12,
    tactics: [
      { id: 'TA0010', name: 'Exfiltration', techniques: [{ id: 'T1041', name: 'Exfil', count: 2 }] },
      { id: 'TA0002', name: 'Execution', techniques: [
        { id: 'T1059', name: 'Shell', count: '3' },
        { id: 'T1059.004', name: 'Unix Shell', count: 9, verified: false },
        { name: 'no id' },
      ] },
    ],
  })
  // The API's own order is kept: it is the kill-chain order of its catalog.
  assert.deepEqual(matrix.columns.map((c) => c.name), ['Exfiltration', 'Execution'])
  assert.deepEqual(matrix.columns[1].techniques.map((t) => t.id), ['T1059.004', 'T1059'])
  assert.equal(matrix.columns[1].techniques[0].verified, false)
  assert.equal(matrix.max, 9)
  assert.equal(matrix.techniqueCount, 3)
  assert.equal(matrix.sessions, 12)
  assert.deepEqual(normaliseMatrix(null), { columns: [], max: 0, techniqueCount: 0, sessions: null, version: null })
  assert.equal(heatStep(0, 9), 0)
  assert.equal(heatStep(1, 9), 1)
  assert.equal(heatStep(9, 9), 4)
})

// ---- replay ---------------------------------------------------------------

test('the replay keeps the attacker\'s pauses and compresses long idle gaps', () => {
  const entries = [{ timestamp: 100 }, { timestamp: 101 }, { timestamp: 161 }, { timestamp: 161.5 }]
  const timeline = buildTimeline(entries, { maxGapSeconds: 3 })
  assert.equal(timeline.timed, true)
  assert.deepEqual(timeline.steps.map((s) => s.at), [0, 1, 4, 4.5])
  assert.equal(timeline.steps[2].skippedBefore, 57)
  assert.equal(timeline.skipped, 57)
  assert.equal(timeline.duration, 4.5)
  assert.equal(timeline.realDuration, 61.5)

  const raw = buildTimeline(entries, { maxGapSeconds: null })
  assert.equal(raw.duration, 61.5)
  assert.equal(raw.skipped, 0)

  assert.equal(visibleCount(timeline, 0), 1)
  assert.equal(visibleCount(timeline, 0.99), 1)
  assert.equal(visibleCount(timeline, 1), 2)
  assert.equal(visibleCount(timeline, 4.5), 4)
  assert.equal(positionOf(timeline, 2), 4)
  assert.equal(positionOf(timeline, 99), 4.5)
  assert.equal(advance(timeline, 4, 10), 4.5)
  assert.equal(advance(timeline, 1, -5), 0)
})

test('a session without timestamps is stepped at a fixed pace and says so', () => {
  const timeline = buildTimeline([{ command: 'id' }, { command: 'ls', timestamp: null }, { command: 'w' }])
  assert.equal(timeline.timed, false)
  assert.deepEqual(timeline.steps.map((s) => s.at), [0, 1, 2])
  // A clock that runs backwards is not a pause.
  const backwards = buildTimeline([{ timestamp: 50 }, { timestamp: 40 }])
  assert.deepEqual(backwards.steps.map((s) => s.at), [0, 0])
  assert.deepEqual(buildTimeline([]).steps, [])
  assert.equal(formatClock(7), '0:07')
  assert.equal(formatClock(754), '12:34')
  assert.equal(formatClock(3729), '1:02:09')
})

// ---- transcript -----------------------------------------------------------

test('a long transcript is windowed in total, not only per command', () => {
  const big = Array.from({ length: 300 }, (_, i) => `line ${i}`).join('\n')
  const entries = Array.from({ length: 50 }, (_, i) => ({ command: `cmd ${i}`, output: big }))
  const first = windowTranscript(entries, { budget: 600 })
  assert.equal(first.rows[0].lines.length, ENTRY_LINE_CAP)
  assert.equal(first.rows[0].hiddenLines, 300 - ENTRY_LINE_CAP)
  assert.ok(first.rows.length < entries.length)
  assert.equal(first.hiddenEntries, entries.length - first.rows.length)
  assert.ok(first.shownLines <= 600 + ENTRY_LINE_CAP + 1)

  const wider = windowTranscript(entries, { budget: 1200, allowances: { 0: 250 } })
  assert.equal(wider.rows[0].lines.length, 250)
  assert.ok(wider.rows.length > first.rows.length)
  // The first command is always drawn, whatever the budget.
  assert.equal(windowTranscript(entries, { budget: 0 }).rows.length, 1)
  assert.deepEqual(windowTranscript(null).rows, [])
})

test('transcript output and request headers are sanitised', () => {
  const ESC = String.fromCharCode(27)
  const { rows } = windowTranscript([{ command: 'x', output: `ok${ESC}[2Kgone\n` }])
  assert.deepEqual(rows[0].lines, [`ok${MARKER}gone`])
  assert.deepEqual(
    headerPairs({ headers: { 'User-Agent': `curl\r\nX-Injected: 1`, Accept: ['a', 'b'] } }),
    [['User-Agent', `curl${MARKER}${MARKER}X-Injected: 1`], ['Accept', 'a, b']],
  )
  assert.deepEqual(headerPairs({ headers: 'nope' }), [])
})

// ---- saved searches and preferences ---------------------------------------

test('saved searches drop the page and the open row, and replace by name', () => {
  assert.equal(canonicalQuery('?protocol=ssh&page=3&session=9&status='), 'protocol=ssh')
  assert.equal(canonicalQuery('?b=2&a=1'), 'a=1&b=2')
  assert.equal(describeQuery('attack_category=exploitation&protocol=ssh'), 'attack category: exploitation · protocol: ssh')
  assert.equal(describeQuery(''), 'no filters')

  const storage = memoryStorage()
  assert.equal(saveSearch(storage, 'sessions', '   ', '?protocol=ssh'), null)
  saveSearch(storage, 'sessions', 'SSH', '?protocol=ssh&page=2', 1)
  saveSearch(storage, 'sessions', 'Web', '?protocol=http', 2)
  saveSearch(storage, 'sessions', 'ssh', '?protocol=ssh&status=active', 3)
  const saved = listSaved(storage, 'sessions')
  assert.deepEqual(saved.map((s) => s.name), ['ssh', 'Web'])
  assert.equal(saved[0].query, 'protocol=ssh&status=active')
  assert.deepEqual(listSaved(storage, 'alerts'), [])
  assert.deepEqual(removeSaved(storage, 'sessions', 'Web').map((s) => s.name), ['ssh'])

  storage.setItem('hs_saved_searches', '{not json')
  assert.deepEqual(listSaved(storage, 'sessions'), [])
})

test('display preferences survive anything found in storage', () => {
  const storage = memoryStorage()
  assert.deepEqual(readPrefs(storage), { ...DEFAULT_PREFS })
  writePrefs(storage, { theme: 'light', zone: 'utc', presentation: true })
  assert.deepEqual(readPrefs(storage), { theme: 'light', zone: 'utc', presentation: true })
  assert.deepEqual(normalisePrefs({ theme: 'neon', zone: 'mars', presentation: 'yes' }), { ...DEFAULT_PREFS })
  storage.setItem('hs_display', '[')
  assert.deepEqual(readPrefs(storage), { ...DEFAULT_PREFS })
  assert.deepEqual(readPrefs(null), { ...DEFAULT_PREFS })
})

// ---- indicators -----------------------------------------------------------

test('only a source address links to an attacker profile', () => {
  assert.equal(isAttackerSource({ type: 'ip', value: '203.0.113.7' }), true)
  assert.equal(isAttackerSource({ type: 'ip', value: '8.8.8.8', tags: ['referenced_ip'] }), false)
  assert.equal(isAttackerSource({ type: 'referenced_ip', value: '8.8.8.8' }), false)
  assert.equal(isReferencedAddress({ type: 'referenced_ip', value: '8.8.8.8' }), true)
  assert.equal(isReferencedAddress({ type: 'ip', value: '8.8.8.8', tags: ['referenced_ip'] }), true)

  assert.equal(indicatorLinks({ type: 'ip', value: '203.0.113.7' }).profile, '/attackers/203.0.113.7')
  const referenced = indicatorLinks({ type: 'referenced_ip', value: '8.8.8.8' })
  assert.equal(referenced.profile, undefined)
  assert.equal(referenced.sessions, '/sessions?search=8.8.8.8')
  assert.deepEqual(indicatorLinks({ type: 'tool', value: 'nmap' }), {})
  assert.equal(indicatorLinks({ type: 'file_hash', value: 'A'.repeat(64) }).payload, `/payloads?sha=${'a'.repeat(64)}`)
  assert.equal(indicatorLinks({ type: 'url', value: 'http://x/a b' }).sessions, '/sessions?search=http%3A%2F%2Fx%2Fa%20b')
})

test('a blocklist is never built from referenced addresses or from one sighting', () => {
  assert.deepEqual(blocklistOffer('', 1), { iocType: 'ip', minSessions: 2, label: 'Blocklist · source addresses' })
  assert.equal(blocklistOffer('ip', 5).minSessions, 5)
  assert.equal(blocklistOffer('domain', 1).iocType, 'domain')
  assert.equal(blocklistOffer('referenced_ip', 10).iocType, undefined)
  assert.match(blocklistOffer('referenced_ip', 10).reason, /never offered as a blocklist/)
  assert.match(blocklistOffer('tool', 2).reason, /not something a firewall/)
})
