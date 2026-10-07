import { test } from 'node:test'
import assert from 'node:assert/strict'
import { sanitizeForDisplay, hasHiddenCharacters, MARKER } from '../src/lib/text.js'
import { formatBytes, formatDuration, nodeLiveness, relativeTime, diskFreeRatio } from '../src/lib/format.js'

const ESC = String.fromCharCode(27)
const cp = (n) => String.fromCodePoint(n)

test('ANSI escape sequences are replaced with a visible marker', () => {
  const input = `${ESC}[31mroot${ESC}[0m@host${ESC}]0;title${String.fromCharCode(7)}`
  assert.equal(sanitizeForDisplay(input), `${MARKER}root${MARKER}@host${MARKER}`)
})

test('carriage returns and other C0 controls are marked, tabs and newlines kept', () => {
  const input = `ok\rOVERWRITTEN\tcol\nline${String.fromCharCode(0)}end`
  assert.equal(sanitizeForDisplay(input), `ok${MARKER}OVERWRITTEN\tcol\nline${MARKER}end`)
})

test('bidi overrides and zero-width characters are marked', () => {
  const input = `cat ${cp(0x202e)}txt.exe${cp(0x200b)}${cp(0x2066)}x${cp(0x2069)}${cp(0xfeff)}`
  assert.equal(sanitizeForDisplay(input), `cat ${MARKER}txt.exe${MARKER}${MARKER}x${MARKER}${MARKER}`)
})

test('ordinary text, including non-Latin scripts and emoji, is untouched', () => {
  for (const text of ['wget http://203.0.113.5/x.sh', 'مرحبا', 'données', '🔥 pwned', '']) {
    assert.equal(sanitizeForDisplay(text), text)
    assert.equal(hasHiddenCharacters(text), false)
  }
})

test('non-strings pass through unchanged', () => {
  assert.equal(sanitizeForDisplay(null), null)
  assert.equal(sanitizeForDisplay(undefined), undefined)
  assert.equal(sanitizeForDisplay(42), 42)
})

test('hasHiddenCharacters flags only strings that would change', () => {
  assert.equal(hasHiddenCharacters(`a${cp(0x200d)}b`), true)
  assert.equal(hasHiddenCharacters('a b'), false)
})

test('relativeTime rounds to the unit a reader expects', () => {
  const now = 1_700_000_000_000
  assert.equal(relativeTime(now - 10_000, now), 'just now')
  assert.equal(relativeTime(now - 3 * 60_000, now), '3 min ago')
  assert.equal(relativeTime(now - 2 * 3_600_000, now), '2 h ago')
  assert.equal(relativeTime(now - 3 * 86_400_000, now), '3 d ago')
  assert.equal(relativeTime(null, now), null)
  assert.equal(relativeTime('not a date', now), null)
})

test('formatDuration and formatBytes', () => {
  assert.equal(formatDuration(42), '42 s')
  assert.equal(formatDuration(125 * 60), '2 h 5 min')
  assert.equal(formatDuration(3 * 86400 + 3600), '3 d 1 h')
  assert.equal(formatDuration(undefined), '—')
  assert.equal(formatBytes(512), '512 B')
  assert.equal(formatBytes(3_400_000), '3.4 MB')
  assert.equal(formatBytes(4_000_000_000), '4 GB')
  assert.equal(formatBytes(120_000_000_000), '120 GB')
  assert.equal(formatBytes(-1), '—')
})

test('nodeLiveness prefers the API verdict and falls back to the heartbeat age', () => {
  const now = 1_700_000_000_000
  assert.deepEqual(nodeLiveness({ online: true, heartbeat_age_seconds: 20 }, now), { state: 'online', ageSeconds: 20 })
  assert.deepEqual(nodeLiveness({ online: false, heartbeat_age_seconds: 900 }, now), { state: 'stale', ageSeconds: 900 })
  // Old API: only last_heartbeat.
  const recent = new Date(now - 60_000).toISOString()
  const old = new Date(now - 3_600_000).toISOString()
  assert.equal(nodeLiveness({ last_heartbeat: recent }, now).state, 'online')
  assert.equal(nodeLiveness({ last_heartbeat: old }, now).state, 'stale')
  assert.deepEqual(nodeLiveness({}, now), { state: 'unknown', ageSeconds: null })
  assert.deepEqual(nodeLiveness(null, now), { state: 'unknown', ageSeconds: null })
})

test('diskFreeRatio tolerates missing or malformed disk blocks', () => {
  assert.equal(diskFreeRatio({ total_bytes: 1000, free_bytes: 50 }), 0.05)
  assert.equal(diskFreeRatio({ total_bytes: 0, free_bytes: 0 }), null)
  assert.equal(diskFreeRatio(null), null)
})
