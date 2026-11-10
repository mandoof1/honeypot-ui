import { test } from 'node:test'
import assert from 'node:assert/strict'
import {
  aggregateFingerprints, aggregateSignals, aiAgentReading, anomalyReading, fingerprintRows, flowAdvisory,
  honeytokenIds, isRefusal, notableEvents, probabilityText, refusalCount, rulesTruncated, scoreText,
  stageDisagreements, verdictSource,
} from '../src/lib/verdict.js'
import { TREND_CATEGORIES, axisTop, normaliseTrend, trendSummary } from '../src/lib/trends.js'

test('a verdict number is named for the stage that produced it', () => {
  const rules = verdictSource({ model_source: 'rules' })
  assert.equal(rules.label, 'Signature rules')
  assert.equal(rules.scoreLabel, 'Rule score')
  assert.match(rules.note, /not a probability/)
  assert.equal(verdictSource({ model_source: 'cicids2017' }).scoreLabel, 'Classifier score')
  assert.equal(verdictSource({ model_source: 'synthetic' }).scoreLabel, 'Placeholder score')
  assert.equal(verdictSource({}).label, 'Source not recorded')
  assert.equal(verdictSource(null).key, null)
  // A score is a decimal; only a probability is a percentage.
  assert.equal(scoreText(0.85), '0.85')
  assert.equal(scoreText(0), '0.00')
  assert.equal(scoreText(undefined), '—')
  assert.equal(probabilityText(0.94), '94%')
  assert.equal(probabilityText(null), '—')
})

test('an uncalibrated detector neither flags nor clears a session', () => {
  assert.deepEqual(
    anomalyReading({ is_anomalous: true, anomaly_score: 0.9, signals: { anomaly: { calibrated: false } } }),
    { state: 'not_calibrated', score: 0.9 },
  )
  assert.equal(anomalyReading({ is_anomalous: true, signals: { anomaly: { calibrated: true } } }).state, 'flagged')
  // Rows from before the signal existed keep the flag they were given.
  assert.equal(anomalyReading({ is_anomalous: true }).state, 'flagged')
  assert.equal(anomalyReading({ is_anomalous: false, anomaly_score: 0.1 }).state, 'normal')
  assert.deepEqual(anomalyReading(undefined), { state: 'normal', score: null })
})

test('a canary is a detection; timing alone is only a note', () => {
  const canary = aiAgentReading({ signals: { ai_agent: { score: 1, canary: true, basis: 'canary', reasons: ['canary triggered: note via shell', 7] } } })
  assert.deepEqual(canary, { level: 'likely', score: 1, reasons: ['canary triggered: note via shell'] })
  // The engine caps a timing score at 0.45; it must still earn the note.
  assert.equal(aiAgentReading({ signals: { ai_agent: { score: 0.25, canary: false, basis: 'timing' } } }).level, 'possible')
  assert.equal(aiAgentReading({ signals: { ai_agent: { score: 0.45, canary: false } } }).level, 'possible')
  assert.equal(aiAgentReading({ signals: { ai_agent: { score: 0, canary: false, basis: 'none' } } }), null)
  assert.equal(aiAgentReading({ signals: {} }), null)
  assert.equal(aiAgentReading({}), null)
})

test('honeytokens, refusals and the advisory readings tolerate missing fields', () => {
  assert.deepEqual(honeytokenIds({ signals: { honeytoken: { token_ids: ['aws-key-7', '', null, 12] } } }), ['aws-key-7', '12'])
  assert.deepEqual(honeytokenIds({ signals: { honeytoken: {} } }), [])
  assert.deepEqual(honeytokenIds(null), [])

  assert.equal(isRefusal({ signals: { refusal: true } }), true)
  assert.equal(isRefusal({ signals: { refusal: 'yes' } }), false)
  assert.equal(isRefusal({}), false)
  assert.equal(refusalCount({ network_events: [{ event_type: 'connection_refused', count: 40 }] }), 40)
  assert.equal(refusalCount({ network_events: [] }), null)

  assert.deepEqual(
    flowAdvisory({ signals: { verdict: { flow: { role: 'advisory', category: 'reconnaissance', confidence: 0.71, model_source: 'cicids2017', disagrees: true } } } }),
    { category: 'reconnaissance', score: 0.71, modelSource: 'cicids2017', disagrees: true },
  )
  assert.equal(flowAdvisory({ signals: { verdict: {} } }), null)
  assert.equal(rulesTruncated({ signals: { verdict: { rules_truncated: true } } }), true)
  assert.equal(rulesTruncated({}), false)

  assert.deepEqual(
    stageDisagreements({ signals: { disagreement: { rules: 'benign', llm: { category: 'exploitation' }, decider: { category: 'reconnaissance' }, junk: 'x' } } }),
    [
      { stage: 'llm', name: 'language model', category: 'exploitation', rules: 'benign' },
      { stage: 'decider', name: 'decision model', category: 'reconnaissance', rules: 'benign' },
    ],
  )
  assert.deepEqual(stageDisagreements({ signals: { disagreement: { rules: 'benign' } } }), [])
})

test('only the engine events worth a line are listed, with their own details', () => {
  const rows = notableEvents({
    network_events: [
      { event_type: 'file_download', url: 'http://x/a' },
      { event_type: 'ai_canary_triggered', canary: 'motd-note', channel: 'shell', at: 5 },
      { event_type: 'honeytoken_used', token_id: 'aws-key-7', kind: 'api_key' },
      { event_type: 'direct_tcpip', dest_host: '10.0.0.5', dest_port: 3306, orig_host: '127.0.0.1', orig_port: 40000 },
      { event_type: 'connection_refused', count: 40, first_seen: 9 },
      { event_type: 'connection_refused', count: 40, first_seen: 9 },
      null,
    ],
  })
  assert.deepEqual(rows.map((row) => [row.type, row.detail, row.at]), [
    ['ai_canary_triggered', 'motd-note via shell', 5],
    ['honeytoken_used', 'api_key · aws-key-7', null],
    ['direct_tcpip', 'to 10.0.0.5:3306, from 127.0.0.1:40000', null],
    ['connection_refused', '40 connections', 9],
  ])
  assert.deepEqual(notableEvents({}), [])
})

test('fingerprints are listed when present and counted across sessions', () => {
  const session = { fingerprints: { ssh_client_version: 'SSH-2.0-Go', hassh: 'abc', hassh_algorithms: 'x;y', telnet_options: [1, 3], ja3: '' } }
  const rows = fingerprintRows(session)
  assert.deepEqual(rows.primary.map((row) => [row.label, row.value]), [['SSH client', 'SSH-2.0-Go'], ['HASSH', 'abc']])
  assert.deepEqual(rows.details.map((row) => [row.label, row.value]), [['HASSH algorithms', 'x;y'], ['Telnet options', '1, 3']])
  assert.deepEqual(fingerprintRows({}), { primary: [], details: [] })
  assert.deepEqual(fingerprintRows({ fingerprints: 'nope' }), { primary: [], details: [] })

  const counted = aggregateFingerprints([session, session, { fingerprints: { hassh: 'zzz' } }, {}])
  assert.deepEqual(counted.map((row) => [row.key, row.value, row.count]), [
    ['hassh', 'abc', 2], ['ssh_client_version', 'SSH-2.0-Go', 2], ['hassh', 'zzz', 1],
  ])
  assert.deepEqual(
    aggregateSignals([
      { signals: { ai_agent: { canary: true, score: 1 } } },
      { signals: { ai_agent: { canary: false, score: 0.25, basis: 'timing' } } },
      { signals: { honeytoken: { token_ids: ['a'] } } },
      {},
    ]),
    { likelyAgent: 1, possibleAgent: 1, honeytoken: 1 },
  )
})

test('the trend series is normalised once, for the chart, the sentence and the table', () => {
  const trend = normaliseTrend({
    bucket: 'day',
    timezone: 'UTC',
    series: [
      { t: '2026-01-02T00:00:00Z', total: 10, benign: 1, reconnaissance: 5, exploitation: 3, exfiltration: 1 },
      { t: '2026-01-01T00:00:00Z', total: 4, reconnaissance: 3 },
      { t: '2026-01-03T00:00:00Z', total: 1, exploitation: 2 },
      { total: 99 },
    ],
  })
  assert.deepEqual(trend.points.map((point) => point.t.slice(0, 10)), ['2026-01-01', '2026-01-02', '2026-01-03'])
  // A day whose total is larger than its categories has unclassified sessions.
  assert.equal(trend.points[0].unclassified, 1)
  // A total smaller than its parts is raised to their sum, never drawn short.
  assert.equal(trend.points[2].total, 2)
  assert.equal(trend.total, 16)
  assert.equal(trend.max, 10)
  assert.equal(trend.busiest.t, '2026-01-02T00:00:00Z')
  assert.deepEqual(TREND_CATEGORIES.map((category) => trend.totals[category]), [1, 8, 5, 1])
  assert.equal(
    trendSummary(trend, 7),
    '16 sessions in the last 7 days (UTC days): reconnaissance 8 (50%), exploitation 5 (31%), benign 1 (6%), exfiltration 1 (6%). The busiest day was Jan 2 with 10.',
  )

  const empty = normaliseTrend({ series: [{ t: '2026-01-01T00:00:00Z', total: 0 }] })
  assert.equal(trendSummary(empty, 30), 'No sessions were captured in the last 30 days (UTC days).')
  assert.equal(trendSummary(normaliseTrend(null), 90), 'No daily figures were returned for the last 90 days.')
  assert.equal(axisTop(0), 4)
  assert.equal(axisTop(9), 10)
  assert.equal(axisTop(17), 20)
  assert.equal(axisTop(41), 50)
  assert.equal(axisTop(1200), 2000)
})
