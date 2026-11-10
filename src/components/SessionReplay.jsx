import { useEffect, useMemo, useRef, useState } from 'react'
import { Pause, Play, RotateCcw, SkipBack, SkipForward } from 'lucide-react'
import TranscriptEntry from './TranscriptEntry'
import Timestamp from './Timestamp'
import { formatDuration } from '../lib/format'
import {
  REPLAY_SPEEDS, advance, buildTimeline, formatClock, positionOf, visibleCount,
} from '../lib/replay'
import { outputLines } from '../lib/transcript'

/*
 * Timed replay.
 *
 * Plays the transcript back on the attacker's own clock, so the rhythm of a
 * session is visible: forty commands inside a second is a script, a pause to
 * read each output is a person. Reading a transcript top to bottom loses
 * that entirely.
 *
 * The replay is a view of evidence, so it invents nothing. Idle time that is
 * skipped is counted and shown at the point it was skipped. A session with
 * no per-command timestamps is stepped at a fixed pace and labelled as such.
 */

/** How long a pause is played before the rest is skipped. */
const MAX_GAP_SECONDS = 3
/** How often the clock advances while playing. */
const TICK_MS = 100
/** Commands kept on screen; older ones scroll off, as in a terminal. */
const TAIL = 30
/** Output lines drawn per command during replay. The transcript has the rest. */
const REPLAY_LINE_CAP = 40

export default function SessionReplay({ entries }) {
  const [compress, setCompress] = useState(true)
  const [speed, setSpeed] = useState(1)
  const [playing, setPlaying] = useState(false)
  const [position, setPosition] = useState(0)
  const viewport = useRef(null)

  const timeline = useMemo(
    () => buildTimeline(entries, { maxGapSeconds: compress ? MAX_GAP_SECONDS : null }),
    [entries, compress],
  )
  const count = visibleCount(timeline, position)
  const finished = position >= timeline.duration
  const total = timeline.steps.length

  // The clock. Measures real elapsed time on every tick instead of assuming
  // the interval was honoured, so a throttled tab does not slow the replay.
  const positionRef = useRef(0)
  useEffect(() => {
    positionRef.current = position
  })
  useEffect(() => {
    if (!playing) return undefined
    let last = Date.now()
    const timer = setInterval(() => {
      const now = Date.now()
      const next = advance(timeline, positionRef.current, ((now - last) / 1000) * speed)
      last = now
      positionRef.current = next
      setPosition(next)
      if (next >= timeline.duration) setPlaying(false)
    }, TICK_MS)
    return () => clearInterval(timer)
  }, [playing, speed, timeline])

  // Keep the newest command in view, as a terminal does.
  useEffect(() => {
    const node = viewport.current
    if (node) node.scrollTop = node.scrollHeight
  }, [count])

  const seekToEntry = (index) => {
    setPosition(positionOf(timeline, index))
  }

  const toggle = () => {
    if (finished) setPosition(0)
    setPlaying((value) => !value)
  }

  const changeCompression = (next) => {
    // Hold the same command on screen across the change of timeline.
    const rebuilt = buildTimeline(entries, { maxGapSeconds: next ? MAX_GAP_SECONDS : null })
    setCompress(next)
    setPosition(positionOf(rebuilt, Math.max(0, count - 1)))
  }

  if (total === 0) {
    return <p className="py-3 text-[13px] text-paper-3">There are no commands to replay.</p>
  }

  const shown = timeline.steps.slice(Math.max(0, count - TAIL), count)
  const scrolledOff = count - shown.length
  const currentStep = count > 0 ? timeline.steps[count - 1] : null
  const nextStep = count < total ? timeline.steps[count] : null
  const startedAt = timeline.timed ? entries[0].timestamp * 1000 : null

  return (
    <div data-testid="session-replay">
      <div className="flex flex-wrap items-center gap-2">
        <button
          type="button"
          className="control control-primary"
          onClick={toggle}
          aria-label={playing ? 'Pause replay' : finished ? 'Replay from the start' : 'Play replay'}
        >
          {playing
            ? <Pause className="h-3.5 w-3.5" strokeWidth={2} aria-hidden="true" />
            : <Play className="h-3.5 w-3.5" strokeWidth={2} aria-hidden="true" />}
          {playing ? 'Pause' : finished ? 'Replay' : 'Play'}
        </button>
        <button
          type="button"
          className="control px-1.5"
          onClick={() => { setPlaying(false); setPosition(0) }}
          aria-label="Back to the start"
        >
          <RotateCcw className="h-3.5 w-3.5" strokeWidth={2} aria-hidden="true" />
        </button>
        <button
          type="button"
          className="control px-1.5"
          onClick={() => seekToEntry(Math.max(0, count - 2))}
          disabled={count <= 1}
          aria-label="Previous command"
        >
          <SkipBack className="h-3.5 w-3.5" strokeWidth={2} aria-hidden="true" />
        </button>
        <button
          type="button"
          className="control px-1.5"
          onClick={() => seekToEntry(count)}
          disabled={count >= total}
          aria-label="Next command"
        >
          <SkipForward className="h-3.5 w-3.5" strokeWidth={2} aria-hidden="true" />
        </button>

        <label className="flex items-center gap-1.5">
          <span className="text-[12px] text-paper-3">Speed</span>
          <select
            className="control py-1"
            value={speed}
            onChange={(event) => setSpeed(Number(event.target.value))}
            aria-label="Replay speed"
          >
            {REPLAY_SPEEDS.map((value) => <option key={value} value={value}>{value}×</option>)}
          </select>
        </label>

        <span className="readout ml-auto text-[12px] text-paper-2" data-testid="replay-clock">
          {formatClock(position)} / {formatClock(timeline.duration)}
        </span>
      </div>

      <input
        type="range"
        min={0}
        max={Math.max(timeline.duration, 0.1)}
        step={0.1}
        value={Math.min(position, timeline.duration)}
        disabled={timeline.duration === 0}
        onChange={(event) => setPosition(Number(event.target.value))}
        aria-label="Replay position"
        aria-valuetext={`${formatClock(position)} of ${formatClock(timeline.duration)}, command ${count} of ${total}`}
        className="mt-2.5 w-full accent-paper"
      />

      <div className="mt-1.5 flex flex-wrap items-center justify-between gap-x-4 gap-y-1">
        <p className="text-[12px] text-paper-2" aria-live="polite" data-testid="replay-progress">
          {count} of {total} command{total === 1 ? '' : 's'}
          {currentStep && timeline.timed && (
            <span className="text-paper-3"> · {formatDuration(currentStep.realAt)} into the session</span>
          )}
        </p>
        {timeline.timed && (
          <label className="flex cursor-pointer items-center gap-1.5 text-[12px] text-paper-2">
            <input
              type="checkbox"
              checked={compress}
              onChange={(event) => changeCompression(event.target.checked)}
              className="h-3.5 w-3.5 accent-paper"
            />
            Skip idle time over {MAX_GAP_SECONDS} s
          </label>
        )}
      </div>

      {!timeline.timed && (
        <p className="mt-1.5 text-[12px] leading-relaxed text-paper-3">
          This session was recorded without per-command timestamps, so it is stepped at one command
          a second. The pacing here is not the attacker&rsquo;s.
        </p>
      )}
      {startedAt !== null && (
        <p className="mt-1.5 text-[12px] leading-relaxed text-paper-3">
          The first command was typed at <Timestamp value={startedAt} />.
        </p>
      )}
      {timeline.timed && compress && timeline.skipped > 0 && (
        <p className="mt-1.5 text-[12px] leading-relaxed text-paper-3">
          {formatDuration(timeline.skipped)} of idle time is skipped; the session really
          lasted {formatDuration(timeline.realDuration)} from first command to last.
        </p>
      )}

      <div
        ref={viewport}
        className="readout mt-2.5 h-72 overflow-y-auto rounded-[4px] border border-line bg-ink-0 p-3 text-[12px] leading-[1.6]"
        role="log"
        aria-label="Session replay output"
        aria-live="off"
        tabIndex={0}
      >
        <div className="space-y-2">
          {scrolledOff > 0 && (
            <p className="text-paper-3">
              {scrolledOff} earlier command{scrolledOff === 1 ? '' : 's'} scrolled off.
            </p>
          )}
          {shown.map((step) => {
            const entry = entries[step.index]
            const all = outputLines(entry)
            const lines = all.slice(0, REPLAY_LINE_CAP)
            return (
              <div key={step.index}>
                {step.skippedBefore > 0 && (
                  <p className="mb-2 text-center text-paper-3" data-testid="replay-gap">
                    {formatDuration(step.skippedBefore)} idle, skipped
                  </p>
                )}
                <TranscriptEntry
                  entry={entry}
                  index={step.index}
                  lines={lines}
                  hiddenLines={all.length - lines.length}
                  current={step.index === count - 1}
                  aside={timeline.timed ? (
                    <span className="shrink-0 select-none text-[12px] text-paper-3">
                      +{formatClock(step.realAt)}
                    </span>
                  ) : null}
                />
              </div>
            )
          })}
          {nextStep && !playing && (
            <p className="text-paper-3">
              Paused. Next command in {formatDuration(Math.max(0, nextStep.at - position))}.
            </p>
          )}
        </div>
      </div>
    </div>
  )
}
