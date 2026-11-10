/*
 * Session replay timeline.
 *
 * A transcript is a list of commands; a replay puts them back on the clock.
 * Each entry carries the moment it was typed (epoch seconds), so the gaps
 * between entries are the attacker's own pauses: a script fires forty
 * commands in a second, a person reads the output first.
 *
 * Real sessions also sit idle for minutes, which nobody wants to watch, so a
 * gap longer than `maxGapSeconds` is played at that length and the time
 * skipped is kept on the step, to be shown rather than hidden.
 *
 * Sessions recorded before timestamps were captured have none. They are
 * stepped at a fixed pace and the timeline says `timed: false`, so the player
 * can state that the pacing is not the attacker's.
 */

export const REPLAY_SPEEDS = [0.5, 1, 2, 4, 8]

/** Pace used when the entries carry no usable timestamps. */
export const UNTIMED_STEP_SECONDS = 1

const usable = (value) => typeof value === 'number' && Number.isFinite(value) && value > 0

/**
 * @param {Array<{timestamp?: number}>} entries transcript entries, in order
 * @param {{maxGapSeconds?: number|null}} options null or 0 disables compression
 * @returns {{steps: Array, duration: number, realDuration: number, timed: boolean, skipped: number}}
 */
export function buildTimeline(entries, { maxGapSeconds = 3 } = {}) {
  const list = Array.isArray(entries) ? entries : []
  const timed = list.length > 0 && list.every((entry) => usable(entry?.timestamp))
  const limit = usable(maxGapSeconds) ? maxGapSeconds : null

  const steps = []
  let at = 0
  let realAt = 0
  let skipped = 0
  for (let index = 0; index < list.length; index += 1) {
    let gap = 0
    if (index > 0) {
      // A clock that steps backwards between two entries is treated as no
      // pause at all, rather than rewinding the replay.
      gap = timed ? Math.max(0, list[index].timestamp - list[index - 1].timestamp) : UNTIMED_STEP_SECONDS
    }
    const played = limit !== null && gap > limit ? limit : gap
    at += played
    realAt += gap
    skipped += gap - played
    steps.push({ index, at, realAt, gap, skippedBefore: gap - played })
  }
  return {
    steps,
    duration: steps.length ? steps[steps.length - 1].at : 0,
    realDuration: steps.length ? steps[steps.length - 1].realAt : 0,
    timed,
    skipped,
  }
}

/** How many entries have been typed by `position` seconds into the replay. */
export function visibleCount(timeline, position) {
  const steps = timeline?.steps || []
  let count = 0
  for (const step of steps) {
    if (step.at <= position + 1e-9) count += 1
    else break
  }
  return count
}

/** The replay position at which entry `index` appears, clamped to the timeline. */
export function positionOf(timeline, index) {
  const steps = timeline?.steps || []
  if (!steps.length) return 0
  const clamped = Math.min(steps.length - 1, Math.max(0, index))
  return steps[clamped].at
}

/** Move a position by `deltaSeconds`, kept inside the timeline. */
export function advance(timeline, position, deltaSeconds) {
  const duration = timeline?.duration || 0
  return Math.min(duration, Math.max(0, position + deltaSeconds))
}

/** "0:07", "12:34", "1:02:09": a position on the replay clock. */
export function formatClock(seconds) {
  const total = Math.max(0, Math.floor(Number(seconds) || 0))
  const hours = Math.floor(total / 3600)
  const minutes = Math.floor((total % 3600) / 60)
  const rest = String(total % 60).padStart(2, '0')
  if (hours > 0) return `${hours}:${String(minutes).padStart(2, '0')}:${rest}`
  return `${minutes}:${rest}`
}
