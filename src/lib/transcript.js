/*
 * How much of a transcript to draw.
 *
 * Output was capped per command but not in total, so a session of five
 * hundred commands with three hundred lines each still became a hundred and
 * fifty thousand nodes and froze the tab. The transcript is now drawn as a
 * window: commands in order, each with a line allowance, until a total line
 * budget is spent. The reader extends either limit on request, a step at a
 * time, so no single click can ask for everything at once.
 */

import { sanitizeForDisplay, sanitizeLine } from './text.js'

/** Output lines drawn for one command before the reader asks for more. */
export const ENTRY_LINE_CAP = 120
/** Lines drawn across the whole transcript before the reader asks for more. */
export const WINDOW_LINE_BUDGET = 600
/** How many more lines one "show more" adds, for a command or for the window. */
export const LINE_STEP = 600

/** A command's output as sanitised lines; empty when there was none. */
export function outputLines(entry) {
  const output = typeof entry?.output === 'string' ? entry.output : ''
  if (!output) return []
  return sanitizeForDisplay(output).replace(/\n+$/, '').split('\n')
}

/**
 * @param {Array} entries transcript entries, in order
 * @param {{budget?: number, allowances?: Object<number, number>}} options
 *   `budget` is the total line budget; `allowances[index]` raises the line
 *   allowance of one command above the default cap.
 * @returns {{rows: Array<{index:number, entry:object, lines:string[], hiddenLines:number}>,
 *            hiddenEntries: number, shownLines: number}}
 */
export function windowTranscript(entries, { budget = WINDOW_LINE_BUDGET, allowances = {} } = {}) {
  const list = Array.isArray(entries) ? entries : []
  const rows = []
  let shownLines = 0

  for (let index = 0; index < list.length; index += 1) {
    // Always draw the first command, however small the budget.
    if (rows.length > 0 && shownLines >= budget) break
    const all = outputLines(list[index])
    const allowance = Math.max(ENTRY_LINE_CAP, allowances[index] || 0)
    const lines = all.length > allowance ? all.slice(0, allowance) : all
    rows.push({ index, entry: list[index], lines, hiddenLines: all.length - lines.length })
    // The command itself is a line too.
    shownLines += 1 + lines.length
  }

  return { rows, hiddenEntries: list.length - rows.length, shownLines }
}

/** Request headers of an HTTP transcript entry as sanitised `[name, value]` pairs. */
export function headerPairs(entry) {
  const headers = entry?.headers
  if (!headers || typeof headers !== 'object' || Array.isArray(headers)) return []
  return Object.entries(headers).map(([name, value]) => [
    sanitizeLine(String(name)),
    sanitizeLine(Array.isArray(value) ? value.join(', ') : String(value ?? '')),
  ])
}
