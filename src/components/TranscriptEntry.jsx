import { clean } from '../lib/text'
import { headerPairs } from '../lib/transcript'

/*
 * One command and what the decoy answered.
 *
 * Shared by the transcript and the replay, so a command looks the same
 * whether it is being read or played back. Every string here was typed by
 * the attacker: it is sanitised before it is drawn, and each line is laid
 * out left-to-right in isolation so that a right-to-left run in one line
 * cannot reorder the text of another.
 */

/** Lines that reveal infrastructure, marked so the eye finds them first. */
function classifyLine(text) {
  if (/^--\d{4}-\d{2}-\d{2}/.test(text) || /\bHTTP request sent\b/.test(text)) {
    return 'fetch'
  }
  if (/No such file|command not found|Permission denied|denied/i.test(text)) {
    return 'refused'
  }
  return 'plain'
}

const LINE_COLOR = {
  fetch: 'var(--color-s3)',
  refused: 'var(--color-s4)',
  plain: 'var(--color-paper-2)',
}

/** The exit status, shown when the transcript recorded one that is not success. */
function ExitCode({ code }) {
  if (typeof code !== 'number' || code === 0) return null
  return (
    <span
      className="shrink-0 select-none text-[12px]"
      style={{ color: 'var(--color-s3)' }}
      title="The exit status the decoy shell returned for this command"
    >
      exit {code}
    </span>
  )
}

function Headers({ entry }) {
  const pairs = headerPairs(entry)
  if (!pairs.length) return null
  return (
    <details className="mt-0.5 pl-[calc(2ch+1.25rem)]">
      <summary className="cursor-pointer select-none text-[12px] text-paper-3 hover:text-paper">
        {pairs.length} request header{pairs.length === 1 ? '' : 's'}
      </summary>
      <dl className="mt-1 space-y-0.5">
        {pairs.map(([name, value], i) => (
          <div key={i} className="bidi-isolate whitespace-pre-wrap break-all">
            <dt className="inline text-paper-3">{name}: </dt>
            <dd className="inline text-paper-2">{value}</dd>
          </div>
        ))}
      </dl>
    </details>
  )
}

/**
 * @param {object} props
 * @param {object} props.entry       the transcript entry
 * @param {number} props.index       its position in the session, from 0
 * @param {string[]} props.lines     sanitised output lines to draw
 * @param {number} props.hiddenLines output lines not drawn
 * @param {Function} [props.onMore]  ask for more of this command's output
 * @param {React.ReactNode} [props.aside] shown at the right of the command line
 * @param {boolean} [props.current]  the command the replay has just reached
 */
export default function TranscriptEntry({ entry, index, lines, hiddenLines, onMore, aside, current = false }) {
  return (
    <div
      className={current ? 'rounded-[3px] bg-ink-2 px-1 -mx-1' : undefined}
      data-testid="transcript-entry"
    >
      <div className="flex items-baseline gap-2">
        <span
          aria-hidden
          className="select-none text-[12px] tabular-nums text-paper-3"
          style={{ minWidth: '2ch', textAlign: 'right' }}
        >
          {index + 1}
        </span>
        <span aria-hidden className="select-none" style={{ color: 'var(--color-s1)' }}>
          $
        </span>
        <span className="bidi-isolate min-w-0 flex-1 whitespace-pre-wrap break-all text-paper">
          {clean(entry.command)}
        </span>
        <ExitCode code={entry.exit_code} />
        {aside}
      </div>

      <Headers entry={entry} />

      {lines.length > 0 && (
        <div className="mt-0.5 pl-[calc(2ch+1.25rem)]">
          {lines.map((line, i) => (
            <div
              key={i}
              className="bidi-isolate whitespace-pre-wrap break-all"
              style={{ color: LINE_COLOR[classifyLine(line)] }}
            >
              {line || ' '}
            </div>
          ))}
          {hiddenLines > 0 && (
            onMore ? (
              <button
                type="button"
                onClick={onMore}
                className="mt-1 text-[12px] font-medium text-paper-2 transition-colors hover:text-paper"
              >
                Show more of this output ({hiddenLines.toLocaleString()} line{hiddenLines === 1 ? '' : 's'} not shown)
              </button>
            ) : (
              <p className="mt-1 text-[12px] text-paper-3">
                {hiddenLines.toLocaleString()} more line{hiddenLines === 1 ? '' : 's'} of output; read them in the transcript.
              </p>
            )
          )}
        </div>
      )}
    </div>
  )
}
