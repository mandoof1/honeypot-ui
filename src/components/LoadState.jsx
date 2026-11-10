import { RotateCw } from 'lucide-react'
import { usePreferences } from '../context/usePreferences'

/*
 * The two states a failed request can leave a view in.
 *
 * They used to be drawn as one: the rows were cleared and the empty state
 * shown, so "the API did not answer" read as "there is nothing here" — and on
 * the overview, as "0 alerts need review". A failure is not an absence.
 *
 *   LoadFailure  nothing has ever loaded for this view. Says so, in the place
 *                the data would have been, with the one action that may help.
 *   StaleNotice  something loaded earlier and the refresh failed. The earlier
 *                data stays on screen, marked with when it is from.
 */

export function LoadFailure({ what, error, onRetry, className = 'px-4 py-14' }) {
  return (
    <div role="alert" className={`text-center ${className}`}>
      <span className="mx-auto block h-2 w-2 rounded-full bg-s4" aria-hidden="true" />
      <p className="mt-3.5 font-display text-[15px] font-semibold text-paper">
        Could not load {what}
      </p>
      <p className="readout mx-auto mt-1 max-w-sm break-words text-[13px] leading-relaxed text-paper-2">
        {error}
      </p>
      <p className="mx-auto mt-1 max-w-sm text-[13px] leading-relaxed text-paper-3">
        Nothing is shown because nothing was received. This is not the same as there being none.
      </p>
      {onRetry && (
        <button type="button" onClick={onRetry} className="control mt-4">
          <RotateCw className="h-3.5 w-3.5" strokeWidth={2} />
          Try again
        </button>
      )}
    </div>
  )
}

export function StaleNotice({ what = 'This view', error, loadedAt, onRetry, className = '' }) {
  const { formatTime } = usePreferences()
  return (
    <div
      role="alert"
      data-testid="stale-notice"
      className={`flex flex-wrap items-center gap-x-3 gap-y-1.5 rounded-[4px] border border-s3/60 bg-ink-1 px-4 py-2.5 ${className}`}
    >
      <span className="h-1.5 w-1.5 shrink-0 rounded-full bg-s3" aria-hidden="true" />
      <p className="min-w-0 flex-1 text-[13px] text-paper-2">
        <span className="font-semibold text-paper">{what} may be out of date.</span>{' '}
        The last refresh failed{error ? <> (<span className="readout break-words">{error}</span>)</> : ''};
        showing what was received at{' '}
        <span className="readout text-paper">{loadedAt ? formatTime(loadedAt, 'time') : 'an earlier time'}</span>.
      </p>
      {onRetry && (
        <button type="button" onClick={onRetry} className="control shrink-0">
          <RotateCw className="h-3.5 w-3.5" strokeWidth={2} />
          Try again
        </button>
      )}
    </div>
  )
}
