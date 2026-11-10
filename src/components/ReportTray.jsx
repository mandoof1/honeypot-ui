import { Loader2, X } from 'lucide-react'
import { useNow } from '../hooks/useNow'
import { formatDuration } from '../lib/format'

/*
 * The reports being written, and how each one ended.
 *
 * One line per report: what it covers, what the model is doing with it and
 * for how long, and afterwards whether it was saved or why it was not. A
 * failure stays here until dismissed, next to the report it belongs to,
 * instead of in a banner that the next action overwrites.
 */

const TONE = {
  working: 'var(--color-paper-2)',
  done: 'var(--color-s1)',
  failed: 'var(--color-s4)',
  cancelled: 'var(--color-paper-3)',
}

const HEADING = {
  working: 'Writing',
  done: 'Saved',
  failed: 'Failed',
  cancelled: 'Stopped',
}

function Job({ job, now, onCancel, onDismiss }) {
  const working = job.status === 'working'
  const elapsed = Math.max(0, ((job.finishedAt || now) - job.startedAt) / 1000)

  return (
    <li
      className="flex flex-wrap items-start gap-x-3 gap-y-1.5 px-4 py-2.5"
      data-testid="report-job"
      data-status={job.status}
    >
      <span className="mt-0.5 shrink-0" style={{ color: TONE[job.status] }} aria-hidden="true">
        {working
          ? <Loader2 className="h-3.5 w-3.5 animate-spin" strokeWidth={2} />
          : <span className="mt-1 block h-1.5 w-1.5 rounded-full" style={{ background: TONE[job.status] }} />}
      </span>
      <div className="min-w-0 flex-1">
        <p className="text-[13px] font-medium text-paper">
          {HEADING[job.status]}: {job.label}
          {job.sensitive && (
            <span className="tag ml-2 align-middle" style={{ color: 'var(--color-s3)' }}>
              includes original credentials
            </span>
          )}
        </p>
        <p
          className="mt-0.5 break-words text-[13px] leading-relaxed text-paper-2"
          role={job.status === 'failed' ? 'alert' : undefined}
          aria-live={job.status === 'failed' ? undefined : 'polite'}
        >
          {job.message}
        </p>
        {working && (
          <p className="readout mt-0.5 text-[12px] text-paper-3">
            {formatDuration(elapsed)} so far. The rest of the console stays usable; leaving this page stops the wait.
          </p>
        )}
      </div>
      {working ? (
        <button type="button" className="control shrink-0" onClick={() => onCancel(job.id)}>
          Stop waiting
        </button>
      ) : (
        <button
          type="button"
          onClick={() => onDismiss(job.id)}
          aria-label={`Dismiss ${job.label}`}
          className="shrink-0 rounded-[3px] p-1 text-paper-3 transition-colors hover:text-paper"
        >
          <X className="h-4 w-4" strokeWidth={1.75} />
        </button>
      )}
    </li>
  )
}

export default function ReportTray({ jobs, onCancel, onDismiss }) {
  const now = useNow(1000)
  if (!jobs.length) return null
  return (
    <section className="panel" aria-label="Investigation reports">
      <ul className="divide-y divide-line">
        {jobs.map((job) => (
          <Job key={job.id} job={job} now={now} onCancel={onCancel} onDismiss={onDismiss} />
        ))}
      </ul>
    </section>
  )
}
