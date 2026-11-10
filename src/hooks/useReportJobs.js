import { useCallback, useEffect, useRef, useState } from 'react'
import { api } from '../services/api'
import { saveBlob } from '../lib/download'

/**
 * Investigation reports in progress.
 *
 * A report is written by the local model and can take minutes. It used to be
 * awaited inside the button that asked for it: every export control on the
 * page stayed disabled until it finished, a failure appeared wherever the
 * reader happened to have scrolled, and leaving the page left a four-second
 * timer polling for up to twenty minutes.
 *
 * Here each report is a job with its own state, shown in a tray, so the page
 * stays usable while it is written. Every job owns an AbortController; they
 * are all aborted when the page unmounts, which clears their timers. Aborting
 * only stops the waiting: the job on the server carries on, and asking for
 * the same report again collects it.
 *
 * Job states: working, done, failed, cancelled.
 */
export function useReportJobs() {
  const [jobs, setJobs] = useState([])
  const controllers = useRef(new Map())
  const sequence = useRef(0)
  const mounted = useRef(true)

  useEffect(() => {
    mounted.current = true
    const active = controllers.current
    return () => {
      mounted.current = false
      active.forEach((controller) => controller.abort())
      active.clear()
    }
  }, [])

  const patch = useCallback((id, changes) => {
    if (!mounted.current) return
    setJobs((list) => list.map((job) => (job.id === id ? { ...job, ...changes } : job)))
  }, [])

  /**
   * @param {{label: string, params: object}} request `params` is what the
   * export route takes: the format, the filters or session ids, and
   * include_sensitive.
   */
  const start = useCallback(({ label, params }) => {
    const id = ++sequence.current
    const controller = new AbortController()
    controllers.current.set(id, controller)
    setJobs((list) => [
      ...list,
      {
        id,
        label,
        format: params.format,
        sensitive: params.include_sensitive === true,
        status: 'working',
        message: 'Sending the selected evidence to the local model.',
        startedAt: Date.now(),
        finishedAt: null,
      },
    ])

    api.export
      .sessions(params, {
        signal: controller.signal,
        onProgress: ({ message }) => patch(id, { message }),
      })
      .then(({ blob, filename, count, truncated }) => {
        if (controller.signal.aborted) return
        saveBlob(blob, filename)
        const scope = `${count.toLocaleString()} session${count === 1 ? '' : 's'}`
        patch(id, {
          status: 'done',
          finishedAt: Date.now(),
          message: truncated
            ? `Saved ${filename}. It covers the newest ${scope}; narrow the filters to report on the rest.`
            : `Saved ${filename}, covering ${scope}.`,
        })
      })
      .catch((error) => {
        if (error?.name === 'AbortError' || controller.signal.aborted) return
        patch(id, {
          status: 'failed',
          finishedAt: Date.now(),
          message: error?.message || 'The report could not be prepared.',
        })
      })
      .finally(() => {
        controllers.current.delete(id)
      })
    return id
  }, [patch])

  /** Stop waiting for a report. The server may still finish writing it. */
  const cancel = useCallback((id) => {
    controllers.current.get(id)?.abort()
    controllers.current.delete(id)
    patch(id, {
      status: 'cancelled',
      finishedAt: Date.now(),
      message: 'Stopped waiting. The report may still be finished on the server; ask for it again to collect it.',
    })
  }, [patch])

  const dismiss = useCallback((id) => {
    setJobs((list) => list.filter((job) => job.id !== id))
  }, [])

  return { jobs, start, cancel, dismiss }
}
