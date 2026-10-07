import { useEffect, useRef } from 'react'

/**
 * Run `fn` now and then every `intervalMs`, but only while the tab is visible.
 *
 * Three pages polled on a timer regardless of whether anyone could see them,
 * so a console left open in a background tab kept the API busy for nothing.
 * When the tab becomes visible again the poll fires immediately, so the
 * reader never looks at data older than one interval.
 *
 * Overlapping requests are suppressed: if the previous tick has not settled,
 * the next one is skipped rather than queued behind it.
 */
export function useVisiblePoll(fn, intervalMs, deps = []) {
  const fnRef = useRef(fn)
  useEffect(() => {
    fnRef.current = fn
  })

  useEffect(() => {
    if (!intervalMs || intervalMs <= 0) return undefined
    let inFlight = false
    let cancelled = false

    const tick = async () => {
      if (cancelled || inFlight || document.hidden) return
      inFlight = true
      try {
        await fnRef.current()
      } finally {
        inFlight = false
      }
    }

    const interval = setInterval(tick, intervalMs)
    const onVisible = () => { if (!document.hidden) tick() }
    document.addEventListener('visibilitychange', onVisible)
    return () => {
      cancelled = true
      clearInterval(interval)
      document.removeEventListener('visibilitychange', onVisible)
    }
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [intervalMs, ...deps])
}
