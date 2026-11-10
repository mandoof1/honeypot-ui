import { useEffect, useState } from 'react'

/**
 * The current time, re-read on an interval, for labels that age while they
 * are on screen ("updated 12 s ago"). Reading the clock during render would
 * freeze such a label at whatever it said when the data arrived.
 */
export function useNow(intervalMs = 1000) {
  const [now, setNow] = useState(() => Date.now())

  useEffect(() => {
    const timer = setInterval(() => setNow(Date.now()), intervalMs)
    return () => clearInterval(timer)
  }, [intervalMs])

  return now
}
