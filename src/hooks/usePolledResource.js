import { useCallback, useEffect, useRef, useState } from 'react'
import { useVisiblePoll } from './useVisiblePoll'

/**
 * Load a resource, keep it fresh, and say truthfully what is on screen.
 *
 * Every list page used to hold its own fetch, loading flag and error string,
 * and each got the same three things wrong:
 *
 *  - A failed load cleared the rows, so "the API is down" and "there is
 *    nothing to show" rendered as the same empty state.
 *  - A background poll committed whatever it received. A poll that started
 *    before a page or filter change landed afterwards and left the old rows
 *    under the new pager until the next tick.
 *  - A manual reload and a poll could finish out of order.
 *
 * Here a request carries the identity (`key`) of what was asked for, and its
 * response is committed only if that is still what the page is asking for and
 * no newer request has already committed.
 *
 * What the caller gets back:
 *
 *   data        the last good result for the current key, or null
 *   loading     nothing has come back for the current key yet
 *   failed      the current key has never loaded, and the last attempt failed
 *   stale       data is shown, but the last attempt to refresh it failed
 *   error       the message of that failure
 *   loadedAt    when `data` was received (epoch ms)
 *   refreshing  a manual reload is in flight
 *   reload()    reload now, visibly
 *   refresh()   reload now, silently (what the poll calls)
 *   mutate(fn)  apply a local change to `data`
 *
 * @param {(ctx: {signal: AbortSignal}) => Promise<any>} loader must resolve to a non-null value
 * @param {{key?: string, intervalMs?: number, enabled?: boolean}} options
 */
export function usePolledResource(loader, { key = '', intervalMs = 0, enabled = true } = {}) {
  const [state, setState] = useState({ key: null, hasData: false, data: null, error: null, loadedAt: null })
  const [refreshing, setRefreshing] = useState(false)

  const loaderRef = useRef(loader)
  const keyRef = useRef(key)
  const mounted = useRef(true)
  // Request counter, and the highest one that has committed a result.
  const issued = useRef(0)
  const committed = useRef(0)

  useEffect(() => {
    loaderRef.current = loader
  })

  const run = useCallback(async (requestKey, signal) => {
    const id = ++issued.current
    const superseded = () =>
      !mounted.current || requestKey !== keyRef.current || id < committed.current
    try {
      const data = await loaderRef.current({ signal })
      if (signal?.aborted || superseded()) return
      committed.current = id
      setState({ key: requestKey, hasData: true, data, error: null, loadedAt: Date.now() })
    } catch (err) {
      if (err?.name === 'AbortError' || signal?.aborted || superseded()) return
      committed.current = id
      const message = err?.message || 'Request failed'
      // Keep the last good data for this key; only the error is new.
      setState((previous) => (previous.key === requestKey
        ? { ...previous, error: message }
        : { key: requestKey, hasData: false, data: null, error: message, loadedAt: null }))
    }
  }, [])

  // The first load for a key. Aborted when the key changes or the page goes.
  useEffect(() => {
    mounted.current = true
    keyRef.current = key
    if (!enabled) return undefined
    const controller = new AbortController()
    // Deferred so no state update happens synchronously in the effect body.
    const timer = setTimeout(() => run(key, controller.signal), 0)
    return () => {
      controller.abort()
      clearTimeout(timer)
    }
  }, [key, enabled, run])

  useEffect(() => () => {
    mounted.current = false
  }, [])

  const refresh = useCallback(() => run(keyRef.current), [run])

  const reload = useCallback(async () => {
    setRefreshing(true)
    try {
      await run(keyRef.current)
    } finally {
      if (mounted.current) setRefreshing(false)
    }
  }, [run])

  useVisiblePoll(refresh, enabled ? intervalMs : 0, [key])

  const mutate = useCallback((change) => {
    setState((previous) => (previous.hasData ? { ...previous, data: change(previous.data) } : previous))
  }, [])

  // A result for another key is not this view's data. Deriving this during
  // render, instead of clearing state in an effect, means the old rows are
  // never painted under the new filters, not even for one frame.
  const current = enabled && state.key === key ? state : null
  const hasData = Boolean(current?.hasData)
  const error = current?.error || null

  return {
    data: hasData ? current.data : null,
    error,
    loading: enabled && !current,
    failed: Boolean(current) && !hasData && Boolean(error),
    stale: hasData && Boolean(error),
    loadedAt: hasData ? current.loadedAt : null,
    refreshing,
    reload,
    refresh,
    mutate,
  }
}
