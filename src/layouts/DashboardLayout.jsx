import { Outlet, NavLink, useLocation } from 'react-router-dom'
import { Suspense, useCallback, useEffect, useRef, useState } from 'react'
import { Bell, ChevronUp, LogOut, Menu, X } from 'lucide-react'
import { useAuth } from '../context/useAuth'
import DisplayControls from '../components/DisplayControls'
import ErrorBoundary from '../components/ErrorBoundary'
import { LoadingRegion } from '../components/Loading'
import { api } from '../services/api'
import { useVisiblePoll } from '../hooks/useVisiblePoll'
import { nodeLiveness, relativeTime } from '../lib/format'
import { cleanLine } from '../lib/text'

const NAV = [
  { to: '/', label: 'Overview' },
  { to: '/sessions', label: 'Sessions' },
  { to: '/alerts', label: 'Alerts' },
  { to: '/indicators', label: 'Indicators' },
  { to: '/payloads', label: 'Payloads' },
  { to: '/map', label: 'Origins' },
  { to: '/settings', label: 'Settings' },
]

const STATUS_POLL_MS = 30000
const PRODUCT = 'HoneySentinel'

/** The name of the view at `pathname`, for the tab title and for assistive technology. */
function pageName(pathname) {
  if (pathname.startsWith('/attackers/')) {
    const address = decodeURIComponent(pathname.slice('/attackers/'.length))
    return `Address ${cleanLine(address)}`
  }
  const match = NAV.find(({ to }) => to === pathname)
  return match ? match.label : 'Console'
}

/** The console's mark: a cell, drawn rather than pulled from an icon set. */
function Mark({ className = '' }) {
  return (
    <svg viewBox="0 0 24 24" className={className} aria-hidden="true" fill="none">
      <path
        d="M12 2.4 20.8 7.2v9.6L12 21.6 3.2 16.8V7.2L12 2.4Z"
        stroke="currentColor" strokeWidth="1.3" strokeLinejoin="round"
      />
      <path d="M12 8 16.4 10.4v4.8L12 17.6 7.6 15.2v-4.8L12 8Z" fill="currentColor" />
    </svg>
  )
}

/**
 * Engine readout, pinned in the rail.
 *
 * This is the one fact that stays relevant on every page: if the engine is
 * down, nothing else on screen is being updated. It sits above the account
 * block so it is the last thing in the reading order before the fold.
 *
 * Two different things can be wrong and they are named separately. "Engine
 * unreachable" means the API answered and said it cannot reach the engine.
 * "Console API unreachable" means the question itself got no answer, in
 * which case nothing is known about the engine at all.
 */
function EngineReadout({ engine, engineError, nodes, nodesStale, now }) {
  const state =
    engineError ? 'api'
      : engine === null ? 'unknown'
        : !engine.reachable ? 'unreachable'
          : engine.running ? 'running' : 'stopped'

  const nodeCount = nodes === null ? null : nodes.length
  const liveness = (nodes || []).map((n) => nodeLiveness(n, now))
  const online = liveness.filter((l) => l.state === 'online').length
  const stale = liveness.filter((l) => l.state === 'stale')
  const oldest = stale.reduce((max, l) => Math.max(max, l.ageSeconds || 0), 0)

  const tone = {
    unknown: 'var(--color-paper-3)',
    api: 'var(--color-s4)',
    unreachable: 'var(--color-s4)',
    stopped: 'var(--color-s3)',
    running: 'var(--color-s1)',
  }[state]

  const text = {
    unknown: 'Checking engine',
    api: 'Console API unreachable',
    unreachable: 'Engine unreachable',
    stopped: 'Engine stopped',
    running: 'Engine running',
  }[state]

  const enginesNote = nodesStale
    ? 'engines · count not refreshed'
    : stale.length
      ? `engines · stale ${relativeTime(now - oldest * 1000, now)}`
      : 'engines online'

  return (
    <div className="border-t border-line px-4 py-3.5">
      <div className="flex items-center gap-2" data-testid="engine-state">
        <span
          className={`h-1.5 w-1.5 shrink-0 rounded-full ${state === 'running' ? 'pulse-live' : ''}`}
          style={{ background: tone }}
          aria-hidden="true"
        />
        <span className="text-[13px] font-medium text-paper">{text}</span>
      </div>
      {state === 'api' && (
        <p className="mt-1 text-[12px] leading-snug text-paper-3">
          The engine&rsquo;s state is unknown until the API answers.
        </p>
      )}
      <NavLink
        to="/settings#engines"
        className="mt-2 flex items-baseline gap-1.5 transition-colors hover:text-paper"
        title={stale.length ? `${stale.length} engine(s) not reporting` : 'Engine status'}
        data-testid="engines-chip"
      >
        <span
          className="readout text-[12px]"
          style={{ color: stale.length ? 'var(--color-s4)' : 'var(--color-paper-2)' }}
        >
          {nodeCount === null ? '—' : `${online}/${nodeCount}`}
        </span>
        <span className="text-[12px] text-paper-3">{enginesNote}</span>
        {!stale.length && !nodesStale && state !== 'api' && engine?.protocols?.length > 0 && (
          <span className="readout ml-auto truncate text-[12px] uppercase text-paper-3">
            {engine.protocols.join(' ')}
          </span>
        )}
      </NavLink>
    </div>
  )
}

export default function DashboardLayout() {
  const { user, logout } = useAuth()
  const [railOpen, setRailOpen] = useState(false)
  const [accountOpen, setAccountOpen] = useState(false)
  const [engine, setEngine] = useState(null)
  const [engineError, setEngineError] = useState(false)
  const [nodes, setNodes] = useState(null)
  const [nodesStale, setNodesStale] = useState(false)
  const [polledAt, setPolledAt] = useState(() => Date.now())
  // null until a count has been received: "not known" is not "none".
  const [newAlerts, setNewAlerts] = useState(null)
  const [alertsStale, setAlertsStale] = useState(false)
  const location = useLocation()
  const name = pageName(location.pathname)

  const poll = useCallback(async () => {
    const [status, nodeRows, alertStats] = await Promise.allSettled([
      api.honeypot.status(),
      api.nodes.list(true),
      api.alerts.stats(),
    ])

    // A failed request leaves the last known value in place, marked as not
    // refreshed. It is never turned into "unreachable", "0" or "none".
    if (status.status === 'fulfilled') setEngine(status.value)
    setEngineError(status.status === 'rejected')

    if (nodeRows.status === 'fulfilled' && Array.isArray(nodeRows.value)) setNodes(nodeRows.value)
    setNodesStale(nodeRows.status === 'rejected')

    if (alertStats.status === 'fulfilled' && typeof alertStats.value?.new === 'number') {
      setNewAlerts(alertStats.value.new)
    }
    setAlertsStale(alertStats.status === 'rejected')
    setPolledAt(Date.now())
  }, [])

  useEffect(() => {
    const timer = setTimeout(poll, 0)
    return () => clearTimeout(timer)
  }, [poll])
  useVisiblePoll(poll, STATUS_POLL_MS)

  // The tab title names the view, so history entries and open tabs can be
  // told apart, and leads with the unread count: an analyst with the console
  // in a background tab should see "(3) Alerts" without switching to it.
  const unread = newAlerts ?? 0
  useEffect(() => {
    const count = unread > 0 ? `(${unread > 99 ? '99+' : unread}) ` : ''
    document.title = `${count}${name} · ${PRODUCT}`
    return () => { document.title = PRODUCT }
  }, [unread, name])

  // After a route change, move focus to the new view. Without this a
  // keyboard or screen-reader user stays on the link they pressed, with no
  // sign that anything changed. Skipped on first load, where the browser's
  // own starting position is right.
  const previousPath = useRef(location.pathname)
  useEffect(() => {
    if (previousPath.current === location.pathname) return
    previousPath.current = location.pathname
    document.getElementById('main-content')?.focus({ preventScroll: true })
  }, [location.pathname])

  useEffect(() => {
    if (!accountOpen && !railOpen) return undefined
    const onKey = (e) => { if (e.key === 'Escape') { setAccountOpen(false); setRailOpen(false) } }
    document.addEventListener('keydown', onKey)
    return () => document.removeEventListener('keydown', onKey)
  }, [accountOpen, railOpen])

  const unreadText =
    newAlerts === null
      ? (alertsStale ? 'Unread count unavailable' : 'Checking alerts')
      : `${newAlerts > 0 ? `${newAlerts} unread alert${newAlerts === 1 ? '' : 's'}` : 'No unread alerts'}${alertsStale ? ' (not refreshed)' : ''}`

  return (
    <div className="flex h-dvh overflow-hidden bg-ink-0">
      <a href="#main-content" className="skip-link">Skip to content</a>
      {railOpen && (
        <div
          className="fixed inset-0 z-20 bg-ink-0/85 lg:hidden"
          onClick={() => setRailOpen(false)}
          role="presentation"
        />
      )}

      {/*
        There is no top bar. The page title it used to hold is already the
        active nav item, and the account menu and alert count live down here —
        which buys back a full row of vertical space on every screen.
      */}
      <aside
        className={`fixed inset-y-0 left-0 z-30 flex w-52 flex-col border-r border-line bg-ink-1 transition-transform duration-200 lg:static lg:translate-x-0 ${
          railOpen ? 'visible translate-x-0' : 'invisible -translate-x-full lg:visible'
        }`}
      >
        <div className="flex items-center gap-2 px-4 pb-3 pt-4">
          <Mark className="h-[18px] w-[18px] shrink-0 text-paper" />
          <span className="font-display text-[15px] font-semibold leading-none tracking-tight text-paper">
            HoneySentinel
          </span>
          <button
            type="button"
            onClick={() => setRailOpen(false)}
            className="ml-auto text-paper-3 hover:text-paper lg:hidden"
            aria-label="Close menu"
          >
            <X className="h-4 w-4" />
          </button>
        </div>

        <nav aria-label="Main navigation" className="flex-1 overflow-y-auto px-2 py-2">
          {NAV.map(({ to, label }) => (
            <NavLink
              key={to}
              to={to}
              end={to === '/'}
              // Closed from the handler rather than an effect on the path:
              // it answers the tap, so it costs no extra render pass.
              onClick={() => setRailOpen(false)}
              className={({ isActive }) =>
                `relative block rounded-[3px] py-1.5 pl-3.5 pr-2.5 font-display text-[15px] transition-colors ${
                  isActive
                    ? 'font-semibold text-paper'
                    : 'font-medium text-paper-2 hover:text-paper'
                }`
              }
            >
              {({ isActive }) => (
                <>
                  {/* Active state is an ivory bar against the rule. The
                      interface has no accent hue to spend on chrome. */}
                  <span
                    className={`absolute left-0 top-1/2 h-4 w-[2px] -translate-y-1/2 ${
                      isActive ? 'bg-paper' : 'bg-transparent'
                    }`}
                    aria-hidden="true"
                  />
                  {label}
                  {to === '/alerts' && unread > 0 && (
                    <span className="readout ml-2 align-middle text-[12px] text-s4">
                      {unread > 99 ? '99+' : unread}
                      <span className="sr-only"> unread</span>
                    </span>
                  )}
                </>
              )}
            </NavLink>
          ))}
        </nav>

        <DisplayControls />

        <EngineReadout
          engine={engine}
          engineError={engineError}
          nodes={nodes}
          nodesStale={nodesStale}
          now={polledAt}
        />

        <div className="relative border-t border-line">
          <button
            type="button"
            onClick={() => setAccountOpen((open) => !open)}
            aria-expanded={accountOpen}
            aria-haspopup="menu"
            className="flex w-full items-center gap-2.5 px-4 py-3 text-left transition-colors hover:bg-ink-2"
          >
            <span className="readout flex h-6 w-6 shrink-0 items-center justify-center rounded-[3px] bg-ink-3 text-[12px] font-semibold text-paper">
              {user?.email?.[0]?.toUpperCase() || '?'}
            </span>
            <span className="min-w-0 flex-1">
              <span className="block truncate text-[13px] text-paper">
                {user?.email || ''}
              </span>
              <span className="block text-[12px] capitalize text-paper-3">
                {user?.role || 'analyst'}
              </span>
            </span>
            <ChevronUp
              className={`h-3.5 w-3.5 shrink-0 text-paper-3 transition-transform ${accountOpen ? '' : 'rotate-180'}`}
            />
          </button>

          {accountOpen && (
            <>
              <div
                className="fixed inset-0 z-40"
                onClick={() => setAccountOpen(false)}
                role="presentation"
              />
              <div
                role="menu"
                className="panel absolute bottom-full left-2 right-2 z-50 mb-1 overflow-hidden"
              >
                <NavLink
                  to="/alerts"
                  role="menuitem"
                  onClick={() => setAccountOpen(false)}
                  className="flex items-center gap-2 px-3 py-2 text-[13px] font-medium text-paper-2 transition-colors hover:bg-ink-2 hover:text-paper"
                >
                  <Bell className="h-3.5 w-3.5" strokeWidth={1.75} />
                  {unreadText}
                </NavLink>
                <button
                  type="button"
                  role="menuitem"
                  onClick={() => { logout(); setAccountOpen(false) }}
                  className="flex w-full items-center gap-2 border-t border-line px-3 py-2 text-[13px] font-medium text-paper-2 transition-colors hover:bg-ink-2 hover:text-s4"
                >
                  <LogOut className="h-3.5 w-3.5" strokeWidth={1.75} />
                  Sign out
                </button>
              </div>
            </>
          )}
        </div>
      </aside>

      <div className="flex min-w-0 flex-1 flex-col overflow-hidden">
        <button
          type="button"
          onClick={() => setRailOpen(true)}
          className="control absolute left-3 top-3 z-10 lg:hidden"
          aria-label="Open menu"
          aria-expanded={railOpen}
        >
          <Menu className="h-4 w-4" />
        </button>

        <main
          id="main-content"
          tabIndex={-1}
          aria-label={name}
          key={location.pathname}
          className="flex-1 overflow-y-auto px-4 pb-6 pt-14 outline-none lg:px-6 lg:pt-6"
        >
          <ErrorBoundary key={location.pathname}>
            <Suspense fallback={<LoadingRegion label="Loading view" />}><Outlet /></Suspense>
          </ErrorBoundary>
        </main>
      </div>
    </div>
  )
}
