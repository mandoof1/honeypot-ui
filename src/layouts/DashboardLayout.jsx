import { Outlet, NavLink, useLocation } from 'react-router-dom'
import { Suspense, useEffect, useState } from 'react'
import { Bell, ChevronUp, LogOut, Menu, X } from 'lucide-react'
import { useAuth } from '../context/useAuth'
import ErrorBoundary from '../components/ErrorBoundary'
import { LoadingRegion } from '../components/Loading'
import { api } from '../services/api'

const NAV = [
  { to: '/', label: 'Overview' },
  { to: '/sessions', label: 'Sessions' },
  { to: '/alerts', label: 'Alerts' },
  { to: '/indicators', label: 'Indicators' },
  { to: '/map', label: 'Origins' },
  { to: '/settings', label: 'Settings' },
]

const STATUS_POLL_MS = 30000

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
 */
function EngineReadout({ engine, nodeCount }) {
  const state =
    engine === null ? 'unknown'
      : !engine.reachable ? 'unreachable'
        : engine.running ? 'running' : 'stopped'

  const tone = {
    unknown: 'var(--color-paper-3)',
    unreachable: 'var(--color-s4)',
    stopped: 'var(--color-s3)',
    running: 'var(--color-s1)',
  }[state]

  const text = {
    unknown: 'Checking engine',
    unreachable: 'Engine unreachable',
    stopped: 'Engine stopped',
    running: 'Engine running',
  }[state]

  return (
    <div className="border-t border-line px-4 py-3.5">
      <div className="flex items-center gap-2">
        <span
          className={`h-1.5 w-1.5 shrink-0 rounded-full ${state === 'running' ? 'pulse-live' : ''}`}
          style={{ background: tone }}
          aria-hidden="true"
        />
        <span className="text-[13px] font-medium text-paper">{text}</span>
      </div>
      <div className="mt-2 flex items-baseline gap-1.5">
        <span className="readout text-[11px] text-paper-2">
          {nodeCount === null ? '—' : nodeCount}
        </span>
        <span className="text-[11px] text-paper-3">
          {nodeCount === 1 ? 'node' : 'nodes'}
        </span>
        {engine?.protocols?.length > 0 && (
          <span className="readout ml-auto truncate text-[11px] uppercase text-paper-3">
            {engine.protocols.join(' ')}
          </span>
        )}
      </div>
      {engine?.reachable && engine.delivery && (
        <div className="mt-2 text-[11px] text-paper-3" aria-label="Capture delivery">
          <p>{typeof engine.delivery.pending !== 'number' ? 'Delivery status unavailable'
            : engine.delivery.pending === 0 ? 'All queued captures delivered'
              : `${engine.delivery.pending} capture${engine.delivery.pending === 1 ? '' : 's'} awaiting delivery`}</p>
          {engine.delivery.retrying > 0 && <p className="mt-1 text-s3">{engine.delivery.retrying} awaiting retry</p>}
          {engine.delivery.capture_errors > 0 && <p className="mt-1 text-s4">Capture storage errors — check engine logs</p>}
          {engine.delivery.last_error && <p className="mt-1 break-words text-s3">{engine.delivery.last_error}</p>}
        </div>
      )}
    </div>
  )
}

export default function DashboardLayout() {
  const { user, logout } = useAuth()
  const [railOpen, setRailOpen] = useState(false)
  const [accountOpen, setAccountOpen] = useState(false)
  const [engine, setEngine] = useState(null)
  const [nodeCount, setNodeCount] = useState(null)
  const [newAlerts, setNewAlerts] = useState(0)
  const location = useLocation()

  useEffect(() => {
    let cancelled = false

    const poll = async () => {
      const [status, nodes, alertStats] = await Promise.all([
        api.honeypot.status().catch(() => ({ reachable: false })),
        api.nodes.list(true).catch(() => null),
        api.alerts.stats().catch(() => null),
      ])
      if (cancelled) return
      setEngine(status)
      setNodeCount(nodes ? nodes.length : null)
      setNewAlerts(alertStats?.new ?? 0)
    }

    poll()
    const interval = setInterval(poll, STATUS_POLL_MS)
    return () => {
      cancelled = true
      clearInterval(interval)
    }
  }, [])

  useEffect(() => {
    if (!accountOpen && !railOpen) return undefined
    const onKey = (e) => { if (e.key === 'Escape') { setAccountOpen(false); setRailOpen(false) } }
    document.addEventListener('keydown', onKey)
    return () => document.removeEventListener('keydown', onKey)
  }, [accountOpen, railOpen])

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
                  {to === '/alerts' && newAlerts > 0 && (
                    <span className="readout ml-2 align-middle text-[11px] text-s4">
                      {newAlerts > 99 ? '99+' : newAlerts}
                    </span>
                  )}
                </>
              )}
            </NavLink>
          ))}
        </nav>

        <EngineReadout engine={engine} nodeCount={nodeCount} />

        <div className="relative border-t border-line">
          <button
            type="button"
            onClick={() => setAccountOpen((open) => !open)}
            aria-expanded={accountOpen}
            aria-haspopup="menu"
            className="flex w-full items-center gap-2.5 px-4 py-3 text-left transition-colors hover:bg-ink-2"
          >
            <span className="readout flex h-6 w-6 shrink-0 items-center justify-center rounded-[3px] bg-ink-3 text-[11px] font-semibold text-paper">
              {user?.email?.[0]?.toUpperCase() || '?'}
            </span>
            <span className="min-w-0 flex-1">
              <span className="block truncate text-[13px] text-paper">
                {user?.email || ''}
              </span>
              <span className="block text-[11px] capitalize text-paper-3">
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
                  {newAlerts > 0 ? `${newAlerts} unread alerts` : 'No unread alerts'}
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
          key={location.pathname}
          className="flex-1 overflow-y-auto px-4 pb-6 pt-14 lg:px-6 lg:pt-6"
        >
          <ErrorBoundary key={location.pathname}>
            <Suspense fallback={<LoadingRegion label="Loading view" />}><Outlet /></Suspense>
          </ErrorBoundary>
        </main>
      </div>
    </div>
  )
}
