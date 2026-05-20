import { Outlet, NavLink, useLocation } from 'react-router-dom'
import { useState } from 'react'
import {
  ShieldAlert, LayoutDashboard, Map, FileText,
  Settings, Bell, ChevronDown, LogOut, Menu,
  Activity,
} from 'lucide-react'
import { useAuth } from '../context/AuthContext'

const NAV = [
  { to: '/',          label: 'Dashboard',    icon: LayoutDashboard },
  { to: '/map',       label: 'Live Map',     icon: Map },
  { to: '/sessions',  label: 'Session Logs', icon: FileText },
  { to: '/settings',  label: 'Settings',     icon: Settings },
]

export default function DashboardLayout() {
  const { user, logout } = useAuth()
  const [sidebarOpen, setSidebarOpen] = useState(false)
  const [profileOpen, setProfileOpen] = useState(false)
  const location = useLocation()

  const pageTitle = NAV.find(n => n.to === location.pathname)?.label ?? 'Dashboard'

  return (
    <div className="flex h-screen bg-surface-900 overflow-hidden">
      {sidebarOpen && (
        <div
          className="fixed inset-0 bg-black/60 z-20 lg:hidden"
          onClick={() => setSidebarOpen(false)}
        />
      )}

      <aside
        className={`fixed lg:static inset-y-0 left-0 z-30 w-60 bg-surface-800 border-r border-border flex flex-col transition-transform duration-300 ${
          sidebarOpen ? 'translate-x-0' : '-translate-x-full lg:translate-x-0'
        }`}
      >
        <div className="flex items-center gap-2.5 px-5 h-16 border-b border-border shrink-0">
          <ShieldAlert className="text-accent-cyan w-6 h-6 text-glow-cyan" />
          <span className="font-mono font-semibold text-sm tracking-widest uppercase text-accent-cyan text-glow-cyan">
            HoneySentinel
          </span>
        </div>

        <div className="px-3 py-2 mt-2">
          <p className="text-[10px] font-mono text-gray-600 uppercase tracking-widest px-2 mb-1">
            Navigation
          </p>
          <nav className="space-y-0.5">
            {NAV.map(({ to, label, icon: Icon }) => (
              <NavLink
                key={to}
                to={to}
                end={to === '/'}
                onClick={() => setSidebarOpen(false)}
                className={({ isActive }) =>
                  `flex items-center gap-3 px-3 py-2.5 rounded-lg text-sm font-medium transition-all ${
                    isActive
                      ? 'bg-surface-600 text-accent-blue border border-border'
                      : 'text-gray-400 hover:text-white hover:bg-surface-700'
                  }`
                }
              >
                <Icon className="w-4 h-4 shrink-0" />
                <span className="font-mono">{label}</span>
              </NavLink>
            ))}
          </nav>
        </div>

        <div className="mt-auto px-4 py-5 border-t border-border">
          <div className="flex items-center gap-2 mb-3">
            <div className="w-2 h-2 rounded-full bg-accent-green animate-pulse-slow" />
            <span className="text-xs font-mono text-gray-400">System Nominal</span>
          </div>
          <div className="text-[10px] font-mono text-gray-600 space-y-0.5">
            <p>4 Honeypots Active</p>
            <p>Threat Feed: Live</p>
          </div>
        </div>
      </aside>

      <div className="flex-1 flex flex-col min-w-0 overflow-hidden">
        <header className="h-16 bg-surface-800 border-b border-border flex items-center justify-between px-4 lg:px-6 shrink-0">
          <div className="flex items-center gap-3">
            <button
              onClick={() => setSidebarOpen(true)}
              className="lg:hidden text-gray-400 hover:text-white transition-colors"
            >
              <Menu className="w-5 h-5" />
            </button>
            <div className="flex items-center gap-2">
              <Activity className="w-4 h-4 text-accent-cyan" />
              <h1 className="font-mono text-sm font-semibold text-white tracking-wider uppercase">
                {pageTitle}
              </h1>
            </div>
          </div>

          <div className="flex items-center gap-2">
            <button className="relative p-2 text-gray-400 hover:text-white transition-colors">
              <Bell className="w-5 h-5" />
              <span className="absolute top-1.5 right-1.5 w-2 h-2 rounded-full bg-accent-red border border-surface-800" />
            </button>

            <div className="relative">
              <button
                onClick={() => setProfileOpen(!profileOpen)}
                className="flex items-center gap-2 bg-surface-700 hover:bg-surface-600 border border-border rounded-lg px-3 py-1.5 transition-all"
              >
                <div className="w-6 h-6 rounded-md bg-gradient-to-br from-accent-blue to-accent-cyan flex items-center justify-center text-xs font-mono font-bold text-surface-900">
                  {user?.email?.[0]?.toUpperCase() || '?'}
                </div>
                <span className="hidden sm:block font-mono text-xs text-gray-300 max-w-[120px] truncate">
                  {user?.email || ''}
                </span>
                <ChevronDown className="w-3 h-3 text-gray-500" />
              </button>

              {profileOpen && (
                <>
                  <div className="fixed inset-0 z-40" onClick={() => setProfileOpen(false)} />
                  <div className="absolute right-0 mt-2 w-52 bg-surface-700 border border-border rounded-xl shadow-xl z-50 animate-fade-in">
                    <div className="px-4 py-3 border-b border-border">
                      <p className="text-xs font-mono text-gray-400">Signed in as</p>
                      <p className="text-sm font-mono text-white truncate">{user?.email}</p>
                      <span className="inline-block mt-1 text-[10px] font-mono bg-accent-green/10 text-accent-green border border-accent-green/30 px-2 py-0.5 rounded-full uppercase tracking-wider">
                        {user?.role || 'analyst'}
                      </span>
                    </div>
                    <div className="p-1.5">
                      <button
                        onClick={() => { logout(); setProfileOpen(false); }}
                        className="w-full flex items-center gap-2 px-3 py-2 text-sm font-mono text-accent-red hover:bg-surface-600 rounded-lg transition-colors"
                      >
                        <LogOut className="w-4 h-4" />
                        Sign Out
                      </button>
                    </div>
                  </div>
                </>
              )}
            </div>
          </div>
        </header>

        <main className="flex-1 overflow-y-auto p-4 lg:p-6">
          <Outlet />
        </main>
      </div>
    </div>
  )
}
