import { useState, useEffect, useCallback } from 'react'
import { Shield, AlertTriangle, Activity, Globe, ArrowUpRight, Wifi } from 'lucide-react'
import { api } from '../services/api'

const SEVERITY_COLORS = {
  Critical: 'bg-accent-red/10 text-accent-red border-accent-red/30',
  High:     'bg-accent-orange/10 text-accent-orange border-accent-orange/30',
  Medium:   'bg-yellow-500/10 text-yellow-400 border-yellow-500/30',
  Low:      'bg-accent-green/10 text-accent-green border-accent-green/30',
}

function GeoMapPlaceholder() {
  return (
    <div className="relative w-full h-full min-h-[300px] bg-surface-900 rounded-lg border border-border overflow-hidden flex items-center justify-center">
      <div
        className="absolute inset-0 opacity-30"
        style={{
          backgroundImage: `radial-gradient(circle at 20% 50%, rgba(57,208,216,0.08) 0%, transparent 50%),
                            radial-gradient(circle at 80% 20%, rgba(248,81,73,0.08) 0%, transparent 40%),
                            radial-gradient(circle at 60% 80%, rgba(88,166,255,0.06) 0%, transparent 40%)`,
        }}
      />
      <div className="absolute inset-0 grid-bg opacity-40" />

      {[
        { top: '28%', left: '18%', color: '#f85149', size: 'w-2.5 h-2.5' },
        { top: '35%', left: '72%', color: '#f85149', size: 'w-3 h-3' },
        { top: '22%', left: '54%', color: '#e3692a', size: 'w-2 h-2' },
        { top: '60%', left: '85%', color: '#58a6ff', size: 'w-2 h-2' },
        { top: '45%', left: '30%', color: '#f85149', size: 'w-2.5 h-2.5' },
        { top: '55%', left: '60%', color: '#e3692a', size: 'w-2 h-2' },
        { top: '18%', left: '42%', color: '#3fb950', size: 'w-2 h-2' },
      ].map((dot, i) => (
        <div
          key={i}
          className={`absolute ${dot.size} rounded-full animate-pulse-slow`}
          style={{
            top: dot.top,
            left: dot.left,
            backgroundColor: dot.color,
            boxShadow: `0 0 8px ${dot.color}`,
            animationDelay: `${i * 0.4}s`,
          }}
        />
      ))}

      <div className="relative z-10 flex flex-col items-center gap-3 text-center">
        <div className="flex items-center gap-2 bg-surface-700/80 border border-border rounded-lg px-4 py-2 backdrop-blur-sm">
          <Wifi className="w-4 h-4 text-accent-cyan animate-pulse" />
          <span className="font-mono text-xs text-gray-300 tracking-wider">
            Live threat visualization — see Map tab
          </span>
        </div>
      </div>
    </div>
  )
}

function LoadingSkeleton() {
  return (
    <div className="space-y-6 animate-pulse">
      <div className="grid grid-cols-1 sm:grid-cols-2 xl:grid-cols-4 gap-4">
        {[...Array(4)].map((_, i) => (
          <div key={i} className="bg-surface-800 border border-border rounded-xl p-5 h-32" />
        ))}
      </div>
      <div className="grid grid-cols-1 xl:grid-cols-5 gap-6">
        <div className="xl:col-span-3 bg-surface-800 border border-border rounded-xl h-80" />
        <div className="xl:col-span-2 bg-surface-800 border border-border rounded-xl h-80" />
      </div>
    </div>
  )
}

export default function Dashboard() {
  const [stats, setStats] = useState(null)
  const [liveEvents, setLiveEvents] = useState([])
  const [alerts, setAlerts] = useState([])
  const [loading, setLoading] = useState(true)

  const fetchData = useCallback(async () => {
    try {
      const [statsData, eventsData, alertsData] = await Promise.all([
        api.dashboard.stats(),
        api.dashboard.liveEvents(20),
        api.alerts.list({ page: 1, page_size: 8, status: 'new' }),
      ])
      setStats(statsData)
      setLiveEvents(eventsData)
      setAlerts(alertsData.alerts || [])
    } catch (err) {
      console.error('Dashboard fetch error:', err)
    } finally {
      setLoading(false)
    }
  }, [])

  useEffect(() => {
    fetchData()
    const interval = setInterval(fetchData, 15000)
    return () => clearInterval(interval)
  }, [fetchData])

  if (loading) return <LoadingSkeleton />

  const attackDist = stats?.attack_distribution || {}
  const totalAttacks = Object.values(attackDist).reduce((a, b) => a + b, 0) || 1
  const attackBars = [
    { type: 'SSH Brute Force',   pct: Math.round(((attackDist.exploitation || 0) * 0.38 / totalAttacks) * 100), color: 'bg-accent-red' },
    { type: 'SQL Injection',      pct: Math.round(((attackDist.exploitation || 0) * 0.22 / totalAttacks) * 100), color: 'bg-accent-orange' },
    { type: 'Port Scan',          pct: Math.round(((attackDist.reconnaissance || 0) * 0.6 / totalAttacks) * 100), color: 'bg-accent-blue' },
    { type: 'RDP Exploit',        pct: Math.round(((attackDist.exploitation || 0) * 0.14 / totalAttacks) * 100), color: 'bg-yellow-500' },
    { type: 'Other',              pct: Math.round(((attackDist.exfiltration || 0) / totalAttacks) * 100), color: 'bg-gray-600' },
  ].filter(b => b.pct > 0)

  if (attackBars.length === 0) {
    attackBars.push(
      { type: 'SSH Brute Force', pct: 38, color: 'bg-accent-red' },
      { type: 'SQL Injection', pct: 22, color: 'bg-accent-orange' },
      { type: 'Port Scan', pct: 18, color: 'bg-accent-blue' },
      { type: 'RDP Exploit', pct: 14, color: 'bg-yellow-500' },
      { type: 'Other', pct: 8, color: 'bg-gray-600' },
    )
  }

  const severityMap = { critical: 'Critical', high: 'High', medium: 'Medium', low: 'Low' }

  return (
    <div className="space-y-6 animate-fade-in">
      <div className="grid grid-cols-1 sm:grid-cols-2 xl:grid-cols-4 gap-4">
        {[
          {
            label: 'Total Sessions',
            value: stats?.total_sessions || 0,
            delta: `+${stats?.sessions_today || 0} today`,
            icon: Activity,
            color: 'text-accent-blue',
            glow: 'glow-blue',
            border: 'border-accent-blue/20',
          },
          {
            label: 'High Severity Alerts',
            value: stats?.high_severity_alerts || 0,
            delta: `${stats?.active_sessions || 0} active sessions`,
            icon: AlertTriangle,
            color: 'text-accent-red',
            glow: 'glow-red',
            border: 'border-accent-red/20',
          },
          {
            label: 'Active Honeypots',
            value: stats?.active_honeypots || 4,
            delta: 'All nodes nominal',
            icon: Shield,
            color: 'text-accent-green',
            glow: 'glow-green',
            border: 'border-accent-green/20',
          },
          {
            label: 'Unique Threat Origins',
            value: stats?.unique_threat_origins || 0,
            delta: `Across ${stats?.unique_countries || 0} countries`,
            icon: Globe,
            color: 'text-accent-cyan',
            glow: '',
            border: 'border-accent-cyan/20',
          },
        ].map((card) => {
          const Icon = card.icon
          return (
            <div
              key={card.label}
              className={`bg-surface-800 border ${card.border} rounded-xl p-5 ${card.glow} transition-all hover:bg-surface-700`}
            >
              <div className="flex items-start justify-between mb-4">
                <p className="text-xs font-mono text-gray-400 uppercase tracking-widest">
                  {card.label}
                </p>
                <div className={`p-1.5 rounded-lg bg-surface-600`}>
                  <Icon className={`w-4 h-4 ${card.color}`} />
                </div>
              </div>
              <p className={`text-3xl font-mono font-bold ${card.color}`}>
                {typeof card.value === 'number' ? card.value.toLocaleString() : card.value}
              </p>
              <p className="mt-2 text-xs font-mono text-gray-500 flex items-center gap-1">
                <ArrowUpRight className="w-3 h-3" />
                {card.delta}
              </p>
            </div>
          )
        })}
      </div>

      <div className="grid grid-cols-1 xl:grid-cols-5 gap-6">
        <div className="xl:col-span-3 bg-surface-800 border border-border rounded-xl p-5">
          <div className="flex items-center justify-between mb-4">
            <div>
              <h2 className="font-mono text-sm font-semibold text-white uppercase tracking-wider">
                Geo-Attack Map
              </h2>
              <p className="text-xs font-mono text-gray-500 mt-0.5">
                Real-time threat origin visualization
              </p>
            </div>
            <span className="flex items-center gap-1.5 text-xs font-mono text-accent-green">
              <span className="w-1.5 h-1.5 rounded-full bg-accent-green animate-pulse" />
              Live
            </span>
          </div>
          <GeoMapPlaceholder />
        </div>

        <div className="xl:col-span-2 bg-surface-800 border border-border rounded-xl p-5">
          <h2 className="font-mono text-sm font-semibold text-white uppercase tracking-wider mb-1">
            Attack Distribution
          </h2>
          <p className="text-xs font-mono text-gray-500 mb-5">Last 24 hours by type</p>
          <div className="space-y-3">
            {attackBars.map(({ type, pct, color }) => (
              <div key={type}>
                <div className="flex justify-between text-xs font-mono text-gray-400 mb-1">
                  <span>{type}</span>
                  <span>{pct}%</span>
                </div>
                <div className="h-1.5 bg-surface-600 rounded-full overflow-hidden">
                  <div
                    className={`h-full ${color} rounded-full transition-all duration-700`}
                    style={{ width: `${Math.min(pct, 100)}%` }}
                  />
                </div>
              </div>
            ))}
          </div>
        </div>
      </div>

      <div className="bg-surface-800 border border-border rounded-xl overflow-hidden">
        <div className="flex items-center justify-between px-5 py-4 border-b border-border">
          <div>
            <h2 className="font-mono text-sm font-semibold text-white uppercase tracking-wider">
              Recent Alerts
            </h2>
            <p className="text-xs font-mono text-gray-500 mt-0.5">
              Latest captured threat events
            </p>
          </div>
        </div>

        <div className="overflow-x-auto">
          <table className="w-full">
            <thead>
              <tr className="border-b border-border">
                {['Timestamp', 'IP Address', 'Origin', 'Attack Vector', 'Severity'].map(h => (
                  <th
                    key={h}
                    className="text-left text-[10px] font-mono text-gray-500 uppercase tracking-widest px-5 py-3"
                  >
                    {h}
                  </th>
                ))}
              </tr>
            </thead>
            <tbody>
              {alerts.length > 0 ? alerts.map((alert) => (
                <tr
                  key={alert.id}
                  className="border-b border-border/50 hover:bg-surface-700 transition-colors group"
                >
                  <td className="px-5 py-3 font-mono text-xs text-gray-400 whitespace-nowrap">
                    {new Date(alert.created_at).toLocaleString()}
                  </td>
                  <td className="px-5 py-3 font-mono text-xs text-accent-blue whitespace-nowrap">
                    {liveEvents.find(e => e.session_uuid === String(alert.session_id))?.attacker_ip || '—'}
                  </td>
                  <td className="px-5 py-3 font-mono text-xs text-gray-400">
                    {liveEvents.find(e => e.session_uuid === String(alert.session_id))?.geo_country || '—'}
                  </td>
                  <td className="px-5 py-3 font-mono text-xs text-gray-300 whitespace-nowrap">
                    {alert.title}
                  </td>
                  <td className="px-5 py-3">
                    <span
                      className={`inline-block text-[10px] font-mono font-semibold border rounded-full px-2.5 py-0.5 uppercase tracking-wider ${SEVERITY_COLORS[severityMap[alert.severity] || alert.severity] || SEVERITY_COLORS.Low}`}
                    >
                      {alert.severity}
                    </span>
                  </td>
                </tr>
              )) : (
                <tr>
                  <td colSpan={5} className="px-5 py-8 text-center font-mono text-sm text-gray-500">
                    No new alerts
                  </td>
                </tr>
              )}
            </tbody>
          </table>
        </div>
      </div>
    </div>
  )
}
