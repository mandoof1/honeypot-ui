import { useState, useEffect, useCallback } from 'react'
import { Search, Filter, Download, ChevronLeft, ChevronRight, X, Eye, AlertTriangle, Shield, Bot, User, Globe, Clock, Terminal, FileBox } from 'lucide-react'
import { api } from '../services/api'

const SEVERITY_BADGE = {
  critical: 'bg-accent-red/10 text-accent-red border-accent-red/30',
  high:     'bg-accent-orange/10 text-accent-orange border-accent-orange/30',
  medium:   'bg-yellow-500/10 text-yellow-400 border-yellow-500/30',
  low:      'bg-accent-green/10 text-accent-green border-accent-green/30',
}

const PROFILE_ICONS = {
  apt: { icon: Shield, color: 'text-accent-red' },
  script_kiddie: { icon: User, color: 'text-accent-orange' },
  automated_bot: { icon: Bot, color: 'text-accent-blue' },
  unknown: { icon: Globe, color: 'text-gray-500' },
}

function SessionDetailModal({ session, onClose }) {
  if (!session) return null

  const mitreTechs = session.mitre_techniques || []
  const tools = session.detected_tools || []
  const intents = session.detected_intents || []

  return (
    <div className="fixed inset-0 bg-black/70 z-50 flex items-center justify-center p-4" onClick={onClose}>
      <div
        className="bg-surface-800 border border-border rounded-xl w-full max-w-3xl max-h-[85vh] overflow-y-auto animate-slide-up"
        onClick={e => e.stopPropagation()}
      >
        <div className="sticky top-0 bg-surface-800 border-b border-border px-6 py-4 flex items-center justify-between z-10">
          <div>
            <h2 className="font-mono text-sm font-semibold text-white uppercase tracking-wider">
              Session Details
            </h2>
            <p className="text-xs font-mono text-gray-500 mt-0.5 truncate max-w-md">
              {session.session_uuid}
            </p>
          </div>
          <button onClick={onClose} className="p-2 text-gray-400 hover:text-white transition-colors">
            <X className="w-5 h-5" />
          </button>
        </div>

        <div className="p-6 space-y-6">
          <div className="grid grid-cols-2 md:grid-cols-4 gap-4">
            {[
              { label: 'Attacker IP', value: session.attacker_ip, icon: Globe },
              { label: 'Country', value: session.geo?.country_name || session.geo?.country || 'Unknown', icon: Globe },
              { label: 'Duration', value: session.duration_seconds ? `${session.duration_seconds.toFixed(1)}s` : 'Active', icon: Clock },
              { label: 'Status', value: session.status, icon: Shield },
            ].map(({ label, value, icon: Icon }) => (
              <div key={label} className="bg-surface-700 rounded-lg p-3">
                <div className="flex items-center gap-2 mb-1">
                  <Icon className="w-3.5 h-3.5 text-gray-500" />
                  <span className="text-[10px] font-mono text-gray-500 uppercase">{label}</span>
                </div>
                <p className="text-sm font-mono text-white truncate">{value}</p>
              </div>
            ))}
          </div>

          <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
            <div className="bg-surface-700 rounded-lg p-4">
              <h3 className="text-xs font-mono text-gray-400 uppercase mb-3 flex items-center gap-2">
                <AlertTriangle className="w-3.5 h-3.5 text-accent-red" />
                AI Classification
              </h3>
              <div className="space-y-2">
                <div className="flex justify-between">
                  <span className="text-xs font-mono text-gray-500">Category</span>
                  <span className="text-xs font-mono text-accent-blue">{session.attack_category || 'N/A'}</span>
                </div>
                <div className="flex justify-between">
                  <span className="text-xs font-mono text-gray-500">Confidence</span>
                  <span className="text-xs font-mono text-white">{(session.attack_confidence * 100)?.toFixed(1)}%</span>
                </div>
                <div className="flex justify-between">
                  <span className="text-xs font-mono text-gray-500">Anomaly Score</span>
                  <span className="text-xs font-mono text-white">{session.anomaly_score?.toFixed(4) || 'N/A'}</span>
                </div>
                <div className="flex justify-between">
                  <span className="text-xs font-mono text-gray-500">Profile</span>
                  <span className="text-xs font-mono text-white">{session.attacker_profile || 'N/A'}</span>
                </div>
              </div>
            </div>

            <div className="bg-surface-700 rounded-lg p-4">
              <h3 className="text-xs font-mono text-gray-400 uppercase mb-3 flex items-center gap-2">
                <Terminal className="w-3.5 h-3.5 text-accent-cyan" />
                NLP Analysis
              </h3>
              <div className="space-y-2">
                <div>
                  <span className="text-[10px] font-mono text-gray-500">Detected Tools</span>
                  <div className="flex flex-wrap gap-1 mt-1">
                    {tools.length > 0 ? tools.map(t => (
                      <span key={t} className="text-[10px] font-mono bg-accent-red/10 text-accent-red border border-accent-red/30 px-1.5 py-0.5 rounded">
                        {t}
                      </span>
                    )) : <span className="text-xs font-mono text-gray-600">None detected</span>}
                  </div>
                </div>
                <div>
                  <span className="text-[10px] font-mono text-gray-500">Intents</span>
                  <div className="flex flex-wrap gap-1 mt-1">
                    {intents.length > 0 ? intents.map(i => (
                      <span key={i} className="text-[10px] font-mono bg-accent-blue/10 text-accent-blue border border-accent-blue/30 px-1.5 py-0.5 rounded">
                        {i}
                      </span>
                    )) : <span className="text-xs font-mono text-gray-600">None detected</span>}
                  </div>
                </div>
              </div>
            </div>
          </div>

          {mitreTechs.length > 0 && (
            <div className="bg-surface-700 rounded-lg p-4">
              <h3 className="text-xs font-mono text-gray-400 uppercase mb-3">MITRE ATT&CK Techniques</h3>
              <div className="flex flex-wrap gap-2">
                {mitreTechs.map((t, i) => (
                  <span key={i} className="text-xs font-mono bg-accent-cyan/10 text-accent-cyan border border-accent-cyan/30 px-2 py-1 rounded">
                    {t.id}: {t.name}
                  </span>
                ))}
              </div>
            </div>
          )}

          {(session.uploaded_files?.length > 0) && (
            <div className="bg-surface-700 rounded-lg p-4">
              <h3 className="text-xs font-mono text-gray-400 uppercase mb-3 flex items-center gap-2">
                <FileBox className="w-3.5 h-3.5" />
                Uploaded Files
              </h3>
              <div className="space-y-1">
                {session.uploaded_files.map((f, i) => (
                  <p key={i} className="text-xs font-mono text-gray-300">{f}</p>
                ))}
              </div>
            </div>
          )}
        </div>
      </div>
    </div>
  )
}

export default function SessionLogs() {
  const [sessions, setSessions] = useState([])
  const [loading, setLoading] = useState(true)
  const [page, setPage] = useState(1)
  const [total, setTotal] = useState(0)
  const [selectedSession, setSelectedSession] = useState(null)
  const [filters, setFilters] = useState({
    search: '',
    status: '',
    attack_category: '',
    country: '',
    is_anomalous: null,
  })
  const [showFilters, setShowFilters] = useState(false)
  const pageSize = 20

  const fetchSessions = useCallback(async () => {
    setLoading(true)
    try {
      const params = { page, page_size: pageSize }
      Object.entries(filters).forEach(([k, v]) => {
        if (v !== '' && v !== null && v !== undefined) params[k] = v
      })
      const data = await api.sessions.list(params)
      setSessions(data.sessions || [])
      setTotal(data.total || 0)
    } catch (err) {
      console.error('SessionLogs fetch error:', err)
    } finally {
      setLoading(false)
    }
  }, [page, filters])

  useEffect(() => {
    fetchSessions()
  }, [fetchSessions])

  const totalPages = Math.ceil(total / pageSize)

  const handleExport = async (format) => {
    try {
      const data = await api.export.sessions({ format })
      const blob = new Blob([JSON.stringify(data, null, 2)], { type: 'application/json' })
      const url = URL.createObjectURL(blob)
      const a = document.createElement('a')
      a.href = url
      a.download = `honeysentinel_sessions_${format}_${Date.now()}.json`
      a.click()
      URL.revokeObjectURL(url)
    } catch (err) {
      console.error('Export error:', err)
    }
  }

  const ProfileIcon = ({ profile }) => {
    const config = PROFILE_ICONS[profile] || PROFILE_ICONS.unknown
    const Icon = config.icon
    return <Icon className={`w-3.5 h-3.5 ${config.color}`} />
  }

  return (
    <div className="space-y-4 animate-fade-in">
      <div className="flex items-center justify-between">
        <div className="flex items-center gap-3">
          <div className="relative">
            <Search className="absolute left-3 top-1/2 -translate-y-1/2 w-4 h-4 text-gray-500" />
            <input
              type="text"
              placeholder="Search IP, UUID..."
              value={filters.search}
              onChange={e => { setFilters(f => ({ ...f, search: e.target.value })); setPage(1) }}
              className="bg-surface-700 border border-border rounded-lg pl-9 pr-4 py-2 text-sm font-mono text-white placeholder-gray-600 outline-none focus:border-accent-blue w-64"
            />
          </div>
          <button
            onClick={() => setShowFilters(!showFilters)}
            className={`flex items-center gap-2 px-3 py-2 text-sm font-mono rounded-lg border transition-all ${
              showFilters ? 'bg-surface-600 border-border text-white' : 'border-border/50 text-gray-400 hover:text-white'
            }`}
          >
            <Filter className="w-4 h-4" />
            Filters
          </button>
        </div>

        <div className="flex items-center gap-2">
          <button onClick={() => handleExport('json')} className="flex items-center gap-1.5 px-3 py-2 text-xs font-mono bg-surface-700 border border-border rounded-lg text-gray-300 hover:text-white hover:bg-surface-600 transition-all">
            <Download className="w-3.5 h-3.5" />
            JSON
          </button>
          <button onClick={() => handleExport('cef')} className="flex items-center gap-1.5 px-3 py-2 text-xs font-mono bg-surface-700 border border-border rounded-lg text-gray-300 hover:text-white hover:bg-surface-600 transition-all">
            <Download className="w-3.5 h-3.5" />
            CEF
          </button>
          <button onClick={() => handleExport('stix')} className="flex items-center gap-1.5 px-3 py-2 text-xs font-mono bg-surface-700 border border-border rounded-lg text-gray-300 hover:text-white hover:bg-surface-600 transition-all">
            <Download className="w-3.5 h-3.5" />
            STIX
          </button>
        </div>
      </div>

      {showFilters && (
        <div className="bg-surface-800 border border-border rounded-xl p-4 grid grid-cols-2 md:grid-cols-4 gap-3 animate-fade-in">
          <select
            value={filters.status}
            onChange={e => { setFilters(f => ({ ...f, status: e.target.value })); setPage(1) }}
            className="bg-surface-700 border border-border rounded-lg px-3 py-2 text-xs font-mono text-white outline-none focus:border-accent-blue"
          >
            <option value="">All Statuses</option>
            <option value="active">Active</option>
            <option value="completed">Completed</option>
            <option value="terminated">Terminated</option>
          </select>

          <select
            value={filters.attack_category}
            onChange={e => { setFilters(f => ({ ...f, attack_category: e.target.value })); setPage(1) }}
            className="bg-surface-700 border border-border rounded-lg px-3 py-2 text-xs font-mono text-white outline-none focus:border-accent-blue"
          >
            <option value="">All Categories</option>
            <option value="benign">Benign</option>
            <option value="reconnaissance">Reconnaissance</option>
            <option value="exploitation">Exploitation</option>
            <option value="exfiltration">Exfiltration</option>
          </select>

          <select
            value={filters.country}
            onChange={e => { setFilters(f => ({ ...f, country: e.target.value })); setPage(1) }}
            className="bg-surface-700 border border-border rounded-lg px-3 py-2 text-xs font-mono text-white outline-none focus:border-accent-blue"
          >
            <option value="">All Countries</option>
            <option value="US">United States</option>
            <option value="CN">China</option>
            <option value="RU">Russia</option>
            <option value="DE">Germany</option>
            <option value="NL">Netherlands</option>
            <option value="IN">India</option>
            <option value="FR">France</option>
            <option value="UA">Ukraine</option>
            <option value="BR">Brazil</option>
            <option value="GB">United Kingdom</option>
          </select>

          <select
            value={filters.is_anomalous ?? ''}
            onChange={e => { setFilters(f => ({ ...f, is_anomalous: e.target.value === '' ? null : e.target.value === 'true' })); setPage(1) }}
            className="bg-surface-700 border border-border rounded-lg px-3 py-2 text-xs font-mono text-white outline-none focus:border-accent-blue"
          >
            <option value="">Anomaly: All</option>
            <option value="true">Anomalous Only</option>
            <option value="false">Normal Only</option>
          </select>
        </div>
      )}

      <div className="bg-surface-800 border border-border rounded-xl overflow-hidden">
        <div className="overflow-x-auto">
          <table className="w-full">
            <thead>
              <tr className="border-b border-border">
                {['Time', 'Session ID', 'Attacker IP', 'Country', 'Category', 'Profile', 'Anomaly', 'Severity', ''].map(h => (
                  <th key={h} className="text-left text-[10px] font-mono text-gray-500 uppercase tracking-widest px-4 py-3 whitespace-nowrap">
                    {h}
                  </th>
                ))}
              </tr>
            </thead>
            <tbody>
              {loading ? (
                <tr><td colSpan={9} className="px-4 py-12 text-center"><div className="flex items-center justify-center gap-3"><div className="w-5 h-5 border-2 border-accent-cyan border-t-transparent rounded-full animate-spin" /><span className="font-mono text-sm text-gray-400">Loading sessions...</span></div></td></tr>
              ) : sessions.length === 0 ? (
                <tr><td colSpan={9} className="px-4 py-12 text-center font-mono text-sm text-gray-500">No sessions found</td></tr>
              ) : (
                sessions.map((s) => (
                  <tr key={s.id} className="border-b border-border/50 hover:bg-surface-700 transition-colors">
                    <td className="px-4 py-2.5 font-mono text-xs text-gray-400 whitespace-nowrap">
                      {new Date(s.started_at).toLocaleString()}
                    </td>
                    <td className="px-4 py-2.5 font-mono text-xs text-accent-blue whitespace-nowrap truncate max-w-[120px]">
                      {s.session_uuid.slice(0, 8)}...
                    </td>
                    <td className="px-4 py-2.5 font-mono text-xs text-white whitespace-nowrap">
                      {s.attacker_ip}
                    </td>
                    <td className="px-4 py-2.5 font-mono text-xs text-gray-400 whitespace-nowrap">
                      {s.geo?.country || '—'}
                    </td>
                    <td className="px-4 py-2.5">
                      <span className="text-[10px] font-mono bg-surface-600 text-gray-300 border border-border px-2 py-0.5 rounded-full">
                        {s.attack_category || 'unknown'}
                      </span>
                    </td>
                    <td className="px-4 py-2.5">
                      <div className="flex items-center gap-1.5">
                        <ProfileIcon profile={s.attacker_profile} />
                        <span className="text-[10px] font-mono text-gray-400">{s.attacker_profile || 'unknown'}</span>
                      </div>
                    </td>
                    <td className="px-4 py-2.5">
                      <span className={`text-[10px] font-mono px-2 py-0.5 rounded-full ${s.is_anomalous ? 'bg-accent-red/10 text-accent-red border border-accent-red/30' : 'bg-accent-green/10 text-accent-green border border-accent-green/30'}`}>
                        {s.is_anomalous ? 'YES' : 'NO'}
                      </span>
                    </td>
                    <td className="px-4 py-2.5">
                      <span className={`text-[10px] font-mono font-semibold border rounded-full px-2 py-0.5 uppercase ${SEVERITY_BADGE[s.attack_category === 'exploitation' ? 'high' : s.attack_category === 'exfiltration' ? 'critical' : s.attack_category === 'reconnaissance' ? 'medium' : 'low']}`}>
                        {s.attack_category === 'exploitation' ? 'HIGH' : s.attack_category === 'exfiltration' ? 'CRIT' : s.attack_category === 'reconnaissance' ? 'MED' : 'LOW'}
                      </span>
                    </td>
                    <td className="px-4 py-2.5">
                      <button
                        onClick={() => setSelectedSession(s)}
                        className="p-1.5 text-gray-500 hover:text-accent-blue transition-colors"
                        title="View details"
                      >
                        <Eye className="w-4 h-4" />
                      </button>
                    </td>
                  </tr>
                ))
              )}
            </tbody>
          </table>
        </div>

        {totalPages > 1 && (
          <div className="flex items-center justify-between px-4 py-3 border-t border-border">
            <span className="text-xs font-mono text-gray-500">
              {((page - 1) * pageSize) + 1}–{Math.min(page * pageSize, total)} of {total}
            </span>
            <div className="flex items-center gap-1">
              <button
                onClick={() => setPage(p => Math.max(1, p - 1))}
                disabled={page === 1}
                className="p-1.5 text-gray-500 hover:text-white disabled:opacity-30 disabled:cursor-not-allowed transition-colors"
              >
                <ChevronLeft className="w-4 h-4" />
              </button>
              {Array.from({ length: Math.min(5, totalPages) }, (_, i) => {
                let p
                if (totalPages <= 5) p = i + 1
                else if (page <= 3) p = i + 1
                else if (page >= totalPages - 2) p = totalPages - 4 + i
                else p = page - 2 + i
                return (
                  <button
                    key={p}
                    onClick={() => setPage(p)}
                    className={`w-8 h-8 text-xs font-mono rounded-lg transition-all ${
                      page === p ? 'bg-accent-blue text-surface-900 font-bold' : 'text-gray-500 hover:text-white'
                    }`}
                  >
                    {p}
                  </button>
                )
              })}
              <button
                onClick={() => setPage(p => Math.min(totalPages, p + 1))}
                disabled={page === totalPages}
                className="p-1.5 text-gray-500 hover:text-white disabled:opacity-30 disabled:cursor-not-allowed transition-colors"
              >
                <ChevronRight className="w-4 h-4" />
              </button>
            </div>
          </div>
        )}
      </div>

      <SessionDetailModal session={selectedSession} onClose={() => setSelectedSession(null)} />
    </div>
  )
}
