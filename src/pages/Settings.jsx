import { useState, useEffect, useCallback } from 'react'
import { Shield, Bell, Globe, Mail, Webhook, Plus, Trash2, Save, RotateCcw, AlertTriangle, Settings as SettingsIcon, Moon, Sun, Activity } from 'lucide-react'
import { api } from '../services/api'

const SEVERITY_OPTIONS = [
  { value: 'low', label: 'Low' },
  { value: 'medium', label: 'Medium' },
  { value: 'high', label: 'High' },
  { value: 'critical', label: 'Critical' },
]

function ThresholdCard({ threshold, onUpdate, onDelete }) {
  const [editing, setEditing] = useState(false)
  const [form, setForm] = useState({
    name: threshold.name,
    min_severity: threshold.min_severity,
    anomaly_score_threshold: threshold.anomaly_score_threshold,
    email_enabled: threshold.email_enabled,
    webhook_enabled: threshold.webhook_enabled,
  })

  const handleSave = async () => {
    await onUpdate(threshold.id, form)
    setEditing(false)
  }

  return (
    <div className="bg-surface-700 border border-border rounded-xl p-5">
      <div className="flex items-center justify-between mb-4">
        <div className="flex items-center gap-2">
          <Bell className="w-4 h-4 text-accent-cyan" />
          <h3 className="font-mono text-sm font-semibold text-white">{threshold.name}</h3>
        </div>
        <div className="flex items-center gap-2">
          <span className={`text-[10px] font-mono px-2 py-0.5 rounded-full ${threshold.is_active ? 'bg-accent-green/10 text-accent-green border border-accent-green/30' : 'bg-gray-600/20 text-gray-500 border border-gray-600/30'}`}>
            {threshold.is_active ? 'ACTIVE' : 'DISABLED'}
          </span>
          {!editing && (
            <button onClick={() => setEditing(true)} className="text-xs font-mono text-accent-blue hover:text-blue-300">
              Edit
            </button>
          )}
        </div>
      </div>

      {editing ? (
        <div className="space-y-4">
          <div>
            <label className="block text-[10px] font-mono text-gray-500 uppercase mb-1">Name</label>
            <input
              type="text"
              value={form.name}
              onChange={e => setForm(f => ({ ...f, name: e.target.value }))}
              className="w-full bg-surface-600 border border-border rounded-lg px-3 py-2 text-xs font-mono text-white outline-none focus:border-accent-blue"
            />
          </div>

          <div className="grid grid-cols-2 gap-3">
            <div>
              <label className="block text-[10px] font-mono text-gray-500 uppercase mb-1">Min Severity</label>
              <select
                value={form.min_severity}
                onChange={e => setForm(f => ({ ...f, min_severity: e.target.value }))}
                className="w-full bg-surface-600 border border-border rounded-lg px-3 py-2 text-xs font-mono text-white outline-none focus:border-accent-blue"
              >
                {SEVERITY_OPTIONS.map(opt => (
                  <option key={opt.value} value={opt.value}>{opt.label}</option>
                ))}
              </select>
            </div>

            <div>
              <label className="block text-[10px] font-mono text-gray-500 uppercase mb-1">Anomaly Threshold</label>
              <input
                type="number"
                step="0.1"
                min="0"
                max="1"
                value={form.anomaly_score_threshold}
                onChange={e => setForm(f => ({ ...f, anomaly_score_threshold: parseFloat(e.target.value) }))}
                className="w-full bg-surface-600 border border-border rounded-lg px-3 py-2 text-xs font-mono text-white outline-none focus:border-accent-blue"
              />
            </div>
          </div>

          <div className="flex items-center gap-6">
            <label className="flex items-center gap-2 cursor-pointer">
              <input
                type="checkbox"
                checked={form.email_enabled}
                onChange={e => setForm(f => ({ ...f, email_enabled: e.target.checked }))}
                className="w-4 h-4 rounded border-border bg-surface-600 text-accent-blue focus:ring-accent-blue"
              />
              <span className="text-xs font-mono text-gray-400 flex items-center gap-1">
                <Mail className="w-3 h-3" /> Email
              </span>
            </label>

            <label className="flex items-center gap-2 cursor-pointer">
              <input
                type="checkbox"
                checked={form.webhook_enabled}
                onChange={e => setForm(f => ({ ...f, webhook_enabled: e.target.checked }))}
                className="w-4 h-4 rounded border-border bg-surface-600 text-accent-blue focus:ring-accent-blue"
              />
              <span className="text-xs font-mono text-gray-400 flex items-center gap-1">
                <Webhook className="w-3 h-3" /> Webhook
              </span>
            </label>
          </div>

          <div className="flex items-center gap-2">
            <button
              onClick={handleSave}
              className="flex items-center gap-1.5 px-3 py-1.5 text-xs font-mono bg-accent-blue text-surface-900 rounded-lg hover:bg-blue-400 transition-colors"
            >
              <Save className="w-3.5 h-3.5" /> Save
            </button>
            <button
              onClick={() => { setForm(threshold); setEditing(false) }}
              className="flex items-center gap-1.5 px-3 py-1.5 text-xs font-mono text-gray-400 hover:text-white transition-colors"
            >
              <RotateCcw className="w-3.5 h-3.5" /> Cancel
            </button>
          </div>
        </div>
      ) : (
        <div className="space-y-2">
          <div className="flex justify-between text-xs">
            <span className="font-mono text-gray-500">Min Severity</span>
            <span className="font-mono text-white capitalize">{threshold.min_severity}</span>
          </div>
          <div className="flex justify-between text-xs">
            <span className="font-mono text-gray-500">Anomaly Score Threshold</span>
            <span className="font-mono text-white">{threshold.anomaly_score_threshold}</span>
          </div>
          <div className="flex justify-between text-xs">
            <span className="font-mono text-gray-500">Email Alerts</span>
            <span className={`font-mono ${threshold.email_enabled ? 'text-accent-green' : 'text-gray-600'}`}>
              {threshold.email_enabled ? 'Enabled' : 'Disabled'}
            </span>
          </div>
          <div className="flex justify-between text-xs">
            <span className="font-mono text-gray-500">Webhook Alerts</span>
            <span className={`font-mono ${threshold.webhook_enabled ? 'text-accent-green' : 'text-gray-600'}`}>
              {threshold.webhook_enabled ? 'Enabled' : 'Disabled'}
            </span>
          </div>
          <button
            onClick={() => onDelete(threshold.id)}
            className="mt-2 flex items-center gap-1.5 text-xs font-mono text-accent-red hover:text-red-400 transition-colors"
          >
            <Trash2 className="w-3.5 h-3.5" /> Delete
          </button>
        </div>
      )}
    </div>
  )
}

export default function Settings() {
  const [thresholds, setThresholds] = useState([])
  const [systemConfig, setSystemConfig] = useState(null)
  const [honeypotMode, setHoneypotMode] = useState('active')
  const [loading, setLoading] = useState(true)
  const [saving, setSaving] = useState(false)
  const [showNewThreshold, setShowNewThreshold] = useState(false)
  const [newThreshold, setNewThreshold] = useState({
    name: '',
    min_severity: 'medium',
    anomaly_score_threshold: 0.7,
    email_enabled: true,
    webhook_enabled: false,
  })

  const fetchData = useCallback(async () => {
    try {
      const [thresholdsData, configData] = await Promise.all([
        api.settings.thresholds(),
        api.settings.systemConfig(),
      ])
      setThresholds(thresholdsData || [])
      setSystemConfig(configData)
      setHoneypotMode(configData?.honeypot_mode || 'active')
    } catch (err) {
      console.error('Settings fetch error:', err)
    } finally {
      setLoading(false)
    }
  }, [])

  useEffect(() => {
    fetchData()
  }, [fetchData])

  const handleUpdateThreshold = async (id, data) => {
    await api.settings.updateThreshold(id, data)
    fetchData()
  }

  const handleDeleteThreshold = async (id) => {
    await api.settings.deleteThreshold(id)
    fetchData()
  }

  const handleCreateThreshold = async () => {
    if (!newThreshold.name.trim()) return
    await api.settings.createThreshold(newThreshold)
    setNewThreshold({ name: '', min_severity: 'medium', anomaly_score_threshold: 0.7, email_enabled: true, webhook_enabled: false })
    setShowNewThreshold(false)
    fetchData()
  }

  const handleUpdateMode = async () => {
    setSaving(true)
    try {
      await api.settings.updateSystemConfig({ honeypot_mode: honeypotMode })
    } catch (err) {
      console.error('Mode update error:', err)
    } finally {
      setSaving(false)
    }
  }

  if (loading) {
    return (
      <div className="flex items-center justify-center h-64">
        <div className="flex items-center gap-3">
          <div className="w-6 h-6 border-2 border-accent-cyan border-t-transparent rounded-full animate-spin" />
          <span className="font-mono text-sm text-gray-400">Loading settings...</span>
        </div>
      </div>
    )
  }

  return (
    <div className="space-y-6 animate-fade-in max-w-5xl">
      <div className="bg-surface-800 border border-border rounded-xl p-6">
        <div className="flex items-center gap-2 mb-6">
          <SettingsIcon className="w-5 h-5 text-accent-cyan" />
          <h2 className="font-mono text-sm font-semibold text-white uppercase tracking-wider">
            Honeypot Configuration
          </h2>
        </div>

        <div className="grid grid-cols-1 md:grid-cols-2 gap-6">
          <div>
            <label className="block text-xs font-mono text-gray-400 mb-2 uppercase tracking-wider">
              Global Emulation Mode
            </label>
            <div className="flex gap-3">
              {[
                { value: 'active', label: 'Active Emulation', desc: 'Full logging & interaction' },
                { value: 'passive', label: 'Passive Monitoring', desc: 'Lightweight detection' },
              ].map(mode => (
                <button
                  key={mode.value}
                  onClick={() => setHoneypotMode(mode.value)}
                  className={`flex-1 p-4 rounded-xl border transition-all text-left ${
                    honeypotMode === mode.value
                      ? 'bg-surface-600 border-accent-blue'
                      : 'bg-surface-700 border-border hover:border-gray-500'
                  }`}
                >
                  <div className="flex items-center gap-2 mb-1">
                    <Activity className={`w-4 h-4 ${honeypotMode === mode.value ? 'text-accent-blue' : 'text-gray-500'}`} />
                    <span className="text-sm font-mono font-semibold text-white">{mode.label}</span>
                  </div>
                  <p className="text-[10px] font-mono text-gray-500">{mode.desc}</p>
                </button>
              ))}
            </div>
            <button
              onClick={handleUpdateMode}
              disabled={saving}
              className="mt-3 flex items-center gap-1.5 px-4 py-2 text-xs font-mono bg-accent-blue text-surface-900 rounded-lg hover:bg-blue-400 disabled:opacity-50 transition-all"
            >
              <Save className="w-3.5 h-3.5" />
              {saving ? 'Saving...' : 'Apply Mode'}
            </button>
          </div>

          <div>
            <label className="block text-xs font-mono text-gray-400 mb-2 uppercase tracking-wider">
              Active Nodes
            </label>
            <div className="bg-surface-700 border border-border rounded-xl p-4 space-y-2">
              <div className="flex justify-between text-xs">
                <span className="font-mono text-gray-500">Total Nodes</span>
                <span className="font-mono text-white">{systemConfig?.active_nodes || 4}</span>
              </div>
              <div className="flex justify-between text-xs">
                <span className="font-mono text-gray-500">Protocols</span>
                <span className="font-mono text-white">{(systemConfig?.protocols || ['ssh', 'http', 'ftp']).join(', ')}</span>
              </div>
              <div className="flex justify-between text-xs">
                <span className="font-mono text-gray-500">Current Mode</span>
                <span className="font-mono text-accent-green capitalize">{honeypotMode}</span>
              </div>
            </div>
          </div>
        </div>
      </div>

      <div className="bg-surface-800 border border-border rounded-xl p-6">
        <div className="flex items-center justify-between mb-6">
          <div className="flex items-center gap-2">
            <AlertTriangle className="w-5 h-5 text-accent-red" />
            <h2 className="font-mono text-sm font-semibold text-white uppercase tracking-wider">
              Alert Thresholds
            </h2>
          </div>
          <button
            onClick={() => setShowNewThreshold(!showNewThreshold)}
            className="flex items-center gap-1.5 px-3 py-1.5 text-xs font-mono bg-surface-600 border border-border rounded-lg text-gray-300 hover:text-white transition-colors"
          >
            <Plus className="w-3.5 h-3.5" />
            New Threshold
          </button>
        </div>

        {showNewThreshold && (
          <div className="bg-surface-700 border border-accent-blue/30 rounded-xl p-5 mb-4 animate-fade-in">
            <h3 className="text-xs font-mono text-accent-blue mb-3">Create New Threshold</h3>
            <div className="grid grid-cols-1 md:grid-cols-2 gap-3 mb-4">
              <div>
                <label className="block text-[10px] font-mono text-gray-500 uppercase mb-1">Name</label>
                <input
                  type="text"
                  value={newThreshold.name}
                  onChange={e => setNewThreshold(f => ({ ...f, name: e.target.value }))}
                  placeholder="e.g., Critical Only"
                  className="w-full bg-surface-600 border border-border rounded-lg px-3 py-2 text-xs font-mono text-white placeholder-gray-600 outline-none focus:border-accent-blue"
                />
              </div>
              <div>
                <label className="block text-[10px] font-mono text-gray-500 uppercase mb-1">Min Severity</label>
                <select
                  value={newThreshold.min_severity}
                  onChange={e => setNewThreshold(f => ({ ...f, min_severity: e.target.value }))}
                  className="w-full bg-surface-600 border border-border rounded-lg px-3 py-2 text-xs font-mono text-white outline-none focus:border-accent-blue"
                >
                  {SEVERITY_OPTIONS.map(opt => (
                    <option key={opt.value} value={opt.value}>{opt.label}</option>
                  ))}
                </select>
              </div>
              <div>
                <label className="block text-[10px] font-mono text-gray-500 uppercase mb-1">Anomaly Threshold</label>
                <input
                  type="number"
                  step="0.1"
                  min="0"
                  max="1"
                  value={newThreshold.anomaly_score_threshold}
                  onChange={e => setNewThreshold(f => ({ ...f, anomaly_score_threshold: parseFloat(e.target.value) }))}
                  className="w-full bg-surface-600 border border-border rounded-lg px-3 py-2 text-xs font-mono text-white outline-none focus:border-accent-blue"
                />
              </div>
              <div className="flex items-center gap-6 pt-5">
                <label className="flex items-center gap-2 cursor-pointer">
                  <input
                    type="checkbox"
                    checked={newThreshold.email_enabled}
                    onChange={e => setNewThreshold(f => ({ ...f, email_enabled: e.target.checked }))}
                    className="w-4 h-4 rounded border-border bg-surface-600 text-accent-blue"
                  />
                  <span className="text-xs font-mono text-gray-400 flex items-center gap-1">
                    <Mail className="w-3 h-3" /> Email
                  </span>
                </label>
                <label className="flex items-center gap-2 cursor-pointer">
                  <input
                    type="checkbox"
                    checked={newThreshold.webhook_enabled}
                    onChange={e => setNewThreshold(f => ({ ...f, webhook_enabled: e.target.checked }))}
                    className="w-4 h-4 rounded border-border bg-surface-600 text-accent-blue"
                  />
                  <span className="text-xs font-mono text-gray-400 flex items-center gap-1">
                    <Webhook className="w-3 h-3" /> Webhook
                  </span>
                </label>
              </div>
            </div>
            <div className="flex items-center gap-2">
              <button
                onClick={handleCreateThreshold}
                disabled={!newThreshold.name.trim()}
                className="flex items-center gap-1.5 px-3 py-1.5 text-xs font-mono bg-accent-blue text-surface-900 rounded-lg hover:bg-blue-400 disabled:opacity-50 transition-colors"
              >
                <Save className="w-3.5 h-3.5" /> Create
              </button>
              <button
                onClick={() => setShowNewThreshold(false)}
                className="px-3 py-1.5 text-xs font-mono text-gray-400 hover:text-white transition-colors"
              >
                Cancel
              </button>
            </div>
          </div>
        )}

        {thresholds.length > 0 ? (
          <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
            {thresholds.map(t => (
              <ThresholdCard
                key={t.id}
                threshold={t}
                onUpdate={handleUpdateThreshold}
                onDelete={handleDeleteThreshold}
              />
            ))}
          </div>
        ) : (
          <div className="text-center py-8">
            <Bell className="w-8 h-8 text-gray-600 mx-auto mb-3" />
            <p className="font-mono text-sm text-gray-500">No alert thresholds configured</p>
            <p className="font-mono text-xs text-gray-600 mt-1">Create one to start receiving notifications</p>
          </div>
        )}
      </div>

      <div className="bg-surface-800 border border-border rounded-xl p-6">
        <div className="flex items-center gap-2 mb-4">
          <Globe className="w-5 h-5 text-accent-blue" />
          <h2 className="font-mono text-sm font-semibold text-white uppercase tracking-wider">
            Integration Endpoints
          </h2>
        </div>
        <div className="bg-surface-700 border border-border rounded-lg p-4 font-mono text-xs space-y-2">
          <div className="flex justify-between">
            <span className="text-gray-500">API Base URL</span>
            <span className="text-accent-blue">{import.meta.env.VITE_API_URL || 'http://localhost:8000/api/v1'}</span>
          </div>
          <div className="flex justify-between">
            <span className="text-gray-500">Export Formats</span>
            <span className="text-white">JSON, CEF, STIX/TAXII</span>
          </div>
          <div className="flex justify-between">
            <span className="text-gray-500">SIEM Compatible</span>
            <span className="text-accent-green">Yes</span>
          </div>
        </div>
      </div>
    </div>
  )
}
