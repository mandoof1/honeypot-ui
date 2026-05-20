import { useState, useEffect, useCallback } from 'react'
import { MapContainer, TileLayer, CircleMarker, Popup, Tooltip } from 'react-leaflet'
import 'leaflet/dist/leaflet.css'
import { api } from '../services/api'

const SEVERITY_CONFIG = {
  critical: { color: '#f85149', radius: 10, opacity: 0.9 },
  high:     { color: '#e3692a', radius: 8, opacity: 0.8 },
  medium:   { color: '#58a6ff', radius: 6, opacity: 0.7 },
  low:      { color: '#3fb950', radius: 4, opacity: 0.6 },
}

export default function LiveMap() {
  const [events, setEvents] = useState([])
  const [loading, setLoading] = useState(true)
  const [filter, setFilter] = useState('all')

  const fetchEvents = useCallback(async () => {
    try {
      const data = await api.dashboard.liveEvents(100)
      setEvents(data || [])
    } catch (err) {
      console.error('LiveMap fetch error:', err)
    } finally {
      setLoading(false)
    }
  }, [])

  useEffect(() => {
    fetchEvents()
    const interval = setInterval(fetchEvents, 10000)
    return () => clearInterval(interval)
  }, [fetchEvents])

  const filteredEvents = events.filter(e => {
    if (filter === 'all') return true
    return e.severity === filter
  })

  const validEvents = filteredEvents.filter(e => e.geo_lat && e.geo_lon)

  const countryCounts = {}
  validEvents.forEach(e => {
    const key = e.geo_country || 'Unknown'
    countryCounts[key] = (countryCounts[key] || 0) + 1
  })

  return (
    <div className="space-y-4">
      <div className="flex items-center justify-between">
        <div className="flex items-center gap-4">
          <span className="text-xs font-mono text-gray-400">
            {validEvents.length} threat markers
          </span>
          <div className="flex gap-2">
            {['all', 'critical', 'high', 'medium', 'low'].map(f => (
              <button
                key={f}
                onClick={() => setFilter(f)}
                className={`px-3 py-1 text-xs font-mono rounded-full border transition-all ${
                  filter === f
                    ? 'bg-surface-600 border-border text-white'
                    : 'border-border/50 text-gray-500 hover:text-gray-300'
                }`}
              >
                {f === 'all' ? `All (${validEvents.length})` : `${f} (${countryCounts})`}
              </button>
            ))}
          </div>
        </div>

        <div className="flex items-center gap-3">
          {Object.entries(SEVERITY_CONFIG).map(([sev, cfg]) => (
            <div key={sev} className="flex items-center gap-1.5">
              <div className="w-2.5 h-2.5 rounded-full" style={{ backgroundColor: cfg.color }} />
              <span className="text-[10px] font-mono text-gray-500 uppercase">{sev}</span>
            </div>
          ))}
        </div>
      </div>

      <div className="h-[calc(100vh-12rem)] rounded-xl overflow-hidden border border-border">
        {loading ? (
          <div className="h-full bg-surface-800 flex items-center justify-center">
            <div className="flex items-center gap-3">
              <div className="w-6 h-6 border-2 border-accent-cyan border-t-transparent rounded-full animate-spin" />
              <span className="font-mono text-sm text-gray-400">Loading threat map...</span>
            </div>
          </div>
        ) : (
          <MapContainer
            center={[20, 0]}
            zoom={2}
            style={{ height: '100%', width: '100%', background: '#0d1117' }}
            attributionControl={false}
            zoomControl={false}
          >
            <TileLayer
              url="https://{s}.basemaps.cartocdn.com/dark_all/{z}/{x}/{y}{r}.png"
              attribution='&copy; <a href="https://carto.com/">CARTO</a>'
            />

            {validEvents.map((event, i) => {
              const cfg = SEVERITY_CONFIG[event.severity] || SEVERITY_CONFIG.low
              return (
                <CircleMarker
                  key={`${event.session_uuid}-${i}`}
                  center={[event.geo_lat, event.geo_lon]}
                  radius={cfg.radius}
                  pathOptions={{
                    color: cfg.color,
                    fillColor: cfg.color,
                    fillOpacity: cfg.opacity,
                    weight: 1,
                  }}
                >
                  <Tooltip direction="top" offset={[0, -10]}>
                    <div className="font-mono text-xs">
                      <div className="font-semibold">{event.attacker_ip}</div>
                      <div className="text-gray-400">{event.geo_country}</div>
                      <div className="text-gray-500">{event.attack_category || 'unknown'}</div>
                    </div>
                  </Tooltip>
                  <Popup>
                    <div className="font-mono text-xs space-y-1">
                      <div className="font-semibold text-accent-blue">{event.attacker_ip}</div>
                      <div>Country: {event.geo_country}</div>
                      <div>Category: {event.attack_category || 'unknown'}</div>
                      <div>Severity: <span style={{ color: cfg.color }}>{event.severity}</span></div>
                      <div className="text-gray-500">{new Date(event.timestamp).toLocaleString()}</div>
                    </div>
                  </Popup>
                </CircleMarker>
              )
            })}
          </MapContainer>
        )}
      </div>
    </div>
  )
}
