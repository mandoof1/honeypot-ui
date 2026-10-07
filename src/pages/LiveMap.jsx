import { useCallback, useEffect, useMemo, useState } from 'react'
import { Link } from 'react-router-dom'
import {
  CircleMarker, MapContainer, Popup, TileLayer, Tooltip, ZoomControl,
} from 'react-leaflet'
import 'leaflet/dist/leaflet.css'
import { api } from '../services/api'
import ErrorBanner from '../components/ErrorBanner'
import { LoadingRegion } from '../components/Loading'
import { useVisiblePoll } from '../hooks/useVisiblePoll'
import { clean } from '../lib/text'
import { SEVERITY_COLOR, SEVERITY_ORDER, CATEGORY_LABEL } from '../lib/severity'

const REFRESH_MS = 10000

/** Marker size follows the severity scale, so magnitude reads without hue. */
const MARKER = {
  low: { radius: 4, opacity: 0.5 },
  medium: { radius: 6, opacity: 0.6 },
  high: { radius: 8, opacity: 0.72 },
  critical: { radius: 11, opacity: 0.85 },
}

const FILTERS = ['all', ...SEVERITY_ORDER]

export default function LiveMap() {
  const [events, setEvents] = useState([])
  const [loading, setLoading] = useState(true)
  const [error, setError] = useState(null)
  const [filter, setFilter] = useState('all')

  const fetchEvents = useCallback(async () => {
    try {
      setEvents((await api.dashboard.liveEvents(200)) || [])
      setError(null)
    } catch (err) {
      setError(err.message)
    } finally {
      setLoading(false)
    }
  }, [])

  useEffect(() => {
    const timer = setTimeout(fetchEvents, 0)
    return () => clearTimeout(timer)
  }, [fetchEvents])
  useVisiblePoll(fetchEvents, REFRESH_MS)

  // An event is mappable only when geolocation actually resolved. Sessions
  // without a location are counted separately rather than silently dropped.
  const locatable = useMemo(
    () =>
      events.filter(
        (e) => typeof e.geo_lat === 'number' && typeof e.geo_lon === 'number',
      ),
    [events],
  )

  // Counts are computed once over the whole set so each filter shows its own
  // total. An earlier version interpolated an object here and rendered
  // "[object Object]" on every chip.
  const counts = useMemo(() => {
    const c = { all: locatable.length }
    for (const key of SEVERITY_ORDER) c[key] = 0
    for (const event of locatable) {
      if (event.severity in c) c[event.severity] += 1
    }
    return c
  }, [locatable])

  const visible = useMemo(
    () => (filter === 'all' ? locatable : locatable.filter((e) => e.severity === filter)),
    [locatable, filter],
  )

  const byCountry = useMemo(() => {
    const acc = {}
    for (const e of locatable) {
      const name = e.geo_country_name || e.geo_country
      if (name) acc[name] = (acc[name] || 0) + 1
    }
    return Object.entries(acc).sort((a, b) => b[1] - a[1]).slice(0, 8)
  }, [locatable])

  const unlocatable = events.length - locatable.length

  return (
    <div className="mx-auto flex h-full max-w-[1600px] flex-col gap-3">
      {error && <ErrorBanner message={error} onRetry={fetchEvents} />}

      {/* The map is the page, not a widget inside it. Controls and readings
          float over it rather than pushing it into a box. */}
      <div className="panel relative min-h-0 flex-1 overflow-hidden">
        {loading ? (
          <LoadingRegion label="Loading origins" className="h-full" />
        ) : (
          <>
            <MapContainer
              center={[25, 10]}
              zoom={2}
              minZoom={2}
              style={{ height: '100%', width: '100%' }}
              worldCopyJump
              // The default control sits top-left, directly under the
              // severity filters that float there.
              zoomControl={false}
            >
              <ZoomControl position="bottomright" />
              {/* CARTO's basemaps now answer any request carrying a Referer
                  with an "API KEY REQUIRED" watermark tile, so the map was
                  blank on every deployment. OpenStreetMap's own tiles need
                  no key; the class darkens them to match the theme. */}
              <TileLayer
                url="https://tile.openstreetmap.org/{z}/{x}/{y}.png"
                className="map-tiles-dark"
                maxZoom={19}
                attribution={
                  '&copy; <a href="https://www.openstreetmap.org/copyright">OpenStreetMap</a> contributors' +
                  // The location database's licence may require credit too
                  // (DB-IP Lite is CC BY 4.0); set per deployment at build time.
                  (import.meta.env.VITE_GEOIP_ATTRIBUTION ? ` | ${import.meta.env.VITE_GEOIP_ATTRIBUTION}` : '')
                }
              />

              {visible.map((event) => {
                const marker = MARKER[event.severity] || MARKER.low
                const color = SEVERITY_COLOR[event.severity] || 'var(--color-paper-3)'
                return (
                  <CircleMarker
                    key={event.session_uuid}
                    center={[event.geo_lat, event.geo_lon]}
                    radius={marker.radius}
                    pathOptions={{
                      color,
                      fillColor: color,
                      fillOpacity: marker.opacity,
                      weight: 1,
                    }}
                  >
                    <Tooltip direction="top" offset={[0, -10]}>
                      <span className="readout text-xs font-semibold">
                        {clean(event.attacker_ip)}
                      </span>
                      <br />
                      <span className="text-xs">
                        {event.geo_country_name || event.geo_country || 'Unknown origin'}
                      </span>
                    </Tooltip>
                    <Popup>
                      <div className="min-w-44 space-y-1">
                        <p className="readout text-xs font-semibold">
                          <Link to={`/attackers/${encodeURIComponent(event.attacker_ip)}`} title="Everything this address has done">
                            {clean(event.attacker_ip)}
                          </Link>
                        </p>
                        <p className="text-xs">
                          {event.geo_country_name || event.geo_country || 'Unknown origin'}
                        </p>
                        <p className="text-xs">
                          <span className="uppercase">{event.protocol || 'unknown'}</span>
                          {' · '}
                          {CATEGORY_LABEL[event.attack_category] || CATEGORY_LABEL.unknown}
                        </p>
                        <p className="text-xs capitalize" style={{ color }}>
                          {event.severity} severity
                        </p>
                        <p className="readout text-[11px] opacity-70">
                          {new Date(event.timestamp).toLocaleString()}
                        </p>
                        <p className="text-xs">
                          <Link to={`/sessions?session=${event.session_id}`}>Open session</Link>
                        </p>
                      </div>
                    </Popup>
                  </CircleMarker>
                )
              })}
            </MapContainer>

            <div className="pointer-events-none absolute inset-x-0 top-0 z-[500] flex flex-wrap items-start justify-between gap-2 p-3">
              <div className="pointer-events-auto flex flex-wrap gap-1.5">
                {FILTERS.map((key) => {
                  const isActive = filter === key
                  const color = key === 'all' ? 'var(--color-paper)' : SEVERITY_COLOR[key]
                  return (
                    <button
                      key={key}
                      type="button"
                      aria-pressed={isActive}
                      onClick={() => setFilter(key)}
                      className="control bg-ink-1/95 capitalize backdrop-blur"
                      style={isActive ? { borderColor: color } : undefined}
                    >
                      {key !== 'all' && (
                        <span
                          className="h-2 w-2 rounded-full"
                          style={{ background: color }}
                          aria-hidden="true"
                        />
                      )}
                      {key === 'all' ? 'All' : key}
                      <span className="readout text-[12px] text-paper-3">
                        {counts[key] ?? 0}
                      </span>
                    </button>
                  )
                })}
              </div>

              {byCountry.length > 0 && (
                <div className="pointer-events-auto w-48 rounded-[4px] border border-line bg-ink-1/95 p-3 backdrop-blur">
                  <p className="eyebrow">Top origins</p>
                  <dl className="mt-2 space-y-1">
                    {byCountry.map(([name, count]) => (
                      <div key={name} className="flex items-baseline gap-2">
                        <dt className="min-w-0 flex-1 truncate text-[12px] text-paper-2">
                          {name}
                        </dt>
                        <dd className="readout text-[12px] text-paper">{count}</dd>
                      </div>
                    ))}
                  </dl>
                </div>
              )}
            </div>

            {/* With no plottable points the map is a blank ocean; say why so it
                doesn't read as broken. On a tailnet/LAN honeypot every source
                is a private address, which no geolocation database can place. */}
            {visible.length === 0 && (
              <div className="pointer-events-none absolute inset-0 z-[400] flex items-center justify-center p-4">
                <div className="max-w-sm rounded-[4px] border border-line bg-ink-1/95 px-4 py-3 text-center backdrop-blur">
                  <p className="text-[13px] text-paper">No origins to plot yet</p>
                  <p className="mt-1 text-[12px] leading-relaxed text-paper-2">
                    {events.length > 0
                      ? 'Recorded sessions all come from private addresses (tailnet or LAN), which have no geographic location. Internet-facing traffic will appear here.'
                      : 'Sessions with a public source address will appear here as they are captured.'}
                  </p>
                </div>
              </div>
            )}

            {unlocatable > 0 && (
              <p className="pointer-events-none absolute bottom-3 left-3 z-[500] max-w-md rounded-[4px] border border-line bg-ink-1/95 px-3 py-2 text-[12px] text-paper-2 backdrop-blur">
                <span className="readout text-paper">{unlocatable}</span>{' '}
                {unlocatable === 1 ? 'session has' : 'sessions have'} no mappable
                location — their source addresses are private (tailnet or LAN) or
                absent from the geolocation database.
              </p>
            )}
          </>
        )}
      </div>
    </div>
  )
}
