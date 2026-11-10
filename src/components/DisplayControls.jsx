import { usePreferences } from '../context/usePreferences'
import { offsetLabel, localOffsetMinutes } from '../lib/time'

/*
 * Display controls, pinned in the rail.
 *
 * Three settings that change how everything on screen reads, so they are one
 * click away on every page rather than on a settings screen: the theme (dark,
 * or light and high-contrast for a projector), the zone every timestamp is
 * printed in, and presentation mode, which keeps passwords and keys masked
 * while the console is being shown to a room.
 */

function Segmented({ label, value, options, onChange }) {
  return (
    <div className="flex items-center justify-between gap-2" role="group" aria-label={label}>
      <span className="text-[12px] text-paper-3">{label}</span>
      <span className="inline-flex overflow-hidden rounded-[3px] border border-line">
        {options.map(([id, text, title]) => {
          const active = value === id
          return (
            <button
              key={id}
              type="button"
              aria-pressed={active}
              title={title}
              onClick={() => onChange(id)}
              className={`px-2 py-0.5 text-[12px] font-medium transition-colors ${
                active ? 'bg-paper text-ink-0' : 'bg-ink-2 text-paper-2 hover:text-paper'
              }`}
            >
              {text}
            </button>
          )
        })}
      </span>
    </div>
  )
}

export default function DisplayControls() {
  const { theme, zone, presentation, setPreference } = usePreferences()
  const local = offsetLabel(localOffsetMinutes())

  return (
    <section aria-label="Display" className="space-y-2 border-t border-line px-4 py-3">
      <Segmented
        label="Theme"
        value={theme}
        onChange={(next) => setPreference('theme', next)}
        options={[
          ['dark', 'Dark', 'The default dark palette'],
          ['light', 'Light', 'Light, high-contrast: for a projector or a bright room'],
        ]}
      />
      <Segmented
        label="Times"
        value={zone}
        onChange={(next) => setPreference('zone', next)}
        options={[
          ['local', 'Local', `Show every time in this browser's zone (${local})`],
          ['utc', 'UTC', 'Show every time in UTC, as the server stores it'],
        ]}
      />
      <label className="flex cursor-pointer items-center justify-between gap-2">
        <span
          className="text-[12px] text-paper-3"
          title="Keeps passwords, keys and codes masked, even after Reveal"
        >
          Presentation mode
        </span>
        <input
          type="checkbox"
          checked={presentation}
          onChange={(event) => setPreference('presentation', event.target.checked)}
          className="h-3.5 w-3.5 accent-paper"
        />
      </label>
      {presentation && (
        <p className="text-[12px] leading-snug text-paper-2" role="note">
          Secrets are masked.
        </p>
      )}
    </section>
  )
}
