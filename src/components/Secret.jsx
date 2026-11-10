import { useState } from 'react'
import { Eye, EyeOff } from 'lucide-react'
import { SECRET_MASK, useSecretsHidden } from '../hooks/useSecretsHidden'
import CopyButton from './CopyButton'

/**
 * A password, key or code.
 *
 * Hidden until asked for, unless `defaultRevealed` (for a value the reader
 * has just been told to write down). It can be copied without being shown,
 * which is how a temporary password should be handed over anyway. In
 * presentation mode it stays masked whatever was asked.
 */
export default function Secret({ value, label, defaultRevealed = false, raw = true, className = '' }) {
  const hidden = useSecretsHidden()
  const [revealed, setRevealed] = useState(defaultRevealed)
  const shown = revealed && !hidden

  return (
    <span className={`inline-flex flex-wrap items-center gap-x-2 gap-y-1 ${className}`} data-testid="secret">
      <span
        className="readout break-all text-paper"
        // Announced as hidden rather than read out as a row of bullets.
        aria-label={shown ? undefined : `${label}, hidden`}
      >
        {shown ? value : SECRET_MASK}
      </span>
      {hidden ? (
        <span className="text-[12px] text-paper-3">masked in presentation mode</span>
      ) : (
        <button
          type="button"
          onClick={() => setRevealed((current) => !current)}
          aria-pressed={revealed}
          className="inline-flex items-center gap-1 text-[12px] font-medium text-paper-2 transition-colors hover:text-paper"
        >
          {revealed
            ? <EyeOff className="h-3.5 w-3.5" strokeWidth={2} aria-hidden="true" />
            : <Eye className="h-3.5 w-3.5" strokeWidth={2} aria-hidden="true" />}
          {revealed ? `Hide ${label}` : `Show ${label}`}
        </button>
      )}
      <CopyButton value={value} label={`Copy ${label}`} raw={raw} />
    </span>
  )
}
