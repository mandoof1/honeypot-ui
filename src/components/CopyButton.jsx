import { useEffect, useRef, useState } from 'react'
import { Check, Copy } from 'lucide-react'
import { cleanLine } from '../lib/text'

/**
 * Copy a value to the clipboard.
 *
 * What is copied is the sanitised, single-line form unless `raw` is set:
 * hidden characters and line breaks an attacker put into a value must not
 * travel into a shell or a blocklist by way of the clipboard. `raw` is for
 * values the console generated itself, such as a temporary password.
 */
export default function CopyButton({ value, label, raw = false, children, className = '' }) {
  const [state, setState] = useState('idle')
  const timer = useRef(null)

  useEffect(() => () => clearTimeout(timer.current), [])

  const copy = async () => {
    try {
      await navigator.clipboard.writeText(raw ? String(value) : cleanLine(String(value)))
      setState('copied')
    } catch {
      // Clipboard access is refused in some contexts (an insecure origin, a
      // denied permission). Say so rather than appear to have worked.
      setState('failed')
    }
    clearTimeout(timer.current)
    timer.current = setTimeout(() => setState('idle'), 1600)
  }

  const iconOnly = !children
  return (
    <span className="inline-flex items-center gap-1">
      <button
        type="button"
        onClick={copy}
        aria-label={label}
        title={iconOnly ? label : undefined}
        className={iconOnly
          ? `shrink-0 rounded-[3px] p-1 text-paper-3 transition-colors hover:text-paper ${className}`
          : `control ${className}`}
      >
        {state === 'copied'
          ? <Check className="h-3.5 w-3.5" strokeWidth={2} aria-hidden="true" />
          : <Copy className="h-3.5 w-3.5" strokeWidth={2} aria-hidden="true" />}
        {children}
      </button>
      <span aria-live="polite" className="text-[12px] text-paper-3">
        {state === 'copied' ? 'copied' : state === 'failed' ? 'copy blocked by the browser' : ''}
      </span>
    </span>
  )
}
