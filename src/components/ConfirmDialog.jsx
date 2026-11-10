import { useState } from 'react'
import Dialog from './Dialog'

/**
 * A question that has to be answered before something consequential happens:
 * downloading a live sample, blocking an address. A real modal — focus is
 * held inside it and Escape cancels — rather than window.confirm, which
 * cannot say enough and cannot be styled to be read from a distance.
 *
 * With `acknowledge`, the confirm button stays disabled until the reader has
 * ticked a statement of what they are about to do.
 */
export default function ConfirmDialog({
  title,
  children,
  confirmLabel,
  cancelLabel = 'Cancel',
  acknowledge,
  busy = false,
  error = null,
  onConfirm,
  onCancel,
}) {
  const [acknowledged, setAcknowledged] = useState(false)
  const blocked = busy || (Boolean(acknowledge) && !acknowledged)

  return (
    <Dialog label={title} onClose={busy ? () => {} : onCancel} width="max-w-lg">
      <div className="p-5">
        <h2 className="text-[17px] font-semibold text-paper">{title}</h2>
        <div className="mt-3 space-y-2.5 text-[13px] leading-relaxed text-paper-2">{children}</div>

        {acknowledge && (
          <label className="mt-4 flex cursor-pointer items-start gap-2.5">
            <input
              type="checkbox"
              checked={acknowledged}
              onChange={(event) => setAcknowledged(event.target.checked)}
              className="mt-0.5 h-4 w-4 shrink-0 accent-paper"
            />
            <span className="text-[13px] font-medium text-paper">{acknowledge}</span>
          </label>
        )}

        {error && <p role="alert" className="mt-3 text-[13px] text-s4">{error}</p>}

        <div className="mt-5 flex flex-wrap justify-end gap-2">
          <button type="button" className="control" onClick={onCancel} disabled={busy}>
            {cancelLabel}
          </button>
          <button type="button" className="control control-primary" onClick={onConfirm} disabled={blocked}>
            {confirmLabel}
          </button>
        </div>
      </div>
    </Dialog>
  )
}
