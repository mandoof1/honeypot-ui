import { usePreferences } from '../context/usePreferences'

/** A fixed-width mask, so the length of the secret is not on screen either. */
export const SECRET_MASK = '••••••••••••'

/**
 * Whether secrets may be drawn at all. Presentation mode masks them even
 * after someone asked to see them: the console is on a projector, and a
 * password shown to a room is a password disclosed.
 */
export function useSecretsHidden() {
  return usePreferences().presentation
}
