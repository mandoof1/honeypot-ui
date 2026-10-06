/* The http_diversion event a session carries, if the decoy application answered it. */
export function diversionOf(session) {
  return (session?.network_events || []).find((e) => e.event_type === 'http_diversion') || null
}
