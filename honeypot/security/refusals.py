"""A record of the connections the engine turned away.

A connection refused at admission — the address is blocked, over its rate,
or the engine is at one of its connection caps — never became a session, so
nothing downstream knew it had happened. That is the wrong thing to be blind
to: the source being refused hardest is usually the one worth looking at.

Recording every refusal as its own session would turn a connection flood
into a disk and ingest flood, which is the thing admission exists to
prevent. So refusals are counted here, per source, protocol and reason, and
written out once a minute as one minimal session per source carrying a
``connection_refused`` event with the count. The number of sources tracked
and the number of records written per flush are both capped; what does not
fit is counted in ``suppressed`` and reported in the heartbeat.
"""

from __future__ import annotations

import logging
import time

logger = logging.getLogger(__name__)

#: Distinct (source, protocol, reason) keys counted between flushes.
MAX_TRACKED = 1024
#: Minimal sessions written per flush: at one flush a minute, a ceiling of
#: this many refusal records a minute however large the flood.
MAX_RECORDS_PER_FLUSH = 20

#: Admission's internal reason names, as they are reported.
REASONS = {
    "rate": "rate_limit",
    "per_ip": "per_address_connection_cap",
    "total": "global_connection_cap",
    "blocked": "address_blocked",
}


class RefusalLog:
    def __init__(self) -> None:
        self._pending: dict[tuple[str, str, str], list] = {}
        #: Refusals that could not be attributed to a record.
        self.suppressed = 0
        self.recorded = 0

    def note(self, source_ip: str, protocol: str, reason: str) -> None:
        """Count one refusal. Synchronous and cheap: called at accept time."""
        key = (source_ip, protocol or "ssh", REASONS.get(reason, reason))
        entry = self._pending.get(key)
        if entry is not None:
            entry[0] += 1
            return
        if len(self._pending) >= MAX_TRACKED:
            self.suppressed += 1
            return
        self._pending[key] = [1, time.time()]

    def reset(self) -> None:
        self._pending.clear()
        self.suppressed = 0
        self.recorded = 0

    async def flush(self) -> int:
        """Write the pending refusals out as minimal sessions; how many."""
        from honeypot.core.session import session_manager

        pending, self._pending = self._pending, {}
        # The sources refused most often first, in case the cap cuts the rest.
        ordered = sorted(pending.items(), key=lambda item: -item[1][0])
        written = 0
        for (source_ip, protocol, reason), (count, first_seen) in ordered:
            if written >= MAX_RECORDS_PER_FLUSH:
                self.suppressed += count
                continue
            try:
                session_id = await session_manager.create_session(
                    protocol, source_ip, 0, {"refused": True}
                )
                await session_manager.record_network_event(
                    session_id, "connection_refused",
                    {"reason": reason, "count": count, "first_seen": first_seen},
                )
                await session_manager.end_session(session_id)
            except Exception as exc:
                logger.warning("Could not record refused connections from %s: %s", source_ip, exc)
                self.suppressed += count
                continue
            written += 1
        self.recorded += written
        return written


refusal_log = RefusalLog()
