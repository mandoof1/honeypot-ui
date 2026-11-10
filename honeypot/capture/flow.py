"""Per-connection flow statistics, measured at the socket.

The stage-1 classifier is trained on CIC-IDS2017, whose features CICFlowMeter
derives from packets on the wire. Until this existed the engine reported each
session's traffic as a list of event names, so the classifier was handed a
vector that was almost entirely zeros and its verdict described nothing.

The engine still never sees packets, only what its sockets deliver, so this
measures the closest equivalents that are observable there and that mean the
same thing on both sides:

* direction follows CICFlowMeter: *forward* is from the client that opened the
  connection (the attacker), *backward* is the honeypot's replies;
* a forward "packet" is one chunk the socket delivered, which for interactive
  traffic is one TCP segment carrying data — CICFlowMeter's
  ``act_data_pkt_fwd``, which likewise ignores bare ACKs;
* byte counts are payload bytes, as in CICFlowMeter's length features;
* timing is inter-arrival time between those chunks.

Where the socket sits below the protocol (SSH, FTP, plain HTTP) the bytes are
the ones on the wire, encrypted SSH included. HTTPS is measured above TLS, so
handshake and record overhead are missing there; ``measured_at`` records which
case applies so the difference stays visible in the data.

Only running aggregates are kept, so a long session costs constant memory.

A web session is not one connection. The HTTP decoys merge every connection a
client makes into one session and deliver it some seconds after the last one
closed, so a web session's meter is an aggregate: each connection keeps its
own meter until the session is known, then ``join``s the session's, which
takes over what was counted so far and everything after. The aggregate stops
its clock when the last connection closes (``close``) and starts it again if
the client comes back (``reopen``), so the seconds the engine spent waiting to
see whether it would are not reported as part of the flow.
"""

from __future__ import annotations

import asyncio
import time
from typing import Any


class FlowMeter:
    __slots__ = (
        "measured_at", "start", "end", "last_any", "first_any",
        "fwd_packets", "fwd_bytes", "fwd_max", "fwd_first", "fwd_last",
        "fwd_iat_sum", "fwd_iat_count", "fwd_iat_max",
        "bwd_packets", "bwd_bytes", "bwd_max", "flow_iat_max",
        "_sink",
    )

    def __init__(self, measured_at: str = "socket", now: float | None = None) -> None:
        self.measured_at = measured_at
        self.start = time.monotonic() if now is None else now
        self.end: float | None = None
        self.last_any = self.start
        #: When the first data moved, either way; None until some has.
        self.first_any: float | None = None
        self.fwd_packets = self.fwd_bytes = self.fwd_max = 0
        self.fwd_first: float | None = None
        self.fwd_last: float | None = None
        self.fwd_iat_sum = 0.0
        self.fwd_iat_count = 0
        self.fwd_iat_max = 0.0
        self.bwd_packets = self.bwd_bytes = self.bwd_max = 0
        self.flow_iat_max = 0.0
        #: The session meter this connection's traffic is counted on, once
        #: it has joined one.
        self._sink: FlowMeter | None = None

    def _tick(self, now: float) -> None:
        self.flow_iat_max = max(self.flow_iat_max, now - self.last_any)
        self.last_any = now

    def inbound(self, size: int, now: float | None = None) -> None:
        """Data from the client: CICFlowMeter's forward direction."""
        if self._sink is not None:
            self._sink.inbound(size, now)
            return
        if size <= 0 or self.end is not None:
            return
        now = time.monotonic() if now is None else now
        self._tick(now)
        if self.first_any is None:
            self.first_any = now
        if self.fwd_first is None:
            self.fwd_first = now
        if self.fwd_last is not None:
            gap = now - self.fwd_last
            self.fwd_iat_sum += gap
            self.fwd_iat_count += 1
            self.fwd_iat_max = max(self.fwd_iat_max, gap)
        self.fwd_last = now
        self.fwd_packets += 1
        self.fwd_bytes += size
        self.fwd_max = max(self.fwd_max, size)

    def outbound(self, size: int, now: float | None = None) -> None:
        """Data the honeypot sent back: the backward direction."""
        if self._sink is not None:
            self._sink.outbound(size, now)
            return
        if size <= 0 or self.end is not None:
            return
        now = time.monotonic() if now is None else now
        self._tick(now)
        if self.first_any is None:
            self.first_any = now
        self.bwd_packets += 1
        self.bwd_bytes += size
        self.bwd_max = max(self.bwd_max, size)

    def close(self, now: float | None = None) -> None:
        """Stop the clock. Closing twice keeps the first time."""
        if self._sink is not None:
            # The session's meter outlives this connection; whoever owns the
            # session closes it.
            return
        if self.end is None:
            now = time.monotonic() if now is None else now
            self._tick(now)
            self.end = now

    def reopen(self) -> None:
        """Start the clock again: the client opened another connection.

        The silence since ``close`` then counts as one gap inside the flow,
        which is what it was.
        """
        self.end = None

    def join(self, session: "FlowMeter") -> None:
        """Count this connection as part of a session's flow from now on.

        A connection is metered from the moment it is accepted, but which
        session it belongs to is only known once its first request has been
        read. What was counted until then is handed to the session's meter,
        and everything after goes straight to it.
        """
        if session is self or self._sink is not None:
            return
        session._absorb(self)
        self._sink = session

    def _absorb(self, other: "FlowMeter") -> None:
        """Fold in the traffic another meter counted before it joined."""
        self.start = min(self.start, other.start)

        if other.fwd_packets:
            if self.fwd_last is not None and other.fwd_first is not None:
                # The gap between the last client data on this flow and the
                # first on the new connection is an inter-arrival time too.
                # Connections can overlap, so it may not be positive.
                gap = max(other.fwd_first - self.fwd_last, 0.0)
                self.fwd_iat_sum += gap
                self.fwd_iat_count += 1
                self.fwd_iat_max = max(self.fwd_iat_max, gap)
            self.fwd_iat_sum += other.fwd_iat_sum
            self.fwd_iat_count += other.fwd_iat_count
            self.fwd_iat_max = max(self.fwd_iat_max, other.fwd_iat_max)
            if self.fwd_first is None:
                self.fwd_first = other.fwd_first
            if self.fwd_last is None or (other.fwd_last or 0.0) > self.fwd_last:
                self.fwd_last = other.fwd_last
            self.fwd_packets += other.fwd_packets
            self.fwd_bytes += other.fwd_bytes
            self.fwd_max = max(self.fwd_max, other.fwd_max)

        self.bwd_packets += other.bwd_packets
        self.bwd_bytes += other.bwd_bytes
        self.bwd_max = max(self.bwd_max, other.bwd_max)

        if other.first_any is not None:
            had_traffic = self.first_any is not None
            if had_traffic:
                # Silence between this flow's last activity and the new
                # connection's first, then whatever gaps it saw of its own.
                self.flow_iat_max = max(
                    self.flow_iat_max, other.first_any - self.last_any, other.flow_iat_max
                )
            else:
                self.flow_iat_max = max(self.flow_iat_max, other.flow_iat_max)
                self.first_any = other.first_any
            self.last_any = max(self.last_any, other.last_any)

    def summary(self) -> dict[str, Any]:
        end = self.end if self.end is not None else time.monotonic()
        return {
            "measured_at": self.measured_at,
            "duration": round(max(end - self.start, 0.0), 6),
            "fwd_packets": self.fwd_packets,
            "fwd_bytes": self.fwd_bytes,
            "fwd_max": self.fwd_max,
            "bwd_packets": self.bwd_packets,
            "bwd_bytes": self.bwd_bytes,
            "bwd_max": self.bwd_max,
            "fwd_iat_mean": round(self.fwd_iat_sum / self.fwd_iat_count, 6)
            if self.fwd_iat_count else 0.0,
            "fwd_iat_max": round(self.fwd_iat_max, 6),
            "flow_iat_max": round(self.flow_iat_max, 6),
        }

    # -- attaching to connections ------------------------------------------

    @classmethod
    def for_stream(
        cls, reader: asyncio.StreamReader, writer: asyncio.StreamWriter, tls: bool = False
    ) -> "FlowMeter":
        """Meter an asyncio stream pair (the FTP and HTTP emulators).

        ``feed_data`` is what the stream's protocol calls with each chunk the
        socket returned, and every reply goes through the transport's
        ``write``; wrapping both sees all traffic without touching the
        emulators' parsing.
        """
        meter = cls("tls_plaintext" if tls else "socket")
        feed, write = reader.feed_data, writer.transport.write

        def metered_feed(data: bytes) -> None:
            meter.inbound(len(data))
            feed(data)

        def metered_write(data: bytes) -> None:
            meter.outbound(len(data))
            write(data)

        reader.feed_data = metered_feed  # type: ignore[method-assign]
        writer.transport.write = metered_write  # type: ignore[method-assign]
        return meter

    @classmethod
    def for_ssh(cls, conn: Any) -> "FlowMeter":
        """Meter an asyncssh connection below its encryption layer.

        asyncssh owns the socket, so this wraps the connection object's
        ``data_received`` and its transport's ``write``. The server's
        ``connection_made`` runs before asyncssh sends its version string, so
        the whole exchange, key exchange included, is counted — which is what
        CICFlowMeter saw for the SSH-Patator flows the model learns from.
        """
        meter = cls("ssh_transport")
        transport = getattr(conn, "_transport", None)
        if transport is None:
            return meter
        received, write = conn.data_received, transport.write

        def metered_received(data: bytes, *args: Any) -> None:
            meter.inbound(len(data))
            received(data, *args)

        def metered_write(data: bytes) -> None:
            meter.outbound(len(data))
            write(data)

        conn.data_received = metered_received
        transport.write = metered_write
        return meter
