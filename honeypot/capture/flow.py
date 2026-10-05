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
"""

from __future__ import annotations

import asyncio
import time
from typing import Any


class FlowMeter:
    __slots__ = (
        "measured_at", "start", "end", "last_any",
        "fwd_packets", "fwd_bytes", "fwd_max", "fwd_last",
        "fwd_iat_sum", "fwd_iat_count", "fwd_iat_max",
        "bwd_packets", "bwd_bytes", "bwd_max", "flow_iat_max",
    )

    def __init__(self, measured_at: str = "socket", now: float | None = None) -> None:
        self.measured_at = measured_at
        self.start = time.monotonic() if now is None else now
        self.end: float | None = None
        self.last_any = self.start
        self.fwd_packets = self.fwd_bytes = self.fwd_max = 0
        self.fwd_last: float | None = None
        self.fwd_iat_sum = 0.0
        self.fwd_iat_count = 0
        self.fwd_iat_max = 0.0
        self.bwd_packets = self.bwd_bytes = self.bwd_max = 0
        self.flow_iat_max = 0.0

    def _tick(self, now: float) -> None:
        self.flow_iat_max = max(self.flow_iat_max, now - self.last_any)
        self.last_any = now

    def inbound(self, size: int, now: float | None = None) -> None:
        """Data from the client: CICFlowMeter's forward direction."""
        if size <= 0 or self.end is not None:
            return
        now = time.monotonic() if now is None else now
        self._tick(now)
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
        if size <= 0 or self.end is not None:
            return
        now = time.monotonic() if now is None else now
        self._tick(now)
        self.bwd_packets += 1
        self.bwd_bytes += size
        self.bwd_max = max(self.bwd_max, size)

    def close(self, now: float | None = None) -> None:
        if self.end is None:
            now = time.monotonic() if now is None else now
            self._tick(now)
            self.end = now

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
