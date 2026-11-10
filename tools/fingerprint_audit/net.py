"""One TCP connection at a time, every wait bounded.

The probes are plain blocking sockets: a probe opens a connection, has a
short exchange, closes it, and the next probe waits its turn. There is no
concurrency anywhere in the audit, and a pause is enforced between
connections so it never looks like load to either target.
"""

from __future__ import annotations

import ipaddress
import socket
import time
from dataclasses import dataclass
from typing import Callable, Optional


@dataclass(frozen=True)
class Target:
    host: str
    port: int

    def __str__(self) -> str:
        return f"{self.host}:{self.port}"


def parse_target(text: str) -> Target:
    """``host:port`` for a loopback address, and nothing else.

    The audit compares the team's own decoy with a reference it started
    itself. Refusing every other address keeps a probe set built to tell
    honeypots apart from being pointed at somebody else's host by accident.
    """
    host, separator, port_text = text.rpartition(":")
    if not separator or not host:
        raise ValueError(f"expected host:port, got {text!r}")
    host = host.strip("[]")
    if host == "localhost":
        host = "127.0.0.1"
    try:
        address = ipaddress.ip_address(host)
    except ValueError as exc:
        raise ValueError(f"{host!r} is not an IP address or 'localhost'") from exc
    if not address.is_loopback:
        raise ValueError(f"{host} is not a loopback address; this tool only audits loopback")
    port = int(port_text)
    if not 0 < port < 65536:
        raise ValueError(f"port {port} out of range")
    return Target(str(address), port)


class Pacer:
    """Keeps a minimum interval between the starts of two connections."""

    def __init__(self, delay: float) -> None:
        self._delay = delay
        self._last_start: Optional[float] = None

    def wait(self) -> None:
        if self._last_start is not None:
            remaining = self._last_start + self._delay - time.monotonic()
            if remaining > 0:
                time.sleep(remaining)
        self._last_start = time.monotonic()


class Connection:
    """A client socket that records when things happened.

    ``closed`` becomes "eof" or "reset" once the peer has ended the
    connection. Which of the two is recorded as evidence only: a proxy or
    port forwarder between the audit and a daemon can turn one into the
    other.
    """

    def __init__(self, target: Target, timeout: float) -> None:
        self._sock = socket.create_connection((target.host, target.port), timeout=timeout)
        self.opened_at = time.monotonic()
        self.first_byte_after: Optional[float] = None
        self.closed: Optional[str] = None
        self.closed_after: Optional[float] = None

    def __enter__(self) -> "Connection":
        return self

    def __exit__(self, *_exc) -> None:
        self.close()

    def _mark_closed(self, how: str) -> None:
        if self.closed is None:
            self.closed = how
            self.closed_after = time.monotonic() - self.opened_at

    def send(self, data: bytes) -> bool:
        """Send everything; False when the peer stopped taking it.

        A failed send does not mark the connection closed: a server that
        answers a too-long request and hangs up mid-upload has still left
        its answer in the receive buffer, and the next read must get it.
        """
        try:
            self._sock.sendall(data)
            return True
        except (BrokenPipeError, ConnectionResetError, ConnectionAbortedError, socket.timeout):
            return False

    def receive(self, timeout: float) -> Optional[bytes]:
        """The next bytes; ``b""`` once the peer has closed; None when
        nothing arrived within ``timeout`` seconds."""
        if self.closed:
            return b""
        self._sock.settimeout(max(timeout, 0.001))
        try:
            data = self._sock.recv(65536)
        except socket.timeout:
            return None
        except (ConnectionResetError, ConnectionAbortedError, BrokenPipeError):
            self._mark_closed("reset")
            return b""
        if not data:
            self._mark_closed("eof")
            return b""
        if self.first_byte_after is None:
            self.first_byte_after = time.monotonic() - self.opened_at
        return data

    def read_until(
        self, done: Callable[[bytes], bool], timeout: float, initial: bytes = b""
    ) -> bytes:
        """Accumulate bytes until ``done(buffer)`` is true, the peer closes,
        or ``timeout`` seconds have passed in total."""
        buffer = initial
        deadline = time.monotonic() + timeout
        while not done(buffer):
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                break
            data = self.receive(remaining)
            if not data:
                # Closed (b"") or out of time (None).
                break
            buffer += data
        return buffer

    def read_quiet(self, quiet: float, timeout: float, initial: bytes = b"") -> bytes:
        """Everything the peer sends until it has been silent for ``quiet``
        seconds, has closed, or ``timeout`` seconds have passed."""
        buffer = initial
        deadline = time.monotonic() + timeout
        while True:
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                break
            data = self.receive(min(quiet, remaining))
            if not data:
                break
            buffer += data
        return buffer

    def wait_closed(self, timeout: float) -> bytes:
        """Wait up to ``timeout`` seconds for the peer to close; returns any
        bytes that arrived meanwhile. Check ``closed`` afterwards."""
        return self.read_until(lambda _buffer: self.closed is not None, timeout)

    def close(self) -> None:
        try:
            self._sock.close()
        except OSError:
            pass


def seconds(value: Optional[float]) -> Optional[float]:
    """A duration rounded for a result file."""
    return None if value is None else round(value, 3)
