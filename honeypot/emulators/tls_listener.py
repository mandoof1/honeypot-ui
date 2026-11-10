"""A TLS listener that looks at the ClientHello before the handshake.

``asyncio.start_server(ssl=...)`` completes the handshake inside the event
loop and hands over a stream that is already decrypted, so nothing above it
ever sees what the client offered. This listener accepts the TCP connection
itself, *peeks* at the first TLS record (the bytes stay in the socket), and
only then gives the untouched socket to asyncio's own TLS implementation. The
handshake is the standard library's from the first byte; this adds a look at
what was sent, not a second implementation of anything.

Rules it keeps:

* It never consumes a byte. What it reads is read with ``MSG_PEEK``.
* It never delays a handshake that could proceed. It waits only for bytes
  the handshake itself is waiting for (the rest of the first record), woken
  by the kernel the moment they are there, and gives up after a short time.
* It never fails a connection. No ClientHello, a malformed one, a platform
  without the socket option it uses: each means "no fingerprint", and the
  socket goes to the handshake regardless.

Connections that have not finished their handshake are bounded in number,
in total and per address, since each one holds a socket and a task.
"""

from __future__ import annotations

import asyncio
import logging
import socket
import ssl
from typing import Awaitable, Callable, Optional

from honeypot.capture.tls_fingerprint import (
    MAX_RECORD_PAYLOAD,
    RECORD_HEADER_BYTES,
    record_length,
)

logger = logging.getLogger(__name__)

#: Longest wait for the first record before handing the socket over anyway.
#: A client sends its ClientHello as soon as the TCP handshake completes.
PEEK_SECONDS = 2.0
#: As asyncio's own default for the TLS handshake would be 60 s; a decoy has
#: no reason to hold a silent socket that long.
HANDSHAKE_SECONDS = 30.0
#: Connections accepted but not yet through their handshake.
MAX_PENDING = 256
MAX_PENDING_PER_ADDRESS = 16

_PEEK_BYTES = RECORD_HEADER_BYTES + MAX_RECORD_PAYLOAD

ClientCallback = Callable[[asyncio.StreamReader, asyncio.StreamWriter, bytes], Awaitable[None]]


def _normalise(address: str) -> str:
    return address[7:] if address.startswith("::ffff:") else address


async def _wait_readable(sock: socket.socket, loop: asyncio.AbstractEventLoop, deadline: float) -> bool:
    """Wait until the socket has something to read; False on timeout."""
    remaining = deadline - loop.time()
    if remaining <= 0:
        return False
    ready: asyncio.Future = loop.create_future()

    def mark_ready() -> None:
        if not ready.done():
            ready.set_result(None)

    fd = sock.fileno()
    loop.add_reader(fd, mark_ready)
    try:
        await asyncio.wait_for(ready, timeout=remaining)
        return True
    except asyncio.TimeoutError:
        return False
    finally:
        loop.remove_reader(fd)


async def peek_first_record(
    sock: socket.socket, loop: asyncio.AbstractEventLoop, timeout: float = PEEK_SECONDS
) -> bytes:
    """What the client sent first, left in the socket for whoever reads next.

    For a TLS client this is its whole first record (the ClientHello). For
    anything else it is whatever arrived first — enough to tell plain HTTP
    from a port scanner's probe. Empty when nothing arrived in time.
    """
    deadline = loop.time() + timeout
    seen = b""
    #: Bytes the low-water mark is currently set to wait for; 0 before any.
    waiting_for = 0
    try:
        while True:
            if not await _wait_readable(sock, loop, deadline):
                return seen
            try:
                seen = sock.recv(_PEEK_BYTES, socket.MSG_PEEK)
            except (BlockingIOError, InterruptedError):
                continue
            if not seen:
                return b""
            if waiting_for and len(seen) < waiting_for:
                # Woken without the bytes asked for: the client has closed
                # or reset, and no more are coming.
                return seen

            if len(seen) < RECORD_HEADER_BYTES:
                target = RECORD_HEADER_BYTES
            else:
                target = record_length(seen)
                if target is None or len(seen) >= target:
                    # Not TLS, or the whole record is already here.
                    return seen
            # Peeked data stays in the socket, so it stays "readable" and
            # waiting for that again would spin. Raising the low-water mark
            # makes the kernel report the socket readable only once the rest
            # has arrived, or the client has gone.
            sock.setsockopt(socket.SOL_SOCKET, socket.SO_RCVLOWAT, target)
            waiting_for = target
    except OSError:
        return b""
    finally:
        if waiting_for:
            try:
                sock.setsockopt(socket.SOL_SOCKET, socket.SO_RCVLOWAT, 1)
            except OSError:
                pass


class PeekingTLSServer:
    """Listen, peek, then let asyncio do TLS. Stands in for asyncio's Server.

    ``client_connected`` is awaited for each connection whose handshake
    succeeded, with the stream pair and the bytes that were peeked.
    ``on_plaintext`` (optional) is awaited with the raw socket when the first
    bytes are not TLS; returning True means it answered and the connection
    is closed, False lets the handshake go ahead. ``on_failed`` (optional)
    is called when a connection was dropped before any stream existed: over
    the pending limit, or a handshake that did not complete.
    """

    def __init__(
        self,
        sockets: list[socket.socket],
        ssl_context: ssl.SSLContext,
        client_connected: ClientCallback,
        on_plaintext: Optional[Callable[[socket.socket, tuple, bytes], Awaitable[bool]]] = None,
        on_failed: Optional[Callable[[tuple, str, bytes], None]] = None,
    ) -> None:
        self.sockets = sockets
        self._ssl = ssl_context
        self._client_connected = client_connected
        self._on_plaintext = on_plaintext
        self._on_failed = on_failed
        self._loop = asyncio.get_running_loop()
        self._pending: set[asyncio.Task] = set()
        self._pending_by_address: dict[str, int] = {}
        self._acceptors = [
            self._loop.create_task(self._accept_loop(sock)) for sock in sockets
        ]

    @classmethod
    async def listen(cls, host: str, port: int, ssl_context: ssl.SSLContext, *args, **kwargs) -> "PeekingTLSServer":
        """Bind ``host``:``port`` the way ``asyncio.start_server`` would."""
        loop = asyncio.get_running_loop()
        infos = await loop.getaddrinfo(
            host or None, port, type=socket.SOCK_STREAM, flags=socket.AI_PASSIVE
        )
        sockets: list[socket.socket] = []
        try:
            for family, kind, proto, _, address in infos:
                sock = socket.socket(family, kind, proto)
                sockets.append(sock)
                sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
                if family == socket.AF_INET6:
                    # One socket per family, as asyncio binds them.
                    sock.setsockopt(socket.IPPROTO_IPV6, socket.IPV6_V6ONLY, 1)
                sock.bind(address)
                sock.listen(100)
                sock.setblocking(False)
        except OSError:
            for sock in sockets:
                sock.close()
            raise
        return cls(sockets, ssl_context, *args, **kwargs)

    # -- asyncio.Server's surface, as BaseEmulator uses it -------------------

    def close(self) -> None:
        for task in self._acceptors:
            task.cancel()
        for task in list(self._pending):
            task.cancel()
        for sock in self.sockets:
            try:
                sock.close()
            except OSError:
                pass

    async def wait_closed(self) -> None:
        tasks = self._acceptors + list(self._pending)
        if tasks:
            await asyncio.gather(*tasks, return_exceptions=True)

    # -- accepting -----------------------------------------------------------

    async def _accept_loop(self, listener: socket.socket) -> None:
        while True:
            try:
                conn, address = await self._loop.sock_accept(listener)
            except asyncio.CancelledError:
                raise
            except OSError as exc:
                if listener.fileno() < 0:
                    return
                # Out of descriptors or memory: accepting again at once would
                # spin. asyncio's own server pauses the same way.
                logger.warning("HTTPS accept failed: %s", exc)
                await asyncio.sleep(1)
                continue

            peer = _normalise(address[0])
            if (
                len(self._pending) >= MAX_PENDING
                or self._pending_by_address.get(peer, 0) >= MAX_PENDING_PER_ADDRESS
            ):
                conn.close()
                self._failed(address, "handshake_backlog", b"")
                continue
            self._pending_by_address[peer] = self._pending_by_address.get(peer, 0) + 1
            task = self._loop.create_task(self._handshake(conn, address, peer))
            self._pending.add(task)
            task.add_done_callback(self._pending.discard)

    def _release(self, peer: str) -> None:
        count = self._pending_by_address.get(peer, 0) - 1
        if count > 0:
            self._pending_by_address[peer] = count
        else:
            self._pending_by_address.pop(peer, None)

    def _failed(self, address: tuple, reason: str, first_bytes: bytes) -> None:
        if self._on_failed is None:
            return
        try:
            self._on_failed(address, reason, first_bytes)
        except Exception:
            logger.debug("refusal hook failed", exc_info=True)

    async def _handshake(self, conn: socket.socket, address: tuple, peer: str) -> None:
        first_bytes = b""
        try:
            conn.setblocking(False)
            try:
                first_bytes = await peek_first_record(conn, self._loop)
            except asyncio.CancelledError:
                raise
            except Exception:
                # Fingerprinting is optional; the connection is not.
                logger.debug("ClientHello peek failed", exc_info=True)
                first_bytes = b""

            if (
                self._on_plaintext is not None
                and first_bytes
                and record_length(first_bytes) is None
                and len(first_bytes) >= RECORD_HEADER_BYTES
            ):
                if await self._on_plaintext(conn, address, first_bytes):
                    return

            reader = asyncio.StreamReader(loop=self._loop)
            peeked = first_bytes

            def connected(stream_reader, stream_writer):
                return self._client_connected(stream_reader, stream_writer, peeked)

            protocol = asyncio.StreamReaderProtocol(reader, connected, loop=self._loop)
            try:
                await self._loop.connect_accepted_socket(
                    lambda: protocol, conn, ssl=self._ssl,
                    ssl_handshake_timeout=HANDSHAKE_SECONDS,
                )
            except asyncio.CancelledError:
                raise
            except Exception as exc:
                logger.debug("TLS handshake with %s failed: %s", peer, exc)
                self._failed(address, "tls_handshake_failed", first_bytes)
                return
            conn = None  # the transport owns it now
        finally:
            self._release(peer)
            if conn is not None:
                try:
                    conn.close()
                except OSError:
                    pass
