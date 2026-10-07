import asyncio
import logging
import random
import time
from abc import ABC, abstractmethod
from typing import Any, Optional

from honeypot.core.config import config
from honeypot.core.session import session_manager
from honeypot.core.modes import mode_handler
from honeypot.security.rate_limiter import rate_limiter

logger = logging.getLogger(__name__)


class BaseEmulator(ABC):
    def __init__(self, protocol: str, port: int, ssl_context=None):
        self.protocol = protocol
        self.port = port
        self.ssl_context = ssl_context
        self._server: Optional[asyncio.AbstractServer] = None
        self._running = False
        self._connection_count = 0
        #: Handler task per open connection, so stop() can really close them.
        #: This dict existed before but nothing ever put a task in it.
        self._active_connections: dict[int, asyncio.Task] = {}

    @abstractmethod
    async def handle_client(
        self, reader: asyncio.StreamReader, writer: asyncio.StreamWriter
    ):
        pass

    @abstractmethod
    def get_banner(self) -> str:
        pass

    async def start(self):
        self._server = await asyncio.start_server(
            self._accept,
            config.bind_address,
            self.port,
            ssl=self.ssl_context,
        )
        self._running = True
        addr = self._server.sockets[0].getsockname()
        logger.info(f"{self.protocol.upper()} honeypot listening on {addr[0]}:{addr[1]}")

    async def _accept(
        self, reader: asyncio.StreamReader, writer: asyncio.StreamWriter
    ):
        """Admission, bookkeeping and the session-length cap around a handler.

        Done here, once, rather than in each emulator: the per-address and
        global connection caps were configured everywhere and enforced
        nowhere, and no connection had an upper bound on how long it could
        live.
        """
        peer_ip, _ = self._get_peer_info(writer)
        if not rate_limiter.admit(peer_ip):
            writer.close()
            try:
                await writer.wait_closed()
            except Exception:
                pass
            return

        task = asyncio.current_task()
        key = id(task)
        self._active_connections[key] = task
        self._connection_count += 1
        try:
            await asyncio.wait_for(
                self.handle_client(reader, writer), timeout=config.max_session_seconds
            )
        except asyncio.TimeoutError:
            logger.info(
                "%s connection from %s closed: over the %ss session limit",
                self.protocol.upper(), peer_ip, config.max_session_seconds,
            )
        except asyncio.CancelledError:
            pass
        except Exception as exc:
            logger.error("%s handler failed for %s: %s", self.protocol.upper(), peer_ip, exc, exc_info=True)
        finally:
            self._active_connections.pop(key, None)
            rate_limiter.release(peer_ip)
            if not writer.is_closing():
                writer.close()
            try:
                await writer.wait_closed()
            except Exception:
                pass

    @property
    def active_connections(self) -> int:
        return len(self._active_connections)

    async def stop(self):
        self._running = False
        if self._server:
            self._server.close()
        tasks = list(self._active_connections.values())
        for task in tasks:
            task.cancel()
        if tasks:
            # Cancelled handlers run their finally blocks, which end the
            # sessions; give them a moment to do so.
            await asyncio.wait(tasks, timeout=5)
        if self._server:
            try:
                await asyncio.wait_for(self._server.wait_closed(), timeout=5)
            except asyncio.TimeoutError:
                logger.warning("%s listener did not close cleanly", self.protocol.upper())
        logger.info(f"{self.protocol.upper()} honeypot stopped")

    async def _apply_response_delay(self):
        if config.enable_anti_fingerprinting:
            delay = random.uniform(
                config.response_delay_min, config.response_delay_max
            )
            await asyncio.sleep(delay)

    async def _send_response(
        self, writer: asyncio.StreamWriter, response: str
    ):
        """Send a protocol response, with anti-fingerprinting jitter."""
        if response:
            await self._apply_response_delay()
            writer.write(response.encode())
            await writer.drain()

    async def _echo(self, writer: asyncio.StreamWriter, text: str):
        """Echo typed input straight back with no jitter.

        The response delay exists to hide the fact that answers are generated
        rather than computed. Applying it per echoed character would add up to
        half a second per keystroke, which is both unusable and itself a
        fingerprint.
        """
        if text:
            writer.write(text.encode())
            await writer.drain()

    async def _check_rate_limit(self, peer_ip: str) -> bool:
        """Whether the address may continue. Admission already counted the
        connection in _accept; this only honours a block placed since."""
        return not rate_limiter.is_blocked(peer_ip)

    def _get_peer_info(self, writer: asyncio.StreamWriter) -> tuple[str, int]:
        peer = writer.get_extra_info("peername")
        if peer:
            return peer[0], peer[1]
        return "0.0.0.0", 0
