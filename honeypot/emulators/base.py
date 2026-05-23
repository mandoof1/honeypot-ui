import asyncio
import logging
import random
import time
from abc import ABC, abstractmethod
from typing import Any, Optional

from honeypot.core.config import config
from honeypot.core.session import session_manager
from honeypot.core.modes import mode_handler

logger = logging.getLogger(__name__)


class BaseEmulator(ABC):
    def __init__(self, protocol: str, port: int):
        self.protocol = protocol
        self.port = port
        self._server: Optional[asyncio.AbstractServer] = None
        self._running = False
        self._connection_count = 0
        self._active_connections: dict[str, asyncio.Task] = {}

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
            self.handle_client, config.bind_address, self.port
        )
        self._running = True
        addr = self._server.sockets[0].getsockname()
        logger.info(f"{self.protocol.upper()} honeypot listening on {addr[0]}:{addr[1]}")

    async def stop(self):
        self._running = False
        for task in self._active_connections.values():
            task.cancel()
        if self._server:
            self._server.close()
            await self._server.wait_closed()
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
        if response:
            await self._apply_response_delay()
            writer.write(response.encode())
            await writer.drain()

    async def _check_rate_limit(self, peer_ip: str) -> bool:
        from honeypot.security.rate_limiter import rate_limiter

        return await rate_limiter.is_allowed(peer_ip)

    def _get_peer_info(self, writer: asyncio.StreamWriter) -> tuple[str, int]:
        peer = writer.get_extra_info("peername")
        if peer:
            return peer[0], peer[1]
        return "0.0.0.0", 0
