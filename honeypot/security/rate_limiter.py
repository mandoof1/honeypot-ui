import asyncio
import logging
import time
from collections import defaultdict
from typing import Optional

from honeypot.core.config import config

logger = logging.getLogger(__name__)


class RateLimiter:
    def __init__(self):
        self._requests: dict[str, list[float]] = defaultdict(list)
        self._blocked: dict[str, float] = {}
        self._block_duration = 300
        self._max_requests = config.rate_limit_per_minute
        self._cleanup_interval = 60
        self._cleanup_task: Optional[asyncio.Task] = None
        # Connections currently open, per address and in total. HONEYPOT_
        # MAX_CONN_PER_IP was set in every compose file and described as
        # per-address throttling, but nothing read it: one address could hold
        # every socket the process had.
        self._active: dict[str, int] = defaultdict(int)
        self._active_total = 0
        self._max_per_ip = config.max_connections_per_ip
        self._max_total = config.max_connections
        #: Admissions refused for each reason since start, for the heartbeat.
        self.refused: dict[str, int] = {"rate": 0, "per_ip": 0, "total": 0, "blocked": 0}

    def reset(self) -> None:
        """Forget every window, block and open-connection count.

        For tests, which run hundreds of connections from one loopback
        address through a process-wide singleton; in production nothing
        calls this.
        """
        self._requests.clear()
        self._blocked.clear()
        self._active.clear()
        self._active_total = 0
        for key in self.refused:
            self.refused[key] = 0

    async def start(self):
        self._cleanup_task = asyncio.create_task(self._cleanup_loop())
        logger.info("Rate limiter started")

    async def stop(self):
        if self._cleanup_task:
            self._cleanup_task.cancel()
            try:
                await self._cleanup_task
            except asyncio.CancelledError:
                pass
        logger.info("Rate limiter stopped")

    def is_blocked(self, ip: str) -> bool:
        """Whether the address is currently blocked; counts nothing."""
        expiry = self._blocked.get(ip)
        if expiry is None:
            return False
        if time.time() < expiry:
            return True
        del self._blocked[ip]
        return False

    def admit(self, ip: str) -> bool:
        """Accept-time admission: rate window plus concurrency caps.

        Synchronous so it can run inside asyncssh's connection_made, before
        the key exchange, where a refused address costs no cryptography. The
        caller must pair a True result with exactly one release().
        """
        if self.is_blocked(ip):
            self.refused["blocked"] += 1
            return False
        if self._active_total >= self._max_total:
            self.refused["total"] += 1
            logger.warning("Connection from %s refused: %d connections open", ip, self._active_total)
            return False
        if self._active[ip] >= self._max_per_ip:
            self.refused["per_ip"] += 1
            logger.warning("Connection from %s refused: %d already open from it", ip, self._active[ip])
            return False
        if not self._allow_sync(ip):
            self.refused["rate"] += 1
            return False
        self._active[ip] += 1
        self._active_total += 1
        return True

    def release(self, ip: str) -> None:
        if self._active.get(ip, 0) > 0:
            self._active[ip] -= 1
            self._active_total -= 1
            if self._active[ip] == 0:
                del self._active[ip]

    def active_connections(self) -> int:
        return self._active_total

    async def is_allowed(self, ip: str) -> bool:
        return self._allow_sync(ip)

    def _allow_sync(self, ip: str) -> bool:
        if self.is_blocked(ip):
            logger.warning(f"IP {ip} is blocked")
            return False

        now = time.time()
        window_start = now - 60

        self._requests[ip] = [
            t for t in self._requests[ip] if t > window_start
        ]

        if len(self._requests[ip]) >= self._max_requests:
            self._blocked[ip] = now + self._block_duration
            logger.warning(
                f"IP {ip} blocked for {self._block_duration}s "
                f"(exceeded {self._max_requests} req/min)"
            )
            return False

        self._requests[ip].append(now)
        return True

    async def get_request_count(self, ip: str) -> int:
        now = time.time()
        window_start = now - 60
        return len(
            [t for t in self._requests.get(ip, []) if t > window_start]
        )

    async def get_blocked_ips(self) -> list[str]:
        now = time.time()
        return [
            ip for ip, expiry in self._blocked.items()
            if expiry > now
        ]

    async def block_ip(self, ip: str, duration: Optional[int] = None):
        self._blocked[ip] = time.time() + (duration or self._block_duration)
        logger.info(f"IP {ip} manually blocked")

    async def unblock_ip(self, ip: str):
        if ip in self._blocked:
            del self._blocked[ip]
            logger.info(f"IP {ip} manually unblocked")

    async def _cleanup_loop(self):
        while True:
            await asyncio.sleep(self._cleanup_interval)
            now = time.time()

            expired_blocks = [
                ip for ip, expiry in self._blocked.items()
                if expiry < now
            ]
            for ip in expired_blocks:
                del self._blocked[ip]

            old_requests = [
                ip for ip, timestamps in self._requests.items()
                if not any(t > now - 300 for t in timestamps)
            ]
            for ip in old_requests:
                del self._requests[ip]

            if expired_blocks or old_requests:
                logger.debug(
                    f"Rate limiter cleanup: {len(expired_blocks)} blocks expired, "
                    f"{len(old_requests)} request logs cleaned"
                )


rate_limiter = RateLimiter()
