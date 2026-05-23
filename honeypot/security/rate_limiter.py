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

    async def is_allowed(self, ip: str) -> bool:
        if ip in self._blocked:
            if time.time() < self._blocked[ip]:
                logger.warning(f"IP {ip} is blocked")
                return False
            else:
                del self._blocked[ip]

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
