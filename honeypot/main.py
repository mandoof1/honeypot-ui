import asyncio
import logging
import signal
import sys
from typing import Optional

from honeypot.core.config import config
from honeypot.core.session import session_manager
from honeypot.core.modes import mode_handler
from honeypot.emulators.ssh import SSHHoneypot
from honeypot.emulators.ftp import FTPHoneypot
from honeypot.emulators.http import HTTPHoneypot
from honeypot.adaptive.fingerprint import fingerprint_engine
from honeypot.security.rate_limiter import rate_limiter
from honeypot.core.control_api import build_control_api
from honeypot.security.breakout import breakout_prevention

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
)
logger = logging.getLogger(__name__)


class HoneypotService:
    def __init__(self):
        self._ssh: Optional[SSHHoneypot] = None
        self._ftp: Optional[FTPHoneypot] = None
        self._http: Optional[HTTPHoneypot] = None
        self._https: Optional[HTTPHoneypot] = None
        self._control_api = None
        self._running = False

    async def start(self):
        logger.info("=" * 60)
        logger.info("HoneySentinel Honeypot Engine Starting")
        logger.info("=" * 60)

        logger.info(f"Operational Mode: {mode_handler.mode.value}")
        logger.info(f"Anti-fingerprinting: {config.enable_anti_fingerprinting}")
        logger.info(f"Adaptive Response: {config.adaptive_response}")
        logger.info(f"Isolation: {config.enable_isolation}")

        if config.ingest_token == "honeypot-ingest-token-change-in-production":
            logger.error(
                "HONEYPOT_INGEST_TOKEN is still the default value. The backend "
                "will reject ingest and the control API is effectively "
                "unauthenticated. Set a unique token before exposing this host."
            )

        isolation = breakout_prevention.verify_isolation()
        if not isolation["overall_secure"]:
            logger.warning(
                "Starting WITHOUT verified isolation. Failing checks: %s",
                ", ".join(
                    name
                    for name, ok in isolation.items()
                    if isinstance(ok, bool) and not ok
                ),
            )

        await rate_limiter.start()

        if config.enable_anti_fingerprinting:
            await fingerprint_engine.start_rotation()

        emulators_to_start = []

        if "ssh" in config.enabled_protocols:
            self._ssh = SSHHoneypot()
            emulators_to_start.append(("SSH", self._ssh.start()))

        if "ftp" in config.enabled_protocols:
            self._ftp = FTPHoneypot()
            emulators_to_start.append(("FTP", self._ftp.start()))

        if "http" in config.enabled_protocols:
            self._http = HTTPHoneypot(use_tls=False)
            emulators_to_start.append(("HTTP", self._http.start()))

        if "https" in config.enabled_protocols:
            self._https = HTTPHoneypot(use_tls=True)
            emulators_to_start.append(("HTTPS", self._https.start()))

        for name, coro in emulators_to_start:
            try:
                await coro
                logger.info(f"{name} honeypot started successfully")
            except Exception as e:
                logger.error(f"Failed to start {name} honeypot: {e}")

        await session_manager.register_node()
        await session_manager.outbox.start(session_manager.register_node)

        self._control_api = build_control_api(self)
        await self._control_api.start()

        self._running = True
        logger.info("All honeypot services started")
        logger.info(f"Active protocols: {[p.value for p in config.enabled_protocols]}")

    async def stop(self):
        logger.info("Stopping honeypot services...")
        self._running = False

        if self._ssh:
            await self._ssh.stop()
        if self._ftp:
            await self._ftp.stop()
        if self._http:
            await self._http.stop()
        if self._https:
            await self._https.stop()

        if self._control_api:
            await self._control_api.stop()

        await fingerprint_engine.stop_rotation()
        await rate_limiter.stop()

        active = await session_manager.get_active_sessions()
        for session in active:
            await session_manager.end_session(session.session_id)

        # Let in-flight ingests reach the backend before the loop closes.
        await session_manager.drain()

        logger.info("All honeypot services stopped")

    async def run(self):
        await self.start()

        loop = asyncio.get_running_loop()
        stop_event = asyncio.Event()

        def signal_handler():
            logger.info("Shutdown signal received")
            stop_event.set()

        for sig in (signal.SIGINT, signal.SIGTERM):
            loop.add_signal_handler(sig, signal_handler)

        logger.info("Honeypot engine running. Press Ctrl+C to stop.")

        try:
            await stop_event.wait()
        except asyncio.CancelledError:
            pass
        finally:
            await self.stop()

    async def get_status(self) -> dict:
        active_sessions = await session_manager.get_active_sessions()
        total_sessions = await session_manager.get_session_count()
        blocked_ips = await rate_limiter.get_blocked_ips()
        isolation_status = breakout_prevention.get_security_status()

        return {
            "running": self._running,
            "mode": mode_handler.mode.value,
            "protocols": [p.value for p in config.enabled_protocols],
            "active_sessions": len(active_sessions),
            "total_sessions": total_sessions,
            "blocked_ips": len(blocked_ips),
            "isolation": isolation_status,
            "node_id": session_manager.node_id,
            "anti_fingerprinting": config.enable_anti_fingerprinting,
            "adaptive_response": config.adaptive_response,
            "delivery": {
                **await session_manager.outbox.stats(),
                "capture_errors": session_manager.capture_errors,
            },
        }


async def main():
    service = HoneypotService()
    await service.run()


if __name__ == "__main__":
    asyncio.run(main())
