import asyncio
import logging
import shutil
import signal
import time
from typing import Optional

from honeypot import ENGINE_VERSION
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
    #: How long shutdown waits for in-flight ingests. Docker's grace period
    #: is set to 20 s in the compose files; this leaves room for the rest.
    DRAIN_TIMEOUT = 8.0

    def __init__(self):
        self._ssh: Optional[SSHHoneypot] = None
        self._ftp: Optional[FTPHoneypot] = None
        self._http: Optional[HTTPHoneypot] = None
        self._https: Optional[HTTPHoneypot] = None
        self._control_api = None
        self._running = False
        self._started_at = time.time()
        #: Listeners that actually bound, as opposed to those configured.
        self._bound: list[str] = []
        self._heartbeat_task: Optional[asyncio.Task] = None

    async def start(self):
        logger.info("=" * 60)
        logger.info("HoneySentinel Honeypot Engine %s Starting", ENGINE_VERSION)
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

        # The sweep probes the network with one-second timeouts; off the loop
        # so nothing else waits on it.
        isolation = await asyncio.to_thread(breakout_prevention.verify_isolation)
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

        # Each emulator is built *and* started inside the try: constructing
        # the HTTP decoy parses its upstream URLs and loads the TLS context,
        # and a bad value there used to take SSH and FTP down with it.
        starters = []
        if "ssh" in config.enabled_protocols:
            starters.append(("ssh", self._start_ssh))
        if "ftp" in config.enabled_protocols:
            starters.append(("ftp", self._start_ftp))
        if "http" in config.enabled_protocols:
            starters.append(("http", self._start_http))
        if "https" in config.enabled_protocols:
            starters.append(("https", self._start_https))

        for name, starter in starters:
            try:
                await starter()
                self._bound.append(name)
                logger.info(f"{name.upper()} honeypot started successfully")
            except Exception as e:
                logger.error(f"Failed to start {name.upper()} honeypot: {e}")

        if not self._bound:
            logger.error("No decoy listener could be started; the engine is capturing nothing")

        await session_manager.register_node()
        session_manager.start_background()
        self._heartbeat_task = asyncio.create_task(self._heartbeat_loop(), name="heartbeat")

        self._control_api = build_control_api(self)
        await self._control_api.start()

        self._running = True
        logger.info("All honeypot services started")
        logger.info(f"Active protocols: {self._bound}")

    async def _start_ssh(self):
        self._ssh = SSHHoneypot()
        await self._ssh.start()

    async def _start_ftp(self):
        self._ftp = FTPHoneypot()
        await self._ftp.start()

    async def _start_http(self):
        self._http = HTTPHoneypot(use_tls=False)
        await self._http.start()

    async def _start_https(self):
        https = HTTPHoneypot(use_tls=True)
        # HTTPHoneypot.start refuses to serve plaintext when the TLS context
        # could not be built, so a failure here means no listener, not a
        # silent downgrade.
        await https.start()
        self._https = https

    async def stop(self):
        logger.info("Stopping honeypot services...")
        self._running = False

        if self._heartbeat_task:
            self._heartbeat_task.cancel()
            try:
                await self._heartbeat_task
            except (asyncio.CancelledError, Exception):
                pass

        # Listeners and their connections first. Closing a connection runs
        # its handler's cleanup, which ends the session and starts the
        # ingest; ending sessions before that (the previous order) sent them
        # while the connection could still add to them.
        for emulator in (self._ssh, self._ftp, self._http, self._https):
            if emulator:
                try:
                    await emulator.stop()
                except Exception as exc:
                    logger.warning("Error stopping %s: %s", emulator.protocol, exc)

        active = await session_manager.get_active_sessions()
        for session in active:
            await session_manager.end_session(session.session_id)

        # Let in-flight ingests reach the backend, within the grace period.
        await session_manager.drain(timeout=self.DRAIN_TIMEOUT)
        await session_manager.stop_background()

        if self._control_api:
            await self._control_api.stop()

        await fingerprint_engine.stop_rotation()
        await rate_limiter.stop()

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

    async def _heartbeat_loop(self):
        """Tell the backend we are alive, on a fixed interval, for ever.

        Failures are the backend's problem to show, not a reason to stop
        trying: the loop survives any exception and logs a streak once.
        """
        interval = max(10, config.heartbeat_interval)
        while True:
            try:
                await session_manager.heartbeat(await self.get_status())
            except asyncio.CancelledError:
                raise
            except Exception as exc:
                logger.warning("Heartbeat loop error: %s", exc)
            await asyncio.sleep(interval)

    @staticmethod
    def _disk_status() -> Optional[dict]:
        try:
            usage = shutil.disk_usage(config.session_capture_dir)
        except OSError:
            return None
        return {
            "path": config.session_capture_dir,
            "total_bytes": usage.total,
            "free_bytes": usage.free,
        }

    async def get_status(self) -> dict:
        active_sessions = await session_manager.get_active_sessions()
        total_sessions = await session_manager.get_session_count()
        blocked_ips = await rate_limiter.get_blocked_ips()
        isolation_status = breakout_prevention.get_security_status()
        spool = session_manager.spool

        return {
            "running": self._running,
            "version": ENGINE_VERSION,
            "mode": mode_handler.mode.value,
            "protocols": [p.value for p in config.enabled_protocols],
            "protocols_bound": list(self._bound),
            "active_sessions": len(active_sessions),
            "total_sessions": total_sessions,
            "open_connections": rate_limiter.active_connections(),
            "blocked_ips": len(blocked_ips),
            "refused_connections": dict(rate_limiter.refused),
            "isolation": isolation_status,
            "node_id": session_manager.node_id,
            "node_registered": session_manager.registered,
            "anti_fingerprinting": config.enable_anti_fingerprinting,
            "adaptive_response": config.adaptive_response,
            "uptime_seconds": round(time.time() - self._started_at, 1),
            "spool_pending": spool.pending,
            "spool_bytes": spool.bytes,
            "ingest": dict(session_manager.ingest_stats),
            "disk": self._disk_status(),
        }


async def main():
    service = HoneypotService()
    await service.run()


if __name__ == "__main__":
    asyncio.run(main())
