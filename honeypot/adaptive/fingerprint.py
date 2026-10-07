"""Service banners, tied to one consistent machine.

This used to keep its own pools and rotate them hourly: the SSH banner, the
FTP greeting, the HTTP ``Server`` header, ``X-Powered-By`` and the OS reported
by ``uname`` were each chosen independently and re-chosen on a timer. So a
scanner could see an Apache ``Server`` header beside a vsftpd greeting beside a
CentOS kernel, none of which agreed, and a returning visitor saw the box change
underneath them. Independent randomness across services is itself the tell.

Now every banner is derived from the engine's :class:`HostIdentity`, which is
decided once and persisted, so the FTP greeting, the HTTP server string and the
kernel ``uname`` reports all describe the same host and stay put across
restarts. The rotation machinery is kept as a no-op shim so the callers that
start and stop it do not need to change, but nothing rotates: a honeypot that
changes its fingerprint every hour is easier to spot, not harder.
"""

import asyncio
import logging
import random
from typing import Optional

from honeypot.core.config import config
from honeypot.core.identity import get_identity

logger = logging.getLogger(__name__)


class FingerprintEngine:
    def __init__(self):
        self._rotation_task: Optional[asyncio.Task] = None

    async def start_rotation(self):
        # Retained for callers; the identity is stable by design, so there is
        # nothing to rotate. Logged once so operators are not surprised.
        logger.info("Service banners pinned to the host identity (no rotation)")

    async def stop_rotation(self):
        if self._rotation_task:
            self._rotation_task.cancel()
            try:
                await self._rotation_task
            except asyncio.CancelledError:
                pass

    # -- banners, all from the one identity ------------------------------

    def get_ssh_banner(self) -> str:
        # The authoritative SSH identity is the transport profile in
        # ssh_profile.py, which pins banner and KEXINIT together; this mirrors
        # it for any caller that only wants the string.
        if not config.enable_anti_fingerprinting:
            return "SSH-2.0-HoneySentinel-1.0"
        from honeypot.adaptive.ssh_profile import get_profile

        return get_profile(config.ssh_profile).banner

    def get_ftp_banner(self) -> str:
        if not config.enable_anti_fingerprinting:
            return "220 (HoneySentinel FTP 1.0)"
        return get_identity().ftp_banner_text()

    def get_http_server_header(self) -> str:
        if not config.enable_anti_fingerprinting:
            return "HoneySentinel/1.0"
        return get_identity().http_server

    def get_x_powered_by(self) -> Optional[str]:
        if not config.enable_anti_fingerprinting:
            return "HoneySentinel/1.0"
        # Only PHP stacks send X-Powered-By, and nginx/static sites send none.
        return get_identity().php_version

    def get_os_signature(self) -> dict:
        identity = get_identity()
        if not config.enable_anti_fingerprinting:
            return {"name": "HoneySentinel", "kernel": "1.0", "arch": "x86_64"}
        return {
            "name": f"{identity.os_name} {identity.os_version}",
            "kernel": identity.kernel,
            "arch": identity.arch,
        }

    def get_response_delay(self) -> float:
        if config.enable_anti_fingerprinting:
            return random.uniform(config.response_delay_min, config.response_delay_max)
        return 0.0

    def get_fake_hostname(self) -> str:
        return get_identity().hostname


fingerprint_engine = FingerprintEngine()
