import asyncio
import logging
import random
import time
from typing import Optional

from honeypot.core.config import config

logger = logging.getLogger(__name__)


class FingerprintEngine:
    def __init__(self):
        self._ssh_banners = [
            "SSH-2.0-OpenSSH_8.9p1 Ubuntu-3ubuntu0.6",
            "SSH-2.0-OpenSSH_8.2p1 Ubuntu-4ubuntu0.9",
            "SSH-2.0-OpenSSH_7.6p1 Ubuntu-4ubuntu0.7",
            "SSH-2.0-OpenSSH_9.0p1 Ubuntu-1ubuntu1",
            "SSH-2.0-OpenSSH_8.4p1 Debian-5+deb11u3",
            "SSH-2.0-OpenSSH_7.4p1 CentOS-7",
            "SSH-2.0-OpenSSH_8.0p1 RHEL-8",
        ]
        self._ftp_banners = [
            "220 (vsFTPd 3.0.5)",
            "220 (vsFTPd 3.0.3)",
            "220 (vsFTPd 2.3.5)",
            "220 ProFTPD 1.3.7a Server",
            "220 ProFTPD 1.3.6c Server",
            "220 (FTPd 1.0.0)",
            "220 Microsoft FTP Service",
        ]
        self._http_servers = [
            "Apache/2.4.52 (Ubuntu)",
            "Apache/2.4.41 (Ubuntu)",
            "Apache/2.4.38 (Debian)",
            "nginx/1.24.0",
            "nginx/1.18.0 (Ubuntu)",
            "Apache/2.4.57 (Unix)",
        ]
        self._x_powered_by = [
            "PHP/8.1.2",
            "PHP/8.0.30",
            "PHP/7.4.33",
            "PHP/8.2.12",
            "Express",
            "ASP.NET",
        ]
        self._os_signatures = [
            {"name": "Ubuntu 22.04", "kernel": "5.15.0-91-generic", "arch": "x86_64"},
            {"name": "Ubuntu 20.04", "kernel": "5.4.0-150-generic", "arch": "x86_64"},
            {"name": "Debian 11", "kernel": "5.10.0-26-amd64", "arch": "x86_64"},
            {"name": "CentOS 7", "kernel": "3.10.0-1160.el7.x86_64", "arch": "x86_64"},
            {"name": "RHEL 8", "kernel": "4.18.0-477.el8.x86_64", "arch": "x86_64"},
        ]
        self._current_ssh_banner = random.choice(self._ssh_banners)
        self._current_ftp_banner = random.choice(self._ftp_banners)
        self._current_http_server = random.choice(self._http_servers)
        self._current_x_powered_by = random.choice(self._x_powered_by)
        self._current_os = random.choice(self._os_signatures)
        self._last_rotation = time.time()
        self._rotation_task: Optional[asyncio.Task] = None

    async def start_rotation(self):
        self._rotation_task = asyncio.create_task(self._rotate_profiles())
        logger.info("Anti-fingerprinting profile rotation started")

    async def stop_rotation(self):
        if self._rotation_task:
            self._rotation_task.cancel()
            try:
                await self._rotation_task
            except asyncio.CancelledError:
                pass
        logger.info("Anti-fingerprinting profile rotation stopped")

    async def _rotate_profiles(self):
        while True:
            await asyncio.sleep(config.banner_rotation_interval)
            self._rotate()
            logger.info("Honeypot profiles rotated")

    def _rotate(self):
        self._current_ssh_banner = random.choice(self._ssh_banners)
        self._current_ftp_banner = random.choice(self._ftp_banners)
        self._current_http_server = random.choice(self._http_servers)
        self._current_x_powered_by = random.choice(self._x_powered_by)
        self._current_os = random.choice(self._os_signatures)
        self._last_rotation = time.time()

    def get_ssh_banner(self) -> str:
        if config.enable_anti_fingerprinting:
            return self._current_ssh_banner
        return "SSH-2.0-HoneySentinel-1.0"

    def get_ftp_banner(self) -> str:
        if config.enable_anti_fingerprinting:
            return self._current_ftp_banner
        return "220 (HoneySentinel FTP 1.0)"

    def get_http_server_header(self) -> str:
        if config.enable_anti_fingerprinting:
            return self._current_http_server
        return "HoneySentinel/1.0"

    def get_x_powered_by(self) -> str:
        if config.enable_anti_fingerprinting:
            return self._current_x_powered_by
        return "HoneySentinel/1.0"

    def get_os_signature(self) -> dict:
        if config.enable_anti_fingerprinting:
            return self._current_os
        return {"name": "HoneySentinel", "kernel": "1.0", "arch": "x86_64"}

    def get_response_delay(self) -> float:
        if config.enable_anti_fingerprinting:
            return random.uniform(
                config.response_delay_min, config.response_delay_max
            )
        return 0.0

    def get_fake_mac(self) -> str:
        return ":".join(
            [f"{random.randint(0, 255):02x}" for _ in range(6)]
        )

    def get_fake_hostname(self) -> str:
        hostnames = [
            "web-server-01",
            "db-primary",
            "app-node-03",
            "mail-server",
            "file-server",
            "dev-server",
            "staging-01",
            "prod-web-02",
            "ubuntu-server",
            "centos-box",
        ]
        return random.choice(hostnames)

    def get_fake_uptime(self) -> str:
        days = random.randint(1, 365)
        hours = random.randint(0, 23)
        minutes = random.randint(0, 59)
        return f"{days} days, {hours:02d}:{minutes:02d}"

    def get_fake_pid(self) -> int:
        return random.randint(100, 65535)

    def get_fake_port(self) -> int:
        common_ports = [22, 80, 443, 8080, 8443, 3000, 5000, 9090]
        return random.choice(common_ports)


fingerprint_engine = FingerprintEngine()
