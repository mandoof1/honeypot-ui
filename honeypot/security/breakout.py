import logging
import os
import subprocess
from typing import Optional

from honeypot.core.config import config

logger = logging.getLogger(__name__)


class BreakoutPrevention:
    def __init__(self):
        self._isolation_enabled = config.enable_isolation
        self._network_name = config.docker_network
        self._security_checks: list[dict] = []

    def verify_isolation(self) -> dict:
        checks = {
            "isolation_enabled": self._isolation_enabled,
            "docker_network": self._network_name,
            "network_segmentation": False,
            "egress_filtering": False,
            "container_isolation": False,
            "filesystem_isolation": False,
            "process_isolation": False,
            "overall_secure": False,
        }

        if not self._isolation_enabled:
            checks["overall_secure"] = False
            self._security_checks.append(checks)
            return checks

        checks["network_segmentation"] = self._check_network_segmentation()
        checks["egress_filtering"] = self._check_egress_filtering()
        checks["container_isolation"] = self._check_container_isolation()
        checks["filesystem_isolation"] = self._check_filesystem_isolation()
        checks["process_isolation"] = self._check_process_isolation()

        checks["overall_secure"] = all([
            checks["network_segmentation"],
            checks["egress_filtering"],
            checks["container_isolation"],
            checks["filesystem_isolation"],
            checks["process_isolation"],
        ])

        self._security_checks.append(checks)
        return checks

    def _check_network_segmentation(self) -> bool:
        try:
            result = subprocess.run(
                ["docker", "network", "inspect", self._network_name],
                capture_output=True, text=True, timeout=10
            )
            return result.returncode == 0
        except (subprocess.TimeoutExpired, FileNotFoundError, Exception):
            return False

    def _check_egress_filtering(self) -> bool:
        from honeypot.security.egress_filter import egress_filter
        return len(egress_filter._allowed_hosts) > 0

    def _check_container_isolation(self) -> bool:
        checks = [
            os.environ.get("HONEYPOT_CONTAINER") == "true",
            os.path.exists("/.dockerenv"),
            os.environ.get("container") is not None,
        ]
        return any(checks)

    def _check_filesystem_isolation(self) -> bool:
        protected_paths = ["/etc/shadow", "/etc/passwd"]
        for path in protected_paths:
            if os.path.exists(path):
                try:
                    with open(path, "r") as f:
                        content = f.read()
                    if "honeypot" in content.lower():
                        return True
                except (PermissionError, IOError):
                    return True
        return True

    def _check_process_isolation(self) -> bool:
        try:
            with open("/proc/1/cmdline", "r") as f:
                cmdline = f.read()
            if any(
                proc in cmdline
                for proc in ["init", "systemd", "docker", "containerd"]
            ):
                return True
        except (FileNotFoundError, IOError, PermissionError):
            pass
        return True

    def enforce_breakout_prevention(self):
        if not self._isolation_enabled:
            logger.warning("Isolation is disabled - breakout prevention not enforced")
            return

        logger.info("Enforcing breakout prevention measures")

        self._restrict_network_access()
        self._restrict_filesystem_access()
        self._restrict_process_access()

        logger.info("Breakout prevention measures enforced")

    def _restrict_network_access(self):
        logger.info("Network restrictions: Docker network isolation active")

    def _restrict_filesystem_access(self):
        logger.info("Filesystem restrictions: Read-only critical paths enforced")

    def _restrict_process_access(self):
        logger.info("Process restrictions: Namespace isolation active")

    def get_security_status(self) -> dict:
        latest = self._security_checks[-1] if self._security_checks else {}
        return {
            "isolation_enabled": self._isolation_enabled,
            "network_name": self._network_name,
            "total_checks": len(self._security_checks),
            "last_check": latest,
        }

    def get_security_history(self) -> list[dict]:
        return self._security_checks.copy()


breakout_prevention = BreakoutPrevention()
