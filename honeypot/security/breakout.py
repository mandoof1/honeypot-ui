"""Container isolation verification for the honeypot engine.

This module *verifies and reports* the isolation the deployment provides. It
deliberately does not claim to enforce anything: the real controls live in the
container runtime (``cap_drop``, ``read_only``, ``no-new-privileges``, an
``internal`` Docker network), and Python running inside the sandbox cannot
tighten its own sandbox. An earlier version logged "breakout prevention
measures enforced" while its enforcement methods only wrote log lines, and
several checks returned ``True`` unconditionally, so the dashboard reported a
secure posture regardless of how the engine was actually deployed.
"""

from __future__ import annotations

import logging
import os
import socket
from typing import Optional
import subprocess

from honeypot.core.config import config

logger = logging.getLogger(__name__)

#: Well-known public endpoints the egress probe tries to reach. Connecting to
#: any of them means the engine could equally reach an attacker's server.
EGRESS_PROBES = (("1.1.1.1", 443), ("8.8.8.8", 53), ("9.9.9.9", 443))


class IsolationReport:
    """Result of one isolation sweep."""

    def __init__(self, checks: dict[str, bool], warnings: list[str]):
        self.checks = checks
        self.warnings = warnings

    @property
    def secure(self) -> bool:
        return all(self.checks.values())

    def to_dict(self) -> dict:
        return {
            **self.checks,
            "overall_secure": self.secure,
            "warnings": self.warnings,
        }


class BreakoutPrevention:
    def __init__(self):
        self._isolation_enabled = config.enable_isolation
        self._network_name = config.docker_network
        self._reports: list[IsolationReport] = []

    def verify_isolation(self) -> dict:
        """Run every isolation check and record the result."""
        warnings: list[str] = []

        if not self._isolation_enabled:
            report = IsolationReport(
                {
                    "network_segmentation": False,
                    "egress_blocked": False,
                    "container_isolation": False,
                    "read_only_rootfs": False,
                    "privilege_restriction": False,
                },
                ["Isolation is disabled via HONEYPOT_ENABLE_ISOLATION"],
            )
            self._reports.append(report)
            return report.to_dict()

        # One probe sweep per report: a dropped SYN only fails by timing out,
        # so each sweep costs up to a few seconds.
        reachable = self._egress_reachable()
        checks = {
            "network_segmentation": self._check_network_segmentation(warnings, reachable),
            "egress_blocked": self._check_egress_blocked(warnings, reachable),
            "container_isolation": self._check_container_isolation(warnings),
            "read_only_rootfs": self._check_read_only_rootfs(warnings),
            "privilege_restriction": self._check_privilege_restriction(warnings),
        }

        report = IsolationReport(checks, warnings)
        self._reports.append(report)

        if not report.secure:
            failed = [name for name, ok in checks.items() if not ok]
            logger.warning(
                "Isolation verification FAILED for: %s. The engine will keep "
                "running, but it is not safely contained.",
                ", ".join(failed),
            )
        else:
            logger.info("Isolation verification passed all checks")

        return report.to_dict()

    def _check_network_segmentation(self, warnings: list[str], reachable: Optional[bool] = None) -> bool:
        """The engine must sit on an internal-only Docker network."""
        try:
            result = subprocess.run(
                [
                    "docker",
                    "network",
                    "inspect",
                    self._network_name,
                    "--format",
                    "{{.Internal}}",
                ],
                capture_output=True,
                text=True,
                timeout=10,
            )
        except (subprocess.SubprocessError, FileNotFoundError):
            # No Docker socket inside the container is the expected, correct
            # state. Fall back to checking that no default route leaves the
            # container towards the public internet.
            return self._check_no_default_route(warnings, reachable)

        if result.returncode != 0:
            warnings.append(
                f"Docker network {self._network_name!r} not found"
            )
            return False
        if result.stdout.strip().lower() != "true":
            warnings.append(
                f"Docker network {self._network_name!r} is not marked internal"
            )
            return False
        return True

    @staticmethod
    def _check_no_default_route(warnings: list[str], reachable: Optional[bool] = None) -> bool:
        try:
            with open("/proc/net/route", "r", encoding="utf-8") as fh:
                lines = fh.read().splitlines()[1:]
        except OSError:
            warnings.append("Could not read /proc/net/route to verify egress")
            return False

        # Destination 00000000 is the default route.
        has_default_route = any(
            len(fields) > 1 and fields[1] == "00000000"
            for fields in (line.split() for line in lines)
        )
        if not has_default_route:
            return True

        # Docker will not publish ports for a container that is only on an
        # internal network, so an engine that must accept connections from
        # the internet has a default route, and egress has to be dropped by
        # the host firewall instead (deploy/server/honeysentinel-egress.sh).
        # The routing table cannot show whether that firewall is in place, so
        # test it.
        if reachable is None:
            reachable = BreakoutPrevention._egress_reachable()
        if reachable:
            warnings.append(
                "Container has a default route and outbound connections "
                "succeed; egress is not blocked"
            )
            return False
        return True

    @staticmethod
    def _egress_reachable(timeout: float = 1.0) -> bool:
        # A dropped SYN only fails by timing out, so the timeout bounds how
        # long a sweep takes when egress is correctly blocked.
        for host, port in EGRESS_PROBES:
            try:
                with socket.create_connection((host, port), timeout=timeout):
                    return True
            except OSError:
                continue
        return False

    @staticmethod
    def _check_egress_blocked(warnings: list[str], reachable: Optional[bool] = None) -> bool:
        """The engine must not be able to open outbound connections.

        This replaced a check that only confirmed an in-process "allowlist"
        was non-empty — it always was, because the backend URL was always
        on it, and nothing consulted the list anyway. The honest test is to
        try: connect to well-known public addresses and pass only when every
        attempt is refused or times out.
        """
        if reachable is None:
            reachable = BreakoutPrevention._egress_reachable()
        if reachable:
            warnings.append("Outbound connections from the engine succeed")
            return False
        return True

    @staticmethod
    def _check_container_isolation(warnings: list[str]) -> bool:
        containerised = (
            os.environ.get("HONEYPOT_CONTAINER") == "true"
            or os.path.exists("/.dockerenv")
            or os.environ.get("container") is not None
        )
        if not containerised:
            warnings.append(
                "Engine does not appear to be running inside a container"
            )
        return containerised

    @staticmethod
    def _check_read_only_rootfs(warnings: list[str]) -> bool:
        """Confirm the root filesystem really is read-only.

        The previous check read /etc/passwd and returned True on success *or*
        failure, so it could never fail.
        """
        probe = "/.honeypot-write-probe"
        try:
            with open(probe, "w", encoding="utf-8") as fh:
                fh.write("probe")
        except OSError:
            return True

        try:
            os.remove(probe)
        except OSError:
            pass
        warnings.append("Root filesystem is writable (expected read_only: true)")
        return False

    @staticmethod
    def _check_privilege_restriction(warnings: list[str]) -> bool:
        """Confirm the process is not running with full root capabilities."""
        if os.geteuid() != 0:
            return True

        try:
            with open("/proc/self/status", "r", encoding="utf-8") as fh:
                for line in fh:
                    if line.startswith("CapEff:"):
                        effective = int(line.split()[1], 16)
                        # A container started with `cap_drop: ALL` keeps at
                        # most NET_BIND_SERVICE (bit 10).
                        if effective & ~(1 << 10):
                            warnings.append(
                                "Process retains Linux capabilities beyond "
                                "NET_BIND_SERVICE"
                            )
                            return False
                        return True
        except (OSError, ValueError):
            warnings.append("Could not read /proc/self/status capabilities")
            return False

        warnings.append("Running as uid 0 with unknown capabilities")
        return False

    def get_security_status(self) -> dict:
        latest = self._reports[-1].to_dict() if self._reports else {}
        return {
            "isolation_enabled": self._isolation_enabled,
            "network_name": self._network_name,
            "total_checks": len(self._reports),
            "overall_secure": bool(latest.get("overall_secure", False)),
            "last_check": latest,
        }

    def get_security_history(self) -> list[dict]:
        return [report.to_dict() for report in self._reports]


breakout_prevention = BreakoutPrevention()
