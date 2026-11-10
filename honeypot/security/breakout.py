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

import errno
import logging
import os
import socket
import time
from typing import Optional
import subprocess

from honeypot.core.config import config

logger = logging.getLogger(__name__)

#: Well-known public endpoints the egress probe tries to reach. Connecting to
#: any of them means the engine could equally reach an attacker's server.
EGRESS_PROBES = (("1.1.1.1", 443), ("8.8.8.8", 53), ("9.9.9.9", 443))

#: Ports tried on the engine's gateway — the host it runs on. SSH, the web
#: ports and the Docker API are what an attacker who got out of the engine
#: would try first.
GATEWAY_PROBE_PORTS = (22, 80, 443, 2375)

#: Reports kept for the status endpoint.
MAX_REPORTS = 48


class IsolationReport:
    """Result of one isolation sweep."""

    def __init__(self, checks: dict[str, bool], warnings: list[str]):
        self.checks = checks
        self.warnings = warnings
        self.checked_at = 0.0

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
            self._record(report)
            return report.to_dict()

        # Each check asks its own question. Segmentation and egress used to be
        # answered by one probe of the public internet, so the report listed
        # five checks and ran four: "the engine cannot reach the host it runs
        # on" was never tested at all.
        checks = {
            "network_segmentation": self._check_network_segmentation(warnings),
            "egress_blocked": self._check_egress_blocked(warnings),
            "container_isolation": self._check_container_isolation(warnings),
            "read_only_rootfs": self._check_read_only_rootfs(warnings),
            "privilege_restriction": self._check_privilege_restriction(warnings),
        }

        report = IsolationReport(checks, warnings)
        self._record(report)

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

    def _record(self, report: IsolationReport) -> None:
        report.checked_at = time.time()
        self._reports.append(report)
        # The sweep now runs for the life of the process; keep a short tail.
        del self._reports[:-MAX_REPORTS]

    def _check_network_segmentation(self, warnings: list[str]) -> bool:
        """The engine must not be able to reach the host or network behind it.

        On an internal-only Docker network there is nothing to reach. An
        engine with published ports has a gateway — the host — and is
        segmented only if the host does not answer it.
        """
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
            # state. Fall back to the routing table and, where it shows a
            # gateway, to whether that gateway can be reached.
            return self._check_gateway_unreachable(warnings)

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
    def _default_gateway() -> tuple[bool, Optional[str]]:
        """(routing table readable, default gateway address or None)."""
        try:
            with open("/proc/net/route", "r", encoding="utf-8") as fh:
                lines = fh.read().splitlines()[1:]
        except OSError:
            return False, None
        for fields in (line.split() for line in lines):
            # Destination 00000000 is the default route; the gateway is the
            # next column, as little-endian hex.
            if len(fields) > 2 and fields[1] == "00000000":
                try:
                    return True, socket.inet_ntoa(bytes.fromhex(fields[2])[::-1])
                except (ValueError, OSError):
                    return True, None
        return True, None

    @staticmethod
    def _probe(host: str, port: int, timeout: float = 1.0) -> str:
        """One connection attempt: ``open``, ``refused``, ``blocked`` or ``error``.

        Which failure it was matters. A timeout or "unreachable" is a
        firewall or a missing route doing its job. A refusal means the packet
        arrived and something answered: the path is open. And a failure of
        any other kind — no file descriptors, a broken resolver — says
        nothing about the network at all. Treating every exception as
        "blocked", as this did, let all three pass.
        """
        try:
            with socket.create_connection((host, port), timeout=timeout):
                return "open"
        except ConnectionRefusedError:
            return "refused"
        except (socket.timeout, TimeoutError):
            return "blocked"
        except OSError as exc:
            if exc.errno in (errno.ENETUNREACH, errno.EHOSTUNREACH, errno.EACCES, errno.EPERM, errno.ETIMEDOUT):
                return "blocked"
            return "error"

    @classmethod
    def _check_gateway_unreachable(cls, warnings: list[str]) -> bool:
        readable, gateway = cls._default_gateway()
        if not readable:
            warnings.append("Could not read /proc/net/route to verify segmentation")
            return False
        if gateway is None:
            # No way out of the network the engine is on.
            return True

        # Docker will not publish ports for a container that is only on an
        # internal network, so an engine that accepts connections from the
        # internet has a gateway: the host. The host firewall is meant to
        # drop everything the engine sends it
        # (deploy/server/honeysentinel-egress.sh, the INPUT rule), and the
        # routing table cannot show whether it does, so ask the host.
        results = {port: cls._probe(gateway, port, 0.7) for port in GATEWAY_PROBE_PORTS}
        answered = [port for port, result in results.items() if result in ("open", "refused")]
        if answered:
            warnings.append(
                f"The host at {gateway} answers the engine (port {answered[0]}); "
                "the engine is not segmented from it"
            )
            return False
        if any(result == "error" for result in results.values()):
            warnings.append(f"Could not determine whether the host at {gateway} is reachable")
            return False
        return True

    @classmethod
    def _check_egress_blocked(cls, warnings: list[str]) -> bool:
        """The engine must not be able to open outbound connections.

        This replaced a check that only confirmed an in-process "allowlist"
        was non-empty — it always was, because the backend URL was always
        on it, and nothing consulted the list anyway. The honest test is to
        try: connect to well-known public addresses and pass only when every
        attempt is dropped. A dropped SYN only fails by timing out, so the
        timeout bounds how long a sweep takes when egress is correctly
        blocked.
        """
        results = [cls._probe(host, port) for host, port in EGRESS_PROBES]
        if any(result in ("open", "refused") for result in results):
            warnings.append("Outbound connections from the engine succeed")
            return False
        if any(result == "error" for result in results):
            warnings.append("Could not determine whether outbound connections are blocked")
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
            # When the answer below was obtained, so a reader can tell a
            # current result from one left over from startup.
            "checked_at": self._reports[-1].checked_at if self._reports else None,
            "last_check": latest,
        }

    def get_security_history(self) -> list[dict]:
        return [report.to_dict() for report in self._reports]


breakout_prevention = BreakoutPrevention()
