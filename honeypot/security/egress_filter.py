import ipaddress
import logging
from typing import Optional

from honeypot.core.config import config

logger = logging.getLogger(__name__)


class EgressFilter:
    def __init__(self):
        self._allowed_hosts: list[str] = config.allowed_egress_hosts
        self._allowed_networks: list[ipaddress.IPv4Network] = [
            ipaddress.IPv4Network("127.0.0.0/8"),
            ipaddress.IPv4Network("10.0.0.0/8"),
            ipaddress.IPv4Network("172.16.0.0/12"),
            ipaddress.IPv4Network("192.168.0.0/16"),
        ]
        self._blocked_networks: list[ipaddress.IPv4Network] = [
            ipaddress.IPv4Network("0.0.0.0/8"),
            ipaddress.IPv4Network("169.254.0.0/16"),
            ipaddress.IPv4Network("224.0.0.0/4"),
            ipaddress.IPv4Network("240.0.0.0/4"),
        ]
        self._denied_connections: list[dict] = []
        self._max_denied_log = 1000

    def is_egress_allowed(self, destination_ip: str, destination_port: int) -> bool:
        try:
            dest = ipaddress.IPv4Address(destination_ip)
        except (ipaddress.AddressValueError, ValueError):
            logger.warning(f"Invalid IP address: {destination_ip}")
            return False

        for blocked in self._blocked_networks:
            if dest in blocked:
                self._log_denied(destination_ip, destination_port, "blocked_network")
                return False

        for allowed_host in self._allowed_hosts:
            try:
                if ":" in allowed_host:
                    host_part = allowed_host.rsplit(":", 1)[0]
                else:
                    host_part = allowed_host

                if host_part == destination_ip:
                    return True

                if not host_part.startswith("http"):
                    if host_part == destination_ip:
                        return True
            except Exception:
                continue

        for network in self._allowed_networks:
            if dest in network:
                return True

        self._log_denied(destination_ip, destination_port, "not_in_allowlist")
        return False

    def add_allowed_host(self, host: str):
        if host not in self._allowed_hosts:
            self._allowed_hosts.append(host)
            logger.info(f"Added allowed egress host: {host}")

    def remove_allowed_host(self, host: str):
        if host in self._allowed_hosts:
            self._allowed_hosts.remove(host)
            logger.info(f"Removed allowed egress host: {host}")

    def get_denied_connections(self) -> list[dict]:
        return self._denied_connections.copy()

    def clear_denied_log(self):
        self._denied_connections.clear()

    def _log_denied(self, ip: str, port: int, reason: str):
        entry = {
            "destination_ip": ip,
            "destination_port": port,
            "reason": reason,
        }
        self._denied_connections.append(entry)

        if len(self._denied_connections) > self._max_denied_log:
            self._denied_connections = self._denied_connections[-500:]

        logger.warning(
            f"Egress denied: {ip}:{port} (reason: {reason})"
        )


egress_filter = EgressFilter()
