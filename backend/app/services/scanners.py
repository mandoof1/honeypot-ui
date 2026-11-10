"""Telling research scanners apart from attackers.

A honeypot on a public address is scanned continuously by organisations that
are not attacking it: Censys, Shodan, Rapid7, Shadowserver, academic measurement
projects. GreyNoise's 2024 profiling of benign scanners puts this at the
majority of unsolicited traffic reaching an arbitrary address.

The pipeline classified all of it as ``reconnaissance``. That is not a bug in
the classifier — a Censys probe genuinely is reconnaissance — but it makes
every number the project reports meaningless. "Sessions observed", "attacks by
country", "reconnaissance is our largest category": all of them are dominated
by traffic that was never adversarial, and none of them can be compared against
anything.

So sessions are attributed rather than dropped. A scan from Censys is still
recorded in full — it is real data about what the internet does to an exposed
host — but it is labelled, and it can be excluded from the counts that are
supposed to describe attackers.

Dropping would be worse than useless: attackers do use scanner-adjacent
infrastructure, the lists go stale, and a honeypot that silently discards
traffic cannot be audited.
"""

from __future__ import annotations

import ipaddress
import json
import logging
import os
from typing import Iterable, Optional

logger = logging.getLogger(__name__)

#: Seed list of networks operated by organisations that publish their scanning
#: activity and offer opt-out. Each entry is documented by its operator; they
#: are listed here so the project has a working default with no network
#: dependency at ingest time.
#:
#: This is a seed, not a maintained feed, and it will go stale. Point
#: SCANNER_LIST_PATH at a MISP warninglist export (the ``*-scanning`` lists at
#: github.com/MISP/misp-warninglists) to override it with something current.
#:
#: What qualifies an entry: a range the scanning organisation itself holds
#: and publishes for opt-out. A range in a hosting provider's space does not,
#: however often a scanner has been seen there: its other tenants would be
#: labelled as that scanner too, and a labelled session is one that raises no
#: alert (when it also behaves like a scan; see services/analysis.py).
#:
#: Removed on that test, because nothing in this file justified them:
#:
#: * every Shodan entry, among them 71.6.128.0/17 — half of a hosting
#:   provider's allocation. Shodan does not publish ranges; its scanners sit
#:   in several hosting providers' space beside unrelated customers.
#: * Rapid7's 71.6.216.0/24 and 146.185.25.0/24, and Shadowserver's
#:   184.105.139.0/24, 184.105.247.0/24 and 216.218.206.0/24: whole /24s of
#:   providers' space with no source given here for the operator holding all
#:   of each.
#:
#: Sessions from those sources are attackers to this system until a
#: maintained list says otherwise, which is the safe direction to be wrong
#: in. Load one with SCANNER_LIST_PATH.
SEED_NETWORKS: dict[str, tuple[str, ...]] = {
    # Censys's own address space, which it publishes for opt-out.
    "censys": (
        "162.142.125.0/24",
        "167.94.138.0/24",
        "167.94.145.0/24",
        "167.94.146.0/24",
        "167.248.133.0/24",
        "199.45.154.0/24",
        "199.45.155.0/24",
    ),
    # Project Sonar, from the ranges Rapid7 publishes for it.
    "rapid7": (
        "5.63.151.96/27",
    ),
}


class ScannerRegistry:
    """Which known scanner, if any, an address belongs to."""

    def __init__(self) -> None:
        self._networks: list[tuple[ipaddress._BaseNetwork, str]] = []
        self._loaded = False

    def _compile(self, source: dict[str, Iterable[str]]) -> None:
        compiled = []
        for operator, cidrs in source.items():
            for cidr in cidrs:
                try:
                    network = ipaddress.ip_network(cidr, strict=False)
                except ValueError:
                    logger.warning("Skipping malformed scanner network %r", cidr)
                    continue
                # A /32 of 0.0.0.0 or an all-addresses net would match
                # everything; refuse rather than silently label the internet.
                if network.prefixlen == 0 or network.network_address.is_unspecified:
                    continue
                compiled.append((network, operator))
        # Longest prefix first, so a specific entry wins over a broad one.
        compiled.sort(key=lambda item: item[0].prefixlen, reverse=True)
        self._networks = compiled

    def load(self) -> None:
        """Load the override list if configured, else the seed."""
        if self._loaded:
            return
        self._loaded = True

        path = os.getenv("SCANNER_LIST_PATH")
        if path and os.path.exists(path):
            try:
                with open(path, "r", encoding="utf-8") as handle:
                    data = json.load(handle)
                # MISP warninglist shape: {"name": ..., "list": [...]}. A plain
                # {operator: [cidr, ...]} mapping is accepted too.
                if isinstance(data, dict) and isinstance(data.get("list"), list):
                    source = {str(data.get("name") or "scanner"): data["list"]}
                elif isinstance(data, dict):
                    source = {k: v for k, v in data.items() if isinstance(v, list)}
                else:
                    raise ValueError("unrecognised scanner list format")
                self._compile(source)
                logger.info(
                    "Loaded %d scanner networks from %s", len(self._networks), path
                )
                return
            except (OSError, ValueError, json.JSONDecodeError) as exc:
                logger.warning(
                    "Could not read scanner list at %s (%s); using the seed list",
                    path,
                    exc,
                )

        self._compile(SEED_NETWORKS)

    def identify(self, ip: str) -> Optional[str]:
        """The operator scanning from this address, or None."""
        self.load()
        if not ip:
            return None
        try:
            address = ipaddress.ip_address(ip)
        except ValueError:
            return None
        for network, operator in self._networks:
            if address in network:
                return operator
        return None


scanner_registry = ScannerRegistry()
