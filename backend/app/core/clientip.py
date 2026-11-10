"""Resolving the real client address behind reverse proxies.

Both the rate limiter and the audit log used to take the *leftmost* entry of
X-Forwarded-For, which is whatever the client chose to send. The address a
proxy adds is appended on the right. So the chain is walked from the right,
skipping the proxies we trust (loopback, the Docker networks, the private
ranges Caddy sits on), and the first address that is not one of ours is the
client. With no trusted header the socket peer is used.

The header is only read at all when the connection itself comes from one of
those proxies. Checking the hops inside the header is not enough: anything
that can reach the API directly (another container on the same network, a
port published by mistake) could otherwise send its own X-Forwarded-For and
be recorded, rate-limited and throttled as whichever address it named.
"""

from __future__ import annotations

import ipaddress
from functools import lru_cache
from typing import Iterable, Optional

from app.core.config import get_settings


@lru_cache(maxsize=1)
def _trusted_networks(spec: str) -> tuple:
    networks = []
    for item in spec.split(","):
        item = item.strip()
        if not item:
            continue
        try:
            networks.append(ipaddress.ip_network(item, strict=False))
        except ValueError:
            continue
    return tuple(networks)


def _is_trusted(address: Optional[str], networks: Iterable) -> bool:
    if not address:
        return False
    try:
        ip = ipaddress.ip_address(address)
    except ValueError:
        return False
    # A proxy reached over a dual-stack socket reports ::ffff:a.b.c.d.
    mapped = getattr(ip, "ipv4_mapped", None)
    if mapped is not None:
        ip = mapped
    return any(ip.version == net.version and ip in net for net in networks)


def client_ip(request) -> Optional[str]:
    """Best available client address for ``request`` (Starlette/FastAPI)."""
    settings = get_settings()
    peer = request.client.host if request.client else None
    if not settings.TRUST_PROXY_HEADERS:
        return peer
    networks = _trusted_networks(settings.TRUSTED_PROXIES)
    if not _is_trusted(peer, networks):
        # Not one of our proxies, so whatever header it sent is its own claim.
        return peer
    forwarded = request.headers.get("x-forwarded-for")
    if not forwarded:
        return peer
    hops = [part.strip() for part in forwarded.split(",") if part.strip()]
    nearest = peer
    for hop in reversed(hops):
        if not _is_address(hop):
            # A proxy only ever appends an address. Anything else was typed
            # by the client, so the chain we can believe ends to its right.
            return nearest
        if not _is_trusted(hop, networks):
            return hop[:45]
        nearest = hop[:45]
    # Every hop was one of ours (a request from inside the deployment);
    # the leftmost is then the originating service.
    return nearest


def _is_address(value: str) -> bool:
    try:
        ipaddress.ip_address(value)
    except ValueError:
        return False
    return True
