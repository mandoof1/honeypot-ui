"""Resolving the real client address behind reverse proxies.

Both the rate limiter and the audit log used to take the *leftmost* entry of
X-Forwarded-For, which is whatever the client chose to send. The address a
proxy adds is appended on the right. So the chain is walked from the right,
skipping the proxies we trust (loopback, the Docker networks, the private
ranges Caddy sits on), and the first address that is not one of ours is the
client. With no trusted header the socket peer is used.
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


def _is_trusted(address: str, networks: Iterable) -> bool:
    try:
        ip = ipaddress.ip_address(address)
    except ValueError:
        return False
    return any(ip in net for net in networks)


def client_ip(request) -> Optional[str]:
    """Best available client address for ``request`` (Starlette/FastAPI)."""
    settings = get_settings()
    peer = request.client.host if request.client else None
    if not settings.TRUST_PROXY_HEADERS:
        return peer
    forwarded = request.headers.get("x-forwarded-for")
    if not forwarded:
        return peer
    hops = [part.strip() for part in forwarded.split(",") if part.strip()]
    networks = _trusted_networks(settings.TRUSTED_PROXIES)
    for hop in reversed(hops):
        if not _is_trusted(hop, networks):
            return hop[:45]
    # Every hop was one of ours (a request from inside the deployment);
    # the leftmost is then the originating service.
    return hops[0][:45] if hops else peer
