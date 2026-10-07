"""Shared rate limiter.

Each router previously constructed its own Limiter, so the limits registered
by the auth router were tracked in a different store from the one attached to
app.state. A single instance keeps counters consistent and lets the
RateLimitExceeded handler fire for every route.
"""

from slowapi import Limiter
from slowapi.util import get_remote_address

from app.core.config import get_settings


def _client_key(request) -> str:
    """Identify the client, honouring a trusted proxy header when configured.

    Behind a proxy the socket address is the proxy, so without this every
    request shares one bucket. The header is read right-to-left past the
    trusted hops (see core/clientip.py); the leftmost value is client-chosen
    and was what the limiter keyed on before, which let anyone pick their own
    bucket.
    """
    from app.core.clientip import client_ip

    settings = get_settings()
    if settings.TRUST_PROXY_HEADERS:
        resolved = client_ip(request)
        if resolved:
            return resolved
    return get_remote_address(request)


limiter = Limiter(key_func=_client_key)
