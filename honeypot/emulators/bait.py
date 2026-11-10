"""Web bait values that differ per deployment, derived from the host identity.

The web decoy used to hand every visitor the same constants: the same
``session=abc123`` cookie after a login, and a ``uname`` line whose hostname
was literally "honeypot". One string seen on two addresses is enough to list
every deployment of this project, and the second names the product outright.

Everything here is computed from the identity's seed (honeypot/core/
identity.py), so a deployment keeps its values across restarts, two
deployments never share one, and nothing has to be stored. The planted
secrets themselves (the ``/.env`` bait and its relatives) are not here: they
come from honeypot/core/honeytokens.py, shared with the shell decoys.
"""

from __future__ import annotations

import hashlib
import hmac
import time
from typing import Optional

from honeypot.core.identity import decoy_digest, get_identity

#: PHP's session id alphabet at its packaged setting (5 bits per character).
_PHP_SID_ALPHABET = "0123456789abcdefghijklmnopqrstuv"


def _digest(label: str) -> bytes:
    """Bytes that are stable for this deployment and this label only."""
    return decoy_digest(f"bait:{label}")


def uname_line() -> str:
    """What ``uname -a`` prints on this host, as the shell decoys show it."""
    return get_identity().uname_a


def stable_mtime(name: str) -> float:
    """A modification time for a decoy file, fixed for this deployment.

    Somewhere between a month and a year before the machine last booted, and
    anchored there rather than to the present, so two requests a second
    apart, or a week apart, report the same time.
    """
    age = 30 * 86400 + int.from_bytes(_digest(f"mtime:{name}")[:4], "big") % (335 * 86400)
    return float(int(get_identity().boot_time) - age)


def stable_microseconds(name: str) -> int:
    """The sub-second part of that time, for servers whose ETag includes it."""
    return int.from_bytes(_digest(f"mtime-usec:{name}")[:4], "big") % 1_000_000


def session_cookie_name() -> str:
    """The session cookie the claimed stack sets: PHP's, or a generic one."""
    return "PHPSESSID" if get_identity().php_version else "sessionid"


def new_session_id(source_ip: str, username: str, now: Optional[float] = None) -> str:
    """A session id for one login, in the claimed stack's format.

    Keyed by the deployment's seed and made from the client, the account and
    the moment, so it is different for every login and every deployment
    without the engine keeping a table of what it issued.
    """
    moment = time.time_ns() if now is None else int(now * 1e9)
    key = _digest("session-key")
    mac = hmac.new(key, f"{source_ip}|{username}|{moment}".encode(), hashlib.sha256).digest()
    if get_identity().php_version:
        return "".join(_PHP_SID_ALPHABET[byte % 32] for byte in mac[:26])
    return mac.hex()[:32]


def allow_rotation() -> int:
    """Which rotation of its Allow list this Apache prints.

    Apache builds the header by walking a hash table whose seed is drawn at
    process start, so the order of ``GET,POST,OPTIONS,HEAD`` differs between
    installations and is constant for one. The decoy picks its own once.
    """
    return _digest("allow-order")[0] % 4
