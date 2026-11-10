"""Prune the engine's local copies of what the backend already holds.

Every session is written to the capture directory as JSON and every upload
under its digest, and neither was ever deleted. On the internet-facing
component that is a disk an attacker can fill by connecting enough times.
The backend is the system of record; the local copies are a convenience for
debugging and a safety net while a session is in flight, and a week of them
is plenty.

Never touched: the spool (sessions still owed to the backend), anything
under ``failed/``, and everything else the engine keeps beside the captures
— the SSH host keys, the host identity, the TLS material, the remembered
logins. The session pass used to delete any ``*.json`` older than the cutoff,
which included ``host-identity.json``: a week after first start the decoy
forgot which machine it was and came back with a new hostname, kernel, MAC
and uptime. So the pass now names what it deletes instead of what it spares:
a session capture is ``<session uuid>.json`` and nothing else is.
"""

from __future__ import annotations

import logging
import os
import re
import time
from typing import Callable, Optional

logger = logging.getLogger(__name__)

PROTECTED_PREFIXES = ("ssh_host_",)

#: The only files the session pass may delete: ``SessionManager`` writes each
#: capture as ``<uuid4>.json``.
SESSION_CAPTURE_NAME = re.compile(
    r"^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}\.json$"
)


def is_session_capture(name: str) -> bool:
    return bool(SESSION_CAPTURE_NAME.match(name))


def prune_directory(
    directory: str,
    max_age_seconds: float,
    suffix: str = "",
    now: float | None = None,
    only: Optional[Callable[[str], bool]] = None,
) -> int:
    """Delete regular files older than the cutoff. Returns how many went.

    ``only`` restricts the pass to names it accepts; without it every regular
    file that is not protected is a candidate.
    """
    cutoff = (now if now is not None else time.time()) - max_age_seconds
    removed = 0
    try:
        entries = list(os.scandir(directory))
    except FileNotFoundError:
        return 0
    except OSError as exc:
        logger.warning("Cannot read %s for retention: %s", directory, exc)
        return 0
    for entry in entries:
        if not entry.is_file(follow_symlinks=False):
            continue
        if suffix and not entry.name.endswith(suffix):
            continue
        if only is not None and not only(entry.name):
            continue
        if entry.name.startswith(PROTECTED_PREFIXES) or entry.name.endswith(".part"):
            continue
        try:
            if entry.stat(follow_symlinks=False).st_mtime < cutoff:
                os.unlink(entry.path)
                removed += 1
        except OSError:
            continue
    return removed


def prune_captures(capture_dir: str, upload_dir: str, capture_days: int, upload_days: int, now: float | None = None) -> dict[str, int]:
    """One retention pass; a zero or negative day count disables that part."""
    result = {"sessions": 0, "uploads": 0}
    if capture_days > 0:
        result["sessions"] = prune_directory(
            capture_dir, capture_days * 86400, now=now, only=is_session_capture
        )
    if upload_days > 0:
        result["uploads"] = prune_directory(upload_dir, upload_days * 86400, now=now)
    if result["sessions"] or result["uploads"]:
        logger.info("Retention: removed %d session file(s) and %d upload(s)", result["sessions"], result["uploads"])
    return result
