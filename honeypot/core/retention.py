"""Prune the engine's local copies of what the backend already holds.

Every session is written to the capture directory as JSON and every upload
under its digest, and neither was ever deleted. On the internet-facing
component that is a disk an attacker can fill by connecting enough times.
The backend is the system of record; the local copies are a convenience for
debugging and a safety net while a session is in flight, and a week of them
is plenty.

Never touched: the spool (sessions still owed to the backend), anything
under ``failed/``, and the SSH host keys, which live in the same directory
and must survive restarts or every returning client sees a MITM warning.
"""

from __future__ import annotations

import logging
import os
import time

logger = logging.getLogger(__name__)

PROTECTED_PREFIXES = ("ssh_host_",)


def prune_directory(directory: str, max_age_seconds: float, suffix: str = "", now: float | None = None) -> int:
    """Delete regular files older than the cutoff. Returns how many went."""
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
        result["sessions"] = prune_directory(capture_dir, capture_days * 86400, suffix=".json", now=now)
    if upload_days > 0:
        result["uploads"] = prune_directory(upload_dir, upload_days * 86400, now=now)
    if result["sessions"] or result["uploads"]:
        logger.info("Retention: removed %d session file(s) and %d upload(s)", result["sessions"], result["uploads"])
    return result
