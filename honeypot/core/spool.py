"""On-disk queue for sessions the backend could not take.

The engine used to make one attempt to deliver each session: a backend that
was restarting, overloaded or unreachable for fifteen seconds lost the
capture for good, and the local JSON copy was never replayed. For a honeypot
that is the worst possible failure mode — the system is most likely to be
down during the burst that was worth recording.

Payloads that fail with a retryable error are written here, one file per
session, and a background loop resends them oldest first. The backend
de-duplicates on the engine's session id, so a payload that was in fact
received before the response was lost is harmless to send again.

The queue is bounded in files and bytes; past either, the oldest entries are
dropped and the loss is logged. Permanent rejections (a 4xx other than 429)
are kept separately under ``failed/`` for inspection, bounded the same way.
"""

from __future__ import annotations

import json
import logging
import os
import time
from typing import Optional

logger = logging.getLogger(__name__)

SPOOL_DIR = "spool"
FAILED_DIR = "failed"
MAX_FAILED_FILES = 200


class Spool:
    def __init__(self, base_dir: str, max_files: int, max_bytes: int) -> None:
        self._dir = os.path.join(base_dir, SPOOL_DIR)
        self._failed_dir = os.path.join(base_dir, FAILED_DIR)
        self.max_files = max_files
        self.max_bytes = max_bytes
        self._count: Optional[int] = None
        self._bytes = 0

    # -- bookkeeping -------------------------------------------------------

    def _scan(self) -> None:
        """Count what is already on disk. Done once, then kept up to date."""
        count = 0
        total = 0
        try:
            with os.scandir(self._dir) as entries:
                for entry in entries:
                    if entry.is_file() and entry.name.endswith(".json"):
                        count += 1
                        try:
                            total += entry.stat().st_size
                        except OSError:
                            pass
        except FileNotFoundError:
            pass
        self._count, self._bytes = count, total

    def _ensure(self) -> None:
        if self._count is None:
            os.makedirs(self._dir, exist_ok=True)
            self._scan()

    @property
    def pending(self) -> int:
        self._ensure()
        return self._count or 0

    @property
    def bytes(self) -> int:
        self._ensure()
        return self._bytes

    # -- writing -----------------------------------------------------------

    def put(self, session_id: str, payload: dict) -> Optional[str]:
        """Queue a payload. Returns the path, or None if it could not be kept."""
        self._ensure()
        data = json.dumps(payload).encode("utf-8")
        if len(data) > self.max_bytes:
            logger.error("Session %s (%d bytes) is larger than the whole spool; dropped", session_id, len(data))
            return None
        self._make_room(len(data))
        path = os.path.join(self._dir, f"{time.time_ns():020d}-{session_id}.json")
        tmp = path + ".part"
        try:
            with open(tmp, "wb") as handle:
                handle.write(data)
            os.replace(tmp, path)
        except OSError as exc:
            logger.error("Could not spool session %s: %s", session_id, exc)
            try:
                os.unlink(tmp)
            except OSError:
                pass
            return None
        self._count = (self._count or 0) + 1
        self._bytes += len(data)
        return path

    def put_failed(self, session_id: str, payload: dict, reason: str) -> None:
        """Keep a permanently rejected payload for inspection."""
        try:
            os.makedirs(self._failed_dir, exist_ok=True)
            names = sorted(n for n in os.listdir(self._failed_dir) if n.endswith(".json"))
            for name in names[: max(0, len(names) - MAX_FAILED_FILES + 1)]:
                os.unlink(os.path.join(self._failed_dir, name))
            path = os.path.join(self._failed_dir, f"{time.time_ns():020d}-{session_id}.json")
            with open(path, "w", encoding="utf-8") as handle:
                json.dump({"reason": reason, "payload": payload}, handle)
        except OSError as exc:
            logger.warning("Could not keep rejected session %s: %s", session_id, exc)

    def _make_room(self, incoming: int) -> None:
        if (self._count or 0) < self.max_files and self._bytes + incoming <= self.max_bytes:
            return
        dropped = 0
        for path in self.oldest(self.max_files):
            if (self._count or 0) < self.max_files and self._bytes + incoming <= self.max_bytes:
                break
            self.remove(path)
            dropped += 1
        if dropped:
            logger.error("Spool full: dropped the %d oldest queued session(s)", dropped)

    # -- reading -----------------------------------------------------------

    def oldest(self, limit: int) -> list[str]:
        """Queued files, oldest first. Names start with a zero-padded clock."""
        self._ensure()
        try:
            names = sorted(n for n in os.listdir(self._dir) if n.endswith(".json"))
        except FileNotFoundError:
            return []
        return [os.path.join(self._dir, n) for n in names[:limit]]

    def load(self, path: str) -> Optional[dict]:
        try:
            with open(path, "rb") as handle:
                return json.loads(handle.read())
        except (OSError, ValueError) as exc:
            logger.warning("Dropping unreadable spool entry %s: %s", path, exc)
            self.remove(path)
            return None

    def remove(self, path: str) -> None:
        try:
            size = os.path.getsize(path)
            os.unlink(path)
        except FileNotFoundError:
            return
        except OSError as exc:
            logger.warning("Could not remove spool entry %s: %s", path, exc)
            return
        if self._count:
            self._count -= 1
        self._bytes = max(0, self._bytes - size)

    @staticmethod
    def session_id_of(path: str) -> str:
        name = os.path.basename(path)[: -len(".json")]
        return name.split("-", 1)[1] if "-" in name else name
