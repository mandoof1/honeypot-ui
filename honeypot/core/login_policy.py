"""Which logins the shell decoys let in, and which they remember.

Two ways in, as before: the weak credential the decoy advertises for a user,
or persistence — once a source has failed ``SOFT_ACCEPT_AFTER`` times, the
next password for a known user is accepted, so a brute-forcer that never
guesses the advertised one still gets in and shows what it does next.

What was missing is memory. A brute-forcer does not use the session in which
its guess succeeded: it writes the credential to a list and something else
logs in with it later. But the soft acceptance was not recorded anywhere and
the failure counter was cleared on success, so when the source came back with
the password that had "worked", it was refused like any other wrong guess and
the second stage — the part worth capturing — never arrived.

So an accepted (source, username, password) is remembered for a week and
honoured on return. It is stored as a digest, not as the credential, and
persisted beside the host identity so a restart does not forget it.

The planted login from ``core/honeytokens.py`` is always accepted: whoever
presents it read it out of the decoy's own files, and what they do next is
exactly what the plant is for.
"""

from __future__ import annotations

import asyncio
import hashlib
import json
import logging
import os
import threading
import time
from typing import Optional

from honeypot.core.config import config

logger = logging.getLogger(__name__)

#: Credentials the decoy accepts. Weak on purpose — the point is to let an
#: attacker in and record what they do next.
FAKE_USERS = {
    "root": "root",
    "admin": "admin",
    "user": "password",
    "test": "test",
    "ubuntu": "ubuntu",
    "pi": "raspberry",
    "oracle": "oracle",
    "postgres": "postgres",
}

#: Attempts after which any password is accepted, so a brute-forcer that
#: never guesses the advertised credential still gets in and reveals what it
#: does next. Instant success on attempt one is a fingerprint.
SOFT_ACCEPT_AFTER = 3

MAX_TRACKED_IPS = 4096
MAX_REMEMBERED = 4096
ACCEPTED_FILE = "accepted-logins.json"


class LoginPolicy:
    def __init__(self) -> None:
        #: Failed attempts per source address, not per connection. Most
        #: brute-force tools open a fresh connection for every password, so a
        #: per-connection counter would never reach the threshold.
        self.failures: dict[str, int] = {}
        self._remembered: dict[str, float] = {}
        self._loaded_from: Optional[str] = None
        self._lock = threading.Lock()

    # -- remembered logins ---------------------------------------------------

    @staticmethod
    def _key(source_ip: str, username: str, password: str) -> str:
        return hashlib.sha256(f"{source_ip}\x00{username}\x00{password}".encode("utf-8", "replace")).hexdigest()

    def _path(self) -> str:
        return os.path.join(config.session_capture_dir, ACCEPTED_FILE)

    def _load(self) -> None:
        """Read the remembered logins for the current data directory, once."""
        directory = config.session_capture_dir
        if self._loaded_from == directory:
            return
        self._loaded_from = directory
        self._remembered = {}
        try:
            with open(self._path(), "r", encoding="utf-8") as handle:
                stored = json.load(handle)
        except (OSError, ValueError):
            return
        now = time.time()
        if isinstance(stored, dict):
            for key, expiry in list(stored.items())[:MAX_REMEMBERED]:
                if isinstance(key, str) and isinstance(expiry, (int, float)) and expiry > now:
                    self._remembered[key] = float(expiry)

    def _save(self, snapshot: dict[str, float]) -> None:
        path = self._path()
        try:
            os.makedirs(os.path.dirname(path), exist_ok=True)
            tmp = path + ".tmp"
            with open(tmp, "w", encoding="utf-8") as handle:
                json.dump(snapshot, handle)
            os.replace(tmp, path)
        except OSError as exc:
            # A read-only data directory: the memory lasts for the process.
            logger.warning("Could not persist remembered logins: %s", exc)

    def remembered(self, source_ip: str, username: str, password: str) -> bool:
        with self._lock:
            self._load()
            expiry = self._remembered.get(self._key(source_ip, username, password))
            return expiry is not None and expiry > time.time()

    def remember(self, source_ip: str, username: str, password: str) -> None:
        ttl = config.accepted_login_ttl
        if ttl <= 0:
            return
        with self._lock:
            self._load()
            now = time.time()
            if len(self._remembered) >= MAX_REMEMBERED:
                # Drop what has expired, then the entries nearest to expiring.
                live = sorted((e, k) for k, e in self._remembered.items() if e > now)
                self._remembered = {k: e for e, k in live[-(MAX_REMEMBERED // 2):]}
            self._remembered[self._key(source_ip, username, password)] = now + ttl
            snapshot = dict(self._remembered)
        try:
            # File I/O stays off the event loop when there is one.
            asyncio.get_running_loop().run_in_executor(None, self._save, snapshot)
        except RuntimeError:
            self._save(snapshot)

    # -- the decision --------------------------------------------------------

    def check(self, source_ip: str, username: str, password: str) -> bool:
        """Whether this attempt "succeeds", updating the failure count."""
        from honeypot.core.honeytokens import get_honeytokens

        prior_failures = self.failures.get(source_ip, 0)
        expected = FAKE_USERS.get(username)
        tokens = get_honeytokens()
        planted = username == tokens.username and password == tokens.password
        advertised = expected is not None and password == expected
        persistent = expected is not None and prior_failures >= SOFT_ACCEPT_AFTER
        returning = self.remembered(source_ip, username, password)

        if not (planted or advertised or persistent or returning):
            if len(self.failures) >= MAX_TRACKED_IPS:
                self.failures.clear()
            self.failures[source_ip] = prior_failures + 1
            return False

        self.failures.pop(source_ip, None)
        if persistent and not advertised:
            # The guess that "worked": whoever reuses it must get in too.
            self.remember(source_ip, username, password)
        return True

    def reset(self) -> None:
        """Forget everything held in memory (tests)."""
        with self._lock:
            self.failures.clear()
            self._remembered = {}
            self._loaded_from = None


login_policy = LoginPolicy()
