"""What every protocol's probe set shares: settings, pacing, error capture."""

from __future__ import annotations

import os
from dataclasses import asdict, dataclass
from typing import Callable, Optional

from .checks import Check
from .net import Connection, Pacer, Target


@dataclass
class Settings:
    #: Longest wait, in seconds, for one reply.
    timeout: float = 10.0
    #: Least time between the starts of two connections. Just over a second
    #: keeps a whole run under the decoy's default limit of 60 connections a
    #: minute from one address, so the audit measures the emulation and not
    #: the rate limiter.
    delay: float = 1.1
    #: Silence, in seconds, that ends a read with no defined end.
    quiet: float = 1.5
    #: How long the "client says nothing" probe keeps a connection open.
    idle_cap: float = 15.0
    #: Wrong logins tried, at most, when counting attempts before disconnect.
    login_attempts: int = 8
    #: An account both the decoy and the FTP reference accept, for the
    #: replies that only exist after login.
    ftp_user: str = "test"
    ftp_password: str = "test"

    def stored(self) -> dict:
        return asdict(self)


class Prober:
    """Runs probes against one target and collects what went wrong."""

    def __init__(
        self,
        target: Target,
        settings: Settings,
        pacer: Pacer,
        raw_dir: Optional[str] = None,
    ) -> None:
        self.target = target
        self.settings = settings
        self._pacer = pacer
        self._raw_dir = raw_dir
        #: Probe group name -> why it could not run.
        self.errors: dict[str, str] = {}

    def pace(self) -> None:
        """Take a turn; called before every connection, whoever opens it."""
        self._pacer.wait()

    def connect(self) -> Connection:
        self.pace()
        return Connection(self.target, self.settings.timeout)

    def keep_raw(self, name: str, data: bytes) -> None:
        """Save a whole capture when the caller asked for raw files."""
        if not self._raw_dir:
            return
        os.makedirs(self._raw_dir, exist_ok=True)
        with open(os.path.join(self._raw_dir, f"{name}.bin"), "wb") as handle:
            handle.write(data)

    def run(self, name: str, group: Callable[["Prober"], list[Check]]) -> list[Check]:
        """Run one group of probes. A group that cannot run (the target
        refused the connection, say) is recorded and the audit carries on, so
        one dead port does not lose the rest of the measurements."""
        try:
            return group(self)
        except Exception as exc:  # noqa: BLE001 - recorded, not swallowed
            self.errors[name] = f"{type(exc).__name__}: {exc}"
            return []
