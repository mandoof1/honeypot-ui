"""SSH probes that need a finished key exchange.

The authentication methods a server offers, its pre-auth banner and how
many wrong passwords it takes before hanging up are all sent encrypted, so
this part uses asyncssh as the client. The same client, with the same
algorithm proposal, talks to both targets.

Some of what is recorded comes from asyncssh's own debug log (the server's
extension info, the reason in a disconnect message), because the library
does not expose those any other way. If a future asyncssh words those lines
differently the affected values come back empty and the result says so.
"""

from __future__ import annotations

import asyncio
import logging
import statistics
import time
from typing import Optional

from .checks import Check
from .net import seconds
from .probe import Prober
from .ssh_probes import CLIENT_SOFTWARE

#: An account neither a stock install nor the decoy's credential list has.
UNKNOWN_USER = "fpaudit-nouser"

#: Longest one authentication exchange may take in total. A real sshd pauses
#: a couple of seconds after each wrong password, so this is generous.
SESSION_TIMEOUT = 90.0


class _LogCapture(logging.Handler):
    """Collects asyncssh's debug records while a connection is made."""

    def __init__(self) -> None:
        super().__init__(level=logging.DEBUG)
        self.records: list[tuple[str, tuple]] = []
        self._logger = logging.getLogger("asyncssh")
        self._saved: tuple = ()

    def emit(self, record: logging.LogRecord) -> None:
        args = record.args if isinstance(record.args, tuple) else (record.args,)
        self.records.append((str(record.msg), args))

    def __enter__(self) -> "_LogCapture":
        import asyncssh

        self._saved = (self._logger.level, self._logger.propagate)
        self._logger.setLevel(logging.DEBUG)
        # Captured here only: these lines would otherwise reach the console.
        self._logger.propagate = False
        self._logger.addHandler(self)
        asyncssh.set_debug_level(2)
        return self

    def __exit__(self, *_exc) -> None:
        import asyncssh

        asyncssh.set_debug_level(1)
        self._logger.removeHandler(self)
        self._logger.setLevel(self._saved[0])
        self._logger.propagate = self._saved[1]

    def arguments(self, message_suffix: str) -> list[tuple]:
        """Arguments of every record whose message ends with the given
        text (asyncssh prefixes messages with a connection label)."""
        return [args for message, args in self.records if message.endswith(message_suffix)]

    def disconnect(self) -> Optional[dict]:
        found = self.arguments("Received disconnect: %s (%d)")
        if not found:
            return None
        reason, code = found[-1]
        return {"reason_code": code, "description": reason}

    def server_sig_algs(self) -> Optional[list[str]]:
        for name, value in self.arguments("  %s: %s"):
            if name == "server-sig-algs":
                return str(value).split(",") if value else []
        return None

    def key_exchange(self) -> Optional[str]:
        found = self.arguments("  Key exchange alg: %s")
        return str(found[0][0]) if found else None

    def remaining_methods(self) -> list[str]:
        return [str(args[0]) for args in self.arguments("Remaining auth methods: %s")]


def _client_options(username: str, timeout: float, **extra):
    import asyncssh

    return asyncssh.SSHClientConnectionOptions(
        username=username,
        client_version=CLIENT_SOFTWARE,
        # Nothing of the person running the audit may reach either target:
        # no keys from ~/.ssh, no agent, no ssh_config, no Kerberos.
        client_keys=None,
        agent_path=None,
        config=None,
        gss_kex=False,
        gss_auth=False,
        # The host key is whatever the target generated; there is nothing to
        # verify it against.
        known_hosts=None,
        connect_timeout=timeout,
        login_timeout=SESSION_TIMEOUT,
        **extra,
    )


async def _offered_methods(prober: Prober, username: str) -> list[str]:
    import asyncssh

    target = prober.target
    methods = await asyncio.wait_for(
        asyncssh.get_server_auth_methods(
            target.host,
            target.port,
            config=None,
            options=_client_options(username, prober.settings.timeout),
        ),
        timeout=SESSION_TIMEOUT,
    )
    return list(methods)


def _wrong_password_client(limit: int):
    """A client that answers every password prompt with a wrong password,
    up to a limit, and notes when each prompt arrived."""
    import asyncssh

    class WrongPasswordClient(asyncssh.SSHClient):
        def __init__(self) -> None:
            self.connection = None
            self.banner: Optional[str] = None
            self.prompt_times: list[float] = []
            self.sent = 0
            self.gave_up = False
            self.transport: dict = {}

        def connection_made(self, conn) -> None:
            self.connection = conn

        def auth_banner_received(self, msg: str, lang: str) -> None:
            self.banner = msg

        def password_auth_requested(self) -> Optional[str]:
            self.prompt_times.append(time.monotonic())
            if not self.transport and self.connection is not None:
                info = self.connection.get_extra_info
                self.transport = {
                    "client_to_server_cipher": info("send_cipher"),
                    "client_to_server_mac": info("send_mac"),
                    "client_to_server_compression": info("send_compression"),
                    "server_to_client_cipher": info("recv_cipher"),
                    "server_to_client_mac": info("recv_mac"),
                    "server_to_client_compression": info("recv_compression"),
                }
            if self.sent >= limit:
                self.gave_up = True
                return None
            self.sent += 1
            return f"fpaudit-wrong-{self.sent}"

    return WrongPasswordClient()


async def _password_session(prober: Prober, username: str) -> dict:
    """Keep offering wrong passwords for one user and record how it ends."""
    import asyncssh

    target = prober.target
    client = _wrong_password_client(prober.settings.login_attempts)
    raised: Optional[BaseException] = None
    accepted = False
    with _LogCapture() as log:
        try:
            conn = await asyncio.wait_for(
                asyncssh.connect(
                    target.host,
                    target.port,
                    client_factory=lambda: client,
                    options=_client_options(
                        username, prober.settings.timeout, preferred_auth="password"
                    ),
                ),
                timeout=SESSION_TIMEOUT,
            )
        except (asyncssh.Error, OSError, asyncio.TimeoutError) as exc:
            raised = exc
        else:
            accepted = True
            finished = time.monotonic()
            conn.close()
            await conn.wait_closed()

    disconnect = log.disconnect()
    if accepted:
        outcome = "accepted"
    elif disconnect is not None:
        outcome = "disconnected"
    elif client.gave_up:
        outcome = "still-prompting"
    elif isinstance(raised, asyncio.TimeoutError):
        outcome = "timeout"
    elif isinstance(raised, asyncssh.PermissionDenied):
        outcome = "password-no-longer-offered"
    else:
        outcome = "connection-lost"

    # The time from one prompt to the next is how long the server took to
    # reject the password sent in between.
    prompts = client.prompt_times + ([finished] if accepted else [])
    intervals = [later - earlier for earlier, later in zip(prompts, prompts[1:])]
    return {
        "outcome": outcome,
        "wrong_passwords_sent": client.sent,
        "disconnect": disconnect,
        "banner": client.banner,
        "transport": {"key_exchange": log.key_exchange(), **client.transport},
        "server_sig_algs": log.server_sig_algs(),
        "remaining_methods_after_each_failure": log.remaining_methods(),
        "raised": f"{type(raised).__name__}: {raised}" if raised else None,
        "rejection_seconds": [seconds(value) for value in intervals],
    }


def collect(prober: Prober) -> list[Check]:
    checks: list[Check] = []

    for label, username in (("root", "root"), ("unknown_user", UNKNOWN_USER)):
        prober.pace()
        checks.append(
            Check(
                f"ssh.auth.methods.{label}",
                f"authentication methods offered to {username}, in order",
                "ordered",
                asyncio.run(_offered_methods(prober, username)),
            )
        )

    # root first: the decoy counts failures per source address, and starting
    # with the account it knows shows that behaviour from a clean count.
    sessions = {}
    for label, username in (("root", "root"), ("unknown_user", UNKNOWN_USER)):
        prober.pace()
        sessions[label] = asyncio.run(_password_session(prober, username))

    first = sessions["root"]
    checks.append(
        Check(
            "ssh.auth.banner",
            "pre-authentication banner (SSH_MSG_USERAUTH_BANNER), if any",
            "exact",
            first["banner"],
        )
    )
    checks.append(
        Check(
            "ssh.transport.negotiated",
            "algorithms negotiated with the audit's client proposal",
            "exact",
            first["transport"],
        )
    )
    checks.append(
        Check(
            "ssh.ext_info.server_sig_algs",
            "server-sig-algs sent in SSH_MSG_EXT_INFO, in order",
            "ordered",
            first["server_sig_algs"],
        )
    )
    for label, username in (("root", "root"), ("unknown_user", UNKNOWN_USER)):
        session = sessions[label]
        checks.append(
            Check(
                f"ssh.auth.password.{label}",
                f"outcome of repeated wrong passwords for {username}",
                "exact",
                {
                    "outcome": session["outcome"],
                    "wrong_passwords_sent": session["wrong_passwords_sent"],
                    "disconnect": session["disconnect"],
                },
                {
                    "attempt_limit": prober.settings.login_attempts,
                    "remaining_methods_after_each_failure": session["remaining_methods_after_each_failure"],
                    "client_exception": session["raised"],
                    "rejection_seconds": session["rejection_seconds"],
                },
            )
        )
    rejections = [
        value for value in sessions["unknown_user"]["rejection_seconds"] if value is not None
    ]
    checks.append(
        Check(
            "ssh.auth.failed_password_delay",
            f"median seconds the server takes to reject a wrong password for {UNKNOWN_USER}",
            "timing",
            seconds(statistics.median(rejections)) if rejections else None,
            {"samples": rejections},
        )
    )
    return checks
