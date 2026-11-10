"""FTP control-channel probes.

Each reply is compared as the bytes the server sent, addresses masked. The
commands are run twice where it makes sense: before login, where most
servers refuse almost everything, and after logging in with an account
both targets accept, where the replies that tell servers apart live.
"""

from __future__ import annotations

import statistics
import time
from typing import Optional

from . import ftpwire
from .checks import Check, escape_bytes
from .net import seconds
from .normalise import mask_ipv4, mask_pasv
from .probe import Prober

#: An account neither a stock install nor the decoy's credential list has.
UNKNOWN_USER = "fpaudit-nouser"

#: Commands sent in both states, with the name used in check ids.
COMMON_COMMANDS = (
    ("syst", b"SYST"),
    ("feat", b"FEAT"),
    ("help", b"HELP"),
    ("stat", b"STAT"),
    ("noop", b"NOOP"),
    ("pasv", b"PASV"),
    ("unknown_command", b"FPAUDIT"),
)

#: Lines longer than a daemon's input buffer, sent before login.
OVERLONG_LINES = (
    ("user_5000", "USER with a 5000-byte argument", b"USER " + b"A" * 5000),
    ("line_70000", "a 70000-byte line", b"A" * 70000),
)


class _Session:
    """One control connection and the replies read from it so far."""

    def __init__(self, prober: Prober) -> None:
        self._timeout = prober.settings.timeout
        self.conn = prober.connect()
        self._buffer = b""
        #: Seconds each command's reply took, for the latency row.
        self.reply_seconds: list[float] = []
        self.greeting = self._read()

    def _read(self) -> bytes:
        """The next whole reply as raw bytes; whatever arrived if the reply
        never completed; empty if nothing did."""
        data = self.conn.read_until(
            lambda buffer: ftpwire.read_reply(buffer) is not None,
            self._timeout,
            initial=self._buffer,
        )
        parsed = ftpwire.read_reply(data)
        if parsed is None:
            self._buffer = b""
            return data
        reply, self._buffer = parsed
        return reply.raw

    def command(self, line: bytes, timed: bool = True) -> bytes:
        started = time.monotonic()
        if not self.conn.send(line + b"\r\n"):
            return b""
        reply = self._read()
        if timed and reply:
            self.reply_seconds.append(time.monotonic() - started)
        return reply

    @property
    def closed(self) -> bool:
        return self.conn.closed is not None

    def closes_within(self, wait: float) -> bool:
        self.conn.wait_closed(wait)
        return self.closed

    def close(self) -> None:
        self.conn.close()


def _normalised(raw: bytes) -> bytes:
    return mask_pasv(mask_ipv4(raw))


def _reply_check(check_id: str, description: str, raw: bytes, **evidence) -> Check:
    return Check(check_id, description, "bytes", _normalised(raw), {"raw": escape_bytes(raw), **evidence})


def greeting(prober: Prober) -> list[Check]:
    session = _Session(prober)
    delay = session.conn.first_byte_after
    session.close()
    return [
        _reply_check("ftp.greeting", "greeting sent on connect", session.greeting),
        Check("ftp.greeting.delay", "seconds from connect to the greeting", "timing", seconds(delay)),
    ]


def _run_commands(prober: Prober, session: _Session, prefix: str, state: str) -> tuple[list[Check], _Session]:
    """Send the common commands on one connection. If the server hangs up
    part-way, the remaining commands go to a fresh connection and the check
    says so, rather than recording silence that is really a closed socket."""
    checks = []
    for name, line in COMMON_COMMANDS:
        fresh = False
        if session.closed:
            session.close()
            session = _Session(prober)
            fresh = True
        reply = session.command(line)
        checks.append(
            _reply_check(
                f"{prefix}.{name}",
                f"reply to {line.decode()} {state}",
                reply,
                on_fresh_connection=fresh,
            )
        )
    return checks, session


def _quit_checks(prober: Prober, session: _Session, prefix: str, state: str) -> list[Check]:
    reply = session.command(b"QUIT")
    closes = session.closes_within(prober.settings.quiet)
    session.close()
    return [
        _reply_check(f"{prefix}.quit", f"reply to QUIT {state}", reply),
        Check(
            f"{prefix}.quit.closes",
            f"whether the server closes the connection after QUIT {state}",
            "exact",
            closes,
        ),
    ]


def before_login(prober: Prober) -> tuple[list[Check], list[float]]:
    session = _Session(prober)
    checks, session = _run_commands(prober, session, "ftp.before_login", "before login")
    checks.append(
        _reply_check(
            "ftp.before_login.pass_before_user",
            "reply to PASS sent before any USER",
            session.command(b"PASS fpaudit"),
        )
    )
    latencies = list(session.reply_seconds)
    checks += _quit_checks(prober, session, "ftp.before_login", "before login")
    return checks, latencies


def wrong_credentials(prober: Prober) -> list[Check]:
    settings = prober.settings
    session = _Session(prober)
    user_reply = session.command(b"USER " + UNKNOWN_USER.encode())
    started = time.monotonic()
    pass_reply = session.command(b"PASS fpaudit-wrong", timed=False)
    pass_seconds = time.monotonic() - started
    session.close()
    checks = [
        _reply_check("ftp.login.unknown_user.user", f"reply to USER {UNKNOWN_USER}", user_reply),
        _reply_check("ftp.login.unknown_user.pass", "reply to a wrong PASS for that user", pass_reply),
        Check(
            "ftp.login.failed_pass_delay",
            "seconds the server takes to reject the wrong PASS",
            "timing",
            seconds(pass_seconds),
        ),
    ]

    # The same account again and again with a wrong password: real daemons
    # count failures and hang up; the question is when, and with what.
    session = _Session(prober)
    replies: list[str] = []
    ended = "still-prompting"
    for attempt in range(1, settings.login_attempts + 1):
        session.command(b"USER " + settings.ftp_user.encode(), timed=False)
        reply = session.command(f"PASS fpaudit-wrong-{attempt}".encode(), timed=False)
        if reply:
            replies.append(_normalised(reply).decode("latin-1"))
        if reply.startswith(b"230"):
            ended = "accepted"
            break
        if session.closed or session.closes_within(0.3):
            ended = "closed-by-server"
            break
    session.close()
    checks.append(
        Check(
            "ftp.login.repeated_wrong_password",
            f"replies to repeated wrong passwords for {settings.ftp_user}, and how it ends",
            "exact",
            {"pass_replies": replies, "ended": ended},
            {"attempt_limit": settings.login_attempts},
        )
    )
    return checks


def after_login(prober: Prober) -> tuple[list[Check], list[float]]:
    settings = prober.settings
    session = _Session(prober)
    user_reply = session.command(b"USER " + settings.ftp_user.encode(), timed=False)
    pass_reply = session.command(b"PASS " + settings.ftp_password.encode(), timed=False)
    logged_in = pass_reply.startswith(b"230")
    checks = [
        _reply_check("ftp.after_login.user", f"reply to USER {settings.ftp_user}", user_reply),
        _reply_check(
            "ftp.after_login.pass",
            "reply to the correct PASS",
            pass_reply,
            logged_in=logged_in,
        ),
    ]
    more, session = _run_commands(prober, session, "ftp.after_login", "after login")
    latencies = list(session.reply_seconds)
    checks += more
    checks += _quit_checks(prober, session, "ftp.after_login", "after login")
    return checks, latencies


def overlong_lines(prober: Prober) -> list[Check]:
    checks = []
    for name, description, line in OVERLONG_LINES:
        session = _Session(prober)
        reply = session.command(line, timed=False)
        closes = session.closes_within(prober.settings.quiet)
        session.close()
        checks.append(
            _reply_check(
                f"ftp.overlong.{name}",
                f"reply to {description}",
                reply,
                sent_length=len(line) + 2,
            )
        )
        checks.append(
            Check(
                f"ftp.overlong.{name}.closes",
                f"whether the server closes the connection after {description}",
                "exact",
                closes,
            )
        )
    return checks


def collect(prober: Prober) -> list[Check]:
    latencies: list[float] = []

    def timed(group):
        def run(inner: Prober) -> list[Check]:
            checks, seconds_taken = group(inner)
            latencies.extend(seconds_taken)
            return checks

        return run

    checks: list[Check] = []
    checks += prober.run("ftp.greeting", greeting)
    checks += prober.run("ftp.before_login", timed(before_login))
    checks += prober.run("ftp.wrong_credentials", wrong_credentials)
    checks += prober.run("ftp.after_login", timed(after_login))
    checks += prober.run("ftp.overlong_lines", overlong_lines)
    checks.append(_latency_check(latencies))
    return checks


def _latency_check(latencies: list[float]) -> Check:
    value: Optional[float] = seconds(statistics.median(latencies)) if latencies else None
    return Check(
        "ftp.reply_latency",
        "median seconds between a command and its reply (login commands excluded)",
        "timing",
        value,
        {
            "samples": len(latencies),
            "min": seconds(min(latencies)) if latencies else None,
            "max": seconds(max(latencies)) if latencies else None,
        },
    )
