"""Telnet probes: option negotiation, the login prompt, failed logins.

The client here agrees to nothing: every option the server asks for is
refused. That is the simplest client there is, it is what a scanner or a
bot's hand-written telnet does, and it makes the server's side of the
negotiation depend on the server alone.
"""

from __future__ import annotations

import re
import time
from typing import Callable, Optional

from . import telnetwire
from .checks import Check, escape_bytes
from .net import seconds
from .normalise import mask_token
from .probe import Prober

#: An account neither a stock install nor the decoy's credential list has.
UNKNOWN_USER = "fpaudit-nouser"

#: An option number with no assignment, for "do you support this?" probes.
UNKNOWN_OPTION = 99

_LOGIN_PROMPT = re.compile(rb"(\S+) login: $")
_PASSWORD_PROMPT = re.compile(rb"assword: ?$")
_SHELL_PROMPT = re.compile(rb"[#$] $")

HOSTNAME_TAG = b"<hostname>"


class _Dialogue:
    """One telnet connection, with negotiation split from text as it arrives."""

    def __init__(self, prober: Prober, refuse: bool = True) -> None:
        self.conn = prober.connect()
        self._refuse = refuse
        self._partial = b""
        #: Every command the server has sent, in order.
        self.labels: list[str] = []
        #: The server's hostname, once a login prompt has shown it.
        self.hostname = b""

    def pump(
        self,
        timeout: float,
        until: Optional[Callable[[bytes], bool]] = None,
        quiet: Optional[float] = None,
    ) -> bytes:
        """Read, answering negotiation as it comes, and return the text
        received. Stops when ``until(text)`` holds, the server closes, the
        server has been silent for ``quiet`` seconds, or ``timeout`` runs out."""
        text = b""
        deadline = time.monotonic() + timeout
        while not (until and until(text)):
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                break
            data = self.conn.receive(min(remaining, quiet) if quiet else remaining)
            if not data:
                break
            tokens, self._partial = telnetwire.tokenize(self._partial + data)
            self.labels += telnetwire.negotiation_labels(tokens)
            if self._refuse:
                reply = telnetwire.refuse_all(tokens)
                if reply:
                    self.conn.send(reply)
            text += telnetwire.text_of(tokens)
        found = _LOGIN_PROMPT.search(text)
        if found and not self.hostname:
            self.hostname = found.group(1)
        return text

    def send_line(self, line: str) -> None:
        # CR LF is how a network virtual terminal ends a line (RFC 854).
        self.conn.send(line.encode("ascii") + b"\r\n")

    def masked(self, text: bytes) -> bytes:
        return mask_token(text, self.hostname, HOSTNAME_TAG)

    @property
    def closed(self) -> bool:
        return self.conn.closed is not None

    def close(self) -> None:
        self.conn.close()


def _at_login_prompt(text: bytes) -> bool:
    return _LOGIN_PROMPT.search(text) is not None


def silent_client(prober: Prober) -> list[Check]:
    """What the server sends to a client that sends nothing back at all."""
    settings = prober.settings
    dialogue = _Dialogue(prober, refuse=False)
    text = dialogue.pump(settings.timeout, quiet=settings.quiet * 2)
    delay = dialogue.conn.first_byte_after
    dialogue.close()
    return [
        Check(
            "telnet.silent.negotiation",
            "commands sent to a client that answers nothing",
            "ordered",
            dialogue.labels,
        ),
        Check(
            "telnet.silent.text",
            "text sent to a client that answers nothing",
            "bytes",
            dialogue.masked(text),
            {"raw": escape_bytes(text)},
        ),
        Check(
            "telnet.silent.first_byte_delay",
            "seconds from connect to the server's first byte",
            "timing",
            seconds(delay),
        ),
    ]


def refusing_client(prober: Prober) -> list[Check]:
    """Negotiation and prompt as seen by a client refusing every option,
    then the answers to requests for an option nobody implements."""
    settings = prober.settings
    dialogue = _Dialogue(prober)
    text = dialogue.pump(settings.timeout, until=_at_login_prompt)
    # A server may still be reacting to the last refusal.
    text += dialogue.pump(settings.quiet, quiet=settings.quiet)
    opening_labels = list(dialogue.labels)

    answers = {}
    for verb, code in (("WILL", telnetwire.WILL), ("DO", telnetwire.DO)):
        before = len(dialogue.labels)
        dialogue.conn.send(bytes([telnetwire.IAC, code, UNKNOWN_OPTION]))
        extra = dialogue.pump(settings.quiet, quiet=settings.quiet)
        answers[verb] = {"commands": dialogue.labels[before:], "text": escape_bytes(extra)}
    dialogue.close()

    return [
        Check(
            "telnet.refusing.negotiation",
            "every command sent to a client that refuses each option: the "
            "server's requests, then its reaction to the refusals",
            "ordered",
            opening_labels,
        ),
        Check(
            "telnet.refusing.login_banner",
            "text up to the first login prompt, hostname masked",
            "bytes",
            dialogue.masked(text),
            {"raw": escape_bytes(text), "hostname": dialogue.hostname.decode("latin-1")},
        ),
        Check(
            "telnet.option.client_will_unknown",
            f"reply to IAC WILL {UNKNOWN_OPTION} (client offers an unassigned option)",
            "exact",
            answers["WILL"],
        ),
        Check(
            "telnet.option.client_do_unknown",
            f"reply to IAC DO {UNKNOWN_OPTION} (client requests an unassigned option)",
            "exact",
            answers["DO"],
        ),
    ]


def _failed_logins(prober: Prober, username: str) -> dict:
    """Log in as ``username`` with wrong passwords until the server ends it,
    lets the client in, or the attempt limit is reached."""
    settings = prober.settings
    dialogue = _Dialogue(prober)
    dialogue.pump(settings.timeout, until=_at_login_prompt)
    attempts = []
    ended = "still-prompting"
    for attempt in range(1, settings.login_attempts + 1):
        dialogue.send_line(username)
        after_username = dialogue.pump(
            settings.timeout,
            until=lambda text: bool(_PASSWORD_PROMPT.search(text)) or _at_login_prompt(text),
        )
        if not _PASSWORD_PROMPT.search(after_username):
            ended = "closed-by-server" if dialogue.closed else "no-password-prompt"
            attempts.append({"after_username": after_username, "after_password": b"", "seconds": None})
            break
        dialogue.send_line(f"fpaudit-wrong-{attempt}")
        started = time.monotonic()
        after_password = dialogue.pump(
            settings.timeout,
            until=lambda text: _at_login_prompt(text) or bool(_SHELL_PROMPT.search(text)),
        )
        attempts.append(
            {
                "after_username": after_username,
                "after_password": after_password,
                "seconds": time.monotonic() - started,
            }
        )
        if _at_login_prompt(after_password):
            continue
        if _SHELL_PROMPT.search(after_password):
            ended = "logged-in"
        elif dialogue.closed:
            ended = "closed-by-server"
        else:
            ended = "no-further-prompt"
        break
    dialogue.close()
    return {"attempts": attempts, "ended": ended, "dialogue": dialogue}


def failed_logins(prober: Prober) -> list[Check]:
    # root first: the decoy counts failures per source address, and starting
    # with the account it knows shows that behaviour from a clean count.
    root = _failed_logins(prober, "root")
    unknown = _failed_logins(prober, UNKNOWN_USER)

    checks = []
    first = root["attempts"][0] if root["attempts"] else None
    masked = root["dialogue"].masked
    checks.append(
        Check(
            "telnet.login.after_username",
            "what the server sends after a username line (echo, password prompt)",
            "bytes",
            masked(first["after_username"]) if first else b"",
        )
    )
    checks.append(
        Check(
            "telnet.login.after_wrong_password",
            "what the server sends after a wrong password, up to the next prompt",
            "bytes",
            masked(first["after_password"]) if first else b"",
        )
    )
    checks.append(
        Check(
            "telnet.login.failed_login_delay",
            "seconds from a wrong password to the next login prompt",
            "timing",
            seconds(first["seconds"]) if first else None,
        )
    )
    for label, session, username in (("root", root, "root"), ("unknown_user", unknown, UNKNOWN_USER)):
        last = session["attempts"][-1] if session["attempts"] else None
        final_text = session["dialogue"].masked(last["after_password"] or last["after_username"]) if last else b""
        checks.append(
            Check(
                f"telnet.login.wrong_passwords.{label}",
                f"how repeated wrong passwords for {username} end, and after how many",
                "exact",
                {"wrong_passwords_sent": len(session["attempts"]), "ended": session["ended"]},
                {
                    "attempt_limit": prober.settings.login_attempts,
                    "final_text": escape_bytes(final_text[-400:]),
                    "seconds_per_attempt": [seconds(a["seconds"]) for a in session["attempts"]],
                },
            )
        )
    return checks


def collect(prober: Prober) -> list[Check]:
    checks: list[Check] = []
    checks += prober.run("telnet.silent_client", silent_client)
    checks += prober.run("telnet.refusing_client", refusing_client)
    checks += prober.run("telnet.failed_logins", failed_logins)
    return checks
