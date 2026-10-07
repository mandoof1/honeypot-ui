"""Which web clients the HTTP decoys hand to the decoy application.

With HONEYPOT_HTTP_DECOY_UPSTREAM set, the HTTP and HTTPS decoys front two
copies of a web application: the live one, and a decoy with the same public
pages and invented private data. A client is moved to the decoy the moment it
does something only an attacker does, and kept there, so what it does next
lands on data worth nothing while the honeypot records all of it. Blocking
would protect the live copy just as well, but it ends the recording and tells
the attacker they were seen.

Only signals a real visitor never produces move a client, because a wrong
call sends a customer to a shop that loses their order:

- a bait path (/.env, /wp-login.php, ...): no page of the application links
  to one;
- an attack pattern in the path, query or body (SQL injection, traversal,
  ...);
- the user agent of attack tooling (sqlmap, nikto, ...);
- failed logins at a rate no person reaches by mistyping.

A client is its address together with its user agent, so one attacker behind
a shared address (a campus NAT, a mobile carrier) does not take everyone
sharing it along. When the application's session cookie is named, the session
counts too, so a diverted client stays diverted if its address changes. The
mark lasts while the client stays active and lapses once it has been quiet
for the TTL.

What this cannot do: an attack the signals do not recognise reaches the live
application, and so does every request before the first one that gives the
attacker away. The table lives in memory, so an engine restart forgets it; a
returning attacker is diverted again by its next attack.
"""

from __future__ import annotations

import time
from collections import OrderedDict
from dataclasses import dataclass
from typing import Callable, Iterable, Optional

from honeypot.core.config import config

#: User-agent substrings of attack and scanning tools, matched
#: case-insensitively. Only names no browser or legitimate crawler sends.
SCANNER_AGENTS = (
    "sqlmap", "nikto", "nuclei", "wpscan", "gobuster", "dirbuster",
    "feroxbuster", "fuzz faster u fool", "wfuzz", "masscan", "zgrab",
    "nmap scripting engine", "acunetix", "netsparker", "openvas", "nessus",
    "commix", "xsstrike", "arachni", "skipfish", "w3af", "whatweb", "zmeu",
    "jaeles", "hydra",
)

#: Bait paths that browsers and crawlers fetch of their own accord. The decoy
#: still answers them, but asking for one says nothing about the client.
HARMLESS_BAIT = frozenset({"/robots.txt", "/sitemap.xml"})

#: Failed logins are counted over this many seconds.
FAILED_LOGIN_WINDOW = 600

#: Longest user agent and session token kept as table keys. Both are
#: attacker-supplied; unbounded, one keep-alive connection could fill each
#: table's 10k entries with 64 KiB strings.
MAX_AGENT_KEY = 512
MAX_TOKEN_KEY = 256


def _key(ip: str, agent: str) -> tuple[str, str]:
    return ip, (agent or "")[:MAX_AGENT_KEY]


def _token_key(token: Optional[str]) -> Optional[str]:
    return token[:MAX_TOKEN_KEY] if token else None


def scanner_agent(agent: str) -> Optional[str]:
    """The attack tool a user agent names, if it names one."""
    lowered = agent.lower()
    return next((name for name in SCANNER_AGENTS if name in lowered), None)


def request_token(headers: dict, cookie_name: str) -> Optional[str]:
    """The value of the session cookie a request carries."""
    if not cookie_name:
        return None
    for part in headers.get("cookie", "").split(";"):
        name, sep, value = part.strip().partition("=")
        if sep and name == cookie_name and value:
            return value
    return None


def issued_tokens(response: bytes, cookie_name: str) -> list[str]:
    """Session cookie values an application's response sets."""
    if not cookie_name:
        return []
    head = response.split(b"\r\n\r\n", 1)[0].decode("latin-1")
    tokens = []
    for line in head.split("\r\n")[1:]:
        name, _, value = line.partition(":")
        if name.strip().lower() != "set-cookie":
            continue
        cookie, sep, token = value.strip().split(";", 1)[0].partition("=")
        if sep and cookie.strip() == cookie_name and token:
            tokens.append(token)
    return tokens


@dataclass
class Mark:
    reason: str
    #: Wall-clock time the client was first diverted, for the records.
    since: float
    #: Clock time after which the mark lapses unless renewed.
    expires: float


class DiversionTable:
    #: Bound on remembered clients and sessions each. An attacker rotating
    #: addresses cannot grow the table past it; the oldest entries go first.
    MAX_ENTRIES = 10_000

    def __init__(
        self,
        ttl: float,
        failed_login_limit: int,
        clock: Callable[[], float] = time.monotonic,
    ):
        self.ttl = ttl
        self.failed_login_limit = failed_login_limit
        self._clock = clock
        self._clients: OrderedDict[tuple[str, str], Mark] = OrderedDict()
        self._tokens: OrderedDict[str, Mark] = OrderedDict()
        self._failures: dict[tuple[str, str], list[float]] = {}

    def lookup(self, ip: str, agent: str, token: Optional[str]) -> Optional[Mark]:
        """The client's mark, renewed, if it is being diverted."""
        now = self._clock()
        token = _token_key(token)
        mark = self._live(self._clients, _key(ip, agent), now)
        if mark is None and token:
            mark = self._live(self._tokens, token, now)
        if mark is None:
            return None
        mark.expires = now + self.ttl
        # Whichever way it was recognised, remember it the other way too: a
        # session seen from a new address keeps that address diverted even if
        # the cookie is later dropped.
        self._remember(self._clients, _key(ip, agent), mark)
        if token:
            self._remember(self._tokens, token, mark)
        return mark

    def divert(self, ip: str, agent: str, token: Optional[str], reason: str) -> Mark:
        mark = Mark(reason=reason, since=time.time(), expires=self._clock() + self.ttl)
        token = _token_key(token)
        self._remember(self._clients, _key(ip, agent), mark)
        if token:
            self._remember(self._tokens, token, mark)
        self._failures.pop(_key(ip, agent), None)
        return mark

    def adopt(self, tokens: Iterable[str], mark: Mark) -> None:
        """Divert the sessions the decoy application issued to a client."""
        for token in tokens:
            token = _token_key(token)
            if token:
                self._remember(self._tokens, token, mark)

    def failed_login(self, ip: str, agent: str) -> int:
        """Count a failed login; the number in the current window."""
        now = self._clock()
        key = _key(ip, agent)
        recent = [t for t in self._failures.get(key, []) if t > now - FAILED_LOGIN_WINDOW]
        recent.append(now)
        self._failures[key] = recent
        if len(self._failures) > self.MAX_ENTRIES:
            self._failures.pop(next(iter(self._failures)))
        return len(recent)

    def clear(self) -> None:
        self._clients.clear()
        self._tokens.clear()
        self._failures.clear()

    def _live(self, table: OrderedDict, key, now: float) -> Optional[Mark]:
        mark = table.get(key)
        if mark is not None and mark.expires <= now:
            del table[key]
            return None
        return mark

    def _remember(self, table: OrderedDict, key, mark: Mark) -> None:
        table[key] = mark
        table.move_to_end(key)
        while len(table) > self.MAX_ENTRIES:
            table.popitem(last=False)


diversion_table = DiversionTable(
    ttl=config.http_divert_ttl,
    failed_login_limit=config.http_divert_failed_logins,
)
