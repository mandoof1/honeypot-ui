import asyncio
import base64
import binascii
import json
import logging
import random
import re
import socket
import time
import weakref
from collections import deque
from dataclasses import dataclass, field
from typing import Optional
from urllib.parse import parse_qs, unquote_plus, urlparse

from honeypot.capture import tls_fingerprint
from honeypot.capture.flow import FlowMeter
from honeypot.capture.http_uploads import extract_files
from honeypot.capture.redact import redact_card_data
from honeypot.core.config import config
from honeypot.core.honeytokens import env_file_text, get_honeytokens
from honeypot.core.identity import get_identity
from honeypot.core.tls import build_tls_context
from honeypot.core.session import session_manager
from honeypot.core.modes import mode_handler
from honeypot.emulators import ai_canary, bait
from honeypot.emulators.base import BaseEmulator
from honeypot.emulators.http_profile import Reply, ServerProfile, build_profile
from honeypot.emulators.tls_listener import PeekingTLSServer
from honeypot.adaptive.response import adaptive_engine
from honeypot.security.diversion import (
    FAILED_LOGIN_WINDOW,
    HARMLESS_BAIT,
    Mark,
    diversion_table,
    header_attack,
    issued_tokens,
    request_token,
    scanner_agent,
)
from honeypot.security.refusals import refusal_log

logger = logging.getLogger(__name__)


@dataclass
class _WebSession:
    """An open web session shared by a client's connections (see
    HTTPHoneypot._attach_session). It ends ``http_session_idle`` seconds after
    the client's last request, unless a new connection reattaches first."""

    session_id: str
    active: int = 0
    last_seen: float = 0.0
    finalize: Optional[asyncio.Task] = None
    #: The session's flow meter. Every connection's own meter joins it, so
    #: the session reports all of its traffic and not just the first
    #: connection's.
    flow: Optional[FlowMeter] = None
    #: connection_refused events already recorded, by reason. A repeat adds
    #: to that event's count instead of adding an event.
    refusals: dict = field(default_factory=dict)
    #: Refused requests written to the transcript so far.
    refused_requests: int = 0


@dataclass
class _Request:
    """One request as read off the wire, before anything is decided."""

    #: The request line as sent, cut to the longest one accepted.
    line: str = ""
    method: str = ""
    target: str = ""
    version: str = "HTTP/1.1"
    #: Lower-cased names; a repeated header's values are joined.
    headers: dict = field(default_factory=dict)
    #: (name, value) in arrival order, repeats included.
    header_list: list = field(default_factory=list)
    #: The body as text for matching and records, card data masked, and the
    #: bytes exactly as sent for capture and forwarding.
    body: str = ""
    body_bytes: bytes = b""
    #: The request line or a header line is not valid HTTP.
    malformed: bool = False
    keep_alive: bool = False
    #: The client asked for keep-alive in so many words, which Apache echoes.
    keepalive_token: bool = False


@dataclass
class _Refusal:
    """Why a request is being turned away unread, and with which status."""

    status: int
    #: The ``reason`` of the connection_refused event.
    reason: str
    #: Which variant of the server's error page applies, if not the plain one.
    note: str = ""


#: Form fields that carry a login, across the decoy's own forms and the
#: products it imitates (WordPress, phpMyAdmin, generic admin panels).
USER_FIELDS = ("username", "user", "log", "pma_username", "email", "login", "uname")
PASSWORD_FIELDS = ("password", "pass", "pwd", "pma_password", "passwd")

#: Characters of a request body kept in the transcript. Bodies are where
#: injection payloads and webshell commands arrive.
TRANSCRIPT_BODY_CHARS = 2000

#: Bytes of a body decoded to text for the records and the login parsers.
#: Decoding and masking all of an 8 MiB upload, on the event loop, to keep
#: two thousand characters of it stalled every other connection.
BODY_TEXT_BYTES = 256 * 1024
#: Bodies from this size are searched and split into files on a worker
#: thread rather than on the event loop.
OFFLOAD_BODY_BYTES = 64 * 1024
#: Largest body a login is looked for in. A login form is a few hundred
#: bytes; megabytes of nested JSON are something else.
CREDENTIAL_BODY_CHARS = 64 * 1024

#: Request headers kept per transcript entry, and how much of each.
TRANSCRIPT_HEADERS = 40
TRANSCRIPT_HEADER_NAME_CHARS = 64
TRANSCRIPT_HEADER_VALUE_CHARS = 512
#: Characters of headers one session's transcript may hold in total. A
#: client usually repeats the same dozen headers, so this is some hundreds
#: of requests; after it, entries are recorded without their headers.
SESSION_HEADER_CHARS = 256 * 1024

#: How much of a refused request's line is kept, and how many refused
#: requests one session writes to its transcript. Enough to see what was
#: attempted; the megabyte that made it a refusal is not kept.
REFUSED_LINE_CHARS = 512
REFUSED_REQUESTS_PER_SESSION = 20

#: Blank lines tolerated before a request line, as real servers skip a few.
MAX_BLANK_LINES = 8
#: Bounds on a chunked request body: the longest chunk-size line, the most
#: chunks, and the most trailer lines after the last one.
MAX_CHUNK_LINE = 256
MAX_REQUEST_CHUNKS = 16384
MAX_TRAILER_LINES = 32

#: Headers that describe one connection rather than the message, so they are
#: never passed between the client and an upstream application.
HOP_BY_HOP = frozenset({
    "connection", "keep-alive", "proxy-connection", "proxy-authenticate",
    "proxy-authorization", "te", "trailer", "transfer-encoding", "upgrade",
})

#: Largest response accepted from an upstream application.
MAX_UPSTREAM_RESPONSE_BYTES = 16 * 1024 * 1024
#: Recent upstream response times remembered, so the decoy's own pages can
#: take as long as the application's do.
UPSTREAM_LATENCY_SAMPLES = 32

#: Methods both servers know. Anything else is not a method to them.
KNOWN_METHODS = frozenset({
    "GET", "HEAD", "POST", "PUT", "DELETE", "OPTIONS", "PATCH", "TRACE",
    "CONNECT", "PROPFIND", "PROPPATCH", "MKCOL", "COPY", "MOVE", "LOCK",
    "UNLOCK",
})

#: Substrings in a request path that mark a probe, and what each one probes for.
PATH_ATTACK_INDICATORS = [
    ("../", "path_traversal"),
    ("etc/passwd", "etc_passwd_probe"),
    ("etc/shadow", "etc_shadow_probe"),
    ("/proc/", "proc_probe"),
    ("<script>", "xss_attempt"),
    ("javascript:", "xss_attempt"),
    ("union+select", "sql_injection"),
    ("union%20select", "sql_injection"),
    ("1=1", "sql_injection"),
    ("1' OR '1'='1", "sql_injection"),
    ("${jndi:", "log4shell_attempt"),
    ("${env:", "log4shell_attempt"),
    ("cmd=", "command_injection"),
    ("exec(", "command_injection"),
    ("shell_exec", "command_injection"),
    ("/etc/passwd", "lfi_attempt"),
    ("php://filter", "lfi_attempt"),
    ("php://input", "lfi_attempt"),
    ("data://", "lfi_attempt"),
    ("expect://", "lfi_attempt"),
]

#: The same for request bodies.
BODY_ATTACK_INDICATORS = [
    ("<?php", "php_injection"),
    ("<script>", "xss_attempt"),
    ("union select", "sql_injection"),
    ("${jndi:", "log4shell_attempt"),
    ("cmd=", "command_injection"),
]

#: Bait pages that are JSON, as an API or a Spring Boot actuator returns it.
_JSON_PAGES = {
    "api_users": '{"users": [{"id": 1, "username": "admin", "role": "administrator"}, {"id": 2, "username": "user", "role": "user"}]}\n',
    "api_admin": '{"status": "ok", "version": "1.0.0", "debug": true}\n',
    "command_endpoint": '{"output": "uid=33(www-data) gid=33(www-data) groups=33(www-data)"}\n',
    "eval_endpoint": '{"result": "evaluated"}\n',
    "spring_actuator": '{"_links": {"self": {"href": "/actuator"}, "health": {"href": "/actuator/health"}, "env": {"href": "/actuator/env"}, "beans": {"href": "/actuator/beans"}}}\n',
    "spring_health": '{"status": "UP", "components": {"diskSpace": {"status": "UP"}, "db": {"status": "UP"}, "ping": {"status": "UP"}}}\n',
}

_VERSION = re.compile(r"HTTP/\d\.\d")
_HOST = re.compile(r"[A-Za-z0-9._\-\[\]:]{1,255}")
_HEADER_NAME = re.compile(r"[a-z0-9!#$%&'*+.^_`|~-]+")
_CONTROL_CHARS = re.compile(r"[\x00-\x08\x0a-\x1f\x7f]")
_HEX_DIGITS = frozenset(b"0123456789abcdefABCDEF")
#: What plain HTTP sent to the TLS port starts with.
_HTTP_REQUEST_START = re.compile(rb"[A-Z]{3,12} \S")


def _status_line(reply: Reply, profile: ServerProfile) -> str:
    return f"HTTP/1.1 {reply.status} {reply.reason or profile.reason(reply.status)}"


def _parse_upstream(url: str) -> Optional[tuple[str, int]]:
    if not url:
        return None
    parsed = urlparse(url)
    if parsed.scheme != "http" or not parsed.hostname:
        raise ValueError(f"HONEYPOT_HTTP_UPSTREAM must be http://host:port, got {url!r}")
    return parsed.hostname, parsed.port or 80


def _split_target(target: str) -> tuple[str, str]:
    """A request target as (path, query), for any string at all.

    ``urlparse`` raises on targets such as ``//[``, which took the whole
    request down before it was recorded, and reads ``//host/x`` as a network
    location, which no web server does with a request line.
    """
    if target.lower().startswith(("http://", "https://")):
        # Absolute form, as sent to a proxy: the path starts after the host.
        after_scheme = target.split("://", 1)[1]
        slash = after_scheme.find("/")
        target = after_scheme[slash:] if slash != -1 else "/"
    path, _, query = target.partition("?")
    return path.split("#", 1)[0], query.split("#", 1)[0]


def _basic_credentials(headers: dict) -> Optional[tuple[str, str]]:
    value = headers.get("authorization", "")
    if not value.lower().startswith("basic "):
        return None
    try:
        decoded = base64.b64decode(value[6:].strip(), validate=True).decode("utf-8", "replace")
    except (binascii.Error, ValueError):
        return None
    user, _, password = decoded.partition(":")
    return user, password


def _json_credentials(headers: dict, body: str) -> Optional[tuple[str, str]]:
    """A login posted as JSON, the way single-page applications send one."""
    if "application/json" not in headers.get("content-type", "") or not body:
        return None
    if len(body) > CREDENTIAL_BODY_CHARS:
        return None
    try:
        fields = json.loads(body)
    except (ValueError, RecursionError):
        # RecursionError: a body of ten thousand opening brackets. It is not
        # a ValueError, so it used to escape and drop the request unrecorded.
        return None
    if not isinstance(fields, dict):
        return None
    user = next((fields[k] for k in USER_FIELDS if isinstance(fields.get(k), str)), None)
    password = next((fields[k] for k in PASSWORD_FIELDS if isinstance(fields.get(k), str)), None)
    if user is None and password is None:
        return None
    return user or "", password or ""


def _form_credentials(headers: dict, body: str) -> Optional[tuple[str, str]]:
    if "application/x-www-form-urlencoded" not in headers.get("content-type", "") or not body:
        return None
    if len(body) > CREDENTIAL_BODY_CHARS:
        return None
    try:
        fields = parse_qs(body, keep_blank_values=True, max_num_fields=200)
    except ValueError:
        return None
    user = next((fields[k][0] for k in USER_FIELDS if k in fields), None)
    password = next((fields[k][0] for k in PASSWORD_FIELDS if k in fields), None)
    if user is None and password is None:
        return None
    return user or "", password or ""


def _first_indicator(text: str, indicators: list[tuple[str, str]]) -> Optional[str]:
    lowered = text.lower()
    for indicator, attack_type in indicators:
        if indicator.lower() in lowered:
            return attack_type
    return None


def _body_indicator(body: bytes) -> Optional[str]:
    """The first probe pattern in a request body, searched as bytes."""
    lowered = body.lower()
    for indicator, attack_type in BODY_ATTACK_INDICATORS:
        if indicator.encode() in lowered:
            return attack_type
    return None


def header_order(header_list: list) -> str:
    """The ``http_header_order`` fingerprint: header names as they arrived.

    Clients differ in which headers they send and in what order, and keep
    that order whatever User-Agent they claim. Names that are not header
    tokens are shown as "?" so an attacker cannot put arbitrary text here.
    """
    names = []
    for name, _ in header_list[:TRANSCRIPT_HEADERS * 2]:
        name = name[:TRANSCRIPT_HEADER_NAME_CHARS]
        names.append(name if _HEADER_NAME.fullmatch(name) else "?")
    return ",".join(names)


class HTTPHoneypot(BaseEmulator):
    MAX_REQUEST_LINE = 8192
    #: Longest header value kept. Header lines are read within the claimed
    #: server's own line limit; storing them whole, a hundred per request,
    #: for every request on a keep-alive connection added up.
    MAX_HEADER_VALUE = 8192
    #: Requests served on one connection. None follows the claimed server
    #: (Apache's MaxKeepAliveRequests, nginx's keepalive_requests).
    MAX_REQUESTS_PER_CONNECTION: Optional[int] = None
    MAX_CONNECTION_SECONDS = 600
    HEAD_DEADLINE_SECONDS = 30
    #: Raised from 1 MiB, which refused most compiled payloads with a 413
    #: before a byte was read. Bounded per request; the per-IP connection and
    #: rate limits bound how many of these one source can hold open.
    MAX_BODY_BYTES = config.http_max_body_bytes

    def __init__(self, use_tls: bool = False):
        protocol = "https" if use_tls else "http"
        port = config.https_port if use_tls else config.http_port
        super().__init__(
            protocol, port, ssl_context=build_tls_context() if use_tls else None
        )
        self.use_tls = use_tls
        self.max_connections_per_ip = config.http_max_connections_per_ip
        self.rate_limit_per_minute = config.http_rate_limit_per_minute
        self._vulnerable_endpoints = {
            "/admin": "admin_panel",
            "/login": "login_form",
            "/wp-admin": "wordpress_admin",
            "/wp-login.php": "wordpress_login",
            "/phpmyadmin": "phpmyadmin",
            "/manager/html": "tomcat_manager",
            "/.env": "env_file",
            "/config.php": "config_file",
            "/api/v1/users": "api_users",
            "/api/v1/admin": "api_admin",
            "/upload": "upload_form",
            "/shell": "web_shell",
            "/cmd": "command_endpoint",
            "/eval": "eval_endpoint",
            "/debug": "debug_panel",
            "/console": "console_panel",
            "/actuator": "spring_actuator",
            "/actuator/env": "spring_env",
            "/actuator/health": "spring_health",
        }
        #: Paths answered from a file. Their contents depend on the host
        #: identity, so they are built when asked for (see _bait_file).
        self._fake_files = (
            "/robots.txt", "/sitemap.xml", "/.env", "/config.php", "/wp-config.php",
        )
        self._upstream = _parse_upstream(config.http_upstream)
        self._decoy_upstream = _parse_upstream(config.http_decoy_upstream)
        if self._decoy_upstream and not self._upstream:
            logger.warning("HONEYPOT_HTTP_DECOY_UPSTREAM ignored: no HONEYPOT_HTTP_UPSTREAM to divert from")
            self._decoy_upstream = None
        owned = {p.strip() for p in config.http_upstream_owns.split(",") if p.strip()}
        self._bait_paths = (set(self._fake_files) | set(self._vulnerable_endpoints)) - owned
        #: Open web sessions by client identity, so a client's requests join
        #: one session across connections. Guarded by _web_lock.
        self._web_sessions: dict[tuple, _WebSession] = {}
        self._web_lock = asyncio.Lock()
        #: Header characters already kept in each open session's transcript.
        self._header_chars: dict[str, int] = {}
        #: What the TLS listener saw of each connection's ClientHello, until
        #: the connection's first request attaches it to a session.
        self._tls_prints: "weakref.WeakKeyDictionary" = weakref.WeakKeyDictionary()
        self._upstream_latency: deque = deque(maxlen=UPSTREAM_LATENCY_SAMPLES)
        self._profile_identity = None
        self._profile_cache: Optional[ServerProfile] = None

    # -- who the decoy claims to be -------------------------------------------

    @property
    def _profile(self) -> ServerProfile:
        """The claimed server's manners, rebuilt if the identity changed."""
        identity = get_identity()
        if self._profile_cache is None or self._profile_identity is not identity:
            self._profile_cache = build_profile(
                identity.http_family, identity.http_server, identity.php_version, self.use_tls
            )
            self._profile_identity = identity
        return self._profile_cache

    def get_banner(self) -> str:
        # Straight from the identity. This went through a switch that, with
        # HONEYPOT_ANTI_FINGERPRINT=false, returned the product's own name
        # as the Server header.
        return get_identity().http_server

    # -- listening --------------------------------------------------------------

    async def start(self) -> None:
        if not self.use_tls:
            await super().start()
            return
        if self.ssl_context is None:
            # Serving plaintext on the HTTPS port, which is what happened
            # before, is both a fingerprint and a lie in the logs.
            raise RuntimeError("no TLS context available; HTTPS listener not started")
        # Not asyncio.start_server(ssl=...): that finishes the handshake out
        # of sight. This listener looks at the ClientHello first and then
        # hands the socket to the same TLS implementation.
        self._server = await PeekingTLSServer.listen(
            config.bind_address, self.port, self.ssl_context, self._tls_connected,
            on_plaintext=self._answer_plain_http, on_failed=self._tls_dropped,
        )
        self._running = True
        addr = self._server.sockets[0].getsockname()
        logger.info(f"HTTPS honeypot listening on {addr[0]}:{addr[1]}")

    async def stop(self) -> None:
        # Flush any web sessions still waiting on their idle window, so a
        # shutdown delivers them now instead of dropping them.
        await super().stop()
        async with self._web_lock:
            entries = list(self._web_sessions.values())
            self._web_sessions.clear()
            self._header_chars.clear()
        for entry in entries:
            if entry.finalize is not None:
                entry.finalize.cancel()
            await session_manager.end_session(entry.session_id)

    async def _tls_connected(self, reader, writer, first_bytes: bytes) -> None:
        prints = tls_fingerprint.fingerprint(first_bytes)
        if prints:
            self._tls_prints[writer] = prints
        await self._accept(reader, writer)

    def _tls_dropped(self, address: tuple, reason: str, first_bytes: bytes) -> None:
        """A connection that never became a stream: its handshake did not
        complete, or too many were already waiting for theirs."""
        refusal_log.note(address[0], self.protocol, reason)

    async def _answer_plain_http(self, sock: socket.socket, address: tuple, first_bytes: bytes) -> bool:
        """Plain HTTP on the HTTPS port gets the claimed server's own answer.

        Both servers recognise it and reply in the clear with a 400 that
        says so. Dropping the connection instead, which is what a failed
        handshake did, is not what either does.
        """
        if not _HTTP_REQUEST_START.match(first_bytes):
            return False
        profile = self._profile
        reply = profile.error(400, note="plain_http")
        data = profile.serialise(reply, keep_alive=False)
        loop = asyncio.get_running_loop()
        try:
            # Take the request out of the socket first: closing with unread
            # data makes the kernel reset the connection, and the reset can
            # overtake the reply.
            try:
                sock.recv(65536)
            except (BlockingIOError, InterruptedError):
                pass
            await asyncio.wait_for(loop.sock_sendall(sock, data), timeout=5)
            sock.shutdown(socket.SHUT_WR)
        except (OSError, asyncio.TimeoutError):
            pass
        refusal_log.note(address[0], self.protocol, "plain_http_on_tls_port")
        return True

    # -- one connection ---------------------------------------------------------

    def _wait_seconds(self, served: int) -> float:
        """How long to wait for the next request line."""
        if config.connection_timeout:
            return config.connection_timeout
        profile = self._profile
        return profile.first_request_timeout if served == 0 else profile.keepalive_timeout

    async def handle_client(
        self, reader: asyncio.StreamReader, writer: asyncio.StreamWriter
    ):
        source_ip, source_port = self._get_peer_info(writer)
        flow = FlowMeter.for_stream(reader, writer, tls=self.use_tls)
        tls_prints = self._tls_prints.pop(writer, None)
        logger.info(f"HTTP connection from {source_ip}:{source_port}")

        if not await self._check_rate_limit(source_ip):
            logger.warning(f"Rate limit exceeded for {source_ip}")
            flow.close()
            refusal_log.note(source_ip, self.protocol, "blocked")
            writer.close()
            await writer.wait_closed()
            return

        if mode_handler.is_passive():
            session_id = await session_manager.create_session(
                self.protocol, source_ip, source_port, flow=flow
            )
            try:
                await self._note_fingerprints(session_id, None, tls_prints)
                await self._observe_passively(session_id, reader)
            finally:
                # A request the reader refused (a line over its limit) used
                # to raise past this point and leave the session open for
                # ever; eviction only removes finished ones.
                await session_manager.end_session(session_id)
                writer.close()
                try:
                    await writer.wait_closed()
                except Exception:
                    pass
            return

        loop = asyncio.get_running_loop()
        profile = self._profile
        connection_deadline = loop.time() + self.MAX_CONNECTION_SECONDS
        request_limit = self.MAX_REQUESTS_PER_CONNECTION or profile.max_requests
        requests_served = 0
        blank_lines = 0
        # The session is attached on the first request, once the client's
        # identity (address, user agent, session cookie) is known, so a
        # client's requests coalesce into one session even across separate
        # connections (see _attach_session). HTTP is request-per-connection
        # for most tools, and one session per connection turned a single scan
        # into dozens of one-request rows, each queued for the model stage.
        session_id: Optional[str] = None
        identity = None
        try:
            while True:
                try:
                    kind, request, refusal = await self._read_request(
                        reader, writer, loop, connection_deadline,
                        self._wait_seconds(requests_served),
                    )
                except (ConnectionError, asyncio.IncompleteReadError) as exc:
                    logger.debug("HTTP request from %s abandoned: %s", source_ip, exc)
                    break
                except Exception as exc:
                    logger.warning("HTTP request from %s failed: %s", source_ip, exc, exc_info=True)
                    break

                if kind == "stop":
                    break
                if kind == "empty":
                    blank_lines += 1
                    if blank_lines > MAX_BLANK_LINES:
                        break
                    continue

                if session_id is None:
                    identity = self._identity(source_ip, request.headers)
                    session_id = await self._attach_session(
                        identity, source_ip, source_port, flow
                    )
                    await self._note_fingerprints(session_id, request, tls_prints)

                if kind == "refused":
                    # Too long, too large or not framed as HTTP. It used to be
                    # answered (or not) and dropped before any session
                    # existed, so nothing recorded that it happened.
                    reply = profile.error(
                        refusal.status, method=request.method or "GET",
                        host=self._host(request), note=refusal.note,
                        user_agent=request.headers.get("user-agent", ""),
                    )
                    await self._record_refused_request(identity, session_id, request, refusal, reply)
                    if refusal.status != 408 or profile.answers_timeouts:
                        await self._send(writer, reply, request, keep_alive=False)
                        await self._linger(reader, writer)
                    break

                requests_served += 1
                requests_left = request_limit - requests_served
                try:
                    reply = await self._handle_request(session_id, request, source_ip)
                except (ConnectionError, asyncio.CancelledError):
                    raise
                except Exception as exc:
                    # Whatever went wrong answering it, the request itself is
                    # still evidence and still gets recorded.
                    logger.warning("HTTP handler failed for %s: %s", source_ip, exc, exc_info=True)
                    reply = profile.error(500, host=self._host(request))

                keep_alive = request.keep_alive and not reply.close and requests_left > 0
                await self._record_exchange(session_id, request, reply)
                await self._send(writer, reply, request, keep_alive, requests_left)
                if not keep_alive:
                    # "Connection: close" was sent on every response while
                    # the socket stayed open for the next request.
                    break

        except (ConnectionResetError, BrokenPipeError, asyncio.CancelledError):
            pass
        except Exception as e:
            logger.error(f"HTTP session error: {e}")
        finally:
            if identity is not None:
                await self._detach_session(identity, session_id)
            else:
                # No request was read, so nothing was attached and this
                # connection's flow meter is the only thing to close.
                flow.close()
            writer.close()
            try:
                await writer.wait_closed()
            except Exception:
                pass

    async def _send(
        self,
        writer: asyncio.StreamWriter,
        reply: Reply,
        request: _Request,
        keep_alive: bool,
        requests_left: int = 0,
    ) -> None:
        data = self._profile.serialise(
            reply,
            head_only=request.method == "HEAD",
            keep_alive=keep_alive,
            keepalive_token=request.keepalive_token,
            requests_left=requests_left,
        )
        if reply.kind != "proxied":
            # An application's own answer took as long as it took; only the
            # decoy's instant ones need time added.
            await self._decoy_delay()
        writer.write(data)
        await writer.drain()

    async def _decoy_delay(self) -> None:
        """Wait about as long as a real answer would have taken.

        With an application behind the decoy, that is how long the
        application has been taking: a bait page that comes back in a
        fraction of the time every other page needs marks itself. Otherwise
        it is the small configured jitter. HONEYPOT_ANTI_FINGERPRINT=false
        turns both off, and nothing else.
        """
        if not config.enable_anti_fingerprinting:
            return
        if self._upstream_latency:
            await asyncio.sleep(random.choice(self._upstream_latency))
            return
        await self._apply_response_delay()

    async def _linger(self, reader: asyncio.StreamReader, writer: asyncio.StreamWriter) -> None:
        """Let a refused client read its answer before the socket closes.

        The client is usually still sending. Closing on unread data resets
        the connection and can discard the reply on its way out, so, like
        the servers imitated, read and drop what arrives for a moment first.
        """
        loop = asyncio.get_running_loop()
        try:
            if writer.can_write_eof():
                writer.write_eof()
            discarded = 0
            deadline = loop.time() + 1.0
            while discarded < 1024 * 1024:
                remaining = deadline - loop.time()
                if remaining <= 0:
                    break
                chunk = await asyncio.wait_for(reader.read(65536), timeout=remaining)
                if not chunk:
                    break
                discarded += len(chunk)
        except (asyncio.TimeoutError, ConnectionError, OSError, ValueError):
            pass

    # -- reading a request --------------------------------------------------------

    async def _read_line(
        self, reader: asyncio.StreamReader, timeout: float, limit: int
    ) -> tuple[bytes, bool]:
        """One line, and whether it was longer than ``limit``.

        ``readline`` raised on a line over the reader's 64 KiB and threw the
        data away, so an oversized request left neither an answer nor a
        record. Here the beginning of such a line is kept, which is all the
        record needs, and the caller refuses the request.
        """
        try:
            line = await asyncio.wait_for(reader.readuntil(b"\n"), timeout=timeout)
        except asyncio.IncompleteReadError as exc:
            # The client closed mid-line; what it sent is still a line.
            return exc.partial, len(exc.partial) > limit
        except asyncio.LimitOverrunError:
            # No line end within the reader's limit. The data is still
            # buffered, so this returns at once.
            return await reader.read(limit), True
        return line, len(line.rstrip(b"\r\n")) > limit

    async def _read_request(self, reader, writer, loop, connection_deadline, wait):
        """Read one request: ``(kind, request, refusal)``.

        ``kind`` is "request" for one to answer; "refused" for one the server
        will not take (``refusal`` says why and with which status), which is
        answered and then the connection closed; "empty" for a blank line to
        skip; "stop" when the connection is finished. Pulled out of the
        connection loop so the first request can be read before the session
        is attached — the client's identity is only known once its headers
        are.
        """
        remaining = connection_deadline - loop.time()
        if remaining <= 0:
            return "stop", None, None
        # The first byte is awaited on its own: a connection that never
        # sends one is idle and simply closes, while one that starts a
        # request and stalls has timed out and is treated as such.
        try:
            first = await asyncio.wait_for(reader.read(1), timeout=min(wait, remaining))
        except asyncio.TimeoutError:
            return "stop", None, None
        if not first:
            return "stop", None, None
        if first == b"\n":
            return "empty", None, None

        request = _Request()
        head_deadline = loop.time() + self.HEAD_DEADLINE_SECONDS
        try:
            rest, overflow = await self._read_line(
                reader, self.HEAD_DEADLINE_SECONDS, self.MAX_REQUEST_LINE
            )
        except asyncio.TimeoutError:
            request.line = first.decode("latin-1")
            return "refused", request, _Refusal(408, "request_timeout")
        text = (first + rest).decode("utf-8", errors="replace").strip()
        if not text:
            return "empty", None, None
        self._parse_request_line(request, text)
        if overflow or len(text) > self.MAX_REQUEST_LINE:
            # Neither server reads further than this; the headers, if any
            # follow, stay unread.
            return "refused", request, _Refusal(414, "request_line_too_long")

        refusal = await self._read_headers(reader, request, head_deadline)
        if refusal is not None:
            return "refused", request, refusal
        self._settle_keep_alive(request)
        refusal = await self._read_body(reader, writer, request)
        if refusal is not None:
            return "refused", request, refusal
        return "request", request, None

    def _parse_request_line(self, request: _Request, text: str) -> None:
        request.line = text[: self.MAX_REQUEST_LINE]
        parts = request.line.split()
        request.method = parts[0] if parts else ""
        request.target = parts[1] if len(parts) > 1 else ""
        if len(parts) == 3 and _VERSION.fullmatch(parts[2]):
            request.version = parts[2]
        elif len(parts) == 2:
            # The headerless form of HTTP/0.9. Answered, then closed.
            request.version = "HTTP/0.9"
        else:
            request.malformed = True
        if _CONTROL_CHARS.search(request.line):
            request.malformed = True

    async def _read_headers(
        self, reader: asyncio.StreamReader, request: _Request, deadline: Optional[float] = None
    ) -> Optional[_Refusal]:
        """Read the header block into ``request``, within a deadline for the
        whole block and the claimed server's limits on its size.

        The timeout used to apply per line, so a client sending one header
        every nine seconds held the handler for the full header count. The
        count was a silent cut-off: the hundred-and-first header was left in
        the stream and read as the next request.
        """
        profile = self._profile
        loop = asyncio.get_running_loop()
        if deadline is None:
            deadline = loop.time() + self.HEAD_DEADLINE_SECONDS
        too_large = _Refusal(400, "header_too_large", "header_too_large")
        total = 0
        while True:
            remaining = deadline - loop.time()
            if remaining <= 0:
                return _Refusal(408, "request_timeout")
            try:
                raw, overflow = await self._read_line(
                    reader, min(10, remaining), profile.max_header_line
                )
            except asyncio.TimeoutError:
                return _Refusal(408, "request_timeout")
            if overflow:
                return too_large
            line = raw.rstrip(b"\r\n")
            if not line:
                return None
            total += len(raw)
            if total > profile.max_header_bytes:
                return too_large
            if len(request.header_list) >= profile.max_header_count:
                return _Refusal(400, "too_many_headers", "too_many_headers")
            if b"\r" in line or b"\x00" in line:
                # A bare carriage return or NUL inside a header is how one
                # header is made to look like two to whatever reads it next.
                request.malformed = True
                continue

            text = line.decode("utf-8", errors="replace")
            if text[0] in " \t" and request.header_list:
                # A folded line continues the header before it.
                name, value = request.header_list[-1]
                value = f"{value} {text.strip()}"[: self.MAX_HEADER_VALUE]
                request.header_list[-1] = (name, value)
                request.headers[name] = value
                continue
            name, separator, value = text.partition(":")
            name = name.strip().lower()[:256]
            if not separator or not name:
                continue
            value = value.strip()[: self.MAX_HEADER_VALUE]
            request.header_list.append((name, value))
            if name in request.headers:
                joiner = "; " if name == "cookie" else ", "
                value = f"{request.headers[name]}{joiner}{value}"[: self.MAX_HEADER_VALUE]
            request.headers[name] = value

    @staticmethod
    def _settle_keep_alive(request: _Request) -> None:
        tokens = {t.strip() for t in request.headers.get("connection", "").lower().split(",")}
        request.keepalive_token = "keep-alive" in tokens
        if "close" in tokens:
            request.keep_alive = False
        elif request.version == "HTTP/1.1":
            request.keep_alive = True
        else:
            request.keep_alive = request.version == "HTTP/1.0" and request.keepalive_token

    async def _read_body(self, reader, writer, request: _Request) -> Optional[_Refusal]:
        headers = request.headers
        declared = headers.get("content-length")
        chunked = False
        codings = [c.strip() for c in headers.get("transfer-encoding", "").lower().split(",") if c.strip()]
        if codings:
            if codings != ["chunked"]:
                return _Refusal(501, "unsupported_transfer_encoding")
            chunked = True
            if declared is not None:
                # A length beside chunked framing is how a request is hidden
                # from one of two servers. The chunks decide, and the
                # connection is not used again.
                request.keep_alive = False

        length = 0
        if not chunked and declared is not None:
            values = {v.strip() for v in declared.split(",")}
            value = next(iter(values))
            if len(values) != 1 or not (value.isascii() and value.isdigit()) or len(value) > 18:
                return _Refusal(400, "bad_content_length")
            length = int(value)
            if length > self.MAX_BODY_BYTES:
                return _Refusal(413, "body_too_large")
        if not chunked and length == 0:
            return None

        if request.version == "HTTP/1.1" and "100-continue" in headers.get("expect", "").lower():
            # curl waits a second for this before sending a large body.
            writer.write(b"HTTP/1.1 100 Continue\r\n\r\n")
            await writer.drain()

        try:
            if chunked:
                body_bytes, refusal = await self._read_chunked_body(reader)
                if refusal is not None:
                    return refusal
            else:
                # Allow time proportional to the size, within bounds: a fixed
                # 30 s dropped large uploads on slow links.
                body_bytes = await asyncio.wait_for(
                    reader.readexactly(length),
                    timeout=min(300, max(30, length / 32_768)),
                )
        except asyncio.TimeoutError:
            return _Refusal(408, "request_timeout")
        except asyncio.IncompleteReadError as exc:
            # The client hung up partway through. What arrived is kept so
            # the request is still recorded.
            body_bytes = exc.partial
            request.keep_alive = False

        # The decoded form feeds the text matching and the records, with
        # card data masked; the raw bytes are what gets captured as a file
        # or forwarded upstream. Decoding with replacement characters used
        # to be the only copy, which destroyed every binary upload.
        request.body_bytes = body_bytes
        request.body = redact_card_data(
            body_bytes[:BODY_TEXT_BYTES].decode("utf-8", errors="replace")
        )
        return None

    async def _read_chunked_body(
        self, reader: asyncio.StreamReader
    ) -> tuple[bytes, Optional[_Refusal]]:
        """Decode a chunked request body, within the same size limit as a
        body with a declared length.

        Chunked bodies were not decoded at all: the body stayed in the
        stream, where each chunk-size line was read as a request line, so
        the payload was never recorded and the client got a 400 per chunk.
        """
        malformed = _Refusal(400, "bad_chunked_body")
        loop = asyncio.get_running_loop()
        started = loop.time()
        body = bytearray()
        chunks = 0
        while True:
            # As for a declared length: time in proportion to the data.
            remaining = started + min(300, max(30, len(body) / 32_768)) - loop.time()
            if remaining <= 0:
                raise asyncio.TimeoutError
            size_line, overflow = await self._read_line(reader, remaining, MAX_CHUNK_LINE)
            token = size_line.split(b";", 1)[0].strip()
            if overflow or not token or len(token) > 8 or not _HEX_DIGITS.issuperset(token):
                return b"", malformed
            size = int(token, 16)
            if size == 0:
                # Trailer fields, if any, up to the blank line.
                for _ in range(MAX_TRAILER_LINES):
                    trailer, overflow = await self._read_line(
                        reader, remaining, self._profile.max_header_line
                    )
                    if overflow or not trailer.strip():
                        break
                return bytes(body), None
            chunks += 1
            if chunks > MAX_REQUEST_CHUNKS:
                return b"", malformed
            if len(body) + size > self.MAX_BODY_BYTES:
                return b"", _Refusal(413, "body_too_large")
            body += await asyncio.wait_for(reader.readexactly(size), timeout=remaining)
            terminator, _ = await self._read_line(reader, remaining, 2)
            if terminator.strip():
                return b"", malformed
            if chunks % 64 == 0:
                # Buffered chunks decode without ever waiting, so thousands
                # of tiny ones would hold the loop; let others run.
                await asyncio.sleep(0)

    # -- sessions -----------------------------------------------------------------

    def _identity(self, source_ip: str, headers: dict) -> tuple:
        """The client a request belongs to: address, user agent, cookie.

        The same identity the diversion table uses (honeypot/security/
        diversion.py), so a session and its diversion verdict agree on who the
        client is.
        """
        agent = (headers.get("user-agent") or "")[:512]
        token = request_token(headers, config.http_session_cookie)
        return (source_ip, agent, token)

    @staticmethod
    def _session_flow(flow: FlowMeter) -> FlowMeter:
        """A meter for a whole session, started by this connection."""
        session_flow = FlowMeter(flow.measured_at, now=flow.start)
        flow.join(session_flow)
        return session_flow

    async def _attach_session(self, identity, source_ip, source_port, flow: FlowMeter) -> str:
        """Reuse this client's open session, or start one. Returns its id."""
        if config.http_session_idle <= 0:
            return await session_manager.create_session(
                self.protocol, source_ip, source_port, flow=flow
            )
        async with self._web_lock:
            entry = self._web_sessions.get(identity)
            if entry is None:
                session_flow = self._session_flow(flow)
                session_id = await session_manager.create_session(
                    self.protocol, source_ip, source_port, flow=session_flow
                )
                entry = _WebSession(session_id=session_id, flow=session_flow)
                self._web_sessions[identity] = entry
            else:
                if entry.finalize is not None:
                    entry.finalize.cancel()
                    entry.finalize = None
                # A later connection's traffic belongs to the session too.
                # Its meter used to be closed and thrown away here, so the
                # session reported only its first connection.
                entry.flow.reopen()
                flow.join(entry.flow)
            entry.active += 1
            entry.last_seen = time.time()
            return entry.session_id

    async def _detach_session(self, identity, session_id: Optional[str] = None) -> None:
        """A connection for this client closed; end the session once idle."""
        if config.http_session_idle <= 0:
            # One session per connection: _attach_session never registered it
            # under the client's identity (two connections from one client
            # would collide there), so the connection ends its own session.
            # Looking it up by identity found nothing, and the session was
            # never ended or delivered.
            if session_id is not None:
                self._header_chars.pop(session_id, None)
                await session_manager.end_session(session_id)
            return
        async with self._web_lock:
            entry = self._web_sessions.get(identity)
            if entry is None:
                return
            entry.active -= 1
            entry.last_seen = time.time()
            if entry.active <= 0:
                # The flow ends here, with the last connection, not when the
                # idle window runs out: those seconds of waiting were being
                # reported as the flow's duration and its longest silence,
                # which is not traffic the client produced.
                entry.flow.close()
                if entry.finalize is None:
                    entry.finalize = asyncio.create_task(self._finalize_session(identity))

    async def _finalize_session(self, identity) -> None:
        try:
            await asyncio.sleep(config.http_session_idle)
        except asyncio.CancelledError:
            return
        async with self._web_lock:
            entry = self._web_sessions.get(identity)
            if entry is None or entry.active > 0:
                return
            if time.time() - entry.last_seen < config.http_session_idle:
                # Reattached and detached again in the meantime; the newer
                # finalize task owns it now.
                return
            self._web_sessions.pop(identity, None)
            session_id = entry.session_id
            self._header_chars.pop(session_id, None)
        await session_manager.end_session(session_id)

    async def _note_fingerprints(
        self, session_id: str, request: Optional[_Request], tls_prints: Optional[dict]
    ) -> None:
        """Put what identifies the client's software on the session.

        The first value seen for a key stays: a session's fingerprint is
        that of the connection and request that opened it.
        """
        session = await session_manager.get_session(session_id)
        if session is None:
            return
        prints = session.fingerprints
        for key in ("ja3", "ja4"):
            if tls_prints and tls_prints.get(key):
                prints.setdefault(key, tls_prints[key])
        if tls_prints and 0 < len(tls_prints.get("ja3_string", "")) <= 2048:
            # A ClientHello stuffed with thousands of ciphers has a JA3
            # string of tens of kilobytes; its hash says as much.
            prints.setdefault("ja3_string", tls_prints["ja3_string"])
        if request is not None and request.header_list:
            prints.setdefault("http_header_order", header_order(request.header_list))

    # -- records --------------------------------------------------------------------

    async def _record_refused_request(
        self, identity, session_id: str, request: _Request, refusal: _Refusal, reply: Reply
    ) -> None:
        """Record a request that was refused unread, in its client's session.

        One connection_refused event per reason and session, whose count
        goes up with each repeat, and a transcript entry for the first few:
        a client that sends a thousand oversized requests leaves one event
        saying so, not a thousand records. Connections refused before any
        request (admission, a failed handshake) are counted per source in
        honeypot/security/refusals.py instead.
        """
        entry = self._web_sessions.get(identity)
        known = entry.refusals.get(refusal.reason) if entry is not None else None
        if known is not None:
            known["count"] += 1
        else:
            await session_manager.record_network_event(session_id, "connection_refused", {
                "reason": refusal.reason, "count": 1, "status": refusal.status,
            })
            session = await session_manager.get_session(session_id)
            # Keep hold of the stored event, so a repeat can raise its count.
            for event in reversed(session.network_events[-8:] if session and entry else []):
                if event.get("event_type") == "connection_refused" and event.get("reason") == refusal.reason:
                    entry.refusals[refusal.reason] = event
                    break

        if entry is not None:
            entry.refused_requests += 1
            if entry.refused_requests > REFUSED_REQUESTS_PER_SESSION:
                return
        command = self._command_text(request)[:REFUSED_LINE_CHARS]
        agent = request.headers.get("user-agent")
        if agent:
            command += f"  [ua: {agent[:300]}]"
        output = f"{_status_line(reply, self._profile)}  [refused: {refusal.reason}]"
        await self._record_command(session_id, redact_card_data(command), output, request)

    @staticmethod
    def _command_text(request: _Request) -> str:
        if request.method and request.target:
            return f"{request.method} {request.target}"
        return request.line

    def _transcript_headers(self, request: _Request) -> dict:
        """The request's headers as the transcript keeps them: at most forty,
        in arrival order, each value cut to 512 characters.

        Three kinds of value are masked rather than stored. Authorization
        credentials go to the session's credentials list, which is
        restricted, not to the transcript, which is not. The application's
        own session cookie (HONEYPOT_HTTP_SESSION_COOKIE) belongs to a real
        visitor of the live site as often as to an attacker. Card numbers
        are masked as everywhere else.
        """
        kept: dict[str, str] = {}
        session_cookie = config.http_session_cookie
        for name, value in request.header_list:
            name = name[:TRANSCRIPT_HEADER_NAME_CHARS]
            if name not in kept and len(kept) >= TRANSCRIPT_HEADERS:
                continue
            if name in ("authorization", "proxy-authorization"):
                scheme = value.split(" ", 1)[0][:32]
                value = f"{scheme} ********" if " " in value else "********"
            elif name == "cookie" and session_cookie:
                value = "; ".join(
                    f"{session_cookie}=********"
                    if part.strip().startswith(f"{session_cookie}=") else part.strip()
                    for part in value.split(";")
                )
            if name in kept:
                value = f"{kept[name]}, {value}"
            kept[name] = redact_card_data(value)[:TRANSCRIPT_HEADER_VALUE_CHARS]
        return kept

    async def _record_command(
        self, session_id: str, command: str, output: str, request: Optional[_Request]
    ) -> None:
        """Add a transcript entry, with the request's headers beside it.

        Only the User-Agent was kept, inside the command text, so an attack
        carried in any other header was in no record at all.
        """
        entry = await session_manager.record_command(session_id, command, output=output)
        if entry is None or request is None:
            return
        headers = self._transcript_headers(request)
        if not headers:
            return
        size = sum(len(name) + len(value) for name, value in headers.items())
        used = self._header_chars.get(session_id, 0)
        if used + size > SESSION_HEADER_CHARS:
            session = await session_manager.get_session(session_id)
            if session is not None:
                session.truncated["headers"] = session.truncated.get("headers", 0) + 1
            return
        entry["headers"] = headers
        self._header_chars[session_id] = used + size

    async def _record_exchange(self, session_id: str, request: _Request, reply: Reply) -> None:
        """Put the request where the backend will see it.

        Requests were only kept as engine-side network events, which the
        ingest does not forward, so every HTTP session reached the dashboard
        with no paths, no payloads and no credentials — an empty row. They
        now go into the transcript (request line, user agent, body, and the
        headers beside them) with the status the decoy answered, and login
        attempts into the credentials, so tool detection, de-obfuscation and
        the NLP stage read them like shell commands.
        """
        command = self._command_text(request)
        headers = request.headers
        agent = headers.get("user-agent")
        if agent:
            command += f"  [ua: {agent[:300]}]"
        if request.body:
            command += "\n" + request.body[:TRANSCRIPT_BODY_CHARS]
        command = redact_card_data(command)
        output = _status_line(reply, self._profile)
        if reply.answered_by == "decoy":
            output += "  [answered by the decoy application]"
        await self._record_command(session_id, command, output, request)

        accepted = reply.status in (200, 302)
        for creds in (
            _basic_credentials(headers),
            _form_credentials(headers, request.body),
            _json_credentials(headers, request.body),
        ):
            if creds is not None:
                # Also where a planted login is recognised: the session
                # manager raises honeytoken_used for one.
                await session_manager.record_auth_attempt(
                    session_id, creds[0][:256], creds[1][:256], accepted
                )

    async def _observe_passively(self, session_id: str, reader: asyncio.StreamReader) -> None:
        """Passive mode: take the request, answer nothing.

        A client speaks first in HTTP, so the request is still there to be
        recorded; the connection is then closed without a byte of reply.
        """
        request = _Request()
        try:
            raw, overflow = await self._read_line(reader, 15, self.MAX_REQUEST_LINE)
            self._parse_request_line(request, raw.decode("utf-8", errors="replace").strip())
            if request.line and not overflow:
                # After a line that ran past the limit there is no telling
                # where the headers start, so none are waited for.
                await self._read_headers(reader, request)
        except (asyncio.TimeoutError, ConnectionError, ValueError):
            pass
        await session_manager.record_network_event(
            session_id, "passive_observation",
            {"protocol": self.protocol, "responded": False},
        )
        if request.line:
            await self._note_fingerprints(session_id, request, None)
            agent = request.headers.get("user-agent")
            command = redact_card_data(" ".join(request.line.split()[:2]))
            if agent:
                command += f"  [ua: {agent[:300]}]"
            await self._record_command(
                session_id, command, "(passive: no response sent)", request
            )

    # -- answering ------------------------------------------------------------------

    @staticmethod
    def _host(request: _Request) -> str:
        """The Host header, if it is one that can be printed in a page."""
        host = request.headers.get("host", "")
        return host if _HOST.fullmatch(host) else ""

    def _error(self, request: _Request, status: int) -> Reply:
        """The claimed server's own page for a status."""
        return self._profile.error(
            status, method=request.method, host=self._host(request),
            user_agent=request.headers.get("user-agent", ""),
        )

    async def _handle_request(
        self, session_id: str, request: _Request, source_ip: str
    ) -> Reply:
        profile = self._profile
        method = request.method
        path, _ = _split_target(request.target)
        agent = request.headers.get("user-agent", "")

        if len(request.body_bytes) >= OFFLOAD_BODY_BYTES:
            uploads = await asyncio.to_thread(
                extract_files, method.upper(), path, request.headers, request.body_bytes
            )
        else:
            uploads = extract_files(method.upper(), path, request.headers, request.body_bytes)
        for upload in uploads:
            await session_manager.record_file_upload(
                session_id,
                upload.filename,
                upload.content,
                remote_path=path,
                source=upload.source,
                methods=[upload.field] if upload.field else [],
            )

        await session_manager.record_network_event(
            session_id,
            "http_request",
            {
                "method": method[:32],
                "path": redact_card_data(request.target),
                "headers": self._transcript_headers(request),
                "body_preview": request.body[:500],
                "source_ip": source_ip,
            },
        )

        await adaptive_engine.profile_actor(session_id, source_ip, {
            "http_method": method[:32],
            "http_path": path,
        })

        # What a front-end server refuses before any application sees it.
        if request.malformed or not request.target:
            return self._error(request, 400)
        if request.version not in ("HTTP/1.1", "HTTP/1.0", "HTTP/0.9"):
            reply = self._error(request, 505 if profile.family == "nginx" else 400)
            reply.close = True
            return reply
        if request.version == "HTTP/1.1" and "host" not in request.headers:
            return self._error(request, 400)
        if request.headers.get("host") and not self._host(request):
            return self._error(request, 400)

        attack = await self._inspect(session_id, request, path, source_ip)

        followed = ai_canary.match(path) if ai_canary.enabled() else None
        if followed is not None:
            # A file no page links to and no wordlist contains, named only
            # in a sentence addressed to automated assistants.
            await self._canary_triggered(
                session_id, followed, f"{method[:16]} {path}; user agent {agent[:120]}"
            )
            return self._serve_file(request, path, ai_canary.document(followed).encode())

        bait_path = self._is_bait(path)
        if self._decoy_upstream and bait_path:
            # Answered by the decoy's own bait page below; everything after
            # it goes to the decoy application.
            if path not in HARMLESS_BAIT:
                await self._divert(session_id, source_ip, request.headers, path, f"requested bait path {path}")
            elif attack is not None:
                await self._divert(session_id, source_ip, request.headers, path, self._attack_reason(attack))

        if self._upstream and not bait_path:
            if not self._decoy_upstream:
                return await self._forward(self._upstream, request, source_ip)
            return await self._serve_diverting(session_id, request, path, source_ip, attack)

        return await self._decoy_reply(session_id, request, path, source_ip)

    async def _canary_triggered(self, session_id: str, kind: str, summary: str) -> None:
        session = await session_manager.get_session(session_id)
        if session is None:
            return
        seen = session.metadata.setdefault("ai_canaries", [])
        if kind in seen:
            return
        seen.append(kind)
        logger.info("AI-agent canary (%s) followed in session %s", kind, session_id)
        await session_manager.record_network_event(
            session_id, "ai_canary_triggered", ai_canary.event(kind, redact_card_data(summary))
        )

    async def _inspect(
        self, session_id: str, request: _Request, path: str, source_ip: str
    ) -> Optional[tuple[str, str]]:
        """Record the probe patterns a request carries: ``(type, where)`` of
        the first, or None.

        The target is matched raw and decoded both, since the patterns
        include encoded forms (union+select) and decoded ones (<script>).
        Headers are looked at as well as the target and the body: a JNDI
        lookup in User-Agent or a shell function in Referer never appeared in
        any record, because only the User-Agent was kept and nothing read it.
        """
        found: Optional[tuple[str, str]] = None

        target_type = _first_indicator(
            f"{request.target}\n{unquote_plus(request.target)}", PATH_ATTACK_INDICATORS
        )
        if target_type:
            await self._record_attack(session_id, source_ip, target_type, {
                "path": redact_card_data(request.target)[:500],
                "source_ip": source_ip,
            })
            found = (target_type, "request")

        if request.body_bytes:
            if len(request.body_bytes) >= OFFLOAD_BODY_BYTES:
                body_type = await asyncio.to_thread(_body_indicator, request.body_bytes)
            else:
                body_type = _body_indicator(request.body_bytes)
            if body_type:
                await self._record_attack(session_id, source_ip, body_type, {
                    "path": redact_card_data(path)[:500],
                    "body_preview": request.body[:200],
                })
                found = found or (body_type, "request")

        header_hit = header_attack(request.header_list)
        if header_hit:
            header_type, name = header_hit
            name = name[:TRANSCRIPT_HEADER_NAME_CHARS]
            await self._record_attack(session_id, source_ip, header_type, {
                "path": redact_card_data(path)[:500],
                "header": name,
                "value_preview": redact_card_data(request.headers.get(name, ""))[:200],
            })
            found = found or (header_type, f"{name} header")
        return found

    async def _record_attack(self, session_id: str, source_ip: str, attack_type: str, details: dict) -> None:
        await session_manager.record_network_event(
            session_id, "attack_detected", {"type": attack_type, **details}
        )
        await adaptive_engine.profile_actor(session_id, source_ip, {"attack_type": attack_type})

    @staticmethod
    def _attack_reason(attack: tuple[str, str]) -> str:
        attack_type, where = attack
        return f"{attack_type} in the {where}"

    # -- the decoy's own site ---------------------------------------------------------

    def _bait_file(self, path: str) -> bytes:
        """The contents of a bait file, for this deployment.

        The secrets are the planted ones (honeypot/core/honeytokens.py), the
        same in every file here and in the shell decoys' copies, so they
        agree the way one machine's files do and any of them being used is
        recognised.
        """
        tokens = get_honeytokens()
        if path == "/robots.txt":
            text = "User-agent: *\nDisallow: /admin/\nDisallow: /config/\nDisallow: /backup/\n"
            if ai_canary.enabled():
                text += ai_canary.robots_note()
        elif path == "/sitemap.xml":
            text = (
                '<?xml version="1.0" encoding="UTF-8"?>\n'
                '<urlset xmlns="http://www.sitemaps.org/schemas/sitemap/0.9">\n'
                "<url><loc>http://localhost/</loc></url>\n</urlset>\n"
            )
        elif path == "/.env":
            text = env_file_text()
        elif path == "/config.php":
            text = (
                "<?php\n"
                "$db_host = 'localhost';\n"
                f"$db_user = '{tokens.db_user}';\n"
                f"$db_pass = '{tokens.db_password}';\n"
                f"$db_name = '{tokens.db_name}';\n"
                "?>\n"
            )
        else:
            text = (
                "<?php\n"
                f"define('DB_NAME', '{tokens.db_name}');\n"
                f"define('DB_USER', '{tokens.db_user}');\n"
                f"define('DB_PASSWORD', '{tokens.db_password}');\n"
                "define('DB_HOST', 'localhost');\n"
                "?>\n"
            )
        return text.encode()

    def _resolve(self, path: str):
        """What the decoy has at a path: ``("file", name, bytes)``,
        ``("script", endpoint)`` or None.

        A file is served the way the claimed server serves any file. A
        script is an application's page, which sees every method.
        """
        index_name, index_page = self._profile.root_page()
        if path in ("/", "/index.html") or path == f"/{index_name}":
            return "file", index_name, index_page

        # Trailing-slash variants of the listed paths resolve to the same
        # place; robots.txt advertises /admin/, and a 404 there contradicts it.
        if path.endswith("/"):
            trimmed = path.rstrip("/")
            if trimmed in self._vulnerable_endpoints or trimmed in self._fake_files:
                path = trimmed

        endpoint = self._vulnerable_endpoints.get(path)
        if path in self._fake_files or endpoint in ("env_file", "config_file"):
            return "file", path, self._bait_file(path)
        if endpoint is not None:
            return "script", endpoint
        # Where the decoy's own login forms post to.
        if path == "/admin/login":
            return "script", "admin_panel"
        if path == "/phpmyadmin/index.php":
            return "script", "phpmyadmin"
        if path.startswith(("/wp-content/", "/wp-includes/")):
            return "file", "wp-asset.html", b"<!-- WordPress asset placeholder -->\n"
        return None

    def _serve_file(self, request: _Request, name: str, content: bytes) -> Reply:
        """A static file, by the claimed server's rules for each method."""
        profile = self._profile
        if request.method in ("GET", "HEAD"):
            # HEAD is the same reply without its body (see _send). It used
            # to be a bare 200 with a length of zero for every path.
            reply = profile.static(name, content)
            return profile.not_modified(reply, request.headers) or reply
        if request.method == "OPTIONS" and profile.family == "apache":
            return self._apache_options(profile.content_type(name))
        # Neither server lets a file be posted to, put or deleted.
        return self._error(request, 405)

    def _apache_options(self, content_type: Optional[str] = None) -> Reply:
        """Apache's default handler answering OPTIONS: its Allow list, no body."""
        return Reply(
            200, b"", content_type=content_type,
            headers=[("Allow", self._profile.allow())], kind="error",
        )

    def _nothing_here(self, request: _Request) -> Reply:
        """The claimed server's answer for a path that does not exist.

        This is where any POST, PUT or DELETE used to be told it had
        succeeded. Apache finds no file for GET and POST (404), lists what
        its handler supports for OPTIONS, and refuses the methods it has no
        handler for (405, with Allow). nginx's packaged site checks that the
        file exists before anything else, so every method gets its 404,
        except TRACE, which it refuses outright; its 405 carries no Allow.
        """
        method = request.method
        if self._profile.family == "apache":
            if method in ("GET", "HEAD", "POST"):
                return self._error(request, 404)
            if method == "OPTIONS":
                return self._apache_options()
            return self._error(request, 405)
        return self._error(request, 405 if method == "TRACE" else 404)

    async def _decoy_reply(
        self, session_id: str, request: _Request, path: str, source_ip: str
    ) -> Reply:
        method = request.method
        if method not in KNOWN_METHODS:
            # Not a method either server has heard of. Apache says it is not
            # implemented; nginx refuses it, or calls it a bad request if it
            # is not even upper-case letters.
            if self._profile.family == "apache":
                return self._error(request, 501)
            return self._error(request, 405 if method.isalpha() and method.isupper() else 400)

        resource = self._resolve(path)
        if resource is None:
            return self._nothing_here(request)
        if resource[0] == "file":
            return self._serve_file(request, resource[1], resource[2])

        endpoint = resource[1]
        if method == "POST":
            return await self._handle_post(session_id, request, path, endpoint, source_ip)
        if method == "PUT":
            await session_manager.record_network_event(
                session_id, "http_put", {"path": path[:500], "body_preview": request.body[:500]}
            )
        elif method == "DELETE":
            await session_manager.record_network_event(
                session_id, "http_delete", {"path": path[:500]}
            )
        # A script runs whatever the method and, unless it looks, prints the
        # same page.
        return self._page(endpoint)

    async def _handle_post(
        self, session_id: str, request: _Request, path: str, endpoint: str, source_ip: str
    ) -> Reply:
        body = request.body
        await session_manager.record_network_event(
            session_id, "http_post", {
                "path": path[:500],
                "body": body[:1000],
                "content_type": request.headers.get("content-type", "")[:200],
            }
        )

        login_targets = {
            "login_form": "/admin/",
            "admin_panel": "/admin/",
            "wordpress_login": "/wp-admin/",
            "wordpress_admin": "/wp-admin/",
            "phpmyadmin": "/phpmyadmin/",
        }
        if endpoint in login_targets:
            creds = _form_credentials(request.headers, body) or _json_credentials(request.headers, body)
            username = creds[0] if creds else ""
            # A session id of the claimed stack's own shape, new for every
            # login. It was "session=abc123" on every deployment, and the
            # redirect went to a page that did not exist.
            cookie = f"{bait.session_cookie_name()}={bait.new_session_id(source_ip, username)}; path=/"
            return Reply(
                302, b"", content_type="text/html; charset=UTF-8",
                headers=[("Set-Cookie", cookie), ("Location", login_targets[endpoint])],
            )

        if endpoint == "upload_form":
            return Reply(
                200,
                b'{"status": "success", "message": "File uploaded", "path": "/uploads/file"}\n',
                content_type="application/json",
            )

        if endpoint in ("web_shell", "command_endpoint", "eval_endpoint"):
            await session_manager.record_network_event(
                session_id, "command_execution_attempt", {
                    "path": path[:500],
                    "body": body[:TRANSCRIPT_BODY_CHARS],
                }
            )
            # The machine every other decoy on this host describes. This
            # line used to read "Linux honeypot 5.15.0-91-generic".
            output = f"uid=33(www-data) gid=33(www-data) groups=33(www-data)\n{bait.uname_line()}\n"
            return Reply(200, output.encode(), content_type="text/plain; charset=UTF-8")

        return self._page(endpoint)

    def _page(self, endpoint: str) -> Reply:
        """The page a bait application shows."""
        html_type = "text/html; charset=UTF-8"

        if endpoint in _JSON_PAGES or endpoint in ("spring_env", "tomcat_manager", "console_panel"):
            # Applications of other stacks behind the same server: no PHP
            # header on these, and JSON is labelled as JSON.
            if endpoint == "tomcat_manager":
                text, content_type = (
                    '<!DOCTYPE html><html><head><title>Apache Tomcat Manager</title></head><body>'
                    '<h1>Tomcat Manager Application</h1>'
                    '<form method="get" action="/manager/html">'
                    '<input type="submit" value="Login to Manager">'
                    "</form></body></html>\n"
                ), html_type
            elif endpoint == "console_panel":
                text, content_type = (
                    '<!DOCTYPE html><html><head><title>Console</title></head><body>'
                    '<h1>Spring Boot Admin Console</h1>'
                    '<p>Application is running.</p>'
                    "</body></html>\n"
                ), html_type
            elif endpoint == "spring_env":
                tokens = get_honeytokens()
                text, content_type = json.dumps({"propertySources": [{
                    "name": "applicationConfig",
                    "properties": {
                        "spring.datasource.url": {"value": f"jdbc:mysql://localhost:3306/{tokens.db_name}"},
                        "spring.datasource.username": {"value": tokens.db_user},
                        "spring.datasource.password": {"value": tokens.db_password},
                    },
                }]}) + "\n", "application/json"
            else:
                text, content_type = _JSON_PAGES[endpoint], "application/json"
            return Reply(200, text.encode(), content_type=content_type, kind="application")

        # Login pages carry the comment for automated agents; see ai_canary.py.
        note = ai_canary.html_comment() if ai_canary.enabled() else ""
        if endpoint == "admin_panel":
            body = (
                '<!DOCTYPE html><html><head><title>Admin Panel</title></head><body>'
                '<h1>Administration Panel</h1>'
                '<form method="POST" action="/admin/login">'
                '<label>Username:</label><br>'
                '<input type="text" name="username"><br>'
                '<label>Password:</label><br>'
                '<input type="password" name="password"><br><br>'
                '<input type="submit" value="Login">'
                f"</form>{note}</body></html>\n"
            )
        elif endpoint == "login_form":
            body = (
                '<!DOCTYPE html><html><head><title>Login</title></head><body>'
                '<h1>Login</h1>'
                '<form method="POST" action="/login">'
                '<input type="text" name="username" placeholder="Username"><br>'
                '<input type="password" name="password" placeholder="Password"><br>'
                '<input type="submit" value="Sign In">'
                f"</form>{note}</body></html>\n"
            )
        elif endpoint in ("wordpress_admin", "wordpress_login"):
            body = (
                '<!DOCTYPE html><html><head><title>WordPress &rsaquo; Log In</title></head><body>'
                '<div id="login"><h1><a href="https://wordpress.org/">Powered by WordPress</a></h1>'
                '<form name="loginform" id="loginform" action="/wp-login.php" method="post">'
                '<p><label>Username or Email Address<br>'
                '<input type="text" name="log" id="user_login" class="input"></label></p>'
                '<p><label>Password<br>'
                '<input type="password" name="pwd" id="user_pass" class="input"></label></p>'
                '<p class="submit"><input type="submit" name="wp-submit" value="Log In"></p>'
                f"</form></div>{note}</body></html>\n"
            )
        elif endpoint == "phpmyadmin":
            body = (
                '<!DOCTYPE html><html><head><title>phpMyAdmin</title></head><body>'
                '<h1>phpMyAdmin</h1>'
                '<form method="post" action="/phpmyadmin/index.php">'
                '<label>Username: <input type="text" name="pma_username"></label><br>'
                '<label>Password: <input type="password" name="pma_password"></label><br>'
                '<input type="submit" value="Go">'
                f"</form>{note}</body></html>\n"
            )
        elif endpoint == "upload_form":
            body = (
                '<!DOCTYPE html><html><head><title>Upload</title></head><body>'
                '<h1>File Upload</h1>'
                '<form method="POST" action="/upload" enctype="multipart/form-data">'
                '<input type="file" name="file"><br>'
                '<input type="submit" value="Upload">'
                "</form></body></html>\n"
            )
        elif endpoint == "web_shell":
            body = (
                '<!DOCTYPE html><html><head><title>Shell</title></head><body>'
                '<h1>Web Shell</h1>'
                '<form method="POST" action="/shell">'
                '<input type="text" name="cmd" placeholder="Command">'
                '<input type="submit" value="Execute">'
                "</form></body></html>\n"
            )
        elif endpoint == "debug_panel":
            # The versions the rest of this host reports, not fixed ones.
            identity = get_identity()
            lines = [f"Server: {identity.http_server}"]
            if identity.php_version:
                lines.insert(0, f"PHP Version: {identity.php_version.split('/', 1)[-1]}")
            lines += ["Document Root: /var/www/html", "Debug Mode: ENABLED"]
            body = (
                '<!DOCTYPE html><html><head><title>Debug</title></head><body>'
                '<h1>Debug Panel</h1>'
                f"<pre>{chr(10).join(lines)}</pre>"
                "</body></html>\n"
            )
        else:
            body = "<html><body>OK</body></html>\n"
        return Reply(200, body.encode(), content_type=html_type)

    # -- applications behind the decoy -------------------------------------------------

    async def _serve_diverting(
        self,
        session_id: str,
        request: _Request,
        path: str,
        source_ip: str,
        attack: Optional[tuple[str, str]],
    ) -> Reply:
        """Have the live or the decoy application answer, by what the client
        has done so far (see honeypot/security/diversion.py)."""
        headers = request.headers
        agent = headers.get("user-agent", "")
        token = request_token(headers, config.http_session_cookie)
        mark = diversion_table.lookup(source_ip, agent, token)
        if mark is None:
            tool = scanner_agent(agent)
            if attack:
                mark = await self._divert(session_id, source_ip, headers, path, self._attack_reason(attack))
            elif tool:
                mark = await self._divert(session_id, source_ip, headers, path, f"attack tool user agent ({tool})")
        else:
            await self._note_diversion(session_id, mark, path)

        if mark is not None:
            reply = await self._forward(self._decoy_upstream, request, source_ip)
            reply.answered_by = "decoy"
            if reply.kind == "proxied":
                # The sessions the decoy application just issued stay diverted.
                head = "\r\n".join(
                    ["HTTP/1.1 200 OK"]
                    + [f"Set-Cookie: {value}" for name, value in reply.headers if name.lower() == "set-cookie"]
                ) + "\r\n\r\n"
                diversion_table.adopt(
                    issued_tokens(head.encode("latin-1", errors="replace"), config.http_session_cookie),
                    mark,
                )
            return reply

        reply = await self._forward(self._upstream, request, source_ip)
        limit = diversion_table.failed_login_limit
        if limit and reply.status in (401, 403) and (
            _basic_credentials(headers)
            or _form_credentials(headers, request.body)
            or _json_credentials(headers, request.body)
        ):
            failures = diversion_table.failed_login(source_ip, agent)
            if failures >= limit:
                # This answer was the live application's; the next one won't be.
                await self._divert(
                    session_id, source_ip, headers, path,
                    f"{failures} failed logins in {FAILED_LOGIN_WINDOW // 60} minutes",
                )
        return reply

    async def _divert(
        self, session_id: str, source_ip: str, headers: dict, path: str, reason: str
    ) -> Mark:
        """Send this client to the decoy application from now on."""
        agent = headers.get("user-agent", "")
        token = request_token(headers, config.http_session_cookie)
        mark = diversion_table.lookup(source_ip, agent, token)
        if mark is None:
            mark = diversion_table.divert(source_ip, agent, token, reason)
            logger.info(f"HTTP client {source_ip} diverted to the decoy application: {reason}")
        await self._note_diversion(session_id, mark, path)
        return mark

    async def _note_diversion(self, session_id: str, mark: Mark, path: str) -> None:
        """Record, once per session, that the decoy application answered it
        and why the client was diverted."""
        session = await session_manager.get_session(session_id)
        if session is None or session.metadata.get("diverted"):
            return
        session.metadata["diverted"] = True
        await session_manager.record_network_event(session_id, "http_diversion", {
            "reason": mark.reason,
            "path": redact_card_data(path),
            "since": mark.since,
        })

    def _is_bait(self, path: str) -> bool:
        return path in self._bait_paths or path.startswith(("/wp-content/", "/wp-includes/"))

    async def _forward(
        self, upstream: tuple[str, int], request: _Request, source_ip: str
    ) -> Reply:
        """Have an upstream application answer, and relay its response.

        One upstream connection per request (Connection: close), so nothing an
        attacker sends can be smuggled into another client's exchange. The
        client's connection is kept alive unless it asked otherwise: a browser
        loads a page over a few connections instead of one per asset, which
        keeps a real visit under the per-address rate limit.

        The answer goes back as the claimed server would relay it, in the
        same header order as the decoy's own pages (http_profile.py): an
        application's pages and the bait pages beside them would otherwise
        be told apart by which headers came first.
        """
        host, port = upstream
        method, headers, body = request.method, request.headers, request.body_bytes
        lines = [f"{method} {request.target} HTTP/1.1"]
        for name, value in headers.items():
            if name in HOP_BY_HOP or name in ("content-length", "x-forwarded-for", "x-forwarded-proto"):
                continue
            if not _HEADER_NAME.fullmatch(name):
                # Not a header name; passing it on would let the client
                # write lines of the upstream request.
                continue
            lines.append(f"{name}: {value}")
        lines += [
            f"X-Forwarded-For: {source_ip}",
            f"X-Forwarded-Proto: {'https' if self.use_tls else 'http'}",
            "Connection: close",
        ]
        if body or method in ("POST", "PUT", "PATCH"):
            lines.append(f"Content-Length: {len(body)}")
        upstream_request = ("\r\n".join(lines) + "\r\n\r\n").encode("utf-8") + body

        loop = asyncio.get_running_loop()
        started = loop.time()
        try:
            reader, writer = await asyncio.wait_for(asyncio.open_connection(host, port), timeout=5)
        except (OSError, asyncio.TimeoutError) as exc:
            logger.warning(f"HTTP upstream {host}:{port} unreachable: {exc}")
            return self._bad_gateway(request, unreachable=True)
        try:
            writer.write(upstream_request)
            await writer.drain()
            status = await asyncio.wait_for(reader.readline(), timeout=30)
            status_parts = status.decode("latin-1").split(None, 2)
            if not status.startswith(b"HTTP/1.") or len(status_parts) < 2 or not status_parts[1].isdigit():
                return self._bad_gateway(request)
            code = int(status_parts[1])
            response_headers: list[tuple[str, str]] = []
            while len(response_headers) < 200:
                line = await asyncio.wait_for(reader.readline(), timeout=30)
                if line in (b"\r\n", b"\n", b""):
                    break
                name, _, value = line.decode("latin-1").partition(":")
                response_headers.append((name.strip(), value.strip()))
            found = {name.lower(): value for name, value in response_headers}
            bodiless = method == "HEAD" or code in (204, 304) or 100 <= code < 200
            if bodiless:
                payload = b""
            elif "chunked" in found.get("transfer-encoding", "").lower():
                payload = await self._read_chunked(reader)
            elif "content-length" in found:
                length = int(found["content-length"])
                if length > MAX_UPSTREAM_RESPONSE_BYTES:
                    return self._bad_gateway(request)
                payload = await asyncio.wait_for(reader.readexactly(length), timeout=60)
            else:
                payload = await asyncio.wait_for(self._read_to_end(reader), timeout=60)
        except (OSError, ValueError, asyncio.TimeoutError, asyncio.IncompleteReadError) as exc:
            logger.warning(f"HTTP upstream {host}:{port} failed: {exc}")
            return self._bad_gateway(request)
        finally:
            writer.close()
        # How long an answer from the application takes, for the bait pages
        # to match (see _decoy_delay).
        self._upstream_latency.append(loop.time() - started)

        if upstream is self._upstream and self._may_plant_canary(code, found, payload):
            cut = payload.rfind(b"</body>")
            payload = payload[:cut] + ai_canary.html_comment().encode() + b"\n" + payload[cut:]

        relayed: list[tuple[str, str]] = []
        length_placed = False
        for name, value in response_headers:
            lowered = name.lower()
            if lowered in HOP_BY_HOP:
                continue
            if lowered == "content-length":
                # The upstream's own figure for a HEAD (there is no body to
                # count); otherwise what is actually being sent, since a
                # chunked body arrives here whole.
                relayed.append((name, value if bodiless else str(len(payload))))
                length_placed = True
                continue
            relayed.append((name, value))
        if not length_placed and not bodiless:
            relayed.append(("Content-Length", str(len(payload))))

        reason = status_parts[2].strip() if len(status_parts) > 2 else ""
        return Reply(
            code, payload, headers=relayed, kind="proxied",
            reason=reason or self._profile.reason(code),
        )

    @staticmethod
    def _may_plant_canary(code: int, found: dict, payload: bytes) -> bool:
        """Whether the agent canary comment can go into an upstream page.

        Off unless HONEYPOT_HTTP_AI_CANARY_UPSTREAM is set, and then only
        for a complete, uncompressed HTML page: anything else (a fragment, a
        compressed body, JSON) cannot be changed without risking the
        application.
        """
        if not (config.http_ai_canary_upstream and ai_canary.enabled()):
            return False
        if code != 200 or found.get("content-encoding"):
            return False
        if not found.get("content-type", "").lower().startswith("text/html"):
            return False
        return b"</body>" in payload[-4096:]

    async def _read_chunked(self, reader: asyncio.StreamReader) -> bytes:
        payload = bytearray()
        while True:
            size_line = await asyncio.wait_for(reader.readline(), timeout=30)
            size = int(size_line.split(b";", 1)[0].strip() or b"0", 16)
            if size == 0:
                while (await asyncio.wait_for(reader.readline(), timeout=30)) not in (b"\r\n", b"\n", b""):
                    pass
                return bytes(payload)
            if size < 0 or len(payload) + size > MAX_UPSTREAM_RESPONSE_BYTES:
                raise ValueError("upstream response too large")
            payload += await asyncio.wait_for(reader.readexactly(size), timeout=60)
            await reader.readline()

    async def _read_to_end(self, reader: asyncio.StreamReader) -> bytes:
        payload = bytearray()
        while chunk := await reader.read(65536):
            payload += chunk
            if len(payload) > MAX_UPSTREAM_RESPONSE_BYTES:
                raise ValueError("upstream response too large")
        return bytes(payload)

    def _bad_gateway(self, request: _Request, unreachable: bool = False) -> Reply:
        """The claimed server's page for an application that did not answer.

        With nothing listening, nginx reports a bad gateway and Apache's
        proxy reports the service unavailable; an answer that could not be
        read is a bad gateway to both.
        """
        apache = self._profile.family == "apache"
        reply = self._error(request, 503 if unreachable and apache else 502)
        # The application's absence is not the client's connection's fault.
        reply.close = False
        return reply
