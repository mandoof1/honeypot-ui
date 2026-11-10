"""HTTP probes: a dozen requests, each compared part by part.

For every request the status line, the header names in the order sent, the
``Server`` header, the remaining header values and the body are separate
checks, so one result says which layer gave the decoy away. Requests are
written out as bytes and identical for both targets, down to the Host
header, because web servers echo it in their error pages.
"""

from __future__ import annotations

import statistics
import time
from dataclasses import dataclass
from typing import Optional

from . import httpwire
from .checks import Check, escape_bytes
from .net import Connection, seconds
from .probe import Prober

#: Sent as Host to both targets. No port, so a server names its own.
HOST = "localhost"
MISSING_PATH = "/fpaudit-no-such-page"

_COMMON_HEADERS = (
    f"Host: {HOST}\r\n"
    "User-Agent: fingerprint-audit\r\n"
    "Accept: */*\r\n"
)


def _request(method: str, path: str, version: str = "HTTP/1.1", extra: str = "") -> bytes:
    return f"{method} {path} {version}\r\n{_COMMON_HEADERS}{extra}\r\n".encode("latin-1")


@dataclass(frozen=True)
class Probe:
    name: str
    description: str
    request: bytes
    head: bool = False


PROBES = (
    Probe("get_root", "GET /", _request("GET", "/")),
    Probe("get_missing", "GET of a path that does not exist", _request("GET", MISSING_PATH)),
    Probe("head_root", "HEAD /", _request("HEAD", "/"), head=True),
    Probe("options_root", "OPTIONS /", _request("OPTIONS", "/")),
    Probe("post_root", "POST / with an empty body", _request("POST", "/", extra="Content-Length: 0\r\n")),
    Probe("delete_root", "DELETE /", _request("DELETE", "/")),
    Probe("unknown_method", "a method that does not exist (FPAUDIT /)", _request("FPAUDIT", "/")),
    Probe("malformed_request_line", "a request line of one word", b"NOT-A-REQUEST\r\n\r\n"),
    Probe("http09_request", "a request line with no protocol version (GET /)", b"GET /\r\n\r\n"),
    Probe("no_host_http11", "HTTP/1.1 GET / with no Host header", b"GET / HTTP/1.1\r\n\r\n"),
    Probe("uri_9000", "GET of a 9000-byte URI", _request("GET", "/" + "A" * 8999)),
    Probe("uri_70000", "GET of a 70000-byte URI", _request("GET", "/" + "A" * 69999)),
    Probe("http10_no_headers", "HTTP/1.0 GET / with no headers at all", b"GET / HTTP/1.0\r\n\r\n"),
    Probe(
        "connection_close",
        "GET / asking for Connection: close",
        _request("GET", "/", extra="Connection: close\r\n"),
    ),
)


def _read_response(conn: Connection, head: bool, timeout: float, quiet: float) -> bytes:
    """One response off the socket.

    Stops as soon as the response is complete by its own framing. A response
    with no framing is read to end of stream, giving up once the server has
    been silent for ``quiet`` seconds without closing.
    """
    data = b""
    deadline = time.monotonic() + timeout
    while not httpwire.is_complete(data, head):
        remaining = deadline - time.monotonic()
        if remaining <= 0:
            break
        # Before any byte, allow the full timeout; after that, a framed
        # response keeps arriving promptly or it is not going to.
        chunk = conn.receive(remaining if not data else min(remaining, quiet))
        if not chunk:
            break
        data += chunk
    return data


def _exchange_checks(prober: Prober, probe: Probe) -> tuple[list[Check], Optional[float]]:
    settings = prober.settings
    with prober.connect() as conn:
        sent_at = time.monotonic()
        conn.send(probe.request)
        raw = _read_response(conn, probe.head, settings.timeout, settings.quiet)
        latency = (
            conn.opened_at + conn.first_byte_after - sent_at
            if conn.first_byte_after is not None
            else None
        )
        conn.wait_closed(settings.quiet)
        closed = conn.closed is not None
        close_evidence = {"closed": conn.closed, "closed_after_seconds": seconds(conn.closed_after)}
    prober.keep_raw(f"http.{probe.name}", raw)

    response = httpwire.parse(raw, probe.head)
    head_end = raw.find(httpwire.HEAD_END)
    request_text = escape_bytes(probe.request[:200]) + ("..." if len(probe.request) > 200 else "")
    evidence = {
        "request": request_text,
        "request_length": len(probe.request),
        "response_head": escape_bytes(raw[:head_end + 4] if head_end >= 0 else raw[:400]),
        "seconds_to_first_byte": seconds(latency),
    }
    prefix = f"http.{probe.name}"
    what = probe.description
    checks = [
        Check(f"{prefix}.status_line", f"status line for {what}", "exact", response.status_line, evidence),
        Check(
            f"{prefix}.header_names",
            f"header names, in the order sent, for {what}",
            "ordered",
            response.header_names,
        ),
        Check(f"{prefix}.server", f"Server header for {what}", "exact", response.header("Server")),
        Check(
            f"{prefix}.header_values",
            f"other header values for {what} (dates and entity tags reduced to their format)",
            "exact",
            httpwire.stable_header_values(response),
        ),
        Check(f"{prefix}.body", f"body for {what}", "bytes", response.body),
        Check(
            f"{prefix}.closes",
            f"whether the server closes the connection after answering {what}",
            "exact",
            closed,
            close_evidence,
        ),
    ]
    return checks, latency


def keep_alive(prober: Prober) -> list[Check]:
    """Two requests on one connection, neither asking to close: is the
    second one answered?"""
    settings = prober.settings
    request = _request("GET", MISSING_PATH)
    with prober.connect() as conn:
        conn.send(request)
        first = _read_response(conn, False, settings.timeout, settings.quiet)
        second = b""
        if conn.send(request):
            second = _read_response(conn, False, settings.timeout, settings.quiet)
    first_response = httpwire.parse(first)
    second_response = httpwire.parse(second)
    return [
        Check(
            "http.keep_alive.second_request_answered",
            "whether a second request on the same connection is answered",
            "exact",
            second_response.status_line is not None,
            {
                "first_connection_header": first_response.header("Connection"),
                "second_status_line": second_response.status_line,
            },
        ),
        Check(
            "http.keep_alive.connection_header",
            "Connection header on a response to a request that did not ask to close",
            "exact",
            first_response.header("Connection"),
        ),
    ]


def collect(prober: Prober) -> list[Check]:
    checks: list[Check] = []
    latencies: list[float] = []
    for probe in PROBES:

        def run(inner: Prober, probe: Probe = probe) -> list[Check]:
            produced, latency = _exchange_checks(inner, probe)
            if latency is not None:
                latencies.append(latency)
            return produced

        checks += prober.run(f"http.{probe.name}", run)
    checks += prober.run("http.keep_alive", keep_alive)
    checks.append(
        Check(
            "http.response_latency",
            "median seconds from sending a request to the first byte of its response",
            "timing",
            seconds(statistics.median(latencies)) if latencies else None,
            {
                "samples": len(latencies),
                "min": seconds(min(latencies)) if latencies else None,
                "max": seconds(max(latencies)) if latencies else None,
            },
        )
    )
    return checks
