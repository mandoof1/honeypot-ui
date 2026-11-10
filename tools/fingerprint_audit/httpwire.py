"""HTTP/1.x responses as raw bytes.

An HTTP library would hide exactly what this audit looks at: the order and
spelling of the header names, the reason phrase, whether a response had a
header block at all. So responses are read off the socket and split here.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from typing import Optional

HEAD_END = b"\r\n\r\n"

#: Status codes whose responses never carry a body (RFC 7230, 3.3.3).
_BODILESS = re.compile(rb"^HTTP/\d\.\d (1\d\d|204|304)\b")

#: IMF-fixdate, the only date format a server should generate (RFC 7231,
#: 7.1.1.1): "Sun, 06 Nov 1994 08:49:37 GMT".
_HTTP_DATE = re.compile(
    r"^(Mon|Tue|Wed|Thu|Fri|Sat|Sun), \d{2} "
    r"(Jan|Feb|Mar|Apr|May|Jun|Jul|Aug|Sep|Oct|Nov|Dec) \d{4} "
    r"\d{2}:\d{2}:\d{2} GMT$"
)
_ETAG = re.compile(r'^(W/)?"[^"]*"$')

#: Headers whose value changes with the clock or the file on disk rather
#: than with the server software. Their presence and position are compared
#: (header order); their values are reduced to a format tag.
DATE_HEADERS = ("date", "last-modified", "expires")


@dataclass
class Response:
    """A response split into its parts. ``status_line`` is None when the
    server sent bytes that do not begin with an HTTP status line (an
    HTTP/0.9-style bare body, or nothing)."""

    raw: bytes
    status_line: Optional[str] = None
    headers: list[tuple[str, str]] = field(default_factory=list)
    body: bytes = b""

    def header(self, name: str) -> Optional[str]:
        wanted = name.lower()
        for key, value in self.headers:
            if key.lower() == wanted:
                return value
        return None

    @property
    def header_names(self) -> list[str]:
        return [name for name, _ in self.headers]


def has_status_line(data: bytes) -> bool:
    return data.startswith(b"HTTP/")


def _split_head(data: bytes) -> Optional[tuple[bytes, bytes]]:
    end = data.find(HEAD_END)
    if end < 0:
        return None
    return data[:end], data[end + len(HEAD_END):]


def _header_lines(head: bytes) -> list[tuple[str, str]]:
    headers = []
    for line in head.split(b"\r\n")[1:]:
        name, separator, value = line.decode("latin-1").partition(":")
        if separator:
            headers.append((name, value.strip()))
    return headers


def dechunk(data: bytes) -> tuple[bytes, bool]:
    """Decode a chunked body. Returns the payload and whether the final
    zero-length chunk (and its trailer) has arrived."""
    body = bytearray()
    at = 0
    while True:
        line_end = data.find(b"\r\n", at)
        if line_end < 0:
            return bytes(body), False
        try:
            size = int(data[at:line_end].split(b";", 1)[0].strip(), 16)
        except ValueError:
            return bytes(body), False
        at = line_end + 2
        if size == 0:
            # Trailer fields, if any, end with an empty line.
            return bytes(body), data.find(b"\r\n", at) >= 0
        if len(data) < at + size + 2:
            return bytes(body), False
        body += data[at:at + size]
        at += size + 2


def is_complete(data: bytes, head_request: bool = False) -> bool:
    """Whether ``data`` already holds one whole response.

    Lets the reader stop without waiting for a keep-alive server to close.
    A response framed only by the connection closing is never complete by
    this test; the caller reads until end of stream.
    """
    if not has_status_line(data):
        return False
    split = _split_head(data)
    if split is None:
        return False
    head, rest = split
    if head_request or _BODILESS.match(head):
        return True
    headers = {name.lower(): value for name, value in _header_lines(head)}
    if "chunked" in headers.get("transfer-encoding", "").lower():
        return dechunk(rest)[1]
    if "content-length" in headers:
        try:
            return len(rest) >= int(headers["content-length"])
        except ValueError:
            return False
    return False


def parse(data: bytes, head_request: bool = False) -> Response:
    """Split one response. Bytes past its declared length are left out of the
    body; a response with no framing takes everything to end of stream."""
    if not has_status_line(data):
        return Response(raw=data, body=data)
    split = _split_head(data)
    if split is None:
        # A status line whose header block never finished.
        first_line = data.split(b"\r\n", 1)[0].decode("latin-1")
        return Response(raw=data, status_line=first_line)
    head, rest = split
    status_line = head.split(b"\r\n", 1)[0].decode("latin-1")
    headers = _header_lines(head)
    response = Response(raw=data, status_line=status_line, headers=headers)
    if head_request or _BODILESS.match(head):
        return response
    if "chunked" in (response.header("transfer-encoding") or "").lower():
        response.body = dechunk(rest)[0]
    elif response.header("content-length") is not None:
        try:
            response.body = rest[:int(response.header("content-length"))]
        except ValueError:
            response.body = rest
    else:
        response.body = rest
    return response


def normalise_header_value(name: str, value: str) -> str:
    """A header value with what depends on the clock or the file removed.

    A well-formed date becomes ``<http-date>`` and an entity tag ``<etag>``
    (``W/<etag>`` when weak); a malformed one is kept as it is, because the
    wrong format is itself a difference.
    """
    lowered = name.lower()
    if lowered in DATE_HEADERS and _HTTP_DATE.match(value):
        return "<http-date>"
    if lowered == "etag":
        found = _ETAG.match(value)
        if found:
            return "W/<etag>" if found.group(1) else "<etag>"
    return value


def stable_header_values(response: Response) -> dict[str, str]:
    """Header values for comparison: normalised, keyed by lower-case name,
    without ``Server`` (which has a check of its own). A repeated header's
    values are joined in order."""
    values: dict[str, str] = {}
    for name, value in response.headers:
        key = name.lower()
        if key == "server":
            continue
        cleaned = normalise_header_value(name, value)
        values[key] = f"{values[key]}, {cleaned}" if key in values else cleaned
    return values
