"""The web server the decoy claims to be: its wording, header order and manners.

The identity says "Apache/2.4.41 (Ubuntu)" or "nginx/1.18.0 (Ubuntu)" in the
``Server`` header, and until now that header was the only thing that changed.
Both identities sent the same headers in the same order, closed (or failed to
close) connections the same way and answered errors with pages neither
product ships. Header order alone separates the two servers in one response,
so a decoy that claims one and orders its headers like neither is identified
by the first request.

Each profile follows what its server does in the default Ubuntu 20.04
package configuration:

* the stock error pages, including Apache's address line and nginx's padding
  for browsers that replace short error pages with their own;
* the order headers leave in. Apache writes Date and Server, then what the
  handler set, then Keep-Alive/Connection, and Content-Type last. nginx writes
  Server, Date, Content-Type, Content-Length, Last-Modified, Location and
  Connection from fixed fields, then everything else;
* which statuses end the connection, and how keep-alive is announced;
* validators on files (Last-Modified, and each server's own ETag format);
* that nginx streams a script's output chunked while Apache buffers a small
  one and sends its length.

A profile only formats. What to answer is decided in http.py.
"""

from __future__ import annotations

import html
import time
from dataclasses import dataclass, field
from email.utils import parsedate_to_datetime
from typing import Optional

from honeypot.emulators import bait

#: Content types Ubuntu's Apache compresses (mods-available/deflate.conf),
#: and so marks with ``Vary: Accept-Encoding`` whether or not it compressed.
_APACHE_DEFLATE_TYPES = frozenset({
    "text/html", "text/plain", "text/xml", "text/css", "text/javascript",
    "application/javascript", "application/x-javascript",
    "application/ecmascript", "application/rss+xml", "application/xml",
})


@dataclass
class Reply:
    """One response, before the claimed server's formatting is applied."""

    status: int
    body: bytes = b""
    content_type: Optional[str] = None
    #: Headers the handler or application set, in the order it set them.
    headers: list[tuple[str, str]] = field(default_factory=list)
    #: Who produced it, which decides the headers around it: "static" is a
    #: file from disk, "dynamic" a script's output, "error" one of the
    #: server's own pages, "proxied" the answer of an application behind it.
    kind: str = "dynamic"
    #: A static file's validators: modification time and entity tag.
    mtime: Optional[float] = None
    etag: Optional[str] = None
    #: The connection ends after this reply whatever the client asked for.
    close: bool = False
    #: The reason phrase, when it is not the server's own (a proxied answer).
    reason: Optional[str] = None
    #: "decoy" when the decoy application, not the live one, answered.
    answered_by: Optional[str] = None

    def header(self, name: str) -> Optional[str]:
        wanted = name.lower()
        for key, value in self.headers:
            if key.lower() == wanted:
                return value
        return None


def http_date(timestamp: Optional[float] = None) -> str:
    moment = time.gmtime(time.time() if timestamp is None else timestamp)
    return time.strftime("%a, %d %b %Y %H:%M:%S GMT", moment)


def _media_type(content_type: Optional[str]) -> str:
    return (content_type or "").split(";", 1)[0].strip().lower()


def _split_host(host: str) -> tuple[str, str]:
    """A Host header as (name, port); the port is "" when none was given."""
    host = host.strip()
    if host.startswith("["):
        # An IPv6 literal keeps its brackets; a port can only follow them.
        end = host.find("]")
        if end == -1:
            return host, ""
        name, rest = host[: end + 1], host[end + 1:]
        port = rest[1:] if rest.startswith(":") else ""
    else:
        name, separator, port = host.rpartition(":")
        if not separator:
            name, port = host, ""
    return name, port if port.isdigit() else ""


class ServerProfile:
    family = ""
    #: Seconds a connection is kept open waiting for its next request, and
    #: for the first one.
    keepalive_timeout = 60.0
    first_request_timeout = 60.0
    #: Requests served on one connection before the server closes it.
    max_requests = 100
    #: Longest header line and whole header block accepted, and the most
    #: header fields.
    max_header_line = 8190
    max_header_bytes = 100 * 8190
    max_header_count = 100
    #: Whether the server sends a response to a request it timed out on.
    answers_timeouts = False
    error_content_type = "text/html"
    #: Methods a static file is served for. Any other gets a 405.
    static_methods: tuple[str, ...] = ("GET", "HEAD")

    _REASONS: dict[int, str] = {}
    _DROPS: frozenset[int] = frozenset()
    _TYPES: dict[str, str] = {}
    _DEFAULT_TYPE: Optional[str] = None

    def __init__(self, server: str, php: Optional[str], tls: bool) -> None:
        self.server = server
        self.php = php
        self.tls = tls

    # -- facts ---------------------------------------------------------------

    def reason(self, status: int) -> str:
        return self._REASONS.get(status, "OK" if status < 300 else "Error")

    def drops_connection(self, status: int) -> bool:
        return status in self._DROPS

    def content_type(self, path: str) -> Optional[str]:
        """The type the server's MIME table gives a file of this name."""
        name = path.rsplit("/", 1)[-1]
        extension = name.rsplit(".", 1)[-1].lower() if "." in name.strip(".") else ""
        return self._TYPES.get(extension, self._DEFAULT_TYPE)

    def etag(self, size: int, mtime: float, microseconds: int = 0) -> str:
        raise NotImplementedError

    def root_page(self) -> tuple[str, bytes]:
        """The landing page a fresh install serves, with its file name."""
        raise NotImplementedError

    def error(
        self,
        status: int,
        method: str = "GET",
        host: str = "",
        note: str = "",
        user_agent: str = "",
    ) -> Reply:
        raise NotImplementedError

    def serialise(
        self,
        reply: Reply,
        head_only: bool = False,
        keep_alive: bool = False,
        keepalive_token: bool = False,
        requests_left: int = 0,
    ) -> bytes:
        raise NotImplementedError

    # -- files ---------------------------------------------------------------

    def static(self, name: str, body: bytes) -> Reply:
        """A file served from disk, with the validators a file has."""
        mtime = bait.stable_mtime(name)
        return Reply(
            200,
            body,
            content_type=self.content_type(name),
            kind="static",
            mtime=mtime,
            etag=self.etag(len(body), mtime, bait.stable_microseconds(name)),
        )

    def not_modified(self, reply: Reply, headers: dict[str, str]) -> Optional[Reply]:
        """A 304 for a conditional request the file satisfies, else None."""
        if reply.kind != "static" or reply.status != 200 or reply.mtime is None:
            return None
        etag = reply.etag
        if_none_match = headers.get("if-none-match")
        if if_none_match is not None:
            candidates = {tag.strip() for tag in if_none_match[:1024].split(",")}
            matched = "*" in candidates or etag in candidates or f"W/{etag}" in candidates
        else:
            matched = False
            since = headers.get("if-modified-since")
            if since:
                try:
                    matched = parsedate_to_datetime(since[:64]).timestamp() >= reply.mtime
                except (TypeError, ValueError, OverflowError):
                    matched = False
        if not matched:
            return None
        return Reply(304, b"", kind="static", mtime=reply.mtime, etag=etag)

    @staticmethod
    def _finish(status_line: str, headers: list[tuple[str, str]], body: bytes) -> bytes:
        lines = [status_line] + [f"{name}: {value}" for name, value in headers]
        # latin-1 so a header value copied from an upstream passes unchanged.
        head = ("\r\n".join(lines) + "\r\n\r\n").encode("latin-1", errors="replace")
        return head + body

    def _status_line(self, reply: Reply) -> str:
        return f"HTTP/1.1 {reply.status} {reply.reason or self.reason(reply.status)}"


class ApacheProfile(ServerProfile):
    family = "apache"
    #: KeepAliveTimeout 5, and mod_reqtimeout's "header=20-40" for the first
    #: request, both as packaged.
    keepalive_timeout = 5.0
    first_request_timeout = 20.0
    #: MaxKeepAliveRequests 100: the first request and a hundred more.
    max_requests = 101
    answers_timeouts = True
    error_content_type = "text/html; charset=iso-8859-1"
    #: Apache's default handler answers a POST to a static file with the
    #: file. Measured on Apache 2.4.41 (http.post_root.* in docs/evaluation/
    #: fingerprint/1-baseline/http-apache-focal.json): "POST /" came back
    #: "200 OK" with the page and the headers of a GET. nginx refuses it.
    static_methods = ("GET", "HEAD", "POST")

    _REASONS = {
        200: "OK", 201: "Created", 204: "No Content", 206: "Partial Content",
        301: "Moved Permanently", 302: "Found", 304: "Not Modified",
        400: "Bad Request", 401: "Unauthorized", 403: "Forbidden",
        404: "Not Found", 405: "Method Not Allowed", 408: "Request Timeout",
        411: "Length Required", 413: "Request Entity Too Large",
        414: "Request-URI Too Long", 416: "Requested Range Not Satisfiable",
        500: "Internal Server Error", 501: "Not Implemented",
        502: "Bad Gateway", 503: "Service Unavailable",
        505: "HTTP Version Not Supported",
    }
    #: ap_status_drops_connection().
    _DROPS = frozenset({400, 408, 411, 413, 414, 500, 501, 503})
    #: /etc/mime.types. A name it does not know gets no Content-Type at all;
    #: .php is unmapped there, so PHP source served as a file has none either.
    _TYPES = {
        "html": "text/html", "htm": "text/html", "txt": "text/plain",
        "xml": "application/xml", "json": "application/json", "css": "text/css",
        "js": "application/javascript", "png": "image/png", "jpg": "image/jpeg",
        "gif": "image/gif", "ico": "image/vnd.microsoft.icon",
    }

    _NOTES = {
        "header_too_large": "Size of a request header field exceeds server limit.",
        "too_many_headers": "The number of request header fields exceeds this server's limit.",
        "plain_http": (
            "Reason: You're speaking plain HTTP to an SSL-enabled server port.<br />\n"
            " Instead use the HTTPS scheme to access this URL, please.<br />\n"
        ),
    }

    def allow(self) -> str:
        """The Allow list of the default handler, in this install's order."""
        methods = ["GET", "POST", "OPTIONS", "HEAD"]
        turn = bait.allow_rotation()
        return ",".join(methods[turn:] + methods[:turn])

    def etag(self, size: int, mtime: float, microseconds: int = 0) -> str:
        # FileETag MTime Size: both in hex, the time in microseconds.
        return f'"{size:x}-{int(mtime) * 1_000_000 + microseconds:x}"'

    def root_page(self) -> tuple[str, bytes]:
        page = (
            "<!DOCTYPE html PUBLIC \"-//W3C//DTD XHTML 1.0 Transitional//EN\" "
            "\"http://www.w3.org/TR/xhtml1/DTD/xhtml1-transitional.dtd\">\n"
            '<html xmlns="http://www.w3.org/1999/xhtml">\n  <head>\n'
            '    <meta http-equiv="Content-Type" content="text/html; charset=UTF-8" />\n'
            "    <title>Apache2 Ubuntu Default Page: It works</title>\n  </head>\n"
            "  <body>\n    <div class=\"main_page\">\n"
            "      <div class=\"page_header\">\n"
            "        <span class=\"floating_element\">Apache2 Ubuntu Default Page</span>\n"
            "      </div>\n      <div class=\"content_section\">\n"
            "        <h1>It works!</h1>\n"
            "        <p>This is the default welcome page used to test the correct "
            "operation of the Apache2 server after installation on Ubuntu systems.</p>\n"
            "      </div>\n    </div>\n  </body>\n</html>\n"
        )
        return "index.html", page.encode()

    def _address(self, host: str) -> str:
        """The signature line, naming the host and port the client asked for.

        Apache takes both from the Host header. Without one it falls back to
        its ServerName, which on an untouched Ubuntu install is the loopback
        alias the hostname resolves to. The port is the public one, never
        the port the engine's container listens on.
        """
        name, port = _split_host(host)
        name = name.lower() or "127.0.1.1"
        shown_port = port or ("443" if self.tls else "80")
        return (
            f"<address>{html.escape(self.server)} Server at "
            f"{html.escape(name)} Port {shown_port}</address>\n"
        )

    def _message(self, status: int, method: str, note: str) -> str:
        method = html.escape(method[:32])
        extra = self._NOTES.get(note, "")
        if status == 400:
            return (
                "<p>Your browser sent a request that this server could not understand.<br />\n"
                f"{extra}</p>\n"
            )
        if status == 403:
            return "<p>You don't have permission to access this resource.</p>\n"
        if status == 404:
            return "<p>The requested URL was not found on this server.</p>\n"
        if status == 405:
            return f"<p>The requested method {method} is not allowed for this URL.</p>\n"
        if status == 408:
            return "<p>Server timeout waiting for the HTTP request from the client.</p>\n"
        if status == 411:
            return (
                f"<p>A request of the requested method {method} requires a valid "
                "Content-length.<br />\n</p>\n"
            )
        if status == 413:
            return (
                f"The requested resource does not allow request data with {method} "
                "requests, or the amount of data provided in\n"
                "the request exceeds the capacity limit.\n"
            )
        if status == 414:
            return (
                "<p>The requested URL's length exceeds the capacity\n"
                "limit for this server.<br />\n</p>\n"
            )
        if status == 501:
            # Two spaces after the method: that is what Apache 2.4.41 sends
            # ("<p>FPAUDIT  not supported for current URL.<br />", the
            # http.unknown_method.body row of the fingerprint baseline).
            return f"<p>{method}  not supported for current URL.<br />\n</p>\n"
        if status == 502:
            return (
                "<p>The proxy server received an invalid\r\n"
                "response from an upstream server.<br />\r\n</p>\n"
            )
        if status == 503:
            return (
                "<p>The server is temporarily unable to service your\n"
                "request due to maintenance downtime or capacity\n"
                "problems. Please try again later.</p>\n"
            )
        return (
            "<p>The server encountered an internal error or\n"
            "misconfiguration and was unable to complete\n"
            "your request.</p>\n"
            "<p>Please contact the server administrator at \n"
            " webmaster@localhost to inform them of the time this error occurred,\n"
            " and the actions you performed just before this error.</p>\n"
            "<p>More information about this error may be available\n"
            "in the server error log.</p>\n"
        )

    def error(self, status, method="GET", host="", note="", user_agent="") -> Reply:
        title = f"{status} {self.reason(status)}"
        page = (
            '<!DOCTYPE HTML PUBLIC "-//IETF//DTD HTML 2.0//EN">\n'
            f"<html><head>\n<title>{title}</title>\n</head><body>\n"
            f"<h1>{self.reason(status)}</h1>\n"
            f"{self._message(status, method, note)}"
            f"<hr>\n{self._address(host)}"
            "</body></html>\n"
        )
        headers = []
        if status in (405, 501):
            # The default handler has merged its methods into the response
            # before it refuses the request, so both carry the list.
            headers.append(("Allow", self.allow()))
        return Reply(
            status, page.encode("latin-1", errors="replace"),
            content_type=self.error_content_type, headers=headers, kind="error",
            close=self.drops_connection(status),
        )

    def _connection(self, keep_alive: bool, keepalive_token: bool, requests_left: int):
        if not keep_alive:
            return [("Connection", "close")]
        if keepalive_token:
            # Announced only to a client that asked; an HTTP/1.1 client that
            # said nothing is kept alive without a word.
            return [
                ("Keep-Alive", f"timeout={int(self.keepalive_timeout)}, max={requests_left}"),
                ("Connection", "Keep-Alive"),
            ]
        return []

    def serialise(self, reply, head_only=False, keep_alive=False, keepalive_token=False, requests_left=0) -> bytes:
        connection = self._connection(keep_alive, keepalive_token, requests_left)
        body = b"" if head_only else reply.body

        if reply.kind == "proxied":
            # mod_proxy passes the application's Date and Server through and
            # only supplies its own when there is none; the rest follow in
            # the application's order.
            out = [
                ("Date", reply.header("Date") or http_date()),
                ("Server", reply.header("Server") or self.server),
            ]
            for name, value in reply.headers:
                if name.lower() not in ("date", "server"):
                    out.append((name, value))
            return self._finish(self._status_line(reply), out + connection, body)

        out = [("Date", http_date()), ("Server", self.server)]
        if reply.status == 304:
            out += connection
            if reply.etag:
                out.append(("ETag", reply.etag))
            return self._finish(self._status_line(reply), out, b"")

        if reply.kind == "dynamic" and self.php and reply.status < 400:
            out.append(("X-Powered-By", self.php))
        if reply.kind == "static" and reply.mtime is not None:
            out += [
                ("Last-Modified", http_date(reply.mtime)),
                ("ETag", reply.etag or ""),
                ("Accept-Ranges", "bytes"),
            ]
        out += reply.headers

        length = ("Content-Length", str(len(reply.body)))
        varies = reply.status == 200 and _media_type(reply.content_type) in _APACHE_DEFLATE_TYPES
        if reply.kind == "static":
            out.append(length)
            if varies:
                out.append(("Vary", "Accept-Encoding"))
        else:
            if varies and reply.kind == "dynamic":
                out.append(("Vary", "Accept-Encoding"))
            out.append(length)
        out += connection
        if reply.content_type:
            out.append(("Content-Type", reply.content_type))
        return self._finish(self._status_line(reply), out, body)


class NginxProfile(ServerProfile):
    family = "nginx"
    #: keepalive_timeout 65 in Ubuntu's nginx.conf; client_header_timeout 60.
    keepalive_timeout = 65.0
    first_request_timeout = 60.0
    #: keepalive_requests, 100 in this release.
    max_requests = 100
    #: large_client_header_buffers 4 8k: one line per buffer, four buffers.
    max_header_line = 8192
    max_header_bytes = 4 * 8192
    max_header_count = 1000
    answers_timeouts = False
    error_content_type = "text/html"

    _REASONS = {
        200: "OK", 201: "Created", 204: "No Content", 206: "Partial Content",
        301: "Moved Permanently", 302: "Moved Temporarily", 304: "Not Modified",
        400: "Bad Request", 401: "Unauthorized", 403: "Forbidden",
        404: "Not Found", 405: "Not Allowed", 408: "Request Time-out",
        411: "Length Required", 413: "Request Entity Too Large",
        414: "Request-URI Too Large", 416: "Requested Range Not Satisfiable",
        500: "Internal Server Error", 501: "Not Implemented",
        502: "Bad Gateway", 503: "Service Temporarily Unavailable",
        504: "Gateway Time-out", 505: "HTTP Version Not Supported",
    }
    #: ngx_http_special_response_handler() turns keep-alive off for these.
    _DROPS = frozenset({400, 408, 413, 414, 500, 501})
    #: conf/mime.types, with default_type application/octet-stream.
    _TYPES = {
        "html": "text/html", "htm": "text/html", "txt": "text/plain",
        "xml": "text/xml", "json": "application/json", "css": "text/css",
        "js": "application/javascript", "png": "image/png", "jpg": "image/jpeg",
        "gif": "image/gif", "ico": "image/x-icon",
    }
    _DEFAULT_TYPE = "application/octet-stream"

    #: Appended to error pages for clients that would otherwise replace a
    #: short page with their own (msie_padding, on by default).
    _PADDING = (
        "<!-- a padding to disable MSIE and Chrome friendly error page -->\r\n" * 6
    )

    #: Pages whose title or second line differ from "<status> <reason>".
    _VARIANTS = {
        "header_too_large": (
            "400 Request Header Or Cookie Too Large",
            "<center>Request Header Or Cookie Too Large</center>\r\n",
        ),
        "plain_http": (
            "400 The plain HTTP request was sent to HTTPS port",
            "<center>The plain HTTP request was sent to HTTPS port</center>\r\n",
        ),
    }

    def etag(self, size: int, mtime: float, microseconds: int = 0) -> str:
        return f'"{int(mtime):x}-{size:x}"'

    def root_page(self) -> tuple[str, bytes]:
        page = (
            "<!DOCTYPE html>\n<html>\n<head>\n<title>Welcome to nginx!</title>\n"
            "<style>\n    body {\n        width: 35em;\n        margin: 0 auto;\n"
            "        font-family: Tahoma, Verdana, Arial, sans-serif;\n    }\n"
            "</style>\n</head>\n<body>\n<h1>Welcome to nginx!</h1>\n"
            "<p>If you see this page, the nginx web server is successfully "
            "installed and\nworking. Further configuration is required.</p>\n\n"
            '<p>For online documentation and support please refer to\n'
            '<a href="http://nginx.org/">nginx.org</a>.<br/>\n'
            'Commercial support is available at\n'
            '<a href="http://nginx.com/">nginx.com</a>.</p>\n\n'
            "<p><em>Thank you for using nginx.</em></p>\n</body>\n</html>\n"
        )
        return "index.nginx-debian.html", page.encode()

    def error(self, status, method="GET", host="", note="", user_agent="") -> Reply:
        heading = f"{status} {self.reason(status)}"
        title, extra = self._VARIANTS.get(note, (heading, ""))
        page = (
            "<html>\r\n"
            f"<head><title>{title}</title></head>\r\n"
            "<body>\r\n"
            f"<center><h1>{heading}</h1></center>\r\n"
            f"{extra}"
            f"<hr><center>{self.server}</center>\r\n"
            "</body>\r\n"
            "</html>\r\n"
        )
        if status >= 400 and ("MSIE " in user_agent or "Chrome/" in user_agent):
            page += self._PADDING
        return Reply(
            status, page.encode("latin-1", errors="replace"),
            content_type=self.error_content_type, kind="error",
            close=self.drops_connection(status),
        )

    def serialise(self, reply, head_only=False, keep_alive=False, keepalive_token=False, requests_left=0) -> bytes:
        connection = ("Connection", "keep-alive" if keep_alive else "close")
        out = [("Server", self.server), ("Date", http_date())]

        if reply.kind == "proxied":
            # The proxy module replaces the application's Server and Date
            # with nginx's own and writes the fields it understands first.
            fixed = ("server", "date", "content-type", "content-length", "last-modified", "location")
            for name in ("Content-Type", "Content-Length", "Last-Modified", "Location"):
                value = reply.header(name)
                if value is not None:
                    out.append((name, value))
            out.append(connection)
            out += [(n, v) for n, v in reply.headers if n.lower() not in fixed]
            return self._finish(self._status_line(reply), out, b"" if head_only else reply.body)

        has_body = reply.status not in (204, 304)
        # A script's output has no known length when its headers leave, so
        # it goes out chunked; a file or an error page has one.
        chunked = reply.kind == "dynamic" and has_body and not head_only
        if reply.content_type and has_body:
            out.append(("Content-Type", reply.content_type))
        if has_body and reply.kind != "dynamic":
            out.append(("Content-Length", str(len(reply.body))))
        is_file = reply.kind == "static" and reply.mtime is not None
        if is_file:
            out.append(("Last-Modified", http_date(reply.mtime)))
        location = reply.header("Location")
        if location is not None:
            out.append(("Location", location))
        if chunked:
            out.append(("Transfer-Encoding", "chunked"))
        out.append(connection)
        if is_file and reply.etag:
            out.append(("ETag", reply.etag))
        if reply.kind == "dynamic" and self.php and reply.status < 400:
            out.append(("X-Powered-By", self.php))
        out += [(n, v) for n, v in reply.headers if n.lower() != "location"]
        if is_file and reply.status == 200:
            out.append(("Accept-Ranges", "bytes"))

        if head_only or not has_body:
            body = b""
        elif chunked:
            body = b"0\r\n\r\n"
            if reply.body:
                body = f"{len(reply.body):x}\r\n".encode() + reply.body + b"\r\n" + body
        else:
            body = reply.body
        return self._finish(self._status_line(reply), out, body)


def build_profile(family: str, server: str, php: Optional[str], tls: bool) -> ServerProfile:
    if family == "nginx":
        return NginxProfile(server, php, tls)
    return ApacheProfile(server, php, tls)
