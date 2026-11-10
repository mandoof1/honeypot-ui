"""Pull attacker-supplied files out of HTTP request bodies.

Web exploitation delivers payloads as request bodies: a webshell posted to an
upload form, a JSP dropped with PUT onto a misconfigured Tomcat, PHP pasted
into a form field that ends up in ``eval``. The emulator read those bodies
and immediately decoded them as UTF-8 with replacement characters — which
destroys any binary on arrival — then kept the first 500 characters.

This works on the raw bytes. It parses ``multipart/form-data`` itself, with
hard bounds on part count and header size, rather than handing an
attacker-shaped body to a general-purpose MIME parser. Attacker-supplied
filenames are kept as metadata only; they never become a path.
"""

from __future__ import annotations

import posixpath
import re
from dataclasses import dataclass
from typing import Optional
from urllib.parse import parse_qsl, unquote

MAX_PARTS = 32
MAX_PART_HEADER_BYTES = 8192
MAX_PART_HEADER_LINES = 32
MAX_FORM_FIELDS = 128
MAX_FILENAME = 255
#: Parameters read from one header value. Content-Disposition carries three
#: at most (name, filename, filename*).
MAX_HEADER_PARAMS = 16
#: How far into a body leading whitespace is skipped when looking for a
#: payload's first bytes.
PAYLOAD_SNIFF_BYTES = 512

#: Leading bytes that mark a body as a payload rather than ordinary form data.
#: The last two are base64 of an ELF and a PE header, which is how binaries
#: are smuggled through text-only upload handlers.
_PAYLOAD_PREFIXES = (
    b"<?php", b"<?=", b"<%", b"#!", b"\x7fELF", b"MZ",
    b"PK\x03\x04", b"\x1f\x8b", b"f0VMR", b"TVqQ",
)

#: Content types that say "this is a file" on their own.
_FILE_CONTENT_TYPES = re.compile(
    r"^(application/(octet-stream|x-(?!www-form-urlencoded)[\w.+-]+|zip|gzip|java-archive)"
    r"|text/x-[\w.+-]+)",
    re.IGNORECASE,
)


@dataclass
class HttpFile:
    filename: str
    content: bytes
    #: http_multipart, http_put, http_body or http_form_field.
    source: str
    field: Optional[str] = None


def looks_like_payload(data: bytes) -> bool:
    # A window, not the whole body: stripping an 8 MiB body copied all of it
    # to look at eight bytes.
    return data[:PAYLOAD_SNIFF_BYTES].lstrip()[:8].startswith(_PAYLOAD_PREFIXES)


def safe_filename(name: Optional[str], fallback: str) -> str:
    """A display name, never a path: basename, no control characters."""
    if not name:
        return fallback
    name = name.replace("\\", "/")
    name = posixpath.basename(name)
    name = re.sub(r"[\x00-\x1f\x7f]", "", name).strip()
    return (name or fallback)[:MAX_FILENAME]


#: The only characters that change how a header value splits.
_PARAM_SPECIALS = re.compile(r'[;"\\]')


def _split_params(value: str) -> list[str]:
    """Split a header value at the semicolons that are outside quotes.

    One pass over the value. This was a single regular expression whose
    lookahead rescanned the rest of the string from every semicolon — about
    0.15 s for one 8 KB header, on the event loop, and a multipart request
    can carry thirty-three of them.
    """
    pieces: list[str] = []
    start = 0
    quoted = False
    escaped_at = -1
    for match in _PARAM_SPECIALS.finditer(value):
        index = match.start()
        if index == escaped_at:
            continue
        char = value[index]
        if char == "\\":
            if quoted:
                # A backslash inside quotes escapes the next character.
                escaped_at = index + 1
        elif char == '"':
            quoted = not quoted
        elif not quoted:
            pieces.append(value[start:index])
            start = index + 1
            if len(pieces) > MAX_HEADER_PARAMS:
                # More parameters than any real header carries; the rest
                # is not worth reading.
                return pieces
    pieces.append(value[start:])
    return pieces


def _header_params(value: str) -> tuple[str, dict[str, str]]:
    """Split ``form-data; name="f"; filename="x.php"`` into its parts."""
    pieces = _split_params(value[:MAX_PART_HEADER_BYTES])
    main = pieces[0].strip().lower()
    params: dict[str, str] = {}
    for piece in pieces[1:]:
        if "=" not in piece:
            continue
        key, raw = piece.split("=", 1)
        key, raw = key.strip().lower(), raw.strip()
        if raw.startswith('"') and raw.endswith('"') and len(raw) >= 2:
            raw = raw[1:-1].replace('\\"', '"')
        if key.endswith("*"):
            # RFC 5987: filename*=UTF-8''name%20here
            key = key[:-1]
            if "''" in raw:
                raw = unquote(raw.split("''", 1)[1])
        params[key] = raw
    return main, params


def parse_multipart(content_type: str, body: bytes) -> list[tuple[dict[str, str], bytes]]:
    """Return (headers, data) for each part. Malformed input yields fewer parts."""
    _, params = _header_params(content_type)
    boundary = params.get("boundary", "")
    if not boundary or len(boundary) > 200:
        return []
    delimiter = b"--" + boundary.encode("latin-1", errors="ignore")

    # Walk the body by offset rather than splitting it: a split made one
    # list entry per delimiter in the body, however many an attacker sent,
    # and copied each part's data three times on the way to trimming it.
    parts: list[tuple[dict[str, str], bytes]] = []
    position = body.find(delimiter)
    for _ in range(MAX_PARTS):
        if position == -1:
            break
        start = position + len(delimiter)
        if body.startswith(b"--", start):
            break
        if body.startswith(b"\r\n", start):
            start += 2
        elif body.startswith(b"\n", start):
            start += 1
        position = body.find(delimiter, start)
        part_end = len(body) if position == -1 else position

        # The part's headers end at the first blank line, which must come
        # within the header bound.
        header_end = body.find(b"\r\n\r\n", start, min(part_end, start + MAX_PART_HEADER_BYTES + 4))
        separator = 4
        if header_end == -1:
            header_end = body.find(b"\n\n", start, min(part_end, start + MAX_PART_HEADER_BYTES + 2))
            separator = 2
        if header_end == -1:
            continue

        data_start, data_end = header_end + separator, part_end
        if body.endswith(b"\r\n", data_start, data_end):
            data_end -= 2
        elif body.endswith(b"\n", data_start, data_end):
            data_end -= 1

        headers: dict[str, str] = {}
        for line in body[start:header_end].splitlines()[:MAX_PART_HEADER_LINES]:
            if b":" in line:
                key, value = line.split(b":", 1)
                headers[key.decode("latin-1").strip().lower()] = value.decode(
                    "utf-8", errors="replace"
                ).strip()
        parts.append((headers, body[data_start:data_end]))
    return parts


def extract_files(method: str, path: str, headers: dict[str, str], body: bytes) -> list[HttpFile]:
    """Every file-like payload a request carries. Ordinary form posts yield none."""
    if not body:
        return []
    content_type = headers.get("content-type", "")
    main_type = content_type.split(";", 1)[0].strip().lower()
    from_path = safe_filename(unquote(path), "")

    if main_type == "multipart/form-data":
        files = []
        for part_headers, data in parse_multipart(content_type, body):
            if not data:
                continue
            _, params = _header_params(part_headers.get("content-disposition", ""))
            field = params.get("name")
            if "filename" in params:
                files.append(HttpFile(
                    safe_filename(params["filename"], f"{field or 'upload'}.bin"),
                    data, "http_multipart", field,
                ))
            elif looks_like_payload(data):
                files.append(HttpFile(
                    safe_filename(field, "field") + ".txt", data, "http_form_field", field,
                ))
        return files

    if method == "PUT":
        return [HttpFile(from_path or "put-body.bin", body, "http_put")]

    if main_type == "application/x-www-form-urlencoded":
        files = []
        try:
            fields = parse_qsl(body, keep_blank_values=False, max_num_fields=MAX_FORM_FIELDS)
        except ValueError:
            return []
        for name, value in fields:
            if looks_like_payload(value):
                label = name.decode("utf-8", errors="replace")
                files.append(HttpFile(
                    safe_filename(label, "field") + ".txt", value, "http_form_field", label,
                ))
        return files

    if looks_like_payload(body) or _FILE_CONTENT_TYPES.match(main_type):
        return [HttpFile(from_path or "post-body.bin", body, "http_body")]
    return []
