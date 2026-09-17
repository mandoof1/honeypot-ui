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
MAX_FORM_FIELDS = 128
MAX_FILENAME = 255

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
    return data.lstrip()[:8].startswith(_PAYLOAD_PREFIXES)


def safe_filename(name: Optional[str], fallback: str) -> str:
    """A display name, never a path: basename, no control characters."""
    if not name:
        return fallback
    name = name.replace("\\", "/")
    name = posixpath.basename(name)
    name = re.sub(r"[\x00-\x1f\x7f]", "", name).strip()
    return (name or fallback)[:MAX_FILENAME]


def _header_params(value: str) -> tuple[str, dict[str, str]]:
    """Split ``form-data; name="f"; filename="x.php"`` into its parts."""
    pieces = re.split(r";(?=(?:[^\"]*\"[^\"]*\")*[^\"]*$)", value)
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

    parts: list[tuple[dict[str, str], bytes]] = []
    segments = body.split(delimiter)
    for segment in segments[1:MAX_PARTS + 1]:
        if segment.startswith(b"--"):
            break
        if segment.startswith(b"\r\n"):
            segment = segment[2:]
        elif segment.startswith(b"\n"):
            segment = segment[1:]
        split = segment.find(b"\r\n\r\n")
        sep_len = 4
        if split == -1:
            split, sep_len = segment.find(b"\n\n"), 2
        if split == -1 or split > MAX_PART_HEADER_BYTES:
            continue
        raw_headers, data = segment[:split], segment[split + sep_len:]
        if data.endswith(b"\r\n"):
            data = data[:-2]
        elif data.endswith(b"\n"):
            data = data[:-1]
        headers: dict[str, str] = {}
        for line in re.split(rb"\r?\n", raw_headers):
            if b":" in line:
                key, value = line.split(b":", 1)
                headers[key.decode("latin-1").strip().lower()] = value.decode(
                    "utf-8", errors="replace"
                ).strip()
        parts.append((headers, data))
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
