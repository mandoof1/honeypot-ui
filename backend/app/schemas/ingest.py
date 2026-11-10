"""The engine's session payload, bounded before anything stores it.

The ingest routes used to take a bare ``dict``. Whatever arrived went to the
analysis pipeline as it was, and the first thing to object was PostgreSQL: a
URL of 501 characters destined for a VARCHAR(500) column, a string where an
integer column expected a number. That surfaced as a 500, which the engine
treats as "try again later", so one unstorable session was resent for ever.

This model sits in front of the pipeline and does three things:

* **Truncates where that is safe.** Free text an attacker typed (a command,
  a filename, an output) is cut to a generous limit; a list longer than the
  engine's own caps is cut to its cap. Nothing downstream depends on the
  tail of a megabyte-long command.
* **Coerces what has an obvious neutral value.** A counter that is not a
  number becomes 0, a port that is not a port becomes null.
* **Refuses (422) what cannot be repaired.** A source address too long to be
  an address, a list where an object belongs. The engine files a 4xx under
  ``failed/`` and moves on.

Keys this model does not know are passed through, size-bounded but otherwise
untouched: the engine and the analysis stage evolve together, and a new key
between them must not need a change here. ``fingerprints``, ``headers`` on
transcript entries and new ``event_type`` values travel that way by design.

``to_pipeline()`` gives back a plain dict holding only what the engine
actually sent, which is the shape the pipeline has always taken.
"""

from __future__ import annotations

import math
from typing import Any, Dict, List, Optional

from pydantic import BaseModel, ConfigDict, field_validator, model_validator

# List caps. Each is at or above what the engine sends (see
# honeypot/core/session.py), so a well-behaved engine is never cut.
MAX_COMMANDS = 5000
MAX_TRANSCRIPT_ENTRIES = 1000
MAX_CREDENTIALS = 500
MAX_EVENTS = 500
MAX_PACKETS = 5000
MAX_UPLOADS = 64

# Text caps, in characters.
MAX_COMMAND_CHARS = 262_144       # the SSH emulator's own line limit
MAX_OUTPUT_CHARS = 16_384
MAX_PAYLOAD_CHARS = 1_000_000
MAX_CREDENTIAL_CHARS = 256
MAX_FILENAME_CHARS = 255          # session_artifacts.filename
MAX_PATH_CHARS = 500              # session_artifacts.remote_path
MAX_SOURCE_CHARS = 32             # session_artifacts.source
MAX_ADDRESS_CHARS = 45            # honeypot_sessions.attacker_ip
MAX_PROTOCOL_CHARS = 20           # honeypot_sessions.protocol
MAX_EVENT_TYPE_CHARS = 64
MAX_HEADER_COUNT = 100
MAX_HEADER_NAME_CHARS = 256
MAX_HEADER_VALUE_CHARS = 8192
MAX_FINGERPRINTS = 64
#: The engine allows this much for the algorithm lists behind HASSH and JA3.
MAX_FINGERPRINT_CHARS = 2048

# Bounds for values this model passes through without knowing their shape.
_PASSTHROUGH_TEXT_CHARS = 8192
_PASSTHROUGH_ITEMS = 500
_PASSTHROUGH_DEPTH = 6

_HEX = set("0123456789abcdef")


def _text(value: Any, limit: int, field: str) -> str:
    """A string no longer than ``limit``; numbers are accepted as text."""
    if isinstance(value, str):
        return value[:limit]
    if isinstance(value, (int, float)) and not isinstance(value, bool):
        return str(value)[:limit]
    raise ValueError(f"{field} must be text")


def _optional_text(value: Any, limit: int, field: str) -> Optional[str]:
    return None if value is None else _text(value, limit, field)


def _count(value: Any) -> int:
    """A non-negative integer, or 0 for anything that is not one."""
    if isinstance(value, bool):
        return int(value)
    try:
        number = float(value)
    except (TypeError, ValueError):
        return 0
    if not math.isfinite(number) or number < 0:
        return 0
    return int(min(number, 2_147_483_647))


def _measure(value: Any) -> float:
    """A finite, non-negative float, or 0.0."""
    if isinstance(value, bool):
        return float(value)
    try:
        number = float(value)
    except (TypeError, ValueError):
        return 0.0
    return number if math.isfinite(number) and number >= 0 else 0.0


def _optional_number(value: Any) -> Optional[float]:
    if value is None or isinstance(value, bool):
        return None
    try:
        number = float(value)
    except (TypeError, ValueError):
        return None
    return number if math.isfinite(number) else None


def _list(value: Any, limit: int, field: str) -> list:
    if value is None:
        return []
    if not isinstance(value, list):
        raise ValueError(f"{field} must be a list")
    return value[:limit]


def _hex_digest(value: Any, length: int) -> str:
    """A lowercase hex digest of exactly ``length`` characters, else ''.

    A hash cannot be shortened into another valid hash, so one of the wrong
    shape is dropped rather than truncated; the upload is then recorded
    without it, as an upload whose hash never arrived would be.
    """
    if not isinstance(value, str):
        return ""
    digest = value.strip().lower()
    if len(digest) != length or not set(digest) <= _HEX:
        return ""
    return digest


def bound_json(value: Any, depth: int = 0) -> Any:
    """Bound a value of unknown shape without changing a reasonable one.

    Strings are cut at 8192 characters, lists and objects at 500 entries, and
    nesting at six levels. Used for the keys this model passes through.
    """
    if isinstance(value, str):
        return value[:_PASSTHROUGH_TEXT_CHARS]
    if value is None or isinstance(value, (bool, int)):
        return value
    if isinstance(value, float):
        return value if math.isfinite(value) else None
    if depth >= _PASSTHROUGH_DEPTH:
        return None
    if isinstance(value, list):
        return [bound_json(item, depth + 1) for item in value[:_PASSTHROUGH_ITEMS]]
    if isinstance(value, dict):
        bounded = {}
        for index, (key, item) in enumerate(value.items()):
            if index >= _PASSTHROUGH_ITEMS:
                break
            bounded[str(key)[:256]] = bound_json(item, depth + 1)
        return bounded
    return str(value)[:_PASSTHROUGH_TEXT_CHARS]


class _Passthrough(BaseModel):
    """Base for payload objects: known fields are checked, others kept."""

    model_config = ConfigDict(extra="allow")

    @model_validator(mode="after")
    def _bound_unknown_keys(self):
        extra = self.__pydantic_extra__
        if extra:
            for key in list(extra):
                extra[key] = bound_json(extra[key])
        return self


class TranscriptEntryIn(_Passthrough):
    command: str = ""
    output: str = ""
    exit_code: int = 0
    timestamp: Optional[float] = None
    #: Request headers, on HTTP entries. Name -> value, passed to analysis.
    headers: Optional[Dict[str, str]] = None

    @field_validator("command", mode="before")
    @classmethod
    def _command(cls, value):
        return "" if value is None else _text(value, MAX_COMMAND_CHARS, "transcript command")

    @field_validator("output", mode="before")
    @classmethod
    def _output(cls, value):
        return "" if value is None else _text(value, MAX_OUTPUT_CHARS, "transcript output")

    @field_validator("exit_code", mode="before")
    @classmethod
    def _exit_code(cls, value):
        try:
            return max(-2_147_483_648, min(int(value), 2_147_483_647))
        except (TypeError, ValueError):
            return 0

    @field_validator("timestamp", mode="before")
    @classmethod
    def _timestamp(cls, value):
        return _optional_number(value)

    @field_validator("headers", mode="before")
    @classmethod
    def _headers(cls, value):
        if value is None:
            return None
        if not isinstance(value, dict):
            raise ValueError("transcript headers must be an object")
        headers = {}
        for index, (name, item) in enumerate(value.items()):
            if index >= MAX_HEADER_COUNT:
                break
            if isinstance(item, (dict, list)) or item is None:
                continue
            headers[str(name)[:MAX_HEADER_NAME_CHARS]] = str(item)[:MAX_HEADER_VALUE_CHARS]
        return headers


class CredentialIn(_Passthrough):
    username: str = ""
    password: str = ""
    success: bool = False
    timestamp: Optional[float] = None

    @field_validator("username", "password", mode="before")
    @classmethod
    def _secret_text(cls, value):
        return "" if value is None else _text(value, MAX_CREDENTIAL_CHARS, "credential")

    @field_validator("success", mode="before")
    @classmethod
    def _success(cls, value):
        return value is True or value == 1

    @field_validator("timestamp", mode="before")
    @classmethod
    def _timestamp(cls, value):
        return _optional_number(value)


class UploadIn(_Passthrough):
    filename: Optional[str] = None
    sha256: str = ""
    md5: Optional[str] = None
    size: int = 0
    source: Optional[str] = None
    remote_path: Optional[str] = None
    url: Optional[str] = None
    methods: List[str] = []
    content_b64: Optional[str] = None

    @field_validator("filename", mode="before")
    @classmethod
    def _filename(cls, value):
        return _optional_text(value, MAX_FILENAME_CHARS, "upload filename")

    @field_validator("remote_path", "url", mode="before")
    @classmethod
    def _path(cls, value):
        return _optional_text(value, MAX_PATH_CHARS, "upload path")

    @field_validator("source", mode="before")
    @classmethod
    def _source(cls, value):
        return _optional_text(value, MAX_SOURCE_CHARS, "upload source")

    @field_validator("sha256", mode="before")
    @classmethod
    def _sha256(cls, value):
        return _hex_digest(value, 64)

    @field_validator("md5", mode="before")
    @classmethod
    def _md5(cls, value):
        return _hex_digest(value, 32) or None

    @field_validator("size", mode="before")
    @classmethod
    def _size(cls, value):
        return _count(value)

    @field_validator("methods", mode="before")
    @classmethod
    def _methods(cls, value):
        if not isinstance(value, list):
            return []
        return [str(item)[:32] for item in value[:8] if isinstance(item, (str, int))]

    @field_validator("content_b64", mode="before")
    @classmethod
    def _content(cls, value):
        # Bounded by the request-body limit; anything but text is no content.
        return value if isinstance(value, str) else None


class EventIn(_Passthrough):
    """A network event. ``event_type`` is open: new kinds pass through."""

    event_type: str

    @field_validator("event_type", mode="before")
    @classmethod
    def _event_type(cls, value):
        return _text(value, MAX_EVENT_TYPE_CHARS, "event_type")


class PacketIn(_Passthrough):
    type: str = "unknown"
    size: int = 0

    @field_validator("type", mode="before")
    @classmethod
    def _type(cls, value):
        return "unknown" if value is None else _text(value, 40, "packet type")

    @field_validator("size", mode="before")
    @classmethod
    def _size(cls, value):
        return _count(value)


class SessionIngest(_Passthrough):
    """One captured session, as the engine posts it."""

    session_id: Optional[str] = None
    protocol: Optional[str] = None
    attacker_ip: str = ""
    attacker_port: Optional[int] = None
    started_at: Optional[str] = None
    status: Optional[str] = None
    duration_seconds: float = 0.0
    commands: List[str] = []
    payload: str = ""
    uploads: List[UploadIn] = []
    failed_logins: int = 0
    connection_rate: float = 0.0
    port_scan_count: int = 0
    error_rate: float = 0.0
    transcript: List[TranscriptEntryIn] = []
    credentials: List[CredentialIn] = []
    keystroke_count: int = 0
    flow: Optional[Dict[str, Any]] = None
    events: List[EventIn] = []
    packets: List[PacketIn] = []
    truncated: Optional[Dict[str, Any]] = None
    #: Client fingerprints the engine computed (for example an SSH or TLS
    #: handshake hash), name -> short string. Stored by the analysis stage.
    fingerprints: Optional[Dict[str, str]] = None

    @field_validator("session_id", mode="before")
    @classmethod
    def _session_id(cls, value):
        return _optional_text(value, 64, "session_id")

    @field_validator("protocol", mode="before")
    @classmethod
    def _protocol(cls, value):
        return _optional_text(value, MAX_PROTOCOL_CHARS, "protocol")

    @field_validator("attacker_ip", mode="before")
    @classmethod
    def _attacker_ip(cls, value):
        if value is None:
            return ""
        if not isinstance(value, str):
            raise ValueError("attacker_ip must be text")
        value = value.strip()
        if len(value) > MAX_ADDRESS_CHARS:
            # Cutting an address makes a different address; refuse instead.
            raise ValueError(f"attacker_ip is longer than {MAX_ADDRESS_CHARS} characters")
        return value

    @field_validator("attacker_port", mode="before")
    @classmethod
    def _attacker_port(cls, value):
        if value is None or isinstance(value, bool):
            return None
        try:
            port = int(value)
        except (TypeError, ValueError):
            return None
        return port if 0 <= port <= 65535 else None

    @field_validator("started_at", "status", mode="before")
    @classmethod
    def _short_text(cls, value):
        return _optional_text(value, 64, "field")

    @field_validator("duration_seconds", "connection_rate", "error_rate", mode="before")
    @classmethod
    def _measures(cls, value):
        return _measure(value)

    @field_validator("failed_logins", "port_scan_count", "keystroke_count", mode="before")
    @classmethod
    def _counts(cls, value):
        return _count(value)

    @field_validator("commands", mode="before")
    @classmethod
    def _commands(cls, value):
        commands = _list(value, MAX_COMMANDS, "commands")
        return [
            "" if item is None else _text(item, MAX_COMMAND_CHARS, "command")
            for item in commands
        ]

    @field_validator("payload", mode="before")
    @classmethod
    def _payload(cls, value):
        return "" if value is None else _text(value, MAX_PAYLOAD_CHARS, "payload")

    @field_validator("uploads", mode="before")
    @classmethod
    def _uploads(cls, value):
        return _objects(_list(value, MAX_UPLOADS, "uploads"))

    @field_validator("transcript", mode="before")
    @classmethod
    def _transcript(cls, value):
        return _objects(_list(value, MAX_TRANSCRIPT_ENTRIES, "transcript"))

    @field_validator("credentials", mode="before")
    @classmethod
    def _credentials(cls, value):
        return _objects(_list(value, MAX_CREDENTIALS, "credentials"))

    @field_validator("events", mode="before")
    @classmethod
    def _events(cls, value):
        # An event with no type says nothing a reader could use.
        return [
            item for item in _objects(_list(value, MAX_EVENTS, "events"))
            if item.get("event_type") is not None
        ]

    @field_validator("packets", mode="before")
    @classmethod
    def _packets(cls, value):
        return _objects(_list(value, MAX_PACKETS, "packets"))

    @field_validator("flow", "truncated", mode="before")
    @classmethod
    def _open_object(cls, value):
        if value is None:
            return None
        if not isinstance(value, dict):
            raise ValueError("expected an object")
        return bound_json(value)

    @field_validator("fingerprints", mode="before")
    @classmethod
    def _fingerprints(cls, value):
        if value is None:
            return None
        if not isinstance(value, dict):
            raise ValueError("fingerprints must be an object")
        fingerprints = {}
        for index, (name, item) in enumerate(value.items()):
            if index >= MAX_FINGERPRINTS:
                break
            if isinstance(item, list):
                # The Telnet option sequence arrives as a list. Kept as one
                # comma-separated string, so every fingerprint is a string.
                item = ",".join(str(part)[:64] for part in item[:128] if not isinstance(part, (dict, list)))
            if isinstance(item, dict) or item is None or item == "":
                continue
            fingerprints[str(name)[:64]] = str(item)[:MAX_FINGERPRINT_CHARS]
        return fingerprints

    def to_pipeline(self) -> Dict[str, Any]:
        """The payload as a plain dict of what was sent, for the pipeline."""
        return self.model_dump(exclude_unset=True)


def _objects(items: list) -> list:
    """Keep the objects in a list; anything else in it carries no fields."""
    return [item for item in items if isinstance(item, dict)]
