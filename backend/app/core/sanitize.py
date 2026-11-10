"""Make attacker-supplied text storable.

PostgreSQL text and JSONB cannot hold U+0000, and a Python string can hold
half of a surrogate pair that no UTF-8 encoder will accept. Captures carry raw
attacker bytes (a TLS ClientHello sent to the plain-HTTP decoy is full of
NULs), and a payload analysis report quotes strings out of an uploaded file.
Either reaching an insert unescaped makes the database reject the whole row:
on ingest the engine then re-sent the session for ever, and a sample's
analysis was re-run every hour for ever.

Escaping, not stripping: it stays visible that the character was there.
"""

from __future__ import annotations

import re
from typing import Any, Optional

#: Half of a UTF-16 surrogate pair on its own. ``json.loads`` produces these
#: from an escape such as ``"\\ud800"``; they cannot be encoded as UTF-8.
_LONE_SURROGATE = re.compile("[\ud800-\udfff]")


def clean_text(value: str) -> str:
    """Escape NUL and replace unpaired surrogates in one string."""
    if "\x00" in value:
        value = value.replace("\x00", "\\x00")
    if _LONE_SURROGATE.search(value):
        value = _LONE_SURROGATE.sub("�", value)
    return value


def clean_json(value: Any) -> Any:
    """``clean_text`` applied to every string in a JSON-like structure."""
    if isinstance(value, str):
        return clean_text(value)
    if isinstance(value, dict):
        return {clean_json(key): clean_json(item) for key, item in value.items()}
    if isinstance(value, list):
        return [clean_json(item) for item in value]
    return value


def clip(value: Any, limit: int) -> Optional[str]:
    """A storable string no longer than a VARCHAR(limit) column, or None."""
    if value is None:
        return None
    return clean_text(str(value))[:limit]
