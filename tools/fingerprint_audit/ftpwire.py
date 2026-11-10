"""FTP control-channel replies (RFC 959, section 4.2).

A reply is one line ``ddd text`` or several: ``ddd-text`` opens a multi-line
reply and the next line starting with the same code and a space closes it.
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from typing import Optional

_FINAL_LINE = re.compile(rb"^(\d{3}) ")
_OPENING_LINE = re.compile(rb"^(\d{3})-")


@dataclass
class Reply:
    code: int
    raw: bytes

    @property
    def lines(self) -> list[str]:
        return self.raw.decode("latin-1").splitlines()


def read_reply(data: bytes) -> Optional[tuple[Reply, bytes]]:
    """Take one whole reply off the front of ``data``.

    Returns the reply and the bytes after it, or None when the reply has not
    finished arriving. A first line that is not a reply line at all is
    returned on its own with code 0, so a server that answers with something
    other than FTP is still recorded.
    """
    end = data.find(b"\n")
    if end < 0:
        return None
    first = data[:end + 1]
    final = _FINAL_LINE.match(first)
    if final:
        return Reply(int(final.group(1)), first), data[end + 1:]
    opening = _OPENING_LINE.match(first)
    if not opening:
        return Reply(0, first), data[end + 1:]
    closing = opening.group(1) + b" "
    at = end + 1
    while True:
        end = data.find(b"\n", at)
        if end < 0:
            return None
        if data[at:end + 1].startswith(closing):
            return Reply(int(opening.group(1)), data[:end + 1]), data[end + 1:]
        at = end + 1
