"""Removing what differs between two hosts for reasons that are not a tell.

The decoy and the reference are different machines as far as their replies
are concerned: different addresses, hostnames, ephemeral ports. Those are
replaced with fixed tags before comparing, so a mismatch always means the
software answered differently. Everything else is compared as sent.
"""

from __future__ import annotations

import re

_IPV4 = re.compile(rb"(?<![\d.])(?:\d{1,3}\.){3}\d{1,3}(?![\d.])")
_PASV_TUPLE = re.compile(rb"\(\d{1,3}(?:,\d{1,3}){5}\)")


def mask_ipv4(data: bytes) -> bytes:
    """Every dotted-quad address becomes ``<ip>``. An IPv4-mapped prefix
    (``::ffff:``) in front of it is kept: whether a server prints one is the
    software's choice."""
    return _IPV4.sub(b"<ip>", data)


def mask_pasv(data: bytes) -> bytes:
    """The address and port of a 227 reply, ``(h1,h2,h3,h4,p1,p2)``, become
    one tag; the wording and punctuation around them are left to compare."""
    return _PASV_TUPLE.sub(b"(<h1,h2,h3,h4,p1,p2>)", data)


def mask_token(data: bytes, token: bytes, tag: bytes) -> bytes:
    """Replace one known host-specific word (a hostname) wherever it
    appears. An empty token leaves the data alone."""
    if not token:
        return data
    return data.replace(token, tag)
