"""Recursive de-obfuscation of attacker commands.

Section V.B.2 records the expert interviews concluding that obfuscated
commands "must be recursively decoded before TTP mapping", and states the
findings were incorporated. They were not. ``base64`` appeared in the codebase
only as a regex to *match on* and a MITRE label to attach — the payload itself
was never decoded, so a dropper that fetched its second stage through
``echo <b64> | base64 -d | sh`` was recorded as one suspicious string and
analysed no further.

That matters because obfuscation is where the actual intent lives. The outer
command is deliberately boring; the inner one names the C2 host.

Encodings unwrapped: base64 and hex (each optionally wrapping gzip/zlib or
UTF-16LE text, the form PowerShell's ``-EncodedCommand`` takes), ``\\xHH``,
octal and ``\\uHHHH`` escapes mixed into a word, percent-encoding, and a blob
assembled from shell variables (``a=…; b=…; echo $a$b``) or from several
``echo … >> file`` lines.

Everything here is layered decoding of attacker-controlled input, so every
loop is bounded: depth, total output size, decompressed size, and the number
of layers kept per chunk. Candidates are ranked *after* decoding: the cap used
to be applied to the longest candidates before any was tried, so a dozen long
strings that decode to noise were enough to hide the payload behind them.
"""

from __future__ import annotations

import base64
import binascii
import re
import urllib.parse
import zlib
from dataclasses import dataclass, field
from typing import Callable, Iterator, List, Optional, Tuple

#: How many nested encodings to unwrap. Real droppers rarely exceed three;
#: past that the cost is not worth paying on hostile input.
MAX_DEPTH = 4

#: Ceiling on decoded output per session, across all layers.
MAX_TOTAL_CHARS = 200_000

#: Decoded layers kept per chunk and decoder, best first.
MAX_CANDIDATES_PER_LAYER = 12

#: Candidates tried per chunk and decoder. They do not overlap, so the work
#: is bounded by the chunk's length whatever this is; the count only keeps a
#: chunk of thousands of tiny candidates cheap.
MAX_ATTEMPTS_PER_LAYER = 2000

#: Most a compressed blob may expand to. A few kilobytes of zlib can describe
#: gigabytes of zeros.
MAX_DECOMPRESSED_BYTES = 65_536

#: Shorter than this and base64 detection is mostly false positives — ordinary
#: words like "passwd" are valid base64.
MIN_B64_LEN = 16

_B64_RE = re.compile(r"[A-Za-z0-9+/]{%d,}={0,2}" % MIN_B64_LEN)
_HEX_RE = re.compile(r"(?:[0-9a-fA-F]{2}){8,}")
#: A run of backslash escapes, possibly mixed with literal characters
#: (``$'\\x77\\x67et'``). Both patterns below start at the first escape and
#: the literal characters in front of it are added afterwards by slicing: a
#: leading ``[^\\s]{0,64}`` in the pattern itself is retried from every
#: position of a long plain word, which is quadratic on padding.
_ESCAPE_RUN_RE = re.compile(r"(?:\\(?:x[0-9a-fA-F]{2}|u[0-9a-fA-F]{4}|[0-3][0-7]{2})[^\s\\]{0,64}){2,256}")
_ESCAPE_RE = re.compile(r"\\(?:x([0-9a-fA-F]{2})|u([0-9a-fA-F]{4})|([0-3][0-7]{2}))")
#: A word with at least two percent-escapes anywhere in it. Four consecutive
#: escapes used to be required, which ``cat%20/etc/passwd%3Bid`` never has.
_URL_RUN_RE = re.compile(r"(?:%[0-9a-fA-F]{2}[^\s%]{0,256}){2,256}")
#: Literal characters kept in front of the first escape of a word.
_WORD_PREFIX_CHARS = 256

_ASSIGNMENT_RE = re.compile(r"(?:^|[;&\s])([A-Za-z_][A-Za-z0-9_]{0,31})=(['\"]?)([A-Za-z0-9+/=_.:%\-]{2,1024})\2(?=[;&\s]|$)")
_REFERENCE_RE = re.compile(r"\$\{?([A-Za-z_][A-Za-z0-9_]{0,31})\}?")
_ECHO_APPEND_RE = re.compile(
    r"echo[ \t]+(?:-[neE]{1,3}[ \t]+)?['\"]?([A-Za-z0-9+/=]{4,4096})['\"]?[ \t]*>>?[ \t]*([^\s;|&]{1,128})"
)

#: Text is only accepted as "decoded" if it looks like something a shell would
#: run. Random bytes that happen to be valid base64 decode to noise, and
#: feeding that to the analyser produces confident nonsense.
_PRINTABLE_RE = re.compile(r"[\x09\x0a\x0d\x20-\x7e]*")
_STRUCTURE_RE = re.compile(r"[ /\-.:=;|&$(){}\[\]]")

#: Substrings that make a decoded candidate look like a command rather than
#: like text that merely happens to be printable. Used only to rank.
_COMMAND_MARKERS = (
    "http://", "https://", "/bin/", "/tmp/", "wget", "curl", "bash", "chmod",
    "python", "powershell", "iex", "echo ", " sh", "|", ";", "$(", "nc ",
)


@dataclass
class Layer:
    """One successful decode, kept so the chain can be shown to an analyst."""

    depth: int
    encoding: str
    source: str
    decoded: str
    #: Offset in the original text of the outermost encoded string this layer
    #: descends from, so a finding inside it can be traced to a recorded line.
    root_offset: int = -1

    def as_dict(self) -> dict:
        return {
            "depth": self.depth,
            "encoding": self.encoding,
            # Truncated: the record is evidence, not a payload store.
            "source": self.source[:200],
            "decoded": self.decoded[:2000],
        }


@dataclass
class Result:
    layers: List[Layer] = field(default_factory=list)
    #: Original text plus every decoded layer, for downstream tool/intent
    #: matching to run over.
    combined: str = ""
    #: True when the size budget stopped decoding early.
    truncated: bool = False

    @property
    def max_depth(self) -> int:
        return max((layer.depth for layer in self.layers), default=0)

    def as_dict(self) -> dict:
        return {
            "layers": [layer.as_dict() for layer in self.layers[:50]],
            "layer_count": len(self.layers),
            "max_depth": self.max_depth,
            "encodings": sorted({layer.encoding for layer in self.layers}),
            "truncated": self.truncated,
        }


def _looks_like_text(value: str) -> bool:
    if not value or len(value) < 4:
        return False
    if not _PRINTABLE_RE.fullmatch(value):
        return False
    # Decoded random bytes are printable surprisingly often; require some
    # structure a command would actually have.
    return bool(_STRUCTURE_RE.search(value)) or value.isalnum()


def _command_likeness(value: str) -> float:
    """How much a decoded string resembles a command. Ranking only."""
    sample = value[:4096].lower()
    score = sum(3.0 for marker in _COMMAND_MARKERS if marker in sample)
    return score + min(len(value), 400) / 400.0


def _inflate(raw: bytes) -> Optional[bytes]:
    """gzip or zlib data, decompressed up to a fixed size."""
    if len(raw) < 6:
        return None
    is_gzip = raw[:2] == b"\x1f\x8b"
    is_zlib = raw[0] == 0x78 and raw[1] in (0x01, 0x5E, 0x9C, 0xDA)
    if not is_gzip and not is_zlib:
        return None
    try:
        # wbits 47: accept either header.
        return zlib.decompressobj(47).decompress(raw, MAX_DECOMPRESSED_BYTES)
    except zlib.error:
        return None


def _bytes_to_text(raw: bytes, may_inflate: bool = True) -> Optional[Tuple[str, str]]:
    """Text carried by decoded bytes, and how it was wrapped ("" for plain)."""
    inflated = _inflate(raw) if may_inflate else None
    if inflated is not None:
        # One level only: compressed data inside compressed data is how a
        # small input is made to cost a large amount of work.
        inner = _bytes_to_text(inflated, may_inflate=False)
        return (inner[0], "+gzip" + inner[1]) if inner is not None else None
    # PowerShell's -EncodedCommand is UTF-16LE: every other byte is zero.
    if len(raw) >= 8 and len(raw) % 2 == 0 and raw[1::2].count(0) >= len(raw) // 2 * 0.8:
        try:
            return raw.decode("utf-16-le"), "+utf16le"
        except UnicodeDecodeError:
            return None
    try:
        return raw.decode("utf-8"), ""
    except UnicodeDecodeError:
        return None


def _try_base64(candidate: str) -> Optional[Tuple[str, str]]:
    # Base64 needs a length that is a multiple of four; attackers strip
    # padding often enough that restoring it is worth the attempt.
    padded = candidate + "=" * (-len(candidate) % 4)
    try:
        raw = base64.b64decode(padded, validate=True)
    except (binascii.Error, ValueError):
        return None
    return _bytes_to_text(raw)


def _try_hex(candidate: str) -> Optional[Tuple[str, str]]:
    try:
        raw = bytes.fromhex(candidate)
    except ValueError:
        return None
    return _bytes_to_text(raw)


def _decode_escape(match: re.Match) -> str:
    hex_byte, unicode_point, octal = match.groups()
    if hex_byte:
        return chr(int(hex_byte, 16))
    if unicode_point:
        return chr(int(unicode_point, 16))
    return chr(int(octal, 8))


def _try_escapes(candidate: str) -> Optional[Tuple[str, str]]:
    decoded = _ESCAPE_RE.sub(_decode_escape, candidate)
    return (decoded, "") if decoded != candidate else None


def _try_url(candidate: str) -> Optional[Tuple[str, str]]:
    decoded = urllib.parse.unquote(candidate)
    return (decoded, "") if decoded != candidate else None


def _plain_matches(pattern: re.Pattern) -> Callable[[str], Iterator[Tuple[int, str]]]:
    def find(chunk: str) -> Iterator[Tuple[int, str]]:
        for match in pattern.finditer(chunk):
            yield match.start(), match.group()
    return find


def _word_matches(pattern: re.Pattern) -> Callable[[str], Iterator[Tuple[int, str]]]:
    """Matches of a run pattern, widened back to the start of their word."""
    def find(chunk: str) -> Iterator[Tuple[int, str]]:
        for match in pattern.finditer(chunk):
            start = match.start()
            floor = max(0, start - _WORD_PREFIX_CHARS)
            while start > floor and not chunk[start - 1].isspace():
                start -= 1
            yield start, chunk[start : match.end()]
    return find


#: (encoding, candidate finder, decoder)
_DECODERS: Tuple[Tuple[str, Callable, Callable], ...] = (
    ("base64", _plain_matches(_B64_RE), _try_base64),
    ("hex", _plain_matches(_HEX_RE), _try_hex),
    ("hex_escape", _word_matches(_ESCAPE_RUN_RE), _try_escapes),
    ("url", _word_matches(_URL_RUN_RE), _try_url),
)


def _assembled(text: str) -> Iterator[Tuple[str, str, str, int]]:
    """Blobs that only exist once pieces of the text are put together.

    Yields (encoding, source, assembled text, offset). Two idioms: a value
    split across shell variables and re-joined by ``$a$b``, and one appended
    to a file a line at a time. Either defeats a decoder that looks at each
    string on its own.
    """
    variables = {}
    for match in _ASSIGNMENT_RE.finditer(text):
        if len(variables) >= 64:
            break
        variables[match.group(1)] = match.group(3)
    if variables:
        for line_match in re.finditer(r"[^\n]{1,4096}", text):
            line = line_match.group()
            if "$" not in line:
                continue
            used = [m.group(1) for m in _REFERENCE_RE.finditer(line) if m.group(1) in variables]
            if len(used) < 2:
                continue
            expanded = _REFERENCE_RE.sub(lambda m: variables.get(m.group(1), m.group()), line)
            yield "variables", line, expanded[:8192], line_match.start()

    pieces: dict = {}
    first_offset: dict = {}
    for match in _ECHO_APPEND_RE.finditer(text):
        target = match.group(2)
        pieces.setdefault(target, []).append(match.group(1))
        first_offset.setdefault(target, match.start())
    for target, parts in pieces.items():
        if len(parts) >= 2:
            yield "concatenated", f"{len(parts)} appends to {target}", "".join(parts)[:65_536], first_offset[target]


def _decode_chunk(chunk: str) -> Iterator[Tuple[str, str, str, int]]:
    """Every decodable candidate in one chunk: (encoding, source, text, offset)."""
    for encoding, finder, decoder in _DECODERS:
        found: List[Tuple[float, int, str, str, str]] = []
        tried = set()
        for attempt, (start, candidate) in enumerate(finder(chunk)):
            if attempt >= MAX_ATTEMPTS_PER_LAYER:
                break
            if candidate in tried:
                continue
            tried.add(candidate)
            outcome = decoder(candidate)
            if outcome is None:
                continue
            decoded, wrapping = outcome
            if decoded == candidate or not _looks_like_text(decoded):
                continue
            found.append((_command_likeness(decoded), start, encoding + wrapping, candidate, decoded))
        # Best first: the cap now drops the least command-like decodes, not
        # whichever candidates happened to be shortest.
        found.sort(key=lambda item: (-item[0], item[1]))
        for _, offset, name, candidate, decoded in found[:MAX_CANDIDATES_PER_LAYER]:
            yield name, candidate, decoded, offset
    yield from _assembled(chunk)


def deobfuscate(text: str) -> Result:
    """Unwrap nested encodings, returning each layer and the combined text."""
    result = Result(combined=text)
    if not text:
        return result

    budget = MAX_TOTAL_CHARS
    #: (chunk, offset of its outermost ancestor in the original text)
    frontier: List[Tuple[str, int]] = [(text, -1)]
    seen: set[str] = {text}

    for depth in range(1, MAX_DEPTH + 1):
        next_frontier: List[Tuple[str, int]] = []

        for chunk, root in frontier:
            for encoding, source, decoded, offset in _decode_chunk(chunk):
                if decoded in seen:
                    continue
                budget -= len(decoded)
                if budget <= 0:
                    result.truncated = True
                    return _finalise(result)

                seen.add(decoded)
                origin = offset if root < 0 else root
                result.layers.append(
                    Layer(depth=depth, encoding=encoding, source=source,
                          decoded=decoded, root_offset=origin)
                )
                next_frontier.append((decoded, origin))

        if not next_frontier:
            break
        frontier = next_frontier

    return _finalise(result)


def _finalise(result: Result) -> Result:
    if result.layers:
        result.combined = result.combined + "\n" + "\n".join(
            layer.decoded for layer in result.layers
        )
    return result


def deobfuscate_commands(commands: List[str]) -> Result:
    """Run the whole command list as one document.

    Attackers split an encoded blob across several lines (``echo A >> f``,
    ``echo B >> f``, ``base64 -d f | sh``), so decoding each command in
    isolation misses the payload that only exists once they are joined.
    """
    return deobfuscate("\n".join(commands))
