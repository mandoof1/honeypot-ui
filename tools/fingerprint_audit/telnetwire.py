"""Telnet option negotiation, separated from the text around it (RFC 854/855).

A telnet server's first bytes are commands, not text: which options it asks
for, in which order, and how it answers a refusal differ between telnetd
implementations and are visible before any login prompt.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Optional

IAC = 255
DONT, DO, WONT, WILL = 254, 253, 252, 251
SB, SE = 250, 240

VERBS = {WILL: "WILL", WONT: "WONT", DO: "DO", DONT: "DONT"}

#: Two-byte commands (IAC + one of these).
SIMPLE_COMMANDS = {
    241: "NOP", 242: "DM", 243: "BRK", 244: "IP", 245: "AO",
    246: "AYT", 247: "EC", 248: "EL", 249: "GA", 239: "EOR",
}

#: Option names from the IANA telnet options registry, for the ones a login
#: server is likely to mention. Anything else is shown by number.
OPTIONS = {
    0: "BINARY", 1: "ECHO", 3: "SUPPRESS-GO-AHEAD", 5: "STATUS",
    6: "TIMING-MARK", 24: "TERMINAL-TYPE", 31: "NAWS", 32: "TERMINAL-SPEED",
    33: "REMOTE-FLOW-CONTROL", 34: "LINEMODE", 35: "X-DISPLAY-LOCATION",
    36: "OLD-ENVIRON", 37: "AUTHENTICATION", 38: "ENCRYPT", 39: "NEW-ENVIRON",
}


def option_name(option: int) -> str:
    return OPTIONS.get(option, f"OPTION-{option}")


@dataclass(frozen=True)
class Token:
    """One piece of a telnet stream.

    kind is "data" (``data`` holds the text bytes), "negotiation" (``verb``
    and ``option``), "subnegotiation" (``option`` and ``data``) or "command"
    (``verb`` holds the command's name).
    """

    kind: str
    verb: Optional[str] = None
    option: Optional[int] = None
    data: bytes = b""

    def label(self) -> str:
        if self.kind == "negotiation":
            return f"{self.verb} {option_name(self.option)}"
        if self.kind == "subnegotiation":
            return f"SB {option_name(self.option)} {self.data.hex()}"
        if self.kind == "command":
            return str(self.verb)
        return "data"


def tokenize(data: bytes) -> tuple[list[Token], bytes]:
    """Split a stream into tokens.

    Returns the tokens and any trailing bytes that are the start of a
    command still arriving, to be put in front of the next read.
    """
    tokens: list[Token] = []
    text = bytearray()
    at = 0

    def flush() -> None:
        if text:
            tokens.append(Token("data", data=bytes(text)))
            text.clear()

    while at < len(data):
        byte = data[at]
        if byte != IAC:
            text.append(byte)
            at += 1
            continue
        if at + 1 >= len(data):
            break
        command = data[at + 1]
        if command == IAC:
            # An escaped 0xFF data byte.
            text.append(IAC)
            at += 2
        elif command in VERBS:
            if at + 2 >= len(data):
                break
            flush()
            tokens.append(Token("negotiation", verb=VERBS[command], option=data[at + 2]))
            at += 3
        elif command == SB:
            end = data.find(bytes([IAC, SE]), at + 2)
            if end < 0 or at + 2 >= len(data):
                break
            flush()
            tokens.append(Token("subnegotiation", option=data[at + 2], data=data[at + 3:end]))
            at = end + 2
        else:
            flush()
            tokens.append(Token("command", verb=SIMPLE_COMMANDS.get(command, f"COMMAND-{command}")))
            at += 2
    flush()
    return tokens, data[at:]


def text_of(tokens: list[Token]) -> bytes:
    """The data bytes of a token list, commands removed."""
    return b"".join(token.data for token in tokens if token.kind == "data")


def negotiation_labels(tokens: list[Token]) -> list[str]:
    """Every command in a token list, in order, as readable labels."""
    return [token.label() for token in tokens if token.kind != "data"]


def refuse_all(tokens: list[Token]) -> bytes:
    """The replies of a client that agrees to nothing.

    DO is answered WONT and WILL is answered DONT, as RFC 855 requires of a
    side that will not enable an option. DONT and WONT need no answer, and a
    sub-negotiation for an option that was refused is ignored.
    """
    reply = bytearray()
    for token in tokens:
        if token.kind != "negotiation":
            continue
        if token.verb == "DO":
            reply += bytes([IAC, WONT, token.option])
        elif token.verb == "WILL":
            reply += bytes([IAC, DONT, token.option])
    return bytes(reply)
