"""SSH probes that read the wire directly.

Everything here happens before encryption starts, which is where a
transport library gives itself away: the identification line, the KEXINIT,
and what the server does with input it should reject. The part of the
protocol that needs a completed key exchange is in ssh_auth.py.
"""

from __future__ import annotations

from . import sshwire
from .checks import Check, escape_bytes
from .net import Connection, seconds
from .probe import Prober

#: The client identification every well-formed probe sends. A current
#: OpenSSH client string, for which OpenSSH applies no compatibility quirks.
CLIENT_SOFTWARE = "OpenSSH_8.9p1"
CLIENT_IDENT = f"SSH-2.0-{CLIENT_SOFTWARE}".encode("ascii")

#: Client identifications a server should refuse, or at least react to.
IDENT_VARIANTS = (
    (
        "no_software_version",
        "client identification with no software version (SSH-2.0)",
        b"SSH-2.0\r\n",
    ),
    (
        "protocol_1",
        "client identification claiming protocol 1.5",
        b"SSH-1.5-FingerprintAudit\r\n",
    ),
    (
        "over_255_bytes",
        "client identification of 300 bytes (RFC 4253 allows 255)",
        b"SSH-2.0-" + b"A" * 290 + b"\r\n",
    ),
    (
        "over_8192_bytes",
        "client identification of 9010 bytes",
        b"SSH-2.0-" + b"A" * 9000 + b"\r\n",
    ),
    (
        "http_request",
        "an HTTP request as the first line instead of an identification",
        b"GET / HTTP/1.1\r\nHost: localhost\r\n\r\n",
    ),
)

#: Bytes sent where the client's first binary packet belongs, after a valid
#: identification exchange.
PACKET_VARIANTS = (
    (
        "bad_length",
        "64 bytes of 0xff in place of the first packet (a packet length of 4294967295)",
        b"\xff" * 64,
    ),
    (
        "unknown_message",
        "a well-formed packet with unassigned message number 192, before any KEXINIT",
        sshwire.build_packet(bytes([192]) + b"fingerprint-audit"),
    ),
)


def _read_identification(conn: Connection, timeout: float) -> tuple[bytes, bytes]:
    """The server's identification line with its line ending, and whatever
    arrived after it in the same read."""
    data = conn.read_until(lambda buffer: b"\n" in buffer, timeout)
    line, newline, rest = data.partition(b"\n")
    return line + newline, rest


def _holds_packet(buffer: bytes) -> bool:
    """True once the buffer holds a whole packet, or cannot be one."""
    try:
        return sshwire.read_packet(buffer) is not None
    except sshwire.WireError:
        return True


def _close_evidence(conn: Connection) -> dict:
    return {"closed": conn.closed, "closed_after_seconds": seconds(conn.closed_after)}


def identification_and_kexinit(prober: Prober) -> list[Check]:
    settings = prober.settings
    with prober.connect() as conn:
        ident, rest = _read_identification(conn, settings.timeout)
        conn.send(CLIENT_IDENT + b"\r\n")
        stream = conn.read_until(_holds_packet, settings.timeout, initial=rest)
        # Whatever else the server volunteers before the client's KEXINIT.
        stream = conn.read_quiet(settings.quiet, settings.quiet * 2, initial=stream)
    prober.keep_raw("ssh.kexinit", ident + stream)

    line = ident.rstrip(b"\r\n")
    raw_ident = {"raw": escape_bytes(ident)}
    checks = [
        Check(
            "ssh.ident.line",
            "server identification string",
            "exact",
            line.decode("latin-1"),
            raw_ident,
        ),
        Check(
            "ssh.ident.line_ending",
            "line ending of the server identification",
            "exact",
            escape_bytes(ident[len(line):]),
            raw_ident,
        ),
    ]

    try:
        parsed = sshwire.read_packet(stream)
    except sshwire.WireError:
        parsed = None
    if parsed is None or parsed[0].message != sshwire.MSG_KEXINIT:
        error = "no KEXINIT received after the identification exchange"
        evidence = {"received": escape_bytes(stream[:512])}
        return checks + [Check("ssh.kexinit", "server KEXINIT", "exact", None, evidence, error)]

    packet = parsed[0]
    kexinit = sshwire.parse_kexinit(packet.payload)
    lists = kexinit.lists
    for name in sshwire.KEXINIT_LISTS[:8]:
        checks.append(
            Check(
                f"ssh.kexinit.{name}",
                f"KEXINIT {name.replace('_', ' ')} name-list, in order",
                "ordered",
                lists[name],
            )
        )
    checks.append(
        Check(
            "ssh.kexinit.languages",
            "KEXINIT language name-lists (client to server, server to client)",
            "exact",
            [lists["languages_client_to_server"], lists["languages_server_to_client"]],
        )
    )
    checks.append(
        Check(
            "ssh.kexinit.first_kex_packet_follows",
            "KEXINIT first_kex_packet_follows flag and reserved field",
            "exact",
            {
                "first_kex_packet_follows": kexinit.first_kex_packet_follows,
                "reserved": kexinit.reserved,
            },
        )
    )
    checks.append(
        Check(
            "ssh.kexinit.padding",
            "how the KEXINIT packet is padded",
            "exact",
            sshwire.padding_behaviour(packet),
            {
                "packet_length": packet.packet_length,
                "padding_length": packet.padding_length,
                "payload_length": len(packet.payload),
                "padding": packet.padding.hex(),
            },
        )
    )
    fingerprint, source = sshwire.hassh_server(kexinit)
    checks.append(
        Check(
            "ssh.kexinit.hassh_server",
            "hasshServer (MD5 of kex;encryption;MAC;compression, server to client)",
            "exact",
            fingerprint,
            {"hassh_server_string": source},
        )
    )
    checks.append(
        Check(
            "ssh.kexinit.unprompted_packets",
            "packets the server sends before the client's own KEXINIT",
            "ordered",
            [item.get("packet", "text") for item in sshwire.describe_stream(stream)],
        )
    )
    return checks


def _reply_checks(prefix: str, description: str, sent: bytes, reply: bytes, conn: Connection) -> list[Check]:
    evidence = {
        "sent": escape_bytes(sent[:160]) + ("..." if len(sent) > 160 else ""),
        "sent_length": len(sent),
        "parsed": sshwire.describe_stream(reply),
        **_close_evidence(conn),
    }
    return [
        Check(
            f"{prefix}.response",
            f"bytes sent back for {description}",
            "bytes",
            # Cookie and padding zeroed: they differ on every connection.
            sshwire.blank_volatile(reply),
            evidence,
        ),
        Check(
            f"{prefix}.closes",
            f"whether the server closes the connection after {description}",
            "exact",
            conn.closed is not None,
            _close_evidence(conn),
        ),
    ]


def identification_replies(prober: Prober) -> list[Check]:
    """What the server sends back for each bad client identification."""
    settings = prober.settings
    checks: list[Check] = []
    for name, description, sent in IDENT_VARIANTS:
        with prober.connect() as conn:
            _ident, rest = _read_identification(conn, settings.timeout)
            conn.send(sent)
            reply = conn.read_quiet(settings.quiet, settings.timeout, initial=rest)
            prober.keep_raw(f"ssh.ident_reply.{name}", reply)
            checks += _reply_checks(f"ssh.ident_reply.{name}", description, sent, reply, conn)
    return checks


def packet_replies(prober: Prober) -> list[Check]:
    """What the server does with a bad first packet. The comparison starts
    after the server's own KEXINIT, which the KEXINIT checks already cover."""
    settings = prober.settings
    checks: list[Check] = []
    for name, description, sent in PACKET_VARIANTS:
        with prober.connect() as conn:
            _ident, rest = _read_identification(conn, settings.timeout)
            conn.send(CLIENT_IDENT + b"\r\n")
            stream = conn.read_until(_holds_packet, settings.timeout, initial=rest)
            try:
                parsed = sshwire.read_packet(stream)
            except sshwire.WireError:
                parsed = None
            after_kexinit = parsed[1] if parsed else stream
            conn.send(sent)
            reply = conn.read_quiet(settings.quiet, settings.timeout, initial=after_kexinit)
            prober.keep_raw(f"ssh.packet_reply.{name}", reply)
            checks += _reply_checks(f"ssh.packet_reply.{name}", description, sent, reply, conn)
    return checks


def silent_client(prober: Prober) -> list[Check]:
    """Connect and say nothing: what arrives unasked, how fast, and how long
    the server tolerates the silence (up to the configured cap)."""
    cap = prober.settings.idle_cap
    with prober.connect() as conn:
        stream = conn.wait_closed(cap)
        banner_delay = conn.first_byte_after
        closed_after = conn.closed_after
        evidence = {"cap_seconds": cap, "parsed": sshwire.describe_stream(stream), **_close_evidence(conn)}
    prober.keep_raw("ssh.silent", stream)
    return [
        Check(
            "ssh.silent.response",
            "everything the server sends to a client that sends nothing",
            "bytes",
            sshwire.blank_volatile(stream),
            evidence,
        ),
        Check(
            "ssh.silent.closes_within_cap",
            f"whether the server drops a silent client within {cap:g} s",
            "exact",
            closed_after is not None,
            evidence,
        ),
        Check(
            "ssh.silent.banner_delay",
            "seconds from connect to the first byte of the identification",
            "timing",
            seconds(banner_delay),
        ),
        Check(
            "ssh.silent.disconnect_after",
            "seconds until the server drops a silent client (none within the cap: null)",
            "timing",
            seconds(closed_after),
            {"cap_seconds": cap},
        ),
    ]


def collect(prober: Prober) -> list[Check]:
    from . import ssh_auth

    checks: list[Check] = []
    checks += prober.run("ssh.identification_and_kexinit", identification_and_kexinit)
    checks += prober.run("ssh.identification_replies", identification_replies)
    checks += prober.run("ssh.packet_replies", packet_replies)
    checks += prober.run("ssh.silent_client", silent_client)
    checks += prober.run("ssh.authentication", ssh_auth.collect)
    return checks
