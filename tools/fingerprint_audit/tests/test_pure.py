"""The parts with no network in them: parsing, normalising, scoring."""

import hashlib
import struct

import pytest

from tools.fingerprint_audit import ftpwire, httpwire, similarity, sshwire, telnetwire
from tools.fingerprint_audit.checks import Check, compare, describe_bytes, escape_bytes, summarise
from tools.fingerprint_audit.net import parse_target
from tools.fingerprint_audit.normalise import mask_ipv4, mask_pasv, mask_token

from .fakes import KEX_LISTS, kexinit_payload


# ---------------------------------------------------------------- similarity

def test_byte_cosine_bounds():
    assert similarity.byte_cosine(b"220 ready\r\n", b"220 ready\r\n") == 1.0
    assert similarity.byte_cosine(b"", b"") == 1.0
    assert similarity.byte_cosine(b"", b"abc") == 0.0
    assert similarity.byte_cosine(b"aaa", b"bbb") == 0.0
    assert 0.0 < similarity.byte_cosine(b"220 vsFTPd", b"220 ProFTPD") < 1.0


def test_byte_cosine_ignores_order_so_it_is_not_a_match_test():
    assert similarity.byte_cosine(b"abc", b"cba") == pytest.approx(1.0)


def test_byte_cosine_known_value():
    # Counts (2,1) against (1,2): 4 / 5.
    assert similarity.byte_cosine(b"aab", b"abb") == pytest.approx(0.8)


def test_sequence_and_set_similarity():
    full = ["a", "b", "c", "d"]
    assert similarity.sequence_similarity(full, full) == 1.0
    assert similarity.sequence_similarity(full, ["x", "y"]) == 0.0
    assert 0.0 < similarity.sequence_similarity(full, ["b", "a", "c", "d"]) < 1.0
    assert similarity.sequence_similarity([], []) == 1.0
    assert similarity.set_similarity(["a", "b"], ["b", "a"]) == 1.0
    assert similarity.set_similarity(["a", "b"], ["b", "c"]) == pytest.approx(1 / 3)


def test_timing_tolerance():
    assert similarity.timings_match(0.001, 0.2)
    assert similarity.timings_match(120.0, 110.0)
    assert not similarity.timings_match(0.01, 2.0)
    assert similarity.timings_match(None, None)
    assert not similarity.timings_match(None, 1.0)
    assert similarity.timing_similarity(1.0, 2.0) == 0.5


# -------------------------------------------------------------------- checks

def test_escape_bytes_is_readable_and_reversible_looking():
    assert escape_bytes(b"220 ok\r\n\xff\x00\\") == "220 ok\\r\\n\\xff\\x00\\\\"


def test_describe_bytes_truncates_but_hashes_everything():
    stored = describe_bytes(b"x" * 10, limit=4)
    assert stored["text"] == "xxxx" and stored["truncated"] and stored["length"] == 10
    assert stored["sha256"] == hashlib.sha256(b"x" * 10).hexdigest()


def test_compare_scores_each_kind():
    decoy = [
        Check("a.raw", "raw", "bytes", b"hello"),
        Check("a.list", "list", "ordered", ["x", "y", "z"]),
        Check("a.flag", "flag", "exact", True),
        Check("a.time", "time", "timing", 0.01),
        Check("a.only_decoy", "only", "exact", 1),
    ]
    reference = [
        Check("a.raw", "raw", "bytes", b"hello"),
        Check("a.list", "list", "ordered", ["x", "z", "y"]),
        Check("a.flag", "flag", "exact", False),
        Check("a.time", "time", "timing", 3.0),
    ]
    rows = {row["id"]: row for row in compare(decoy, reference)}
    assert rows["a.raw"]["match"] and rows["a.raw"]["similarity"] == 1.0
    assert not rows["a.list"]["match"] and 0 < rows["a.list"]["similarity"] < 1
    assert not rows["a.flag"]["match"] and rows["a.flag"]["similarity"] == 0.0
    assert rows["a.time"]["informational"] and not rows["a.time"]["match"]
    assert rows["a.only_decoy"]["reference"]["error"] == "check not produced"
    summary = summarise(list(rows.values()))
    assert summary["checks"] == 4 and summary["matches"] == 1 and summary["mismatches"] == 3
    assert summary["informational_timing_rows"] == 1


def test_compare_does_not_confuse_true_with_one():
    row = compare([Check("a", "a", "exact", True)], [Check("a", "a", "exact", 1)])[0]
    assert not row["match"]


def test_a_probe_error_is_never_a_match():
    row = compare([Check("a", "a", "exact", None, error="refused")], [Check("a", "a", "exact", None)])[0]
    assert not row["match"]


# ----------------------------------------------------------------------- SSH

def test_parse_identification():
    parsed = sshwire.parse_identification(b"SSH-2.0-OpenSSH_8.2p1 Ubuntu-4ubuntu0.9")
    assert parsed == {
        "protocol_version": "2.0",
        "software_version": "OpenSSH_8.2p1",
        "comments": "Ubuntu-4ubuntu0.9",
    }
    assert sshwire.parse_identification(b"SSH-2.0-x")["comments"] is None
    for bad in (b"HTTP/1.1 200 OK", b"SSH-2.0", b"SSH--x"):
        with pytest.raises(sshwire.WireError):
            sshwire.parse_identification(bad)


def test_minimum_padding_matches_rfc_4253():
    # Whole packet a multiple of 8, with at least 4 bytes of padding.
    for payload_length in range(0, 64):
        padding = sshwire.minimum_padding(payload_length)
        assert 4 <= padding <= 11
        assert (4 + 1 + payload_length + padding) % 8 == 0


def test_packet_round_trip_and_incomplete_input():
    wire = sshwire.build_packet(b"\x14hello")
    packet, rest = sshwire.read_packet(wire + b"tail")
    assert packet.payload == b"\x14hello" and rest == b"tail" and packet.message == 20
    assert sshwire.read_packet(wire[:-1]) is None
    assert sshwire.read_packet(b"\x00\x00") is None
    with pytest.raises(sshwire.WireError):
        sshwire.read_packet(b"Invalid SSH identification string.\r\n")


def test_parse_kexinit_and_hassh():
    cookie = bytes(range(16))
    kexinit = sshwire.parse_kexinit(kexinit_payload(cookie=cookie))
    assert kexinit.cookie == cookie
    assert kexinit.lists == KEX_LISTS
    assert kexinit.first_kex_packet_follows is False and kexinit.reserved == 0
    fingerprint, source = sshwire.hassh_server(kexinit)
    assert source == (
        "curve25519-sha256,diffie-hellman-group14-sha256;aes128-ctr,aes256-ctr;hmac-sha2-256;none"
    )
    assert fingerprint == hashlib.md5(source.encode()).hexdigest()
    with pytest.raises(sshwire.WireError):
        sshwire.parse_kexinit(kexinit_payload()[:-3])


def test_padding_behaviour_tells_zero_from_random_padding():
    packet, _ = sshwire.read_packet(sshwire.build_packet(kexinit_payload()))
    assert sshwire.padding_behaviour(packet) == {
        "packet_is_multiple_of_8": True,
        "padding_is_minimum": True,
        "padding_bytes": "all-zero",
    }
    payload = b"\x14abc"
    random_padded = struct.pack(">IB", len(payload) + 13, 12) + payload + b"\x07" * 12
    packet, _ = sshwire.read_packet(random_padded)
    behaviour = sshwire.padding_behaviour(packet)
    assert behaviour["padding_bytes"] == "non-zero" and not behaviour["padding_is_minimum"]


def test_describe_stream_separates_text_from_packets():
    disconnect = bytes([1]) + struct.pack(">I", 2) + struct.pack(">I", 14) + b"Packet corrupt" + struct.pack(">I", 0)
    stream = sshwire.build_packet(kexinit_payload()) + sshwire.build_packet(disconnect)
    assert sshwire.describe_stream(stream) == [
        {"packet": "SSH_MSG_KEXINIT"},
        {"packet": "SSH_MSG_DISCONNECT", "reason_code": 2, "description": "Packet corrupt"},
    ]
    assert sshwire.describe_stream(b"Invalid SSH identification string.\r\n") == [
        {"text": "Invalid SSH identification string.\r\n"}
    ]
    assert sshwire.describe_stream(b"") == []


def test_blank_volatile_makes_two_kexinits_equal():
    first = sshwire.build_packet(kexinit_payload())
    second = sshwire.build_packet(kexinit_payload())
    assert first != second
    assert sshwire.blank_volatile(first) == sshwire.blank_volatile(second)
    assert sshwire.blank_volatile(b"plain text\r\n") == b"plain text\r\n"


# ---------------------------------------------------------------------- HTTP

RESPONSE = (
    b"HTTP/1.1 404 Not Found\r\nDate: Tue, 10 Nov 2026 01:02:03 GMT\r\n"
    b"Server: Apache/2.4.41 (Ubuntu)\r\nETag: W/\"abc\"\r\nContent-Length: 5\r\n\r\nhello"
)


def test_http_parse_keeps_order_and_spelling():
    response = httpwire.parse(RESPONSE + b"EXTRA")
    assert response.status_line == "HTTP/1.1 404 Not Found"
    assert response.header_names == ["Date", "Server", "ETag", "Content-Length"]
    assert response.header("server") == "Apache/2.4.41 (Ubuntu)"
    assert response.body == b"hello"
    assert httpwire.stable_header_values(response) == {
        "date": "<http-date>",
        "etag": "W/<etag>",
        "content-length": "5",
    }


def test_http_completeness():
    assert httpwire.is_complete(RESPONSE)
    assert not httpwire.is_complete(RESPONSE[:-1])
    assert not httpwire.is_complete(RESPONSE[:30])
    assert httpwire.is_complete(RESPONSE[:-5], head_request=True)
    assert httpwire.is_complete(b"HTTP/1.1 204 No Content\r\n\r\n")
    chunked = b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n3\r\nabc\r\n"
    assert not httpwire.is_complete(chunked)
    assert httpwire.is_complete(chunked + b"0\r\n\r\n")
    assert httpwire.parse(chunked + b"0\r\n\r\n").body == b"abc"
    # No framing: only the end of the stream ends it.
    assert not httpwire.is_complete(b"HTTP/1.0 200 OK\r\n\r\nbody")


def test_http_without_a_status_line_is_all_body():
    response = httpwire.parse(b"<html>bare</html>")
    assert response.status_line is None and response.headers == [] and response.body == b"<html>bare</html>"
    assert httpwire.parse(b"").status_line is None


def test_malformed_date_is_kept_as_a_difference():
    assert httpwire.normalise_header_value("Date", "10 Nov 2026") == "10 Nov 2026"
    assert httpwire.normalise_header_value("ETag", '"x"') == "<etag>"


# ----------------------------------------------------------------------- FTP

def test_ftp_single_and_multi_line_replies():
    reply, rest = ftpwire.read_reply(b"220 hello\r\n331 next\r\n")
    assert reply.code == 220 and reply.raw == b"220 hello\r\n" and rest == b"331 next\r\n"
    multi = b"211-Features:\r\n PASV\r\n 211 not the end\r\n211 End\r\n"
    reply, rest = ftpwire.read_reply(multi + b"x")
    assert reply.code == 211 and reply.raw == multi and rest == b"x"
    assert reply.lines[1] == " PASV"
    assert ftpwire.read_reply(b"211-Features:\r\n PASV\r\n") is None
    assert ftpwire.read_reply(b"220 no newline yet") is None


def test_ftp_non_reply_line_is_still_recorded():
    reply, _ = ftpwire.read_reply(b"SSH-2.0-OpenSSH\r\n")
    assert reply.code == 0


# -------------------------------------------------------------------- Telnet

def test_telnet_tokenize():
    stream = bytes([255, 253, 24, 255, 251, 1]) + b"login: " + bytes([255, 250, 24, 1, 255, 240, 255, 246])
    tokens, rest = telnetwire.tokenize(stream)
    assert rest == b""
    assert telnetwire.negotiation_labels(tokens) == [
        "DO TERMINAL-TYPE", "WILL ECHO", "SB TERMINAL-TYPE 01", "AYT",
    ]
    assert telnetwire.text_of(tokens) == b"login: "
    assert telnetwire.refuse_all(tokens) == bytes([255, 252, 24, 255, 254, 1])


def test_telnet_command_split_across_reads_and_escaped_iac():
    tokens, rest = telnetwire.tokenize(b"ab" + bytes([255, 253]))
    assert telnetwire.text_of(tokens) == b"ab" and rest == bytes([255, 253])
    tokens, rest = telnetwire.tokenize(rest + bytes([99]) + bytes([255, 255]))
    assert telnetwire.negotiation_labels(tokens) == ["DO OPTION-99"]
    assert telnetwire.text_of(tokens) == b"\xff" and rest == b""


# ----------------------------------------------------------------- normalise

def test_masks():
    assert mask_ipv4(b"220 ProFTPD Server [::ffff:172.18.0.2]") == b"220 ProFTPD Server [::ffff:<ip>]"
    assert mask_ipv4(b"Apache/2.4.41 vsFTPd 3.0.3") == b"Apache/2.4.41 vsFTPd 3.0.3"
    assert mask_pasv(b"227 Entering Passive Mode (127,0,0,1,195,80).") == (
        b"227 Entering Passive Mode (<h1,h2,h3,h4,p1,p2>)."
    )
    assert mask_token(b"web-01 login: ", b"web-01", b"<hostname>") == b"<hostname> login: "
    assert mask_token(b"unchanged", b"", b"<hostname>") == b"unchanged"


# ------------------------------------------------------------------- targets

def test_only_loopback_targets_are_accepted():
    assert str(parse_target("127.0.0.1:2222")) == "127.0.0.1:2222"
    assert str(parse_target("localhost:21")) == "127.0.0.1:21"
    assert str(parse_target("[::1]:22")) == "::1:22"
    for refused in ("192.0.2.10:22", "example.org:22", "127.0.0.1", "127.0.0.1:0"):
        with pytest.raises(ValueError):
            parse_target(refused)
