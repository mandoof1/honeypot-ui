"""Every probe set, run start to finish against in-process fake servers.

Two fakes that differ in known ways stand in for the decoy and the
reference, so the tests can assert both that the probes run and that the
differences planted are the differences reported.
"""

import json

import pytest

from tools.fingerprint_audit import ftp_probes, http_probes, ssh_probes, telnet_probes
from tools.fingerprint_audit.__main__ import main
from tools.fingerprint_audit.checks import compare
from tools.fingerprint_audit.net import Pacer
from tools.fingerprint_audit.probe import Prober, Settings

from . import fakes

#: No pacing and short waits: the fakes answer at once.
FAST = Settings(timeout=3.0, delay=0.0, quiet=0.3, idle_cap=0.6, login_attempts=5)


@pytest.fixture
def serve():
    """Start fake servers that are closed again after the test."""
    started = []

    def start(handler):
        server = fakes.FakeServer(handler)
        started.append(server)
        return server.target

    yield start
    for server in started:
        server.close()


def collect(module, target, settings=FAST):
    prober = Prober(target, settings, Pacer(settings.delay))
    checks = module.collect(prober)
    return {check.id: check for check in checks}, prober.errors


def rows_for(module, decoy, reference, settings=FAST):
    decoy_checks, decoy_errors = collect(module, decoy, settings)
    reference_checks, reference_errors = collect(module, reference, settings)
    assert decoy_errors == {} and reference_errors == {}
    rows = compare(list(decoy_checks.values()), list(reference_checks.values()))
    assert len({row["id"] for row in rows}) == len(rows)
    return {row["id"]: row for row in rows}, decoy_checks


def differing(rows):
    return {name for name, row in rows.items() if not row["match"] and not row["informational"]}


# ----------------------------------------------------------------------- FTP

def test_ftp_probe_set(serve):
    decoy = serve(fakes.ftp_handler())
    reference = serve(
        fakes.ftp_handler(
            greeting=b"220 ProFTPD Server (Debian) [::ffff:10.1.2.3]\r\n",
            unknown=b"500 FPAUDIT not understood\r\n",
        )
    )
    rows, checks = rows_for(ftp_probes, decoy, reference)

    assert differing(rows) == {"ftp.greeting", "ftp.after_login.unknown_command"}
    assert 0.0 < rows["ftp.greeting"]["similarity"] < 1.0
    assert checks["ftp.before_login.pass_before_user"].value == b"503 Login with USER first.\r\n"
    assert checks["ftp.before_login.syst"].value == b"530 Please login with USER and PASS.\r\n"
    assert checks["ftp.before_login.feat"].value.startswith(b"211-Features:")
    assert checks["ftp.after_login.pass"].value == b"230 Login successful.\r\n"
    assert checks["ftp.after_login.pasv"].value == b"227 Entering Passive Mode (<h1,h2,h3,h4,p1,p2>).\r\n"
    assert b"Connected to <ip>" in checks["ftp.after_login.stat"].value
    assert checks["ftp.after_login.quit.closes"].value is True
    assert checks["ftp.login.unknown_user.pass"].value == b"530 Login incorrect.\r\n"
    assert checks["ftp.login.repeated_wrong_password"].value == {
        "pass_replies": ["530 Login incorrect.\r\n"] * 3,
        "ended": "closed-by-server",
    }
    for name in ("user_5000", "line_70000"):
        assert checks[f"ftp.overlong.{name}"].value == b"500 Input line too long.\r\n"
        assert checks[f"ftp.overlong.{name}.closes"].value is True
    assert rows["ftp.reply_latency"]["informational"]


def test_ftp_address_masking_hides_only_the_address(serve):
    one = serve(fakes.ftp_handler(greeting=b"220 Server [::ffff:10.1.2.3]\r\n"))
    other = serve(fakes.ftp_handler(greeting=b"220 Server [::ffff:172.18.0.9]\r\n"))
    rows, checks = rows_for(ftp_probes, one, other)
    assert differing(rows) == set()
    assert checks["ftp.greeting"].value == b"220 Server [::ffff:<ip>]\r\n"
    assert "10.1.2.3" in checks["ftp.greeting"].evidence["raw"]


# ---------------------------------------------------------------------- HTTP

def test_http_probe_set(serve):
    decoy = serve(fakes.http_handler())
    reference = serve(
        fakes.http_handler(
            server=b"OtherHTTPd/2.0",
            order=(b"Server", b"Date", b"Content-Type", b"Content-Length"),
            not_found=b"<h1>404</h1>\n",
        )
    )
    rows, checks = rows_for(http_probes, decoy, reference)

    names = [probe.name for probe in http_probes.PROBES]
    assert differing(rows) == (
        {f"http.{name}.server" for name in names}
        | {f"http.{name}.header_names" for name in names}
        | {"http.get_missing.body", "http.get_missing.header_values"}
    )
    assert 0.0 < rows["http.get_root.header_names"]["similarity"] < 1.0
    assert 0.0 < rows["http.get_missing.body"]["similarity"] < 1.0

    status = {name: checks[f"http.{name}.status_line"].value for name in names}
    assert status["get_root"] == "HTTP/1.1 200 OK"
    assert status["get_missing"] == "HTTP/1.1 404 Not Found"
    assert status["head_root"] == "HTTP/1.1 200 OK"
    assert status["delete_root"] == "HTTP/1.1 405 Method Not Allowed"
    assert status["unknown_method"] == "HTTP/1.1 405 Method Not Allowed"
    assert status["malformed_request_line"] == "HTTP/1.1 400 Bad Request"
    assert status["http09_request"] == "HTTP/1.1 400 Bad Request"
    assert status["no_host_http11"] == "HTTP/1.1 400 Bad Request"
    assert status["uri_9000"] == "HTTP/1.1 414 Request-URI Too Long"
    assert status["uri_70000"] == "HTTP/1.1 414 Request-URI Too Long"
    assert status["http10_no_headers"] == "HTTP/1.1 200 OK"

    assert checks["http.get_root.header_names"].value == ["Date", "Server", "Content-Length", "Content-Type"]
    assert checks["http.get_root.server"].value == "FakeHTTPd/1.0"
    assert checks["http.get_root.header_values"].value["date"] == "<http-date>"
    assert checks["http.get_root.body"].value == b"<html>It works</html>\n"
    assert checks["http.head_root.body"].value == b""
    assert checks["http.head_root.header_values"].value["content-length"] == "22"
    assert checks["http.options_root.header_values"].value["allow"] == "GET,HEAD,OPTIONS"
    # Keep-alive by default, closed when asked or after an error.
    assert checks["http.get_root.closes"].value is False
    assert checks["http.connection_close.closes"].value is True
    assert checks["http.no_host_http11.closes"].value is True
    assert checks["http.keep_alive.second_request_answered"].value is True
    assert checks["http.keep_alive.connection_header"].value is None


def test_http_server_that_says_nothing_is_a_value_not_a_crash(serve):
    silent = serve(lambda connection: connection.recv(65536))
    checks, errors = collect(http_probes, silent, Settings(timeout=0.5, delay=0.0, quiet=0.2))
    assert errors == {}
    assert checks["http.get_root.status_line"].value is None
    assert checks["http.get_root.body"].value == b""
    assert checks["http.get_root.closes"].value is True


def test_a_dead_port_is_recorded_and_does_not_stop_the_run(serve):
    target = serve(fakes.http_handler())
    # A port that was just in use and now has nothing listening on it.
    dead = fakes.FakeServer(lambda connection: None)
    dead_target = dead.target
    dead.close()
    checks, errors = collect(http_probes, dead_target)
    assert "http.get_root" in errors and "ConnectionRefusedError" in errors["http.get_root"]
    live_checks, _ = collect(http_probes, target)
    rows = compare(list(live_checks.values()), list(checks.values()))
    get_root = next(row for row in rows if row["id"] == "http.get_root.status_line")
    assert not get_root["match"] and get_root["reference"]["error"] == "check not produced"


# -------------------------------------------------------------------- Telnet

def test_telnet_probe_set(serve):
    decoy = serve(fakes.telnet_handler(hostname=b"web-01", eager=True))
    reference = serve(fakes.telnet_handler(hostname=b"ref-focal"))
    rows, checks = rows_for(telnet_probes, decoy, reference)

    # The eager fake announces itself to a silent client and negotiates
    # differently; the login dialogue itself is the same once the hostname
    # is masked.
    assert differing(rows) == {
        "telnet.silent.negotiation",
        "telnet.silent.text",
        "telnet.refusing.negotiation",
    }
    assert checks["telnet.silent.negotiation"].value == ["WILL ECHO", "WILL SUPPRESS-GO-AHEAD"]
    assert checks["telnet.silent.text"].value == b"Fake OS 1.0\r\n<hostname> login: "
    assert checks["telnet.refusing.login_banner"].value == b"Fake OS 1.0\r\n<hostname> login: "
    assert checks["telnet.refusing.login_banner"].evidence["hostname"] == "web-01"
    assert checks["telnet.option.client_will_unknown"].value == {"commands": ["DONT OPTION-99"], "text": ""}
    assert checks["telnet.option.client_do_unknown"].value == {"commands": ["WONT OPTION-99"], "text": ""}
    assert checks["telnet.login.after_username"].value == b"Password: "
    assert checks["telnet.login.after_wrong_password"].value == b"\r\nLogin incorrect\r\n<hostname> login: "
    for account in ("root", "unknown_user"):
        assert checks[f"telnet.login.wrong_passwords.{account}"].value == {
            "wrong_passwords_sent": 3,
            "ended": "closed-by-server",
        }


def test_telnet_reference_side_waits_for_answers(serve):
    waiting = serve(fakes.telnet_handler())
    checks, errors = collect(telnet_probes, waiting)
    assert errors == {}
    assert checks["telnet.silent.negotiation"].value == ["DO TERMINAL-TYPE", "DO NAWS"]
    assert checks["telnet.silent.text"].value == b""
    assert checks["telnet.refusing.negotiation"].value == ["DO TERMINAL-TYPE", "DO NAWS"]


# ----------------------------------------------------------------------- SSH

def test_ssh_clear_text_probes_against_an_openssh_style_server(serve):
    target = serve(fakes.ssh_text_handler())
    prober = Prober(target, FAST, Pacer(0.0))
    checks = {}
    for group in (
        ssh_probes.identification_and_kexinit,
        ssh_probes.identification_replies,
        ssh_probes.packet_replies,
        ssh_probes.silent_client,
    ):
        checks.update({check.id: check for check in group(prober)})

    assert checks["ssh.ident.line"].value == "SSH-2.0-FakeSSH_1.0"
    assert checks["ssh.ident.line_ending"].value == "\\r\\n"
    for name in ("kex_algorithms", "server_host_key_algorithms", "mac_server_to_client"):
        assert checks[f"ssh.kexinit.{name}"].value == fakes.KEX_LISTS[name]
    assert checks["ssh.kexinit.languages"].value == [[], []]
    assert checks["ssh.kexinit.first_kex_packet_follows"].value == {
        "first_kex_packet_follows": False,
        "reserved": 0,
    }
    assert checks["ssh.kexinit.padding"].value["padding_bytes"] == "all-zero"
    assert len(checks["ssh.kexinit.hassh_server"].value) == 32
    assert checks["ssh.kexinit.unprompted_packets"].value == ["SSH_MSG_KEXINIT"]

    invalid = b"Invalid SSH identification string.\r\n"
    for name in ("no_software_version", "over_8192_bytes", "http_request"):
        assert checks[f"ssh.ident_reply.{name}.response"].value == invalid
        assert checks[f"ssh.ident_reply.{name}.closes"].value is True
    assert checks["ssh.ident_reply.protocol_1.response"].value == b"Protocol major versions differ.\r\n"
    # 300 bytes is over the RFC's limit but this server, like OpenSSH,
    # accepts it and carries on to its KEXINIT.
    accepted = checks["ssh.ident_reply.over_255_bytes.response"]
    assert accepted.evidence["parsed"] == [{"packet": "SSH_MSG_KEXINIT"}]
    assert checks["ssh.ident_reply.over_255_bytes.closes"].value is False

    assert checks["ssh.packet_reply.bad_length.response"].evidence["parsed"] == [
        {"packet": "SSH_MSG_DISCONNECT", "reason_code": 2, "description": "Packet corrupt"}
    ]
    assert checks["ssh.packet_reply.bad_length.closes"].value is True
    assert checks["ssh.packet_reply.unknown_message.response"].evidence["parsed"] == [
        {"packet": "SSH_MSG_UNIMPLEMENTED", "rejected_sequence_number": 0}
    ]

    assert checks["ssh.silent.response"].value == b"SSH-2.0-FakeSSH_1.0\r\n"
    assert checks["ssh.silent.closes_within_cap"].value is False
    assert checks["ssh.silent.disconnect_after"].value is None
    assert checks["ssh.silent.banner_delay"].value is not None


def test_ssh_whole_probe_set_against_a_real_ssh_server():
    """asyncssh on both ends: the clear-text probes and the authentication
    probes all run, and a server compared with itself matches everywhere
    even though its cookie and padding are random."""
    server = fakes.AsyncsshServer()
    try:
        settings = Settings(timeout=3.0, delay=0.0, quiet=0.3, idle_cap=0.6, login_attempts=2)
        rows, checks = rows_for(ssh_probes, server.target, server.target, settings)
    finally:
        server.close()

    assert differing(rows) == set()
    assert checks["ssh.ident.line"].value.startswith("SSH-2.0-AsyncSSH_")
    assert checks["ssh.kexinit.padding"].value["padding_bytes"] == "non-zero"
    assert "ssh-ed25519" in checks["ssh.kexinit.server_host_key_algorithms"].value
    # asyncssh's server also offers password by way of keyboard-interactive.
    assert checks["ssh.auth.methods.root"].value == ["keyboard-interactive", "password"]
    assert checks["ssh.auth.methods.unknown_user"].value == ["keyboard-interactive", "password"]
    assert checks["ssh.auth.banner"].value is None
    assert checks["ssh.auth.password.unknown_user"].value == {
        "outcome": "still-prompting",
        "wrong_passwords_sent": 2,
        "disconnect": None,
    }
    assert checks["ssh.transport.negotiated"].value["key_exchange"]
    assert checks["ssh.transport.negotiated"].value["server_to_client_cipher"]
    assert "ssh-ed25519" in checks["ssh.ext_info.server_sig_algs"].value
    assert checks["ssh.auth.failed_password_delay"].value is not None


# ----------------------------------------------------------------------- CLI

def test_command_line_writes_json_and_markdown(serve, tmp_path, monkeypatch, capsys):
    decoy = serve(fakes.http_handler())
    reference = serve(fakes.http_handler(server=b"OtherHTTPd/2.0"))
    monkeypatch.setenv("GIT_REVISION", "0123abc")
    out, table = tmp_path / "result.json", tmp_path / "result.md"
    code = main([
        "--decoy", str(decoy), "--reference", str(reference), "--protocol", "http",
        "--out", str(out), "--markdown", str(table),
        "--decoy-description", "fake decoy", "--reference-description", "fake reference 2.0",
        "--delay", "0", "--quiet", "0.3", "--timeout", "3",
    ])
    assert code == 0
    result = json.loads(out.read_text())
    assert result["protocol"] == "http"
    assert result["generated_at"].endswith("Z")
    assert result["tool"]["git_revision"] == "0123abc"
    assert result["tool"]["git_revision_source"] == "GIT_REVISION"
    assert result["decoy"] == {"address": str(decoy), "description": "fake decoy", "probe_errors": {}}
    assert result["reference"]["description"] == "fake reference 2.0"
    assert "loopback" in result["environment"]["network"]
    assert result["summary"]["mismatches"] == len(http_probes.PROBES)
    row = next(row for row in result["checks"] if row["id"] == "http.get_root.server")
    assert row["match"] is False and 0.0 <= row["similarity"] <= 1.0
    assert row["decoy"]["value"] == "FakeHTTPd/1.0" and row["reference"]["value"] == "OtherHTTPd/2.0"
    body = next(row for row in result["checks"] if row["id"] == "http.get_root.body")
    assert body["decoy"]["value"]["length"] == 22 and len(body["decoy"]["value"]["sha256"]) == 64

    text = table.read_text()
    assert "| `http.get_root.server` | exact | MISMATCH | " in text
    assert "| `http.get_root.status_line` | exact | match | 1.00 | `HTTP/1.1 200 OK` | `HTTP/1.1 200 OK` |" in text
    assert "Tool revision: 0123abc" in text and "fake reference 2.0" in text
    assert "differs  http.get_root.server" in capsys.readouterr().out


def test_command_line_refuses_a_target_that_is_not_loopback(tmp_path):
    with pytest.raises(SystemExit) as exit_info:
        main([
            "--decoy", "192.0.2.10:22", "--reference", "127.0.0.1:22",
            "--protocol", "ssh", "--out", str(tmp_path / "never.json"),
        ])
    assert exit_info.value.code == 2
    assert not (tmp_path / "never.json").exists()
