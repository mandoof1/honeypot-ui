"""The FTP decoy checks the password, answers consistently, and speaks the
dialect of the server its banner names.

The password used to be ignored — any password for a known user was accepted
on the first try, which is a fingerprint — and sizes and dates were random on
every call, so two listings of the same file disagreed. Every reply was
vsftpd's (or no server's) whatever the banner said, RETR sent random bytes of
a random length, and MKD, DELE and RNFR/RNTO changed nothing.

Identity seeds are fixed: seed 4 claims vsftpd, seed 3 ProFTPD.
"""

import asyncio
import ftplib
import io
import socket
import time

import pytest

from honeypot.core import honeytokens
from honeypot.core.config import config
from honeypot.core.identity import get_identity, reset_identity
from honeypot.core.session import session_manager
from honeypot.emulators.ftp import FTPHoneypot, FTPSessionState, _file_content, _stable_meta

VSFTPD, PROFTPD = 4, 3
PORT = 24610
PASV_RANGE = "24620-24639"


def _use_seed(monkeypatch, tmp_path, seed):
    monkeypatch.setattr(config, "session_capture_dir", str(tmp_path / f"cap-{seed}"))
    monkeypatch.setenv("HONEYPOT_IDENTITY_SEED", str(seed))
    reset_identity()


@pytest.fixture(autouse=True)
def _capture_dir(tmp_path, monkeypatch):
    monkeypatch.setattr(config, "enable_anti_fingerprinting", True)
    _use_seed(monkeypatch, tmp_path, VSFTPD)
    yield
    reset_identity()


@pytest.fixture
def ftp():
    return FTPHoneypot()


async def test_anonymous_accepts_any_password(ftp):
    state = FTPSessionState()
    ftp._cmd_user("anonymous", state)
    reply = await ftp._cmd_pass("anything@example.com", state, "sess")
    assert reply.startswith("230")
    assert state.authenticated


async def test_a_named_user_with_the_wrong_password_is_refused(ftp):
    state = FTPSessionState()
    ftp._cmd_user("admin", state)
    reply = await ftp._cmd_pass("not-the-password", state, "sess")
    assert reply.startswith("530")
    assert not state.authenticated


async def test_a_named_user_with_the_weak_password_gets_in(ftp):
    state = FTPSessionState()
    ftp._cmd_user("admin", state)
    reply = await ftp._cmd_pass("admin", state, "sess")
    assert reply.startswith("230")


async def test_brute_force_is_soft_accepted_after_several_tries(ftp):
    state = FTPSessionState()
    ftp._cmd_user("admin", state)
    for _ in range(3):
        await ftp._cmd_pass("wrong", state, "sess")
    reply = await ftp._cmd_pass("still-wrong", state, "sess")
    assert reply.startswith("230")


def test_listing_sizes_are_stable(ftp):
    state = FTPSessionState()
    first = ftp._listing("", state, names_only=False)
    second = ftp._listing("", state, names_only=False)
    assert first == second


def test_size_matches_the_listing(ftp):
    state = FTPSessionState()
    # readme.txt is in the root fake tree.
    size, _ = _stable_meta("/readme.txt")
    reply = ftp._cmd_size("readme.txt", state)
    assert reply.strip() == f"213 {size}"


def test_stat_reports_the_clients_address_not_zero(ftp):
    state = FTPSessionState()
    state.username = "anonymous"
    state.client_ip = "203.0.113.50"
    reply = ftp._cmd_stat(state)
    assert "Connected to 0.0.0.0" not in reply
    assert "     Connected to ::ffff:203.0.113.50\r\n" in reply
    assert reply.endswith("     vsFTPd 3.0.3 - secure, fast, stable\r\n211 End of status\r\n")


# -- one file, one answer -------------------------------------------------------

def test_modification_times_do_not_move_with_the_clock(ftp, monkeypatch):
    state = FTPSessionState()
    first = ftp._cmd_mdtm("readme.txt", state)
    # MDTM counted back from "now", so it changed from one second to the next.
    monkeypatch.setattr(time, "time", lambda: 4_000_000_000.0)
    assert ftp._cmd_mdtm("readme.txt", state) == first
    assert first.startswith("213 ") and len(first.strip()) == 18


def test_generated_files_are_deterministic_and_exactly_their_listed_size():
    for path in ("/readme.txt", "/pub/documents/data.csv", "/pub/files/backup.tar.gz", "/pub/software/update.exe"):
        content = _file_content(path)
        assert len(content) == _stable_meta(path)[0]
        assert content == _file_content(path)
    assert _file_content("/pub/files/backup.tar.gz").startswith(b"\x1f\x8b")
    assert _file_content("/pub/software/update.exe").startswith(b"MZ")
    # The planted backup is the same file the shell decoys show.
    assert _file_content("/config.bak") == honeytokens.get_honeytokens().config_backup().encode()


def test_files_differ_between_deployments(tmp_path, monkeypatch):
    here = (_stable_meta("/readme.txt"), _file_content("/pub/documents/notes.txt"))
    _use_seed(monkeypatch, tmp_path, 6)
    assert (_stable_meta("/readme.txt"), _file_content("/pub/documents/notes.txt")) != here


# -- a client sees its own changes ------------------------------------------------

def test_mkd_rmd_dele_and_rename_change_what_the_session_sees(ftp):
    state = FTPSessionState()
    assert ftp._cmd_mkd("drop", state) == '257 "/drop" created\r\n'
    assert ftp._cmd_mkd("drop", state).startswith("550")
    assert "drop\r\n" in ftp._listing("", state, names_only=True)
    assert ftp._cmd_cwd("drop", state).startswith("250")
    assert state.cwd == "/drop"
    ftp._cmd_cdup(state)

    assert ftp._cmd_dele("readme.txt", state) == "250 Delete operation successful.\r\n"
    assert ftp._cmd_dele("readme.txt", state) == "550 Delete operation failed.\r\n"
    assert "readme.txt" not in ftp._listing("", state, names_only=True)
    assert ftp._cmd_size("readme.txt", state).startswith("550")

    assert ftp._cmd_rnto("x", state) == "503 RNFR required first.\r\n"
    assert ftp._cmd_rnfr("config.bak", state) == "350 Ready for RNTO.\r\n"
    assert ftp._cmd_rnto("drop/old.bak", state) == "250 Rename successful.\r\n"
    assert ftp._listing("/drop", state, names_only=True) == "old.bak\r\n"
    # The renamed file is still the same file.
    assert ftp._cmd_size("/drop/old.bak", state).strip() == f"213 {_stable_meta('/config.bak')[0]}"

    assert ftp._cmd_rmd("drop", state) == "550 Remove directory operation failed.\r\n"
    ftp._cmd_dele("drop/old.bak", state)
    assert ftp._cmd_rmd("drop", state) == "250 Remove directory operation successful.\r\n"
    assert ftp._cmd_cwd("drop", state).startswith("550")

    # A directory moves with what is in it.
    ftp._cmd_rnfr("pub", state)
    assert ftp._cmd_rnto("public", state).startswith("250")
    assert "notes.txt" in ftp._listing("/public/documents", state, names_only=True)

    # Another client's tree is untouched.
    other = FTPSessionState()
    assert "readme.txt" in ftp._listing("", other, names_only=True)
    assert "pub\r\n" in ftp._listing("", other, names_only=True)


def test_a_sessions_tree_is_bounded(ftp):
    state = FTPSessionState()
    replies = [ftp._cmd_mkd(f"d{n}", state) for n in range(600)]
    assert replies[0].startswith("257") and replies[-1].startswith("550")
    assert len(state.tree.dirs) + len(state.tree.files) <= state.tree.MAX_ENTRIES


# -- two dialects -------------------------------------------------------------------

@pytest.fixture
async def server(tmp_path, monkeypatch):
    """A decoy over the wire: ``start(seed)`` returns a logged-in ftplib client."""
    monkeypatch.setattr(config, "bind_address", "127.0.0.1")
    monkeypatch.setattr(config, "enable_anti_fingerprinting", False)
    monkeypatch.setattr(config, "ftp_pasv_ports", PASV_RANGE)
    monkeypatch.setattr(config, "ftp_pasv_address", "127.0.0.1")
    monkeypatch.setattr(config, "file_capture_dir", str(tmp_path / "uploads"))

    async def swallow(session):
        return None

    monkeypatch.setattr(session_manager, "_send_to_backend", swallow)
    running = []

    async def start(seed):
        _use_seed(monkeypatch, tmp_path, seed)
        honeypot = FTPHoneypot()
        honeypot.port = PORT
        await honeypot.start()
        running.append(honeypot)

    yield start
    for honeypot in running:
        await honeypot.stop()


def _login():
    client = ftplib.FTP()
    banner = client.connect("127.0.0.1", PORT, timeout=10)
    client.login("anonymous", "probe@example.com")
    return client, banner


def _say(client, command):
    """One command's reply, whatever its code."""
    try:
        return client.sendcmd(command)
    except ftplib.Error as exc:
        return str(exc)


async def test_vsftpd_speaks_vsftpd(server):
    await server(VSFTPD)

    def session():
        client, banner = _login()
        replies = {c: _say(client, c) for c in (
            "XYZZY", "SIZE nope", "MDTM nope", "CWD nope", "CWD /pub", "PWD",
            "TYPE I", "NOOP", "FEAT", "HELP", "MKD made", "DELE nope", "SITE FOO",
            "MLSD", "OPTS UTF8 ON", "REST 5",
        )}
        client.quit()
        return banner, replies

    banner, replies = await asyncio.to_thread(session)
    assert banner == "220 (vsFTPd 3.0.3)"
    # It was "502 Command not implemented: XYZZY", which neither server says.
    assert replies["XYZZY"] == "500 Unknown command."
    assert replies["MLSD"] == "500 Unknown command."
    assert replies["SIZE nope"] == "550 Could not get file size."
    assert replies["MDTM nope"] == "550 Could not get file modification time."
    assert replies["CWD nope"] == "550 Failed to change directory."
    assert replies["CWD /pub"] == "250 Directory successfully changed."
    assert replies["PWD"] == '257 "/pub" is the current directory'
    assert replies["TYPE I"] == "200 Switching to Binary mode."
    assert replies["NOOP"] == "200 NOOP ok."
    assert replies["MKD made"] == '257 "/pub/made" created'
    assert replies["DELE nope"] == "550 Delete operation failed."
    assert replies["SITE FOO"] == "500 Unknown SITE command."
    assert replies["OPTS UTF8 ON"] == "200 Always in UTF8 mode."
    assert replies["REST 5"] == "350 Restart position accepted (5)."
    assert replies["FEAT"].split("\n") == [
        "211-Features:", " EPRT", " EPSV", " MDTM", " PASV", " REST STREAM",
        " SIZE", " TVFS", " UTF8", "211 End",
    ]
    assert replies["HELP"].startswith("214-The following commands are recognized.\n ABOR ACCT ALLO")
    assert replies["HELP"].endswith("214 Help OK.")


async def test_proftpd_speaks_proftpd(server):
    await server(PROFTPD)

    def session():
        client = ftplib.FTP()
        banner = client.connect("127.0.0.1", PORT, timeout=10)
        user = _say(client, "USER anonymous")
        password = _say(client, "PASS probe@example.com")
        replies = {c: _say(client, c) for c in (
            "XYZZY", "SIZE readme.txt", "TYPE I", "SIZE readme.txt", "SIZE nope",
            "CWD nope", "CWD /pub", "NOOP", "FEAT", "HELP", "MKD made",
            "DELE nope", "STAT", "MLST documents", "RNTO x", "CLNT probe 1.0",
        )}
        listing = []
        client.retrlines("MLSD", listing.append)
        plain = []
        client.retrlines("LIST", plain.append)
        client.quit()
        return banner, user, password, replies, listing, plain

    banner, user, password, replies, listing, plain = await asyncio.to_thread(session)
    identity = get_identity()
    assert banner == f"220 ProFTPD 1.3.6c Server (Debian) [::ffff:{identity.ip}]"
    assert user == "331 Anonymous login ok, send your complete email address as your password"
    assert password == "230 Anonymous access granted, restrictions apply"
    assert replies["XYZZY"] == "500 XYZZY not understood"
    assert replies["CWD nope"] == "550 nope: No such file or directory"
    assert replies["CWD /pub"] == "250 CWD command successful"
    assert replies["NOOP"] == "200 NOOP command successful"
    assert replies["TYPE I"] == "200 Type set to I"
    assert replies["MKD made"] == '257 "/pub/made" - Directory successfully created'
    assert replies["DELE nope"] == "550 nope: No such file or directory"
    assert replies["RNTO x"] == "503 Bad sequence of commands"
    assert replies["SIZE nope"] == "550 nope: No such file or directory"
    assert " MLST modify*;perm*;size*;" in replies["FEAT"] and " SITE COPY" in replies["FEAT"]
    assert replies["HELP"].endswith(f"214 Direct comments to root@{identity.fqdn}")
    assert "211-Status of 'Debian'" in replies["STAT"]
    assert " Connected from ::ffff:127.0.0.1 (::ffff:127.0.0.1)" in replies["STAT"]
    assert replies["MLST documents"].startswith("250-Start of list for /pub/documents\n modify=")
    # What its FEAT advertises works: MLSD lists facts, LIST its own layout.
    names = {line.rsplit(" ", 1)[-1] for line in listing}
    assert names == {"documents", "files", "made", "software"}
    assert all(line.startswith("modify=") and "type=dir;" in line for line in listing)
    assert all(line.startswith("drwxr-xr-x   2 ftp      ftp ") for line in plain)


async def test_proftpd_will_not_size_a_file_in_ascii_type(server):
    await server(PROFTPD)

    def session():
        client, _ = _login()
        before = _say(client, "SIZE readme.txt")
        client.sendcmd("TYPE I")
        after = _say(client, "SIZE readme.txt")
        client.quit()
        return before, after

    before, after = await asyncio.to_thread(session)
    assert before == "550 SIZE not allowed in ASCII mode"
    assert after == f"213 {_stable_meta('/readme.txt')[0]}"


@pytest.mark.parametrize("seed", [VSFTPD, PROFTPD])
async def test_list_size_mdtm_and_retr_agree_and_repeat(server, seed):
    await server(seed)

    def session():
        client, _ = _login()
        client.cwd("/pub/documents")
        listing = []
        client.retrlines("LIST", listing.append)
        client.sendcmd("TYPE I")
        size = int(client.sendcmd("SIZE notes.txt").split()[1])
        stamp = client.sendcmd("MDTM notes.txt")
        downloads = []
        for _ in range(2):
            buffer = io.BytesIO()
            client.retrbinary("RETR notes.txt", buffer.write)
            downloads.append(buffer.getvalue())
        again = client.sendcmd("MDTM notes.txt")
        client.quit()
        return listing, size, stamp, again, downloads

    listing, size, stamp, again, downloads = await asyncio.to_thread(session)
    [line] = [entry for entry in listing if entry.endswith(" notes.txt")]
    # RETR used to send 512-4096 random bytes, new ones each time.
    assert int(line.split()[4]) == size == len(downloads[0])
    assert downloads[0] == downloads[1] == _file_content("/pub/documents/notes.txt")
    assert stamp == again


@pytest.mark.parametrize("seed", [VSFTPD, PROFTPD])
async def test_active_mode_is_acknowledged_and_never_connected(server, seed):
    await server(seed)
    listener = socket.socket()
    listener.bind(("127.0.0.1", 0))
    listener.listen(1)
    listener.settimeout(0.5)
    port = listener.getsockname()[1]

    def session():
        client, _ = _login()
        own = _say(client, f"PORT 127,0,0,1,{port // 256},{port % 256}")
        transfer = _say(client, "LIST")
        # Naming someone else's address is the FTP bounce both servers refuse.
        bounce = _say(client, "PORT 198,51,100,7,0,80")
        client.quit()
        return own, transfer, bounce

    own, transfer, bounce = await asyncio.to_thread(session)
    assert own.startswith("200 PORT command successful")
    assert transfer.startswith("425 ")
    assert bounce.startswith("500 Illegal PORT command")
    # The engine never connects out, to the client or to anyone.
    with pytest.raises(socket.timeout):
        listener.accept()
    listener.close()


async def test_the_banner_never_names_the_product(server, monkeypatch):
    await server(VSFTPD)
    # Jitter off used to mean "220 (HoneySentinel FTP 1.0)".
    monkeypatch.setattr(config, "enable_anti_fingerprinting", False)
    client, banner = await asyncio.to_thread(_login)
    await asyncio.to_thread(client.quit)
    assert banner == "220 (vsFTPd 3.0.3)"
