"""The FTP decoy answers the way vsftpd 3.0.3 and ProFTPD 1.3.6 answered.

Every expected reply here is copied from the reference side of
docs/evaluation/fingerprint/baseline/ftp-vsftpd-focal.json and
ftp-proftpd-focal.json, the first probe-by-probe comparison of the decoy with
the real daemons; each test sends what the named probe sent
(tools/fingerprint_audit/ftp_probes.py). The check id is in each test's
docstring. The identity seeds are the ones that comparison used: 8 claims
vsftpd, 75 ProFTPD.
"""

import asyncio
import dataclasses
import re
import time

import pytest

from honeypot.core.config import HoneypotConfig, config
from honeypot.core.identity import get_identity, reset_identity
from honeypot.core.session import session_manager
from honeypot.emulators.ftp import FTPHoneypot

PORT = 24630
VSFTPD, PROFTPD = 8, 75

_LAST_LINE = re.compile(rb"(?:^|\r\n)\d{3} [^\r\n]*\r\n$")


@pytest.fixture
async def server(tmp_path, monkeypatch):
    """``await server(seed)`` starts the decoy with that identity."""
    monkeypatch.setattr(config, "bind_address", "127.0.0.1")
    monkeypatch.setattr(config, "file_capture_dir", str(tmp_path / "uploads"))

    async def discard(session):
        return None

    monkeypatch.setattr(session_manager, "_send_to_backend", discard)
    running = []

    async def start(seed):
        monkeypatch.setattr(config, "session_capture_dir", str(tmp_path / f"cap-{seed}"))
        monkeypatch.setenv("HONEYPOT_IDENTITY_SEED", str(seed))
        reset_identity()
        honeypot = FTPHoneypot()
        honeypot.port = PORT
        await honeypot.start()
        running.append(honeypot)
        return honeypot

    yield start
    for honeypot in running:
        await honeypot.stop()
    reset_identity()


class _Control:
    """A control connection read as raw bytes, one whole reply at a time."""

    def __init__(self, reader, writer, greeting: bytes) -> None:
        self.reader, self.writer, self.greeting = reader, writer, greeting

    @classmethod
    async def open(cls) -> "_Control":
        reader, writer = await asyncio.open_connection("127.0.0.1", PORT)
        control = cls(reader, writer, b"")
        control.greeting = await control.reply()
        return control

    async def reply(self) -> bytes:
        """The next reply, multi-line ones included, or what arrived before
        the server closed."""
        data = b""
        while not _LAST_LINE.search(data):
            chunk = await asyncio.wait_for(self.reader.read(4096), timeout=5)
            if not chunk:
                break
            data += chunk
        return data

    async def command(self, line: bytes) -> bytes:
        self.writer.write(line + b"\r\n")
        await self.writer.drain()
        return await self.reply()

    async def send(self, line: bytes) -> None:
        self.writer.write(line + b"\r\n")
        await self.writer.drain()

    async def closed_by_server(self, within: float = 2.0) -> bool:
        """True when the server ends the connection without another byte."""
        try:
            return await asyncio.wait_for(self.reader.read(1), timeout=within) == b""
        except asyncio.TimeoutError:
            return False

    async def silent_and_open(self, during: float = 0.6) -> bool:
        try:
            await asyncio.wait_for(self.reader.read(1), timeout=during)
        except asyncio.TimeoutError:
            return True
        return False

    def close(self) -> None:
        self.writer.close()


# -- vsftpd -------------------------------------------------------------------------

class TestVsftpd:
    async def test_feat_does_not_list_utf8(self, server):
        """ftp.before_login.feat and ftp.after_login.feat — the decoy's
        list had " UTF8" before the last line."""
        await server(VSFTPD)
        control = await _Control.open()
        try:
            before = await control.command(b"FEAT")
            await control.command(b"USER test")
            await control.command(b"PASS test")
            after = await control.command(b"FEAT")
        finally:
            control.close()
        expected = (
            b"211-Features:\r\n EPRT\r\n EPSV\r\n MDTM\r\n PASV\r\n REST STREAM\r\n"
            b" SIZE\r\n TVFS\r\n211 End\r\n"
        )
        assert before == expected
        assert after == expected

    async def test_the_third_wrong_password_ends_the_connection(self, server):
        """ftp.login.repeated_wrong_password — reference: three
        "530 Login incorrect." and "ended": "closed-by-server". The decoy
        answered a fourth with "230 Login successful."."""
        await server(VSFTPD)
        control = await _Control.open()
        replies = []
        try:
            for attempt in (1, 2, 3):
                await control.command(b"USER test")
                replies.append(await control.command(f"PASS fpaudit-wrong-{attempt}".encode()))
            assert await control.closed_by_server()
        finally:
            control.close()
        assert replies == [b"530 Login incorrect.\r\n"] * 3

    async def test_a_persistent_guesser_is_still_let_in_on_its_next_connection(self, server):
        """The decoy lets a brute-forcer in after three wrong passwords on
        purpose. That stays; the fourth guess now needs a new connection,
        as it would against the real server."""
        await server(VSFTPD)
        control = await _Control.open()
        try:
            for attempt in (1, 2, 3):
                await control.command(b"USER test")
                await control.command(f"PASS fpaudit-wrong-{attempt}".encode())
        finally:
            control.close()
        control = await _Control.open()
        try:
            await control.command(b"USER test")
            assert await control.command(b"PASS fpaudit-wrong-4") == b"230 Login successful.\r\n"
        finally:
            control.close()

    async def test_a_5000_byte_user_line_is_too_long(self, server):
        """ftp.overlong.user_5000 and .closes — reference:
        "500 Input line too long.", then closed. The decoy answered
        "331 Please specify the password." and stayed."""
        await server(VSFTPD)
        control = await _Control.open()
        try:
            reply = await control.command(b"USER " + b"A" * 5000)
            assert reply == b"500 Input line too long.\r\n"
            assert await control.closed_by_server()
        finally:
            control.close()

    async def test_a_70000_byte_line_is_still_too_long(self, server):
        """ftp.overlong.line_70000 — matched before; must go on matching."""
        await server(VSFTPD)
        control = await _Control.open()
        try:
            reply = await control.command(b"A" * 70000)
            assert reply == b"500 Input line too long.\r\n"
            assert await control.closed_by_server()
        finally:
            control.close()

    def test_the_default_delay_is_the_measured_one(self):
        """ftp.login.failed_pass_delay — reference value 3.031 s."""
        defaults = {field.name: field.default for field in dataclasses.fields(HoneypotConfig)}
        assert defaults["ftp_fail_delay"] == 3.031

    async def test_a_wrong_password_is_refused_only_after_the_delay(self, server, monkeypatch):
        """The decoy answered in 0.008 s. A shorter configured value keeps
        the test quick; the mechanism is the same."""
        monkeypatch.setattr(config, "enable_anti_fingerprinting", True)
        monkeypatch.setattr(config, "ftp_fail_delay", 0.6)
        await server(VSFTPD)
        control = await _Control.open()
        try:
            await control.command(b"USER fpaudit-nouser")
            started = time.monotonic()
            reply = await control.command(b"PASS fpaudit-wrong")
            elapsed = time.monotonic() - started
        finally:
            control.close()
        assert reply == b"530 Login incorrect.\r\n"
        assert 0.6 <= elapsed < 1.0


# -- ProFTPD ------------------------------------------------------------------------

class TestProftpd:
    async def test_the_greeting_names_no_version(self, server):
        """ftp.greeting — reference: "220 ProFTPD Server (Debian)
        [::ffff:<ip>]". The decoy said "ProFTPD 1.3.6c Server"."""
        await server(PROFTPD)
        control = await _Control.open()
        control.close()
        expected = f"220 ProFTPD Server (Debian) [::ffff:{get_identity().ip}]\r\n"
        assert control.greeting == expected.encode()

    async def test_syst_noop_and_unknown_commands_are_answered_before_login(self, server):
        """ftp.before_login.syst, .noop and .unknown_command — the decoy
        answered all three "530 Please login with USER and PASS"."""
        await server(PROFTPD)
        control = await _Control.open()
        try:
            assert await control.command(b"SYST") == b"215 UNIX Type: L8\r\n"
            assert await control.command(b"NOOP") == b"200 NOOP command successful\r\n"
            assert await control.command(b"FPAUDIT") == b"500 FPAUDIT not understood\r\n"
            # These matched before and still need a login.
            assert await control.command(b"STAT") == b"530 Please login with USER and PASS\r\n"
            assert await control.command(b"PASV") == b"530 Please login with USER and PASS\r\n"
        finally:
            control.close()

    async def test_help_is_answered_before_login_with_a_code_on_every_line(self, server):
        """ftp.before_login.help and ftp.after_login.help — the reference's
        text. Its last line names the reference's own host
        ("root@ref-focal"); the decoy's names the decoy's."""
        await server(PROFTPD)
        control = await _Control.open()
        try:
            before = await control.command(b"HELP")
            await control.command(b"USER test")
            await control.command(b"PASS test")
            after = await control.command(b"HELP")
        finally:
            control.close()
        expected = (
            b"214-The following commands are recognized (* =>'s unimplemented):\r\n"
            b"214-CWD     XCWD    CDUP    XCUP    SMNT*   QUIT    PORT    PASV    \r\n"
            b"214-EPRT    EPSV    ALLO*   RNFR    RNTO    DELE    MDTM    RMD     \r\n"
            b"214-XRMD    MKD     XMKD    PWD     XPWD    SIZE    SYST    HELP    \r\n"
            b"214-NOOP    FEAT    OPTS    HOST    CLNT    AUTH*   CCC*    CONF*   \r\n"
            b"214-ENC*    MIC*    PBSZ*   PROT*   TYPE    STRU    MODE    RETR    \r\n"
            b"214-STOR    STOU    APPE    REST    ABOR    USER    PASS    ACCT*   \r\n"
            b"214-REIN*   LIST    NLST    STAT    SITE    MLSD    MLST    \r\n"
            b"214 Direct comments to root@" + get_identity().fqdn.encode() + b"\r\n"
        )
        assert before == expected
        assert after == expected

    async def test_feat_has_a_code_on_every_line(self, server):
        """ftp.before_login.feat and ftp.after_login.feat — the decoy
        indented the features with a space, as vsftpd does."""
        await server(PROFTPD)
        control = await _Control.open()
        try:
            before = await control.command(b"FEAT")
            await control.command(b"USER test")
            await control.command(b"PASS test")
            after = await control.command(b"FEAT")
        finally:
            control.close()
        expected = (
            b"211-Features:\r\n211-CLNT\r\n211-EPRT\r\n211-EPSV\r\n211-HOST\r\n"
            b"211-LANG en-US*\r\n211-MDTM\r\n211-MFF modify;UNIX.group;UNIX.mode;\r\n"
            b"211-MFMT\r\n"
            b"211-MLST modify*;perm*;size*;type*;unique*;UNIX.group*;UNIX.groupname*;"
            b"UNIX.mode*;UNIX.owner*;UNIX.ownername*;\r\n"
            b"211-REST STREAM\r\n211-SITE COPY\r\n211-SITE MKDIR\r\n211-SITE RMDIR\r\n"
            b"211-SITE SYMLINK\r\n211-SITE UTIME\r\n211-SIZE\r\n211-TVFS\r\n211-UTF8\r\n"
            b"211 End\r\n"
        )
        assert before == expected
        assert after == expected

    async def test_stat_has_a_code_on_every_line_and_the_plain_client_address(self, server):
        """ftp.after_login.stat — reference: "211-Connected from <ip>
        (<ip>)". The decoy sent " Connected from ::ffff:<ip> (::ffff:<ip>)"."""
        await server(PROFTPD)
        control = await _Control.open()
        try:
            await control.command(b"USER test")
            await control.command(b"PASS test")
            reply = await control.command(b"STAT")
        finally:
            control.close()
        assert reply == (
            b"211-Status of 'Debian'\r\n"
            b"211-Connected from 127.0.0.1 (127.0.0.1)\r\n"
            b"211-Logged in as test\r\n"
            b"211-TYPE: ASCII, STRUcture: File, Mode: Stream\r\n"
            b"211-No data connection\r\n"
            b"211 End of status\r\n"
        )

    async def test_the_third_wrong_password_ends_the_connection(self, server):
        """ftp.login.repeated_wrong_password — as for vsftpd: three
        "530 Login incorrect." and closed; the decoy answered a fourth with
        "230 User test logged in"."""
        await server(PROFTPD)
        control = await _Control.open()
        replies = []
        try:
            for attempt in (1, 2, 3):
                await control.command(b"USER test")
                replies.append(await control.command(f"PASS fpaudit-wrong-{attempt}".encode()))
            assert await control.closed_by_server()
        finally:
            control.close()
        assert replies == [b"530 Login incorrect.\r\n"] * 3

    async def test_a_wrong_password_is_refused_at_once(self, server, monkeypatch):
        """ftp.login.failed_pass_delay — the reference ProFTPD took 0.0 s,
        so the delay configured for vsftpd must not apply here."""
        monkeypatch.setattr(config, "enable_anti_fingerprinting", True)
        monkeypatch.setattr(config, "ftp_fail_delay", 5.0)
        await server(PROFTPD)
        control = await _Control.open()
        try:
            await control.command(b"USER fpaudit-nouser")
            started = time.monotonic()
            reply = await control.command(b"PASS fpaudit-wrong")
            elapsed = time.monotonic() - started
        finally:
            control.close()
        assert reply == b"530 Login incorrect.\r\n"
        assert elapsed < 1.0

    async def test_a_5000_byte_user_line_gets_no_reply_and_no_close(self, server):
        """ftp.overlong.user_5000 and .closes — reference: nothing sent
        ("length": 0), connection left open. The decoy answered "331
        Password required for AAAA...". The line is not taken as a USER:
        a PASS after it is still out of sequence."""
        await server(PROFTPD)
        control = await _Control.open()
        try:
            await control.send(b"USER " + b"A" * 5000)
            assert await control.silent_and_open()
            assert await control.command(b"PASS x") == b"503 Login with USER first\r\n"
        finally:
            control.close()

    async def test_a_70000_byte_line_gets_no_reply_and_a_close(self, server):
        """ftp.overlong.line_70000 and .closes — reference: nothing sent,
        connection closed. The decoy sent "500 Invalid command: try being
        more creative" first."""
        await server(PROFTPD)
        control = await _Control.open()
        try:
            await control.send(b"A" * 70000)
            assert await control.closed_by_server()
        finally:
            control.close()
