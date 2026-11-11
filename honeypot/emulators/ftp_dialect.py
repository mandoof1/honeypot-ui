"""What vsftpd and ProFTPD each say.

The host identity gives the FTP decoy a vsftpd or a ProFTPD banner, and every
reply after the banner used to be vsftpd's (or nobody's: "502 Command not
implemented", "250 DELE command successful" and the old HELP and STAT texts
are sent by neither). A ProFTPD greeting followed by "230 Login successful."
is two servers in one session, and telling the two apart takes one command:
their replies differ in wording, in punctuation and, for an unknown command
or a failed SIZE, in what they say at all.

Each dialect here is the reply texts of one server at its packaged defaults
(vsftpd 3.0.3; ProFTPD 1.3.6 as Debian builds it), keyed by what happened.
The emulator decides what happened; this only words it.

Where a comment below says "reference", the text or behaviour was read off
the real daemon in docs/evaluation/fingerprint/1-baseline/ftp-vsftpd-focal.json
and ftp-proftpd-focal.json.
"""

from __future__ import annotations

import time
from typing import Optional

#: Longest command line, line ending included, that is treated as a command.
#: The references bracket it: ordinary commands are read, a 5007-byte USER
#: line is not, by either server. 4096 is vsftpd's own limit
#: (VSFTP_MAX_COMMAND_LINE), and the same figure is used for ProFTPD.
MAX_COMMAND_LINE = 4096
#: Failed PASS commands after which both servers hang up: each reference
#: answered the third "530 Login incorrect." and closed the connection.
MAX_LOGIN_FAILS = 3

_VSFTPD = {
    "user_ok": "331 Please specify the password.",
    "anonymous_user_ok": "331 Please specify the password.",
    "pass_before_user": "503 Login with USER first.",
    "login_ok": "230 Login successful.",
    "anonymous_login_ok": "230 Login successful.",
    "login_failed": "530 Login incorrect.",
    "need_login": "530 Please login with USER and PASS.",
    "unknown": "500 Unknown command.",
    "line_too_long": "500 Input line too long.",
    "timeout": "421 Timeout.",
    "syst": "215 UNIX Type: L8",
    "noop": "200 NOOP ok.",
    "quit": "221 Goodbye.",
    "opts_utf8": "200 Always in UTF8 mode.",
    "opts_bad": "501 Option not understood.",
    "pwd": '257 "{path}" is the current directory',
    "cwd_ok": "250 Directory successfully changed.",
    "cwd_failed": "550 Failed to change directory.",
    "cdup_ok": "250 Directory successfully changed.",
    "type_binary": "200 Switching to Binary mode.",
    "type_ascii": "200 Switching to ASCII mode.",
    "type_bad": "500 Unrecognised TYPE command.",
    "mode_ok": "200 Mode set to S.",
    "mode_bad": "504 Bad MODE command.",
    "stru_ok": "200 Structure set to F.",
    "stru_bad": "504 Bad STRU command.",
    "allo": "202 ALLO command ignored.",
    "abor": "225 No transfer to ABOR.",
    "pasv": "227 Entering Passive Mode ({quad},{high},{low}).",
    "pasv_failed": "425 Could not open passive connection.",
    "pasv_ipv6": "425 Use EPSV instead.",
    "epsv": "229 Entering Extended Passive Mode (|||{port}|)",
    "port_ok": "200 PORT command successful. Consider using PASV.",
    "eprt_ok": "200 EPRT command successful. Consider using EPSV.",
    "port_illegal": "500 Illegal PORT command.",
    "no_data_channel": "425 Use PORT or PASV first.",
    "data_failed": "425 Failed to establish connection.",
    "list_open": "150 Here comes the directory listing.",
    "list_done": "226 Directory send OK.",
    "retr_open": "150 Opening BINARY mode data connection for {name} ({size} bytes).",
    "retr_failed": "550 Failed to open file.",
    "stor_open": "150 Ok to send data.",
    "transfer_done": "226 Transfer complete.",
    "stor_too_large": "552 Requested file action aborted. Exceeded storage allocation.",
    "stor_failed": "553 Could not create file.",
    "dele_ok": "250 Delete operation successful.",
    "dele_failed": "550 Delete operation failed.",
    "rmd_ok": "250 Remove directory operation successful.",
    "rmd_failed": "550 Remove directory operation failed.",
    "rmd_not_empty": "550 Remove directory operation failed.",
    "mkd_ok": '257 "{path}" created',
    "mkd_failed": "550 Create directory operation failed.",
    "rnfr_ok": "350 Ready for RNTO.",
    "rnfr_failed": "550 RNFR command failed.",
    "rnto_ok": "250 Rename successful.",
    "rnto_failed": "550 Rename failed.",
    "rnto_without_rnfr": "503 RNFR required first.",
    "size_failed": "550 Could not get file size.",
    "mdtm_failed": "550 Could not get file modification time.",
    "rest": "350 Restart position accepted ({offset}).",
    "syntax": "501 Syntax error.",
    "site": "500 Unknown SITE command.",
    "not_implemented": "502 {command} not implemented.",
}

_PROFTPD = {
    "user_ok": "331 Password required for {user}",
    "anonymous_user_ok": "331 Anonymous login ok, send your complete email address as your password",
    "pass_before_user": "503 Login with USER first",
    "login_ok": "230 User {user} logged in",
    "anonymous_login_ok": "230 Anonymous access granted, restrictions apply",
    "login_failed": "530 Login incorrect.",
    "need_login": "530 Please login with USER and PASS",
    "unknown": "500 {command} not understood",
    "timeout": "421 Idle timeout (600 seconds): closing control connection",
    "syst": "215 UNIX Type: L8",
    "noop": "200 NOOP command successful",
    "quit": "221 Goodbye.",
    "opts_utf8": "200 UTF8 set to on",
    "opts_bad": "501 OPTS: {arg} not understood",
    "pwd": '257 "{path}" is the current directory',
    "cwd_ok": "250 CWD command successful",
    "cwd_failed": "550 {arg}: No such file or directory",
    "cdup_ok": "250 CDUP command successful",
    "type_binary": "200 Type set to I",
    "type_ascii": "200 Type set to A",
    "type_bad": "504 TYPE not implemented for '{arg}' parameter",
    "mode_ok": "200 Mode set to S",
    "mode_bad": "504 '{arg}' unsupported transfer mode",
    "stru_ok": "200 Structure set to F",
    "stru_bad": "504 '{arg}' unsupported structure type",
    "allo": "202 No storage allocation necessary",
    "abor": "226 Abort successful",
    "pasv": "227 Entering Passive Mode ({quad},{high},{low}).",
    "pasv_failed": "425 Unable to build data connection: Address already in use",
    "pasv_ipv6": "501 PASV: Illegal PASV command, EPSV ALL in effect",
    "epsv": "229 Entering Extended Passive Mode (|||{port}|)",
    "port_ok": "200 PORT command successful",
    "eprt_ok": "200 EPRT command successful",
    "port_illegal": "500 Illegal PORT command",
    # With no PASV or PORT it tries the client's default data port.
    "no_data_channel": "425 Unable to build data connection: Connection refused",
    "data_failed": "425 Unable to build data connection: Connection refused",
    "list_open": "150 Opening ASCII mode data connection for file list",
    "list_done": "226 Transfer complete",
    "retr_open": "150 Opening BINARY mode data connection for {name} ({size} bytes)",
    "retr_failed": "550 {arg}: No such file or directory",
    "stor_open": "150 Opening BINARY mode data connection for {name}",
    "transfer_done": "226 Transfer complete",
    "stor_too_large": "552 Transfer aborted. Disk quota exceeded",
    "stor_failed": "550 {arg}: Permission denied",
    "dele_ok": "250 DELE command successful",
    "dele_failed": "550 {arg}: No such file or directory",
    "rmd_ok": "250 RMD command successful",
    "rmd_failed": "550 {arg}: No such file or directory",
    "rmd_not_empty": "550 {arg}: Directory not empty",
    "mkd_ok": '257 "{path}" - Directory successfully created',
    "mkd_failed": "550 {arg}: File exists",
    "rnfr_ok": "350 File or directory exists, ready for destination name",
    "rnfr_failed": "550 {arg}: No such file or directory",
    "rnto_ok": "250 Rename successful",
    "rnto_failed": "550 Rename {arg}: No such file or directory",
    "rnto_without_rnfr": "503 Bad sequence of commands",
    "size_failed": "550 {arg}: No such file or directory",
    # ProFTPD starts in ASCII type and will not size a file in it.
    "size_ascii": "550 SIZE not allowed in ASCII mode",
    "mdtm_failed": "550 {arg}: No such file or directory",
    "rest": "350 Restarting at {offset}. Send STORE or RETRIEVE to initiate transfer",
    "syntax": "501 Invalid number of arguments",
    "site": "500 'SITE {arg}' not understood",
    "not_implemented": "502 {command} command not implemented",
    "clnt": "200 OK",
    "host": "504 {arg}: Unknown hostname provided",
    "mlsd_open": "150 Opening ASCII mode data connection for MLSD",
    "mlst_failed": "550 '{arg}' cannot be listed",
}

_MONTHS = ("Jan", "Feb", "Mar", "Apr", "May", "Jun", "Jul", "Aug", "Sep", "Oct", "Nov", "Dec")
#: Listings show the year instead of the time for files older than this.
_SIX_MONTHS = 182 * 86400


class Dialect:
    def __init__(self, family: str, hostname: str = "localhost") -> None:
        self.family = "proftpd" if family == "proftpd" else "vsftpd"
        self.hostname = hostname
        self._replies = _PROFTPD if self.family == "proftpd" else _VSFTPD

    def has(self, key: str) -> bool:
        return key in self._replies

    @property
    def before_login(self) -> frozenset[str]:
        """Commands answered before a login, beyond the login itself.

        Reference: vsftpd answers SYST, HELP and NOOP with "530 Please login
        with USER and PASS."; ProFTPD answers them as it does afterwards
        ("215 UNIX Type: L8", its HELP text, "200 NOOP command successful").
        """
        common = {"USER", "PASS", "QUIT", "BYE", "FEAT", "OPTS"}
        if self.family == "proftpd":
            return frozenset(common | {"SYST", "HELP", "NOOP"})
        return frozenset(common)

    @property
    def refuses_unknown_before_login(self) -> bool:
        """Whether a command the server has never heard of is told so even
        before a login. Reference, for "FPAUDIT": ProFTPD "500 FPAUDIT not
        understood", vsftpd "530 Please login with USER and PASS."."""
        return self.family == "proftpd"

    @property
    def delays_failed_login(self) -> bool:
        """Whether a wrong password is refused only after a pause. Reference:
        vsftpd took 3.031 s, ProFTPD answered at once (0.0 s)."""
        return self.family == "vsftpd"

    def overlong_line(self, length: Optional[int]) -> tuple[str, bool]:
        """What a command line over ``MAX_COMMAND_LINE`` gets: the reply, and
        whether the connection closes. ``length`` is None for a line longer
        than the engine reads at all (64 KiB).

        Reference, for a 5007-byte USER line and a 70002-byte line: vsftpd
        answered both "500 Input line too long." and closed. ProFTPD said
        nothing to either; it kept the connection open after the first and
        closed it after the second. Where between the two ProFTPD gives up
        was not measured, and is drawn here at four buffers' worth.
        """
        if self.family == "vsftpd":
            return self.reply("line_too_long"), True
        return "", length is None or length > 4 * MAX_COMMAND_LINE

    def reply(self, key: str, **values) -> str:
        """One reply line. Values taken from the client are cut short."""
        values = {name: str(value)[:255] for name, value in values.items()}
        return self._replies[key].format(**values) + "\r\n"

    # -- multi-line replies -------------------------------------------------

    def feat(self) -> str:
        if self.family == "proftpd":
            features = [
                "CLNT", "EPRT", "EPSV", "HOST", "LANG en-US*", "MDTM",
                "MFF modify;UNIX.group;UNIX.mode;", "MFMT",
                "MLST modify*;perm*;size*;type*;unique*;UNIX.group*;UNIX.groupname*;"
                "UNIX.mode*;UNIX.owner*;UNIX.ownername*;",
                "REST STREAM", "SITE COPY", "SITE MKDIR", "SITE RMDIR",
                "SITE SYMLINK", "SITE UTIME", "SIZE", "TVFS", "UTF8",
            ]
        else:
            # No UTF8: the reference's list ends at TVFS.
            features = ["EPRT", "EPSV", "MDTM", "PASV", "REST STREAM", "SIZE", "TVFS"]
        lines = ["211-Features:"] + [self._inner(211, feature) for feature in features] + ["211 End"]
        return "\r\n".join(lines) + "\r\n"

    def _inner(self, code: int, text: str) -> str:
        """A line between the first and last of a multi-line reply.

        vsftpd indents them with a space. The reference ProFTPD starts every
        one with the reply code and a hyphen instead ("211-CLNT",
        "214-CWD     XCWD ...", "211-Logged in as test").
        """
        if self.family == "proftpd":
            return f"{code}-{text}"
        return f" {text}"

    def help(self) -> str:
        if self.family == "proftpd":
            lines = [
                "214-The following commands are recognized (* =>'s unimplemented):",
                "214-CWD     XCWD    CDUP    XCUP    SMNT*   QUIT    PORT    PASV    ",
                "214-EPRT    EPSV    ALLO*   RNFR    RNTO    DELE    MDTM    RMD     ",
                "214-XRMD    MKD     XMKD    PWD     XPWD    SIZE    SYST    HELP    ",
                "214-NOOP    FEAT    OPTS    HOST    CLNT    AUTH*   CCC*    CONF*   ",
                "214-ENC*    MIC*    PBSZ*   PROT*   TYPE    STRU    MODE    RETR    ",
                "214-STOR    STOU    APPE    REST    ABOR    USER    PASS    ACCT*   ",
                "214-REIN*   LIST    NLST    STAT    SITE    MLSD    MLST    ",
                f"214 Direct comments to root@{self.hostname}",
            ]
        else:
            lines = [
                "214-The following commands are recognized.",
                " ABOR ACCT ALLO APPE CDUP CWD  DELE EPRT EPSV FEAT HELP LIST MDTM MKD",
                " MODE NLST NOOP OPTS PASS PASV PORT PWD  QUIT REIN REST RETR RMD  RNFR",
                " RNTO SITE SIZE SMNT STAT STOR STOU STRU SYST TYPE USER XCUP XCWD XMKD",
                " XPWD XRMD",
                "214 Help OK.",
            ]
        return "\r\n".join(lines) + "\r\n"

    def stat(self, client_ip: str, user: str, binary: bool) -> str:
        """The server status. Both report the *client's* address: vsftpd an
        IPv4 client in IPv4-mapped form ("Connected to ::ffff:172.18.0.1"),
        ProFTPD as it is ("Connected from 172.18.0.1 (172.18.0.1)")."""
        kind = "BINARY" if binary else "ASCII"
        if self.family == "proftpd":
            lines = [
                "211-Status of 'Debian'",
                f"211-Connected from {client_ip} ({client_ip})",
                f"211-Logged in as {user}",
                f"211-TYPE: {kind}, STRUcture: File, Mode: Stream",
                "211-No data connection",
                "211 End of status",
            ]
        else:
            if "." in client_ip and ":" not in client_ip:
                client_ip = f"::ffff:{client_ip}"
            lines = [
                "211-FTP server status:",
                f"     Connected to {client_ip}",
                f"     Logged in as {user}",
                f"     TYPE: {kind}",
                "     No session bandwidth limit",
                "     Session timeout in seconds is 300",
                "     Control connection is plain text",
                "     Data connections will be plain text",
                "     At session startup, client count was 1",
                "     vsFTPd 3.0.3 - secure, fast, stable",
                "211 End of status",
            ]
        return "\r\n".join(lines) + "\r\n"

    # -- listings -----------------------------------------------------------

    def list_line(self, name: str, is_dir: bool, size: int, mtime: float, now: float) -> str:
        """One LIST line, in the server's own column layout.

        vsftpd prints numeric ids, a four-wide link count and a zero-padded
        day; ProFTPD prints names, a three-wide count and a space-padded day.
        """
        moment = time.gmtime(mtime)
        recent = 0 <= now - mtime <= _SIX_MONTHS
        clock = f"{moment.tm_hour:02d}:{moment.tm_min:02d}" if recent else f" {moment.tm_year}"
        month = _MONTHS[moment.tm_mon - 1]
        mode = "drwxr-xr-x" if is_dir else "-rw-r--r--"
        links = 2 if is_dir else 1
        size = 4096 if is_dir else size
        if self.family == "proftpd":
            return (
                f"{mode} {links:3d} {'ftp':<8} {'ftp':<8} {size:8d} "
                f"{month} {moment.tm_mday:2d} {clock} {name}\r\n"
            )
        return (
            f"{mode} {links:4d} {'0':<8} {'0':<8} {size:8d} "
            f"{month} {moment.tm_mday:02d} {clock} {name}\r\n"
        )

    @staticmethod
    def facts_line(name: str, is_dir: bool, size: int, mtime: float, unique: int) -> str:
        """One MLSD/MLST entry (ProFTPD only)."""
        stamp = time.strftime("%Y%m%d%H%M%S", time.gmtime(mtime))
        if is_dir:
            facts = f"modify={stamp};perm=flcdmpe;type=dir;unique=801U{unique:X};"
            facts += "UNIX.group=65534;UNIX.groupname=nogroup;UNIX.mode=0755;UNIX.owner=107;UNIX.ownername=ftp;"
        else:
            facts = f"modify={stamp};perm=adfrw;size={size};type=file;unique=801U{unique:X};"
            facts += "UNIX.group=65534;UNIX.groupname=nogroup;UNIX.mode=0644;UNIX.owner=107;UNIX.ownername=ftp;"
        return f"{facts} {name}"
