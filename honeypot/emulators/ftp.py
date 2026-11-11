import asyncio
import hashlib
import inspect
import logging
import os
import posixpath
import random
import time
from dataclasses import dataclass
from typing import Optional

from honeypot.capture.flow import FlowMeter
from honeypot.core.config import config
from honeypot.core.honeytokens import get_honeytokens
from honeypot.core.identity import get_identity
from honeypot.core.login_delay import login_delay
from honeypot.core.session import session_manager
from honeypot.core.modes import mode_handler
from honeypot.emulators.base import BaseEmulator
from honeypot.emulators.ftp_dialect import MAX_COMMAND_LINE, MAX_LOGIN_FAILS, Dialect
from honeypot.adaptive.response import adaptive_engine

logger = logging.getLogger(__name__)

#: Wrong passwords for a named account, from one source, after which the
#: next password is accepted whatever it is.
SOFT_ACCEPT_AFTER = 3
#: Sources remembered for that count; the table is emptied when it is full.
MAX_TRACKED_SOURCES = 4096

#: The files every client finds, before it changes anything.
_BASE_FS = {
    "/": ["pub", "incoming", "readme.txt", "config.bak"],
    "/pub": ["documents", "software", "files"],
    "/pub/documents": ["report.pdf", "notes.txt", "data.csv"],
    "/pub/software": ["update.exe", "patch.zip", "installer.msi"],
    "/pub/files": ["backup.tar.gz", "database.sql", "logs.zip"],
    "/incoming": [],
}

#: Leading bytes for the generated files, so each is the type its name says.
_MAGIC = {
    "pdf": b"%PDF-1.4\n%\xe2\xe3\xcf\xd3\n",
    "zip": b"PK\x03\x04\x14\x00\x00\x00\x08\x00",
    "gz": b"\x1f\x8b\x08\x00\x00\x00\x00\x00\x00\x03",
    "exe": b"MZ\x90\x00\x03\x00\x00\x00\x04\x00\x00\x00\xff\xff\x00\x00",
    "msi": b"\xd0\xcf\x11\xe0\xa1\xb1\x1a\xe1",
}
_TEXT_EXTENSIONS = ("txt", "csv", "sql")
_WORDS = (
    "backup", "nightly", "transfer", "completed", "archive", "rotated",
    "report", "pending", "checked", "mirror", "updated", "invoice",
    "queue", "export", "window", "verified",
)


def _stable_meta(name: str) -> tuple[int, float]:
    """A size and mtime for a listed file, stable for its name on this host.

    Derived from the host identity's seed, so LIST, SIZE, MDTM and what RETR
    sends agree with one another and do not change between two calls. The
    time is anchored to the machine's boot time, not to now: counted back
    from the present it moved with every call, so two MDTMs a second apart
    disagreed.
    """
    identity = get_identity()
    digest = hashlib.sha256(f"{identity.seed}:{name}".encode()).digest()
    if name.endswith("config.bak"):
        # The planted configuration backup: its size is the file's own.
        size = len(get_honeytokens().config_backup().encode())
    else:
        size = 180 + int.from_bytes(digest[:4], "big") % 240_000
    # Between ~30 and ~400 days before boot, stable per name.
    age = 30 * 86400 + int.from_bytes(digest[4:8], "big") % (370 * 86400)
    return size, float(int(identity.boot_time) - age)


def _file_content(path: str) -> bytes:
    """The bytes of a deployment file: always the same, and exactly as many
    as SIZE and LIST report.

    RETR used to send a random number of random bytes, a different file on
    every download and never the size just listed.
    """
    if path.endswith("config.bak"):
        return get_honeytokens().config_backup().encode()
    size, _ = _stable_meta(path)
    seed = f"{get_identity().seed}:{path}"
    extension = path.rsplit(".", 1)[-1].lower()
    if extension in _TEXT_EXTENSIONS:
        rng = random.Random(seed)
        lines: list[str] = []
        length = 0
        while length < size:
            if extension == "csv":
                line = f"{rng.randint(1000, 99999)},2024-{rng.randint(1, 12):02d}-{rng.randint(1, 28):02d},{rng.randint(1, 90000) / 100:.2f}"
            elif extension == "sql":
                line = f"INSERT INTO records VALUES ({rng.randint(1, 999999)}, '{rng.choice(_WORDS)}', {rng.randint(0, 9999)});"
            else:
                line = " ".join(rng.choice(_WORDS) for _ in range(rng.randint(4, 11)))
            lines.append(line)
            length += len(line) + 1
        return ("\n".join(lines)[: size - 1] + "\n").encode()
    magic = _MAGIC.get(extension, b"")
    return (magic + hashlib.shake_256(seed.encode()).digest(size))[:size]


#: How long to wait for the client to open the data connection, and for a
#: transfer to finish once it has.
DATA_CONNECT_TIMEOUT = 30
DATA_TRANSFER_TIMEOUT = 300


def _normalise_ip(address: str) -> str:
    return address[7:] if address.startswith("::ffff:") else address


def _pasv_ports() -> list[int]:
    """The configured passive range, e.g. ``50000-50019``."""
    low, _, high = config.ftp_pasv_ports.partition("-")
    try:
        start, end = int(low), int(high or low)
    except ValueError:
        return []
    ports = list(range(max(1024, start), min(65535, end) + 1))
    random.shuffle(ports)
    return ports


class PassiveDataChannel:
    """One single-use passive data socket.

    The emulator used to answer PASV with a port nothing listened on and
    reply "226 Transfer complete" to STOR without reading a byte, so no FTP
    upload was ever captured — and any real client that tried to transfer
    found a dead socket, which is a fingerprint in itself.

    This listens for exactly one connection, and only from the address that
    owns the control connection, which is what vsftpd does by default
    (``pasv_promiscuous=NO``). A connection from anywhere else is closed: it
    is either a port-theft attempt or a scanner, and never the client.
    """

    def __init__(self, allowed_ip: str) -> None:
        self.allowed_ip = _normalise_ip(allowed_ip)
        self.port: Optional[int] = None
        self._server: Optional[asyncio.AbstractServer] = None
        self._connected: asyncio.Future = asyncio.get_running_loop().create_future()
        self._finished = asyncio.Event()
        self.rejected = 0

    async def open(self) -> Optional[int]:
        for port in _pasv_ports():
            try:
                self._server = await asyncio.start_server(
                    self._on_connect, config.bind_address, port
                )
            except OSError:
                continue
            self.port = port
            return port
        return None

    async def _on_connect(self, reader, writer) -> None:
        peer = writer.get_extra_info("peername")
        if (
            not peer
            or _normalise_ip(peer[0]) != self.allowed_ip
            or self._connected.done()
        ):
            self.rejected += 1
            writer.close()
            return
        self._connected.set_result((reader, writer))
        # Hold the handler open until the transfer is done, so the stream is
        # never closed underneath it.
        await self._finished.wait()

    async def accept(self):
        try:
            return await asyncio.wait_for(
                asyncio.shield(self._connected), timeout=DATA_CONNECT_TIMEOUT
            )
        except asyncio.TimeoutError:
            return None

    async def close(self) -> None:
        self._finished.set()
        if self._connected.done() and not self._connected.cancelled():
            _, writer = self._connected.result()
            writer.close()
        if self._server is not None:
            self._server.close()
            self._server = None


@dataclass
class _File:
    size: int
    mtime: float
    #: The deployment file whose bytes this is, wherever it was renamed to.
    origin: Optional[str] = None
    #: An upload's digest, under which its bytes sit in the capture directory.
    sha: Optional[str] = None


class FtpTree:
    """One client's view of the files: the deployment's, plus its changes.

    MKD, RMD, DELE and RNFR/RNTO used to answer "successful" and change
    nothing, so a client that made a directory could not enter it and a file
    it deleted was still listed. Each session now has its own tree, starting
    from the same files, so a client sees what it did and nobody else does.
    """

    #: Entries one session's tree may hold, so MKD in a loop is not a way to
    #: use the engine's memory.
    MAX_ENTRIES = 512
    MAX_PATH = 1024

    def __init__(self) -> None:
        self.dirs: set[str] = set(_BASE_FS)
        self.files: dict[str, _File] = {}
        for directory, names in _BASE_FS.items():
            for name in names:
                path = posixpath.join(directory, name)
                if path not in _BASE_FS:
                    self.files[path] = _File(*_stable_meta(path), origin=path)

    def is_dir(self, path: str) -> bool:
        return path in self.dirs

    def exists(self, path: str) -> bool:
        return path in self.dirs or path in self.files

    def _room(self, path: str) -> bool:
        return (
            len(path) <= self.MAX_PATH
            and len(self.dirs) + len(self.files) < self.MAX_ENTRIES
        )

    def children(self, path: str) -> list[tuple[str, Optional[_File]]]:
        """(name, file) for each entry of a directory; file is None for a
        directory. Sorted by name, as both servers list."""
        entries: list[tuple[str, Optional[_File]]] = []
        for directory in self.dirs:
            if directory != "/" and posixpath.dirname(directory) == path:
                entries.append((posixpath.basename(directory), None))
        for file_path, node in self.files.items():
            if posixpath.dirname(file_path) == path:
                entries.append((posixpath.basename(file_path), node))
        return sorted(entries, key=lambda entry: entry[0])

    def mkdir(self, path: str) -> bool:
        if self.exists(path) or posixpath.dirname(path) not in self.dirs or not self._room(path):
            return False
        self.dirs.add(path)
        return True

    def rmdir(self, path: str) -> str:
        """"ok", "missing" or "not_empty"."""
        if path == "/" or path not in self.dirs:
            return "missing"
        if self.children(path):
            return "not_empty"
        self.dirs.discard(path)
        return "ok"

    def delete(self, path: str) -> bool:
        return self.files.pop(path, None) is not None

    def put(self, path: str, node: _File) -> bool:
        if path in self.dirs or posixpath.dirname(path) not in self.dirs:
            return False
        if path not in self.files and not self._room(path):
            return False
        self.files[path] = node
        return True

    def rename(self, source: str, target: str) -> bool:
        if not self.exists(source) or source == "/" or len(target) > self.MAX_PATH:
            return False
        if posixpath.dirname(target) not in self.dirs or target in self.dirs:
            return False
        if source in self.files:
            self.files[target] = self.files.pop(source)
            return True
        if target == source or target.startswith(source + "/"):
            return False
        # A directory takes everything under it along.
        prefix = source + "/"
        for directory in [d for d in self.dirs if d == source or d.startswith(prefix)]:
            self.dirs.discard(directory)
            self.dirs.add(target + directory[len(source):])
        for file_path in [f for f in self.files if f.startswith(prefix)]:
            self.files[target + file_path[len(source):]] = self.files.pop(file_path)
        return True


class FTPSessionState:
    def __init__(self):
        self.username: Optional[str] = None
        self.password: Optional[str] = None
        self.authenticated = False
        #: Failed PASS commands on this connection.
        self.auth_failures = 0
        self.cwd = "/"
        self.client_ip = ""
        #: Both servers start a session in ASCII type.
        self.transfer_type = "A"
        self.data_channel: Optional[PassiveDataChannel] = None
        #: The client asked for an active-mode transfer (PORT/EPRT).
        self.active_mode = False
        self.rename_from: Optional[str] = None
        self.restart_at = 0
        self._tree: Optional[FtpTree] = None

    @property
    def tree(self) -> FtpTree:
        if self._tree is None:
            self._tree = FtpTree()
        return self._tree


class FTPHoneypot(BaseEmulator):
    def __init__(self):
        super().__init__("ftp", config.ftp_port)
        self._fake_users = {
            "anonymous": "",
            "ftp": "",
            "admin": "admin",
            "root": "root",
            "user": "password",
            "test": "test",
        }
        #: Failed passwords per (source address, account), across
        #: connections. See _cmd_pass.
        self._failures: dict[tuple[str, str], int] = {}

    def get_banner(self) -> str:
        # Straight from the identity. This went through a switch that, with
        # HONEYPOT_ANTI_FINGERPRINT=false, greeted clients with the
        # product's own name.
        return get_identity().ftp_banner_text()

    @staticmethod
    def _dialect() -> Dialect:
        """The reply texts of the server the banner names."""
        identity = get_identity()
        return Dialect(identity.ftp_family, identity.fqdn)

    async def _observe_passively(self, session_id: str, reader: asyncio.StreamReader) -> None:
        """Passive mode: record the connection, send nothing.

        FTP's server speaks first, so most clients will wait for a banner
        that never comes; whatever a client does send in the meantime is kept.
        """
        await session_manager.record_network_event(
            session_id, "passive_observation", {"protocol": "ftp", "responded": False}
        )
        try:
            data = await asyncio.wait_for(reader.read(4096), timeout=15)
        except (asyncio.TimeoutError, ConnectionError):
            data = b""
        for line in data.decode("utf-8", errors="replace").splitlines()[:20]:
            if line.strip():
                await session_manager.record_command(
                    session_id, line.strip(), output="(passive: no response sent)"
                )

    async def handle_client(
        self, reader: asyncio.StreamReader, writer: asyncio.StreamWriter
    ):
        source_ip, source_port = self._get_peer_info(writer)
        flow = FlowMeter.for_stream(reader, writer)
        logger.info(f"FTP connection from {source_ip}:{source_port}")

        if not await self._check_rate_limit(source_ip):
            logger.warning(f"Rate limit exceeded for {source_ip}")
            writer.close()
            await writer.wait_closed()
            return

        session_id = await session_manager.create_session(
            "ftp", source_ip, source_port, flow=flow
        )
        state = FTPSessionState()
        state.client_ip = source_ip
        dialect = self._dialect()
        # vsftpd's idle_session_timeout and ProFTPD's TimeoutIdle.
        idle = config.connection_timeout or (600 if dialect.family == "proftpd" else 300)

        try:
            if mode_handler.is_passive():
                await self._observe_passively(session_id, reader)
                return

            # The banner string carries no line terminator; without CRLF a
            # real FTP client blocks forever waiting for the greeting.
            banner = self.get_banner().rstrip("\r\n") + "\r\n"
            await self._send_response(writer, banner)
            await session_manager.record_network_event(
                session_id, "ftp_banner_sent", {"banner": banner.strip()}
            )

            while True:
                try:
                    data = await asyncio.wait_for(reader.readline(), timeout=idle)
                except asyncio.TimeoutError:
                    await self._send_response(writer, dialect.reply("timeout"))
                    break
                except ValueError:
                    # A line past the stream's limit of 64 KiB.
                    data = None
                if data is None or len(data) > MAX_COMMAND_LINE:
                    # Longer than either server reads as a command. The line
                    # used to be handled as one: a 5000-byte USER got "331".
                    reply, closes = dialect.overlong_line(None if data is None else len(data))
                    if data is None:
                        shown = "(command line over 64 KiB)"
                    else:
                        shown = data.decode("utf-8", errors="replace").strip()[:2000]
                    await session_manager.record_command(
                        session_id, shown, output=reply.strip() or "(no reply: line too long)"
                    )
                    await self._send_response(writer, reply)
                    if closes:
                        break
                    continue
                if not data:
                    break

                line = data.decode("utf-8", errors="replace").strip()
                if not line:
                    continue

                await session_manager.record_network_event(
                    session_id, "ftp_command_received", {"command": line[:2000]}
                )

                response = await self._process_command(
                    session_id, line, state, source_ip, reader, writer
                )
                verb = line.split(" ", 1)[0].upper()
                # Into the transcript the backend reads; network events
                # never leave the engine. LIST records itself with its
                # listing. The password is already in the credentials,
                # which are admin-only — the transcript is not.
                if verb != "LIST":
                    await session_manager.record_command(
                        session_id,
                        "PASS ********" if verb == "PASS" else line[:2000],
                        output=(response or "").strip()[:2000],
                    )
                await self._send_response(writer, response)

                if verb in ("QUIT", "BYE"):
                    break
                if verb == "PASS" and not state.authenticated and state.auth_failures >= MAX_LOGIN_FAILS:
                    # The third refusal is the last thing either server says.
                    break

        except (ConnectionResetError, BrokenPipeError, asyncio.CancelledError):
            pass
        except Exception as e:
            logger.error(f"FTP session error: {e}")
        finally:
            if state.data_channel is not None:
                await state.data_channel.close()
            await session_manager.end_session(session_id)
            writer.close()
            try:
                await writer.wait_closed()
            except Exception:
                pass

    async def _process_command(
        self,
        session_id: str,
        line: str,
        state: FTPSessionState,
        source_ip: str,
        reader: asyncio.StreamReader,
        writer: asyncio.StreamWriter,
    ) -> str:
        local_ip = self._get_local_ip(writer)
        dialect = self._dialect()

        parts = line.split(None, 1)
        cmd = parts[0].upper()[:32]
        arg = parts[1] if len(parts) > 1 else ""

        await adaptive_engine.profile_actor(session_id, source_ip, {"ftp_command": cmd})

        handlers = {
            "USER": lambda: self._cmd_user(arg, state),
            "PASS": lambda: self._cmd_pass(arg, state, session_id),
            "QUIT": lambda: dialect.reply("quit"),
            "BYE": lambda: dialect.reply("quit"),
            "NOOP": lambda: dialect.reply("noop"),
            "SYST": lambda: dialect.reply("syst"),
            "FEAT": dialect.feat,
            "HELP": dialect.help,
            "OPTS": lambda: dialect.reply(
                "opts_utf8" if arg.upper().replace(" ", "") == "UTF8ON" else "opts_bad", arg=arg
            ),
            "PWD": lambda: self._cmd_pwd(state),
            "XPWD": lambda: self._cmd_pwd(state),
            "CWD": lambda: self._cmd_cwd(arg, state),
            "XCWD": lambda: self._cmd_cwd(arg, state),
            "CDUP": lambda: self._cmd_cdup(state),
            "XCUP": lambda: self._cmd_cdup(state),
            "TYPE": lambda: self._cmd_type(arg, state),
            "MODE": lambda: dialect.reply("mode_ok" if arg.upper() == "S" else "mode_bad", arg=arg),
            "STRU": lambda: dialect.reply("stru_ok" if arg.upper() == "F" else "stru_bad", arg=arg),
            "ALLO": lambda: dialect.reply("allo"),
            "ABOR": lambda: dialect.reply("abor"),
            "PASV": lambda: self._cmd_pasv(local_ip, state, source_ip),
            "EPSV": lambda: self._cmd_epsv(state, source_ip),
            "PORT": lambda: self._cmd_port(session_id, cmd, arg, state),
            "EPRT": lambda: self._cmd_port(session_id, cmd, arg, state),
            "LIST": lambda: self._cmd_list(session_id, arg, state, writer),
            "NLST": lambda: self._cmd_nlst(arg, state, writer),
            "RETR": lambda: self._cmd_retr(session_id, arg, state, writer),
            "STOR": lambda: self._cmd_stor(session_id, arg, state, writer),
            "STOU": lambda: self._cmd_stor(session_id, arg, state, writer),
            "APPE": lambda: self._cmd_stor(session_id, arg, state, writer),
            "DELE": lambda: self._cmd_dele(arg, state),
            "RMD": lambda: self._cmd_rmd(arg, state),
            "XRMD": lambda: self._cmd_rmd(arg, state),
            "MKD": lambda: self._cmd_mkd(arg, state),
            "XMKD": lambda: self._cmd_mkd(arg, state),
            "RNFR": lambda: self._cmd_rnfr(arg, state),
            "RNTO": lambda: self._cmd_rnto(arg, state),
            "SIZE": lambda: self._cmd_size(arg, state),
            "MDTM": lambda: self._cmd_mdtm(arg, state),
            "REST": lambda: self._cmd_rest(arg, state),
            "STAT": lambda: self._cmd_stat(state),
            "SITE": lambda: dialect.reply("site", arg=arg),
            "REIN": lambda: dialect.reply("not_implemented", command=cmd),
            "ACCT": lambda: dialect.reply("not_implemented", command=cmd),
            "SMNT": lambda: dialect.reply("not_implemented", command=cmd),
        }
        if dialect.family == "proftpd":
            # Commands its FEAT lists and vsftpd has never heard of.
            handlers["CLNT"] = lambda: dialect.reply("clnt")
            handlers["HOST"] = lambda: dialect.reply("host", arg=arg)
            handlers["MLSD"] = lambda: self._cmd_mlsd(arg, state, writer)
            handlers["MLST"] = lambda: self._cmd_mlst(arg, state)

        handler = handlers.get(cmd)
        if not state.authenticated and cmd not in dialect.before_login:
            if handler is None and dialect.refuses_unknown_before_login:
                # ProFTPD looks a command up before it asks who is asking, so
                # one it does not have is "not understood" even now. With no
                # TLS module that includes AUTH, PBSZ and PROT.
                return dialect.reply("unknown", command=cmd)
            return dialect.reply("need_login")
        if handler is None:
            # Neither server answers "502 Command not implemented" here.
            return dialect.reply("unknown", command=cmd)

        result = handler()
        if inspect.isawaitable(result):
            result = await result
        return result

    # -- login ---------------------------------------------------------------

    def _cmd_user(self, arg: str, state: FTPSessionState) -> str:
        state.username = arg or "anonymous"
        anonymous = state.username in ("anonymous", "ftp")
        return self._dialect().reply(
            "anonymous_user_ok" if anonymous else "user_ok", user=state.username
        )

    async def _cmd_pass(
        self, arg: str, state: FTPSessionState, session_id: str
    ) -> str:
        dialect = self._dialect()
        if state.username is None:
            return dialect.reply("pass_before_user")
        state.password = arg
        username = state.username

        # The password is actually checked now. Anonymous and ftp accept any
        # string, as real anonymous FTP does. A named account is accepted on
        # its advertised weak password, or — like the SSH decoy — after a few
        # failures, so a brute-forcer that never guesses the exact password
        # still gets in and reveals what it does next. Accepting every
        # password on the first try was its own fingerprint.
        #
        # The failures are counted per source and account, not per
        # connection: both real servers hang up after the third wrong
        # password, and so does the decoy now, which means the guess that is
        # let in arrives on a later connection.
        anonymous = username in ("anonymous", "ftp")
        expected = self._fake_users.get(username)
        source = (state.client_ip, username)
        earlier_failures = self._failures.get(source, 0)
        if anonymous:
            accepted = True
        else:
            accepted = expected is not None and (
                arg == expected or earlier_failures >= SOFT_ACCEPT_AFTER
            )

        # Also where a planted login is recognised: the session manager
        # raises honeytoken_used for one.
        await session_manager.record_auth_attempt(
            session_id, username, arg, accepted
        )

        if accepted:
            self._failures.pop(source, None)
            state.authenticated = True
            return dialect.reply("anonymous_login_ok" if anonymous else "login_ok", user=username)

        state.auth_failures += 1
        if expected is not None:
            # Only accounts that can be let in are worth remembering.
            if len(self._failures) >= MAX_TRACKED_SOURCES:
                self._failures.clear()
            self._failures[source] = earlier_failures + 1
        if dialect.delays_failed_login:
            # The attempt is recorded already; only the answer waits.
            await login_delay.pause(config.ftp_fail_delay)
        return dialect.reply("login_failed")

    # -- navigation ------------------------------------------------------------

    @staticmethod
    def _get_local_ip(writer: asyncio.StreamWriter) -> str:
        sock = writer.get_extra_info("sockname")
        return sock[0] if sock else "0.0.0.0"

    def _resolve(self, arg: str, state: FTPSessionState) -> str:
        return posixpath.normpath(arg if arg.startswith("/") else posixpath.join(state.cwd, arg))

    def _cmd_pwd(self, state: FTPSessionState) -> str:
        return self._dialect().reply("pwd", path=state.cwd.replace('"', '""'))

    def _cmd_cwd(self, arg: str, state: FTPSessionState) -> str:
        dialect = self._dialect()
        if not arg:
            return dialect.reply("cwd_failed", arg=arg)
        path = self._resolve(arg, state)
        if state.tree.is_dir(path):
            state.cwd = path
            return dialect.reply("cwd_ok")
        return dialect.reply("cwd_failed", arg=arg)

    def _cmd_cdup(self, state: FTPSessionState) -> str:
        state.cwd = posixpath.dirname(state.cwd) or "/"
        return self._dialect().reply("cdup_ok")

    def _cmd_type(self, arg: str, state: FTPSessionState) -> str:
        dialect = self._dialect()
        kind = arg.upper().replace(" ", "")
        if kind in ("I", "L8"):
            state.transfer_type = "I"
            return dialect.reply("type_binary")
        if kind in ("A", "AN"):
            state.transfer_type = "A"
            return dialect.reply("type_ascii")
        return dialect.reply("type_bad", arg=arg)

    # -- data connections ---------------------------------------------------------

    async def _open_data_channel(
        self, state: FTPSessionState, source_ip: str
    ) -> Optional[int]:
        if state.data_channel is not None:
            await state.data_channel.close()
        state.active_mode = False
        state.data_channel = PassiveDataChannel(source_ip)
        port = await state.data_channel.open()
        if port is None:
            state.data_channel = None
        return port

    async def _cmd_pasv(
        self, local_ip: str, state: FTPSessionState, source_ip: str
    ) -> str:
        # PASV must advertise the address clients can reach. Behind NAT that
        # is not the socket's own address, so it is configurable. IPv6 cannot
        # be expressed in the PASV quad form at all.
        dialect = self._dialect()
        address = config.ftp_pasv_address or local_ip
        octets = address.split(".")
        if len(octets) != 4:
            return dialect.reply("pasv_ipv6")
        port = await self._open_data_channel(state, source_ip)
        if port is None:
            return dialect.reply("pasv_failed")
        return dialect.reply("pasv", quad=",".join(octets), high=port // 256, low=port % 256)

    async def _cmd_epsv(self, state: FTPSessionState, source_ip: str) -> str:
        dialect = self._dialect()
        port = await self._open_data_channel(state, source_ip)
        if port is None:
            return dialect.reply("pasv_failed")
        return dialect.reply("epsv", port=port)

    async def _cmd_port(self, session_id: str, cmd: str, arg: str, state: FTPSessionState) -> str:
        """PORT and EPRT: accepted as either server accepts them, and never
        acted on.

        Active mode has the server connect out to an address the client
        names — for a honeypot, an outbound connection to the attacker or,
        with FTP bounce, to anyone. The engine makes none. A request naming
        the client's own address is acknowledged, and the transfer that
        follows fails the way it does when a server's outbound connection is
        refused. One naming any other address is the bounce attempt both
        servers reject.
        """
        dialect = self._dialect()
        address = ""
        if cmd == "PORT":
            fields = arg.split(",")
            if len(fields) == 6 and all(f.strip().isdigit() and int(f) < 256 for f in fields):
                address = ".".join(f.strip() for f in fields[:4])
        else:
            fields = arg.split(arg[:1]) if arg else []
            if len(fields) >= 4 and fields[3].isdigit():
                address = fields[2]
        own = bool(address) and _normalise_ip(address) == _normalise_ip(state.client_ip)
        await session_manager.record_network_event(
            session_id, "ftp_active_mode_requested" if own else "ftp_bounce_attempt",
            {"command": cmd, "argument": arg[:200]},
        )
        if not own:
            return dialect.reply("port_illegal")
        if state.data_channel is not None:
            await state.data_channel.close()
            state.data_channel = None
        state.active_mode = True
        return dialect.reply("port_ok" if cmd == "PORT" else "eprt_ok")

    async def _with_data_connection(self, state, writer, preamble):
        """Send the 150, then wait for the client's data connection."""
        dialect = self._dialect()
        channel = state.data_channel
        state.data_channel = None
        if channel is None:
            failed = "data_failed" if state.active_mode else "no_data_channel"
            state.active_mode = False
            return None, dialect.reply(failed)
        await self._send_response(writer, preamble)
        connection = await channel.accept()
        if connection is None:
            await channel.close()
            return None, dialect.reply("data_failed")
        return (channel, connection), None

    async def _send_data(self, state, writer, preamble: str, data: bytes, done: str) -> str:
        opened, error = await self._with_data_connection(state, writer, preamble)
        if error:
            return error
        channel, (_, data_writer) = opened
        try:
            data_writer.write(data)
            await asyncio.wait_for(data_writer.drain(), timeout=DATA_TRANSFER_TIMEOUT)
        except (ConnectionError, asyncio.TimeoutError):
            pass
        finally:
            await channel.close()
        return done

    # -- listings ---------------------------------------------------------------------

    def _entries(self, arg: str, state: FTPSessionState):
        """What a listing command names: the entries of a directory, or the
        one file. Options such as ``-la`` are not a path."""
        target = " ".join(word for word in arg.split() if not word.startswith("-"))
        path = self._resolve(target, state) if target else state.cwd
        tree = state.tree
        if tree.is_dir(path):
            return tree.children(path)
        if path in tree.files:
            return [(posixpath.basename(path), tree.files[path])]
        return []

    def _listing(self, arg: str, state: FTPSessionState, names_only: bool) -> str:
        dialect = self._dialect()
        now = time.time()
        lines = []
        for name, node in self._entries(arg, state):
            if names_only:
                lines.append(f"{name}\r\n")
            elif node is None:
                _, mtime = _stable_meta(name)
                lines.append(dialect.list_line(name, True, 4096, mtime, now))
            else:
                lines.append(dialect.list_line(name, False, node.size, node.mtime, now))
        return "".join(lines)

    async def _cmd_list(
        self, session_id: str, arg: str, state: FTPSessionState, writer
    ) -> str:
        dialect = self._dialect()
        listing = self._listing(arg, state, names_only=False)
        await session_manager.record_command(session_id, "LIST", listing)
        return await self._send_data(
            state, writer, dialect.reply("list_open"), listing.encode(), dialect.reply("list_done")
        )

    async def _cmd_nlst(self, arg: str, state: FTPSessionState, writer) -> str:
        dialect = self._dialect()
        return await self._send_data(
            state, writer, dialect.reply("list_open"),
            self._listing(arg, state, names_only=True).encode(), dialect.reply("list_done"),
        )

    def _facts(self, name: str, node: Optional[_File], path: str) -> str:
        unique = int.from_bytes(hashlib.sha256(path.encode()).digest()[:3], "big")
        if node is None:
            return Dialect.facts_line(name, True, 4096, _stable_meta(name)[1], unique)
        return Dialect.facts_line(name, False, node.size, node.mtime, unique)

    async def _cmd_mlsd(self, arg: str, state: FTPSessionState, writer) -> str:
        dialect = self._dialect()
        path = self._resolve(arg, state) if arg else state.cwd
        if not state.tree.is_dir(path):
            return dialect.reply("mlst_failed", arg=arg)
        listing = "".join(
            self._facts(name, node, posixpath.join(path, name)) + "\r\n"
            for name, node in state.tree.children(path)
        )
        return await self._send_data(
            state, writer, dialect.reply("mlsd_open"), listing.encode(), dialect.reply("list_done")
        )

    def _cmd_mlst(self, arg: str, state: FTPSessionState) -> str:
        dialect = self._dialect()
        path = self._resolve(arg, state) if arg else state.cwd
        tree = state.tree
        if not tree.exists(path):
            return dialect.reply("mlst_failed", arg=arg)
        facts = self._facts(path, tree.files.get(path), path)
        return f"250-Start of list for {path}\r\n {facts}\r\n250 End of list\r\n"

    # -- files ---------------------------------------------------------------------------

    async def _cmd_retr(
        self, session_id: str, arg: str, state: FTPSessionState, writer
    ) -> str:
        dialect = self._dialect()
        if not arg:
            return dialect.reply("syntax")
        path = self._resolve(arg, state)

        await session_manager.record_network_event(
            session_id, "ftp_download_attempt", {"filename": arg[:255], "path": path[:500]}
        )

        node = state.tree.files.get(path)
        if node is None:
            return dialect.reply("retr_failed", arg=arg)
        if node.sha is not None:
            # Their own upload comes back byte for byte, as it would.
            try:
                with open(os.path.join(config.file_capture_dir, node.sha), "rb") as handle:
                    data = handle.read()
            except OSError:
                return dialect.reply("retr_failed", arg=arg)
        elif node.origin is not None:
            data = _file_content(node.origin)
        elif node.size == 0:
            data = b""
        else:
            # An upload whose bytes were not kept (over the session's cap).
            return dialect.reply("retr_failed", arg=arg)

        offset, state.restart_at = state.restart_at, 0
        return await self._send_data(
            state, writer,
            dialect.reply("retr_open", name=posixpath.basename(path), size=len(data)),
            data[offset:], dialect.reply("transfer_done"),
        )

    async def _cmd_stor(
        self, session_id: str, arg: str, state: FTPSessionState, writer
    ) -> str:
        dialect = self._dialect()
        if not arg:
            return dialect.reply("syntax")
        path = self._resolve(arg, state)
        tree = state.tree
        if tree.is_dir(path) or not tree.is_dir(posixpath.dirname(path)):
            return dialect.reply("stor_failed", arg=arg)

        opened, error = await self._with_data_connection(
            state, writer, dialect.reply("stor_open", name=posixpath.basename(path))
        )
        if error:
            return error
        channel, (data_reader, _) = opened

        cap = session_manager.MAX_UPLOAD_BYTES
        received = bytearray()
        oversize = False
        loop = asyncio.get_running_loop()
        deadline = loop.time() + DATA_TRANSFER_TIMEOUT
        try:
            while True:
                remaining = deadline - loop.time()
                if remaining <= 0:
                    break
                chunk = await asyncio.wait_for(data_reader.read(65536), timeout=remaining)
                if not chunk:
                    break
                if len(received) + len(chunk) > cap:
                    oversize = True
                    break
                received += chunk
        except (ConnectionError, asyncio.TimeoutError):
            pass
        finally:
            await channel.close()

        await session_manager.record_network_event(
            session_id, "ftp_upload", {
                "filename": arg[:255], "path": path[:500],
                "bytes": len(received), "oversize": oversize,
            }
        )
        if oversize:
            return dialect.reply("stor_too_large")

        sha = await session_manager.record_file_upload(
            session_id, posixpath.basename(path) or arg, bytes(received),
            remote_path=path, source="ftp_stor",
        )
        # Listed and retrievable afterwards, whether or not the bytes could
        # be kept: the client just watched the transfer succeed.
        tree.put(path, _File(len(received), float(int(time.time())), sha=sha))
        return dialect.reply("transfer_done")

    def _cmd_dele(self, arg: str, state: FTPSessionState) -> str:
        deleted = bool(arg) and state.tree.delete(self._resolve(arg, state))
        return self._dialect().reply("dele_ok" if deleted else "dele_failed", arg=arg)

    def _cmd_rmd(self, arg: str, state: FTPSessionState) -> str:
        outcome = state.tree.rmdir(self._resolve(arg, state)) if arg else "missing"
        key = {"ok": "rmd_ok", "not_empty": "rmd_not_empty"}.get(outcome, "rmd_failed")
        return self._dialect().reply(key, arg=arg)

    def _cmd_mkd(self, arg: str, state: FTPSessionState) -> str:
        dialect = self._dialect()
        path = self._resolve(arg, state) if arg else ""
        if path and state.tree.mkdir(path):
            return dialect.reply("mkd_ok", path=path.replace('"', '""'))
        return dialect.reply("mkd_failed", arg=arg)

    def _cmd_rnfr(self, arg: str, state: FTPSessionState) -> str:
        dialect = self._dialect()
        path = self._resolve(arg, state) if arg else ""
        if path and path != "/" and state.tree.exists(path):
            state.rename_from = path
            return dialect.reply("rnfr_ok")
        state.rename_from = None
        return dialect.reply("rnfr_failed", arg=arg)

    def _cmd_rnto(self, arg: str, state: FTPSessionState) -> str:
        dialect = self._dialect()
        source, state.rename_from = state.rename_from, None
        if source is None:
            return dialect.reply("rnto_without_rnfr")
        if arg and state.tree.rename(source, self._resolve(arg, state)):
            return dialect.reply("rnto_ok")
        return dialect.reply("rnto_failed", arg=arg)

    def _cmd_size(self, arg: str, state: FTPSessionState) -> str:
        dialect = self._dialect()
        if dialect.has("size_ascii") and state.transfer_type == "A":
            return dialect.reply("size_ascii")
        node = state.tree.files.get(self._resolve(arg, state)) if arg else None
        if node is None:
            return dialect.reply("size_failed", arg=arg)
        return f"213 {node.size}\r\n"

    def _cmd_mdtm(self, arg: str, state: FTPSessionState) -> str:
        path = self._resolve(arg, state) if arg else ""
        tree = state.tree
        if path in tree.files:
            mtime = tree.files[path].mtime
        elif path and tree.is_dir(path):
            mtime = _stable_meta(posixpath.basename(path))[1]
        else:
            return self._dialect().reply("mdtm_failed", arg=arg)
        return "213 " + time.strftime("%Y%m%d%H%M%S", time.gmtime(mtime)) + "\r\n"

    def _cmd_rest(self, arg: str, state: FTPSessionState) -> str:
        offset = arg.strip()
        if not (offset.isascii() and offset.isdigit()) or len(offset) > 12:
            return self._dialect().reply("syntax")
        state.restart_at = int(offset)
        return self._dialect().reply("rest", offset=state.restart_at)

    def _cmd_stat(self, state: FTPSessionState) -> str:
        # The client's own address, as both servers report it; each in its
        # own form, which is the dialect's business.
        client = state.client_ip or get_identity().ip
        return self._dialect().stat(
            client, state.username or "anonymous", state.transfer_type == "I"
        )
