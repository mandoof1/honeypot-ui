import asyncio
import inspect
import logging
import os
import random
from typing import Optional

from honeypot.core.config import config
from honeypot.core.session import session_manager
from honeypot.core.modes import mode_handler
from honeypot.emulators.base import BaseEmulator
from honeypot.adaptive.fingerprint import fingerprint_engine
from honeypot.adaptive.response import adaptive_engine

logger = logging.getLogger(__name__)


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


class FTPSessionState:
    def __init__(self):
        self.username: Optional[str] = None
        self.password: Optional[str] = None
        self.authenticated = False
        self.cwd = "/"
        self.passive_mode = False
        self.transfer_type = "I"
        self.data_port: Optional[int] = None
        self.data_channel: Optional[PassiveDataChannel] = None
        #: Files uploaded this session: path -> (sha256, size). Kept per
        #: session so one attacker never sees another's uploads.
        self.uploaded: dict[str, tuple[str, int]] = {}


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
        self._fake_fs = {
            "/": ["pub", "incoming", "readme.txt", "config.bak"],
            "/pub": ["documents", "software", "files"],
            "/pub/documents": ["report.pdf", "notes.txt", "data.csv"],
            "/pub/software": ["update.exe", "patch.zip", "installer.msi"],
            "/pub/files": ["backup.tar.gz", "database.sql", "logs.zip"],
            "/incoming": [],
        }

    def get_banner(self) -> str:
        return fingerprint_engine.get_ftp_banner()

    async def handle_client(
        self, reader: asyncio.StreamReader, writer: asyncio.StreamWriter
    ):
        source_ip, source_port = self._get_peer_info(writer)
        logger.info(f"FTP connection from {source_ip}:{source_port}")

        if not await self._check_rate_limit(source_ip):
            logger.warning(f"Rate limit exceeded for {source_ip}")
            writer.close()
            await writer.wait_closed()
            return

        session_id = await session_manager.create_session(
            "ftp", source_ip, source_port
        )
        state = FTPSessionState()

        try:
            # The rotating banner strings carry no line terminator; without
            # CRLF a real FTP client blocks forever waiting for the greeting.
            banner = self.get_banner().rstrip("\r\n") + "\r\n"
            await self._send_response(writer, banner)
            await session_manager.record_network_event(
                session_id, "ftp_banner_sent", {"banner": banner.strip()}
            )

            while True:
                try:
                    data = await asyncio.wait_for(reader.readline(), timeout=120)
                    if not data:
                        break

                    line = data.decode("utf-8", errors="replace").strip()
                    if not line:
                        continue

                    await session_manager.record_network_event(
                        session_id, "ftp_command_received", {"command": line}
                    )

                    response = await self._process_command(
                        session_id, line, state, source_ip, reader, writer
                    )
                    await self._send_response(writer, response)

                    if line.upper() in ("QUIT", "BYE"):
                        break

                except asyncio.TimeoutError:
                    await self._send_response(writer, "421 Connection timed out.\r\n")
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

        parts = line.split(None, 1)
        cmd = parts[0].upper()
        arg = parts[1] if len(parts) > 1 else ""

        await adaptive_engine.profile_actor(session_id, source_ip, {"ftp_command": cmd})

        if not state.authenticated and cmd not in (
            "USER", "PASS", "QUIT", "BYE", "FEAT", "OPTS", "AUTH", "PBSZ", "PROT",
        ):
            return "530 Please login with USER and PASS.\r\n"

        handlers = {
            "USER": lambda: self._cmd_user(arg, state),
            "PASS": lambda: self._cmd_pass(arg, state, session_id),
            "QUIT": lambda: self._cmd_quit(),
            "BYE": lambda: self._cmd_quit(),
            "NOOP": lambda: "200 NOOP ok.\r\n",
            "SYST": lambda: "215 UNIX Type: L8\r\n",
            "FEAT": lambda: (
                "211-Features:\r\n"
                " EPRT\r\n"
                " EPSV\r\n"
                " MDTM\r\n"
                " PASV\r\n"
                " REST STREAM\r\n"
                " SIZE\r\n"
                " TVFS\r\n"
                " UTF8\r\n"
                "211 End\r\n"
            ),
            "OPTS": lambda: "200 OK\r\n",
            "PWD": lambda: self._cmd_pwd(state),
            "XPWD": lambda: self._cmd_pwd(state),
            "CWD": lambda: self._cmd_cwd(arg, state),
            "XCWD": lambda: self._cmd_cwd(arg, state),
            "CDUP": lambda: self._cmd_cdup(state),
            "XCUP": lambda: self._cmd_cdup(state),
            "TYPE": lambda: self._cmd_type(arg, state),
            "PASV": lambda: self._cmd_pasv(local_ip, state, source_ip),
            "EPSV": lambda: self._cmd_epsv(state, source_ip),
            "PORT": lambda: self._cmd_port(arg, state),
            "EPRT": lambda: self._cmd_port(arg, state),
            "LIST": lambda: self._cmd_list(session_id, arg, state, writer),
            "NLST": lambda: self._cmd_nlst(arg, state, writer),
            "RETR": lambda: self._cmd_retr(session_id, arg, state, writer),
            "STOR": lambda: self._cmd_stor(session_id, arg, state, writer),
            "STOU": lambda: self._cmd_stor(session_id, arg, state, writer),
            "DELE": lambda: self._cmd_dele(arg),
            "RMD": lambda: self._cmd_rmd(arg),
            "MKD": lambda: self._cmd_mkd(arg),
            "XMKD": lambda: self._cmd_mkd(arg),
            "RNFR": lambda: "350 Ready for RNTO.\r\n",
            "RNTO": lambda: "250 Rename successful.\r\n",
            "SIZE": lambda: self._cmd_size(arg, state),
            "MDTM": lambda: self._cmd_mdtm(arg, state),
            "REST": lambda: f"350 Restart position accepted ({arg}).\r\n",
            "APPE": lambda: self._cmd_stor(session_id, arg, state, writer),
            "STAT": lambda: self._cmd_stat(state),
            "HELP": lambda: (
                "214-The following commands are recognized:\r\n"
                " USER PASS QUIT NOOP SYST FEAT OPTS PWD CWD CDUP\r\n"
                " TYPE PASV EPSV PORT LIST NLST RETR STOR DELE\r\n"
                " RMD MKD RNFR RNTO SIZE MDTM REST APPE STAT HELP\r\n"
                "214 Help OK.\r\n"
            ),
        }

        handler = handlers.get(cmd)
        if handler is None:
            return f"502 Command not implemented: {cmd}\r\n"

        result = handler()
        if inspect.isawaitable(result):
            result = await result
        return result

    def _cmd_user(self, arg: str, state: FTPSessionState) -> str:
        state.username = arg or "anonymous"
        return "331 Please specify the password.\r\n"

    async def _cmd_pass(
        self, arg: str, state: FTPSessionState, session_id: str
    ) -> str:
        state.password = arg
        username = state.username or "anonymous"
        accepted = username in self._fake_users

        # Log the credentials the attacker tried together with whether the
        # emulator accepted them. Recording every attempt as a success would
        # make the captured brute-force data useless.
        await session_manager.record_auth_attempt(
            session_id, username, arg, accepted
        )

        if accepted:
            state.authenticated = True
            return "230 Login successful.\r\n"

        return "530 Login incorrect.\r\n"

    @staticmethod
    def _get_local_ip(writer: asyncio.StreamWriter) -> str:
        sock = writer.get_extra_info("sockname")
        return sock[0] if sock else "0.0.0.0"

    def _cmd_quit(self) -> str:
        return "221 Goodbye.\r\n"

    def _cmd_pwd(self, state: FTPSessionState) -> str:
        return f'257 "{state.cwd}" is the current directory\r\n'

    def _cmd_cwd(self, arg: str, state: FTPSessionState) -> str:
        if not arg:
            return '501 Syntax error.\r\n'

        if arg.startswith("/"):
            new_path = arg
        else:
            new_path = os.path.join(state.cwd, arg)

        new_path = os.path.normpath(new_path)
        if new_path in self._fake_fs:
            state.cwd = new_path
            return f'250 Directory successfully changed to "{state.cwd}".\r\n'

        return f'550 Failed to change directory.\r\n'

    def _cmd_cdup(self, state: FTPSessionState) -> str:
        parent = os.path.dirname(state.cwd)
        if parent in self._fake_fs or parent == "/":
            state.cwd = parent if parent else "/"
            return '250 Directory successfully changed to "..".\r\n'
        return '550 Failed to change directory.\r\n'

    def _cmd_type(self, arg: str, state: FTPSessionState) -> str:
        state.transfer_type = arg.upper() if arg else "I"
        return f"200 Switching to {'Binary' if state.transfer_type == 'I' else 'ASCII'} mode.\r\n"

    async def _open_data_channel(
        self, state: FTPSessionState, source_ip: str
    ) -> Optional[int]:
        if state.data_channel is not None:
            await state.data_channel.close()
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
        address = config.ftp_pasv_address or local_ip
        octets = address.split(".")
        if len(octets) != 4:
            return "425 Use EPSV instead.\r\n"
        port = await self._open_data_channel(state, source_ip)
        if port is None:
            return "425 Could not open passive connection.\r\n"
        state.passive_mode = True
        return (
            f"227 Entering Passive Mode ({octets[0]},{octets[1]},"
            f"{octets[2]},{octets[3]},{port // 256},{port % 256}).\r\n"
        )

    async def _cmd_epsv(self, state: FTPSessionState, source_ip: str) -> str:
        port = await self._open_data_channel(state, source_ip)
        if port is None:
            return "425 Could not open passive connection.\r\n"
        state.passive_mode = True
        return f"229 Entering Extended Passive Mode (|||{port}|)\r\n"

    def _cmd_port(self, arg: str, state: FTPSessionState) -> str:
        # Active mode means the server connects out to an address the client
        # names. For a honeypot that is an outbound connection to the attacker
        # — or, with FTP bounce, to anyone — and the engine makes none. vsftpd
        # configured with port_enable=NO answers exactly this.
        return "500 Illegal PORT command.\r\n"

    async def _with_data_connection(self, state, writer, preamble):
        """Send the 150, then wait for the client's data connection."""
        channel = state.data_channel
        state.data_channel = None
        if channel is None:
            return None, "425 Use PORT or PASV first.\r\n"
        await self._send_response(writer, preamble)
        connection = await channel.accept()
        if connection is None:
            await channel.close()
            return None, "425 Failed to establish connection.\r\n"
        return (channel, connection), None

    def _listing(self, arg: str, state: FTPSessionState, names_only: bool) -> str:
        path = state.cwd
        if arg and not arg.startswith("-"):
            path = arg if arg.startswith("/") else os.path.join(state.cwd, arg)
        path = os.path.normpath(path)

        entries = list(self._fake_fs.get(path, []))
        uploaded = {
            os.path.basename(p): size
            for p, (_, size) in state.uploaded.items()
            if os.path.dirname(p) == path
        }
        lines = []
        for entry in entries + sorted(set(uploaded) - set(entries)):
            if names_only:
                lines.append(f"{entry}\r\n")
                continue
            full_path = os.path.join(path, entry)
            if full_path in self._fake_fs:
                lines.append(f"drwxr-xr-x    2 0        0            4096 Jan 15 10:30 {entry}\r\n")
            else:
                size = uploaded.get(entry) or random.randint(100, 100000)
                lines.append(f"-rw-r--r--    1 0        0        {size:>8} Jan 15 10:30 {entry}\r\n")
        return "".join(lines)

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

    async def _cmd_list(
        self, session_id: str, arg: str, state: FTPSessionState, writer
    ) -> str:
        listing = self._listing(arg, state, names_only=False)
        await session_manager.record_command(session_id, "LIST", listing)
        return await self._send_data(
            state, writer, "150 Here comes the directory listing.\r\n",
            listing.encode(), "226 Directory send OK.\r\n",
        )

    async def _cmd_nlst(self, arg: str, state: FTPSessionState, writer) -> str:
        return await self._send_data(
            state, writer, "150 Here comes the directory listing.\r\n",
            self._listing(arg, state, names_only=True).encode(),
            "226 Directory send OK.\r\n",
        )

    async def _cmd_retr(
        self, session_id: str, arg: str, state: FTPSessionState, writer
    ) -> str:
        if not arg:
            return "501 Syntax error.\r\n"
        path = os.path.normpath(arg if arg.startswith("/") else os.path.join(state.cwd, arg))

        await session_manager.record_network_event(
            session_id, "ftp_download_attempt", {"filename": arg[:255], "path": path[:500]}
        )

        if path in state.uploaded:
            # Their own upload comes back byte for byte, as it would.
            sha, _ = state.uploaded[path]
            try:
                with open(os.path.join(config.file_capture_dir, sha), "rb") as handle:
                    data = handle.read()
            except OSError:
                return "550 Failed to open file.\r\n"
        elif os.path.basename(path) in self._fake_fs.get(os.path.dirname(path), []):
            data = random.randbytes(random.randint(512, 4096))
        else:
            return "550 Failed to open file.\r\n"

        return await self._send_data(
            state, writer,
            f"150 Opening BINARY mode data connection for {os.path.basename(path)} "
            f"({len(data)} bytes).\r\n",
            data, "226 Transfer complete.\r\n",
        )

    async def _cmd_stor(
        self, session_id: str, arg: str, state: FTPSessionState, writer
    ) -> str:
        if not arg:
            return "501 Syntax error.\r\n"
        path = os.path.normpath(arg if arg.startswith("/") else os.path.join(state.cwd, arg))

        opened, error = await self._with_data_connection(state, writer, "150 Ok to send data.\r\n")
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
            return "552 Requested file action aborted. Exceeded storage allocation.\r\n"

        sha = await session_manager.record_file_upload(
            session_id, os.path.basename(path) or arg, bytes(received),
            remote_path=path, source="ftp_stor",
        )
        if sha:
            state.uploaded[path] = (sha, len(received))
        return "226 Transfer complete.\r\n"

    def _cmd_dele(self, arg: str) -> str:
        return f"250 DELE command successful.\r\n"

    def _cmd_rmd(self, arg: str) -> str:
        return f"250 RMD command successful.\r\n"

    def _cmd_mkd(self, arg: str) -> str:
        return f'257 "{arg}" created.\r\n'

    def _cmd_size(self, arg: str, state: FTPSessionState) -> str:
        return f"213 {random.randint(100, 100000)}\r\n"

    def _cmd_mdtm(self, arg: str, state: FTPSessionState) -> str:
        return "213 20240115103000\r\n"

    def _cmd_stat(self, state: FTPSessionState) -> str:
        return (
            "211-FTP server status:\r\n"
            "     Connected to 0.0.0.0\r\n"
            "     Logged in as anonymous\r\n"
            "     TYPE: Binary\r\n"
            f"     Current directory: {state.cwd}\r\n"
            "211 End\r\n"
        )
