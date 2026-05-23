import asyncio
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


class FTPSessionState:
    def __init__(self):
        self.username: Optional[str] = None
        self.password: Optional[str] = None
        self.authenticated = False
        self.cwd = "/"
        self.passive_mode = False
        self.transfer_type = "I"
        self.data_port: Optional[int] = None


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
            banner = self.get_banner()
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
            "PASV": lambda: self._cmd_pasv(source_ip),
            "EPSV": lambda: "229 Entering Extended Passive Mode (|||50000|)\r\n",
            "PORT": lambda: self._cmd_port(arg, state),
            "LIST": lambda: self._cmd_list(session_id, arg, state),
            "NLST": lambda: self._cmd_nlst(arg, state),
            "RETR": lambda: self._cmd_retr(session_id, arg, state),
            "STOR": lambda: self._cmd_stor(session_id, arg, state, reader),
            "DELE": lambda: self._cmd_dele(arg),
            "RMD": lambda: self._cmd_rmd(arg),
            "MKD": lambda: self._cmd_mkd(arg),
            "XMKD": lambda: self._cmd_mkd(arg),
            "RNFR": lambda: "350 Ready for RNTO.\r\n",
            "RNTO": lambda: "250 Rename successful.\r\n",
            "SIZE": lambda: self._cmd_size(arg, state),
            "MDTM": lambda: self._cmd_mdtm(arg, state),
            "REST": lambda: f"350 Restart position accepted ({arg}).\r\n",
            "APPE": lambda: self._cmd_stor(session_id, arg, state, reader),
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
        if handler:
            return handler()

        return f"502 Command not implemented: {cmd}\r\n"

    def _cmd_user(self, arg: str, state: FTPSessionState) -> str:
        state.username = arg or "anonymous"
        return "331 Please specify the password.\r\n"

    def _cmd_pass(
        self, arg: str, state: FTPSessionState, session_id: str
    ) -> str:
        state.password = arg
        username = state.username or "anonymous"

        if username in self._fake_users:
            state.authenticated = True
            return "230 Login successful.\r\n"

        return "530 Login incorrect.\r\n"

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

    def _cmd_pasv(self, source_ip: str) -> str:
        port = random.randint(50000, 50100)
        p1 = port // 256
        p2 = port % 256
        ip_parts = source_ip.split(".")
        return (
            f"227 Entering Passive Mode ({ip_parts[0]},{ip_parts[1]},"
            f"{ip_parts[2]},{ip_parts[3]},{p1},{p2}).\r\n"
        )

    def _cmd_port(self, arg: str, state: FTPSessionState) -> str:
        try:
            parts = arg.split(",")
            if len(parts) == 6:
                state.data_port = int(parts[4]) * 256 + int(parts[5])
                return "200 PORT command successful.\r\n"
        except (ValueError, IndexError):
            pass
        return "501 Syntax error.\r\n"

    def _cmd_list(self, session_id: str, arg: str, state: FTPSessionState) -> str:
        path = state.cwd
        if arg and not arg.startswith("-"):
            if arg.startswith("/"):
                path = arg
            else:
                path = os.path.join(state.cwd, arg)

        entries = self._fake_fs.get(path, [])
        if not entries:
            return "150 Here comes the directory listing.\r\n226 Transfer complete.\r\n"

        listing = "150 Here comes the directory listing.\r\n"
        for entry in entries:
            full_path = os.path.join(path, entry)
            is_dir = full_path in self._fake_fs
            if is_dir:
                listing += (
                    f"drwxr-xr-x    2 0        0            4096 "
                    f"Jan 15 10:30 {entry}\r\n"
                )
            else:
                size = random.randint(100, 100000)
                listing += (
                    f"-rw-r--r--    1 0        0            {size:>6} "
                    f"Jan 15 10:30 {entry}\r\n"
                )
        listing += "226 Directory send OK.\r\n"

        await session_manager.record_command(session_id, "LIST", listing)
        return listing

    def _cmd_nlst(self, arg: str, state: FTPSessionState) -> str:
        path = state.cwd
        if arg and not arg.startswith("-"):
            if arg.startswith("/"):
                path = arg
            else:
                path = os.path.join(state.cwd, arg)

        entries = self._fake_fs.get(path, [])
        result = "150 Here comes the directory listing.\r\n"
        for entry in entries:
            result += f"{entry}\r\n"
        result += "226 Transfer complete.\r\n"
        return result

    def _cmd_retr(self, session_id: str, arg: str, state: FTPSessionState) -> str:
        if not arg:
            return "501 Syntax error.\r\n"

        await session_manager.record_network_event(
            session_id, "ftp_download_attempt", {
                "filename": arg,
                "path": os.path.join(state.cwd, arg),
            }
        )

        return (
            f"150 Opening BINARY mode data connection for {arg} "
            f"({random.randint(100, 50000)} bytes).\r\n"
            f"226 Transfer complete.\r\n"
        )

    async def _cmd_stor(
        self,
        session_id: str,
        arg: str,
        state: FTPSessionState,
        reader: asyncio.StreamReader,
    ) -> str:
        if not arg:
            return "501 Syntax error.\r\n"

        await session_manager.record_network_event(
            session_id, "ftp_upload_attempt", {
                "filename": arg,
                "path": os.path.join(state.cwd, arg),
            }
        )

        return f"150 Ok to send data.\r\n226 Transfer complete.\r\n"

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
