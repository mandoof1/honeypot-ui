import asyncio
import logging
import random
import time
from typing import Optional

from honeypot.core.config import config
from honeypot.core.session import session_manager
from honeypot.core.modes import mode_handler
from honeypot.emulators.base import BaseEmulator
from honeypot.adaptive.fingerprint import fingerprint_engine
from honeypot.adaptive.response import adaptive_engine

logger = logging.getLogger(__name__)


class SSHSessionState:
    def __init__(self):
        self.username: Optional[str] = None
        self.password: Optional[str] = None
        self.authenticated = False
        self.cwd = "/home/user"
        self.is_root = False
        self.env_vars: dict = {}
        self.command_buffer = ""


class SSHHoneypot(BaseEmulator):
    def __init__(self):
        super().__init__("ssh", config.ssh_port)
        self._fake_users = {
            "root": "root",
            "admin": "admin",
            "user": "password",
            "test": "test",
            "ubuntu": "ubuntu",
            "pi": "raspberry",
            "oracle": "oracle",
            "postgres": "postgres",
        }
        self._allowed_users = set(self._fake_users.keys())

    def get_banner(self) -> str:
        return fingerprint_engine.get_ssh_banner()

    async def handle_client(
        self, reader: asyncio.StreamReader, writer: asyncio.StreamWriter
    ):
        source_ip, source_port = self._get_peer_info(writer)
        logger.info(f"SSH connection from {source_ip}:{source_port}")

        if not await self._check_rate_limit(source_ip):
            logger.warning(f"Rate limit exceeded for {source_ip}")
            writer.close()
            await writer.wait_closed()
            return

        session_id = await session_manager.create_session(
            "ssh", source_ip, source_port, {"protocol_version": "SSH-2.0"}
        )
        state = SSHSessionState()

        try:
            await self._negotiate_ssh(reader, writer, session_id, source_ip)
            await self._handle_auth(reader, writer, session_id, state, source_ip)

            if state.authenticated:
                await self._handle_shell_session(
                    reader, writer, session_id, state, source_ip
                )
            else:
                await session_manager.record_auth_attempt(
                    session_id,
                    state.username or "unknown",
                    state.password or "",
                    False,
                )

        except (ConnectionResetError, BrokenPipeError, asyncio.CancelledError):
            pass
        except Exception as e:
            logger.error(f"SSH session error: {e}")
        finally:
            await session_manager.end_session(session_id)
            writer.close()
            try:
                await writer.wait_closed()
            except Exception:
                pass

    async def _negotiate_ssh(
        self,
        reader: asyncio.StreamReader,
        writer: asyncio.StreamWriter,
        session_id: str,
        source_ip: str,
    ):
        banner = self.get_banner() + "\r\n"
        await self._send_response(writer, banner)

        await session_manager.record_network_event(
            session_id, "ssh_banner_sent", {"banner": banner.strip()}
        )

        try:
            client_banner = await asyncio.wait_for(reader.readline(), timeout=30)
            client_banner_str = client_banner.decode("utf-8", errors="replace").strip()
            await session_manager.record_network_event(
                session_id, "ssh_client_banner", {"banner": client_banner_str}
            )
        except asyncio.TimeoutError:
            writer.close()
            return

    async def _handle_auth(
        self,
        reader: asyncio.StreamReader,
        writer: asyncio.StreamWriter,
        session_id: str,
        state: SSHSessionState,
        source_ip: str,
    ):
        max_attempts = 6
        attempts = 0

        while attempts < max_attempts:
            username_prompt = "login as: "
            await self._send_response(writer, username_prompt)

            try:
                username_data = await asyncio.wait_for(reader.read(256), timeout=120)
                if not username_data:
                    return
                username = username_data.decode("utf-8", errors="replace").strip()
                username = username.replace("\r", "").replace("\n", "")

                if not username:
                    attempts += 1
                    continue

                state.username = username
                await session_manager.record_keystroke(session_id, username)

            except asyncio.TimeoutError:
                return

            password_prompt = f"{username}@{source_ip}'s password: "
            await self._send_response(writer, password_prompt)

            try:
                password_data = await asyncio.wait_for(reader.read(256), timeout=120)
                if not password_data:
                    return
                password = password_data.decode("utf-8", errors="replace").strip()
                password = password.replace("\r", "").replace("\n", "")

                state.password = password
                await session_manager.record_auth_attempt(
                    session_id, username, password, True
                )

            except asyncio.TimeoutError:
                return

            if username in self._allowed_users:
                state.authenticated = True
                if username == "root":
                    state.is_root = True
                    state.cwd = "/root"

                await adaptive_engine.profile_actor(session_id, source_ip, {
                    "auth_attempts": attempts + 1,
                    "username_used": username,
                    "password_used": password,
                })

                welcome = await mode_handler.handle_interaction(
                    session_id, "ssh", "auth_success",
                    {"source_ip": source_ip, "username": username},
                )
                await self._send_response(writer, welcome)
                return
            else:
                await self._send_response(writer, "Access denied\r\n")
                attempts += 1

        await self._send_response(writer, "Connection closed.\r\n")

    async def _handle_shell_session(
        self,
        reader: asyncio.StreamReader,
        writer: asyncio.StreamWriter,
        session_id: str,
        state: SSHSessionState,
        source_ip: str,
    ):
        prompt = await mode_handler.handle_interaction(
            session_id, "ssh", "prompt",
            {
                "username": state.username,
                "hostname": "honeypot",
                "cwd": state.cwd,
                "is_root": state.is_root,
            },
        )
        await self._send_response(writer, prompt)

        buffer = ""
        while True:
            try:
                data = await asyncio.wait_for(reader.read(1024), timeout=300)
                if not data:
                    break

                decoded = data.decode("utf-8", errors="replace")

                for char in decoded:
                    await session_manager.record_keystroke(session_id, char)

                    if char == "\r" or char == "\n":
                        if buffer.strip():
                            command = buffer.strip()
                            await session_manager.record_command(
                                session_id, command, "", 0
                            )

                            await adaptive_engine.profile_actor(
                                session_id, source_ip, {"command": command}
                            )

                            response = await mode_handler.handle_interaction(
                                session_id, "ssh", "command",
                                {
                                    "command": command,
                                    "username": state.username,
                                    "cwd": state.cwd,
                                    "is_root": state.is_root,
                                },
                            )

                            if command in ("exit", "logout"):
                                await session_manager.end_session(session_id)
                                return

                            await self._send_response(writer, response)

                            prompt = await mode_handler.handle_interaction(
                                session_id, "ssh", "prompt",
                                {
                                    "username": state.username,
                                    "hostname": "honeypot",
                                    "cwd": state.cwd,
                                    "is_root": state.is_root,
                                },
                            )
                            await self._send_response(writer, prompt)
                        buffer = ""
                    elif char == "\x7f" or char == "\x08":
                        if buffer:
                            buffer = buffer[:-1]
                            await self._send_response(writer, "\x08 \x08")
                    elif ord(char) >= 32:
                        buffer += char
                        await self._send_response(writer, char)

            except asyncio.TimeoutError:
                await self._send_response(writer, "\r\nConnection timed out.\r\n")
                break
