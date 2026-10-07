import asyncio
import posixpath
import random
from datetime import datetime, timezone
from enum import Enum
from typing import Any, Optional

from honeypot.core.config import OperationalMode, config
from honeypot.capture.shell_writes import _Lexer, interpret
from honeypot.core import dropper
from honeypot.core.commands import CommandEmulator
from honeypot.core.identity import get_identity
from honeypot.core.shell_state import DroppedFile, resolve_path, shell_states
from honeypot.adaptive.fingerprint import fingerprint_engine
from honeypot.core.session import session_manager

#: busybox applets this emulator can answer. Mirai and its forks probe with
#: ``/bin/busybox <APPLET>`` and read the reply, so the ones that are not a
#: fetch get busybox's real "applet not found" wording.
_BUSYBOX_FETCH_APPLETS = {"wget", "ftpget", "tftp"}
#: Filters that can appear on the right of a pipe and whose output we can
#: produce from the left side's text.
_PIPE_FILTERS = {"grep", "egrep", "fgrep", "head", "tail", "wc", "cat",
                 "sort", "uniq", "cut", "tr", "base64", "md5sum", "sha256sum"}


class ModeHandler:
    def __init__(self):
        self._mode = config.operational_mode
        self._response_templates: dict[str, dict] = {
            "active": {
                "ssh_welcome": "Welcome to Ubuntu 22.04.3 LTS (GNU/Linux 5.15.0-91-generic x86_64)\n\n * Documentation:  https://help.ubuntu.com\n * Management:     https://landscape.canonical.com\n * Support:        https://ubuntu.com/advantage\n\nLast login: {login_time} from {source_ip}\n",
                "ssh_prompt": "$ ",
                "ssh_root_prompt": "# ",
                "command_not_found": "bash: {cmd}: command not found\n",
                "permission_denied": "bash: {cmd}: Permission denied\n",
                "file_list": "total {size}\ndrwxr-xr-x  2 root root 4096 {date} .\ndrwxr-xr-x 22 root root 4096 {date} ..\n{files}",
                "ftp_welcome": "220 (vsFTPd 3.0.5)\n",
                "ftp_login_ok": "331 Please specify the password.\n",
                "ftp_login_fail": "530 Login incorrect.\n",
                "ftp_success": "230 Login successful.\n",
                "ftp_prompt": "ftp> ",
                "http_404": "<!DOCTYPE HTML PUBLIC \"-//IETF//DTD HTML 2.0//EN\">\n<html><head>\n<title>404 Not Found</title>\n</head><body>\n<h1>Not Found</h1>\n<p>The requested URL was not found on this server.</p>\n<hr>\n<address>{server} Server at {host} Port {port}</address>\n</body></html>\n",
                "http_200": "<!DOCTYPE html>\n<html>\n<head><title>Default Page</title></head>\n<body>\n<h1>It works!</h1>\n<p>This is the default web page for this server.</p>\n<hr>\n<address>{server} Server at {host} Port {port}</address>\n</body>\n</html>\n",
            },
            "passive": {
                "ssh_welcome": "",
                "ssh_prompt": "",
                "ssh_root_prompt": "",
                "command_not_found": "",
                "permission_denied": "",
                "file_list": "",
                "ftp_welcome": "",
                "ftp_login_ok": "",
                "ftp_login_fail": "",
                "ftp_success": "",
                "ftp_prompt": "",
                "http_404": "",
                "http_200": "",
            },
        }

    @property
    def mode(self) -> OperationalMode:
        return self._mode

    @mode.setter
    def mode(self, value: OperationalMode):
        self._mode = value

    def is_active(self) -> bool:
        return self._mode == OperationalMode.ACTIVE_EMULATION

    def is_passive(self) -> bool:
        return self._mode == OperationalMode.PASSIVE_MONITORING

    async def handle_interaction(
        self,
        session_id: str,
        protocol: str,
        interaction_type: str,
        data: Optional[dict] = None,
    ) -> str:
        if self.is_passive():
            if data:
                await self._log_passive(session_id, protocol, interaction_type, data)
            return ""

        response = await self._generate_active_response(
            session_id, protocol, interaction_type, data or {}
        )
        return response

    async def _log_passive(
        self, session_id: str, protocol: str, interaction_type: str, data: dict
    ):
        """Record an interaction that the emulator itself does not capture.

        Emulators already persist commands, credentials, keystrokes and
        network events as they read them off the wire, so passive mode only
        needs to note that a request arrived and was deliberately not answered.
        Re-recording here would duplicate every command in the session.
        """
        await session_manager.record_network_event(
            session_id,
            "passive_observation",
            {
                "protocol": protocol,
                "interaction_type": interaction_type,
                "responded": False,
            },
        )

    async def _generate_active_response(
        self, session_id: str, protocol: str, interaction_type: str, data: dict
    ) -> str:
        templates = self._response_templates["active"]

        if protocol == "ssh":
            return await self._ssh_response(session_id, interaction_type, data, templates)
        elif protocol == "ftp":
            return await self._ftp_response(session_id, interaction_type, data, templates)
        elif protocol in ("http", "https"):
            return await self._http_response(session_id, interaction_type, data, templates)

        return ""

    def _welcome(self, data: dict) -> str:
        """The MOTD and the "Last login" line, as Ubuntu 20.04 prints them.

        The identity decides the OS, and the login line shows the *previous*
        login — a plausible earlier session from somewhere else — rather than
        the attacker's own address at the current instant, which no real sshd
        would show on a first connection and which was a giveaway here.
        """
        identity = get_identity()
        from honeypot.core.commands import _last_login_line

        banner = (
            f"Welcome to Ubuntu {identity.os_version} LTS "
            f"(GNU/Linux {identity.kernel} {identity.arch})\n\n"
            " * Documentation:  https://help.ubuntu.com\n"
            " * Management:     https://landscape.canonical.com\n"
            " * Support:        https://ubuntu.com/advantage\n\n"
        )
        welcome = banner + _last_login_line(identity)
        # Advance the stored last-login so a second connection sees this one.
        source_ip = data.get("source_ip")
        if source_ip:
            identity.note_login(source_ip)
        return welcome

    async def _ssh_response(
        self, session_id: str, interaction_type: str, data: dict, templates: dict
    ) -> str:
        if interaction_type in ("welcome", "auth_success"):
            return self._welcome(data)

        elif interaction_type == "prompt":
            is_root = data.get("is_root", False)
            identity = get_identity()
            shell = shell_states.get(session_id)
            home = "/root" if is_root else identity.home_for(data.get("username") or "user")
            shell.home = home
            cwd = shell.display_cwd(home)
            prompt_char = "#" if is_root else "$"
            return f"{data.get('username', 'user')}@{identity.hostname}:{cwd}{prompt_char} "

        elif interaction_type == "command":
            # Case preserved: lowercasing corrupts base64 payloads and the
            # case-sensitive paths a dropper checks (``./Mozi.m``).
            return await self._process_command_line(
                session_id, data.get("command", ""), data
            )

        return ""

    async def _process_command_line(
        self, session_id: str, raw: str, data: dict
    ) -> str:
        """Run one command line the attacker typed, as a real shell would.

        The line is split into statements on ``;`` ``&&`` ``||`` and into
        pipeline stages on ``|`` by the same quote-aware lexer that captures
        shell writes, so a compound loader line is handled one segment at a
        time with the previous segment's exit code honoured — rather than the
        old behaviour, which matched the whole lowercased line against a
        dictionary and answered ``cd /tmp || cd /var/run; wget …`` as a single
        unknown command.
        """
        shell = shell_states.get(session_id)
        identity = get_identity()
        is_root = bool(data.get("is_root"))
        username = data.get("username") or ("root" if is_root else "user")
        shell.home = "/root" if is_root else identity.home_for(username)
        shell.remember(raw.strip())

        try:
            statements = _Lexer(raw).run()
        except Exception:
            statements = [(";", [type("S", (), {"words": raw.split(), "redirects": [], "heredoc": None})()])]

        emulator = CommandEmulator(identity)
        out_parts: list[str] = []
        last_status = shell.last_status
        for connector, pipeline in statements:
            if connector == "&&" and last_status != 0:
                continue
            if connector == "||" and last_status == 0:
                continue
            text, last_status = await self._run_pipeline(
                session_id, pipeline, shell, emulator, username, is_root, data
            )
            if text:
                out_parts.append(text)
        shell.last_status = last_status
        return "".join(out_parts)

    async def _run_pipeline(
        self, session_id, pipeline, shell, emulator, username, is_root, data
    ) -> tuple[str, int]:
        """Run a single pipeline (stages joined by ``|``)."""
        piped: Optional[bytes] = None
        display = ""
        status = 0
        # A fetch piped into an interpreter (``curl … | sh``) is the loader
        # handing its payload straight to a shell; the download recorder needs
        # to know even though the ``| sh`` is a later stage.
        pipes_to_shell = any(
            posixpath.basename((getattr(s, "words", []) or [""])[0])
            in ("sh", "bash", "dash", "ash", "ksh", "zsh", "python", "python3", "perl")
            for s in pipeline[1:]
        )
        for index, stage in enumerate(pipeline):
            words = list(getattr(stage, "words", []))
            if not words:
                continue
            redirects = getattr(stage, "redirects", [])
            redirected = any(r.op in (">", ">>") and r.fd == 1 for r in redirects)
            is_last = index == len(pipeline) - 1

            text, status, piped = await self._run_stage(
                session_id, words, shell, emulator, username, is_root, data,
                piped, index, pipes_to_shell,
            )
            # Output of a non-final stage feeds the next as stdin, not the
            # terminal. A stage writing to a file prints nothing.
            if is_last and not redirected:
                display = "" if text is None else text
            elif is_last:
                display = ""
        return display, status

    async def _run_stage(
        self, session_id, words, shell, emulator, username, is_root, data,
        piped, index, pipes_to_shell=False,
    ) -> tuple[Optional[str], int, Optional[bytes]]:
        name = words[0]
        base = posixpath.basename(name)

        # Retrieval tools keep the whole session alive; handled specially so
        # the C2 URL, filename and intent are recorded as events.
        if base in ("wget", "curl"):
            line = " ".join(words)
            if pipes_to_shell:
                line += " | sh"
            text = await self._emulate_download(session_id, line, data)
            return text, 0, (text.encode() if text else b"")

        if base == "busybox":
            return await self._busybox(session_id, words, shell, emulator, username, is_root, data)

        if base in ("chmod", "chown", "chgrp"):
            self._apply_chmod(shell, words)
            return "", 0, b""

        if base == "cd":
            text, status = self._change_dir(shell, words, data)
            return text, status, b""

        if base in ("sh", "bash", "dash", "ash", "ksh", "zsh") and "-c" in words:
            # `sh -c '<inner>'`: run the inner line through the same machinery.
            try:
                inner = words[words.index("-c") + 1]
            except (ValueError, IndexError):
                inner = ""
            if inner:
                text = await self._process_command_line(session_id, inner, data)
                return text, shell.last_status, (text.encode() if text else b"")
            return "", 0, b""

        if name.startswith(("./", "/", "../")) or name.startswith("~"):
            # Running something the attacker put here.
            text, status = await self._run_dropped(session_id, name, shell, emulator, username, is_root)
            if text is not None or status != 127:
                return text, status, (text.encode() if text else b"")

        # A pipe filter consuming the previous stage's output.
        if index > 0 and base in _PIPE_FILTERS and piped is not None:
            text = self._apply_filter(base, words[1:], piped)
            return text, 0, (text.encode() if text else b"")

        text, status = emulator.run(words, shell, username, is_root, piped)
        return text, status, (text.encode() if text else b"")

    async def _busybox(self, session_id, words, shell, emulator, username, is_root, data):
        if len(words) < 2:
            return "BusyBox v1.30.1 (Ubuntu 1:1.30.1-7ubuntu3) multi-call binary.\n", 0, b""
        applet = words[1]
        low = applet.lower()
        if low in _BUSYBOX_FETCH_APPLETS and low in ("wget",):
            text = await self._emulate_download(session_id, " ".join(words[1:]), data)
            return text, 0, (text.encode() if text else b"")
        # A known applet: run it as the bare command.
        if posixpath.basename(low) in [b.lstrip("/usr/bin/") for b in []] or hasattr(emulator, f"_cmd_{low}"):
            text, status = emulator.run([low] + words[2:], shell, username, is_root, None)
            return text, status, (text.encode() if text else b"")
        # Mirai probes with an invented applet name and reads the reply; real
        # busybox answers exactly this, which also satisfies the probe.
        return f"{applet}: applet not found\n", 127, b""

    def _apply_chmod(self, shell, words) -> None:
        for arg in words[1:]:
            if arg.startswith(("-", "+", "0", "1", "2", "3", "4", "5", "6", "7", "u", "a", "g", "o", "=")):
                continue
            path = resolve_path(shell.cwd, arg, shell.home)
            file = shell.files.get(path)
            if file is not None:
                file.executable = True

    def _change_dir(self, shell, words, data) -> tuple[str, int]:
        target_arg = words[1] if len(words) > 1 else "~"
        if target_arg == "-":
            target = getattr(shell, "prev_cwd", shell.home)
        else:
            target = resolve_path(shell.cwd, target_arg, shell.home)
        # Standard roots an ordinary host has; cd beneath any of them, into
        # anywhere writable, or into a directory the attacker created, works.
        # Being too strict here is its own tell — a loader that cds somewhere
        # ordinary and is told it is missing knows it is on a decoy.
        roots = (
            "/", "/bin", "/boot", "/dev", "/etc", "/home", "/lib", "/lib64",
            "/media", "/mnt", "/opt", "/proc", "/root", "/run", "/sbin",
            "/srv", "/sys", "/tmp", "/usr", "/var", shell.home,
        )
        if (
            target in roots
            or target in shell.dirs
            or target.startswith(tuple(r + "/" for r in roots))
        ):
            shell.prev_cwd = shell.cwd
            shell.cwd = target
            data["cwd_after"] = target
            return "", 0
        return f"-bash: cd: {target_arg}: No such file or directory\n", 1

    async def _run_dropped(self, session_id, name, shell, emulator, username, is_root):
        path = resolve_path(shell.cwd, name, shell.home)
        file = shell.files.get(path)
        if file is None:
            return f"-bash: {name}: No such file or directory\n", 127
        if name.startswith("./") and not file.executable:
            return f"-bash: {name}: Permission denied\n", 126
        await session_manager.record_network_event(
            session_id,
            "payload_execution",
            {"path": path, "source_url": file.source_url, "bytes": file.size, "executed": False},
        )
        # A real loader daemonises and prints nothing; silence keeps the
        # session going and is the accurate answer.
        return "", 0

    def _apply_filter(self, base: str, args: list, piped: bytes) -> str:
        text = piped.decode("utf-8", errors="replace")
        lines = text.splitlines()
        if base in ("grep", "egrep", "fgrep"):
            import re
            invert = any(a in ("-v", "--invert-match") for a in args)
            pats = [a for a in args if not a.startswith("-")]
            pat = pats[0] if pats else ""
            try:
                rx = re.compile(pat)
            except re.error:
                rx = re.compile(re.escape(pat))
            kept = [ln for ln in lines if bool(rx.search(ln)) != invert]
            return "\n".join(kept) + ("\n" if kept else "")
        if base == "head":
            n = self._filter_n(args, 10)
            return "\n".join(lines[:n]) + ("\n" if lines[:n] else "")
        if base == "tail":
            n = self._filter_n(args, 10)
            return "\n".join(lines[-n:]) + ("\n" if lines[-n:] else "")
        if base == "wc":
            if args and "-l" in args:
                return f"{len(lines)}\n"
            return f" {len(lines)} {len(text.split())} {len(text)}\n"
        if base == "cat":
            return text
        if base == "sort":
            uniq = "-u" in args
            s = sorted(lines)
            if uniq:
                out = []
                for ln in s:
                    if not out or out[-1] != ln:
                        out.append(ln)
                s = out
            return "\n".join(s) + ("\n" if s else "")
        if base == "uniq":
            out = []
            for ln in lines:
                if not out or out[-1] != ln:
                    out.append(ln)
            return "\n".join(out) + ("\n" if out else "")
        if base == "base64":
            import base64 as _b64
            if any(a in ("-d", "--decode") for a in args):
                try:
                    return _b64.b64decode(text).decode("utf-8", errors="replace")
                except Exception:
                    return ""
            return _b64.b64encode(piped).decode() + "\n"
        if base in ("md5sum", "sha256sum"):
            import hashlib
            algo = hashlib.md5 if base == "md5sum" else hashlib.sha256
            return f"{algo(piped).hexdigest()}  -\n"
        if base == "tr":
            if len(args) >= 2 and not args[0].startswith("-"):
                table = str.maketrans(args[0], args[1][: len(args[0])])
                return text.translate(table)
            return text
        if base == "cut":
            return text
        return text

    @staticmethod
    def _filter_n(args: list, default: int) -> int:
        skip = False
        for idx, a in enumerate(args):
            if skip:
                skip = False
                continue
            if a == "-n" and idx + 1 < len(args):
                try:
                    return int(args[idx + 1].lstrip("+"))
                except ValueError:
                    return default
            if a.startswith("-n"):
                try:
                    return int(a[2:])
                except ValueError:
                    return default
            if a.startswith("-") and a[1:].isdigit():
                return int(a[1:])
        return default


    async def _emulate_download(self, session_id: str, cmd: str, data: dict) -> str:
        """Answer wget/curl as though the fetch worked.

        No request is made. The URL is parsed, recorded against the session as
        a network event so it reaches the backend as an indicator, and a
        plausible transcript is returned. Letting the fetch "succeed" is the
        whole point: the attacker's next commands — chmod, execute, the second
        stage, the kill-competitor loop — only happen if this one does.
        """
        download = dropper.parse(cmd)
        if download is None:
            # A bare `wget` or a form we cannot read: reply the way the real
            # tool does for a missing argument rather than inventing output.
            tool = cmd.split()[0]
            if tool == "wget":
                return (
                    "wget: missing URL\n"
                    "Usage: wget [OPTION]... [URL]...\n\n"
                    "Try `wget --help' for more options.\n"
                )
            return (
                "curl: try 'curl --help' or 'curl --manual' for more information\n"
            )

        size = dropper.size_for(download)

        await session_manager.record_network_event(
            session_id,
            "file_download",
            {
                "tool": download.tool,
                "url": download.url,
                "host": download.host,
                "port": download.port,
                "filename": download.filename,
                "piped_to_shell": download.piped,
                "bytes": size,
                # Recorded so an analyst reading the session knows the honeypot
                # never actually retrieved the payload.
                "fetched": False,
            },
        )

        if download.saves:
            shell = shell_states.get(session_id)
            path = resolve_path(shell.cwd, download.target)
            shell.add_file(
                path,
                DroppedFile(
                    name=download.filename,
                    size=size,
                    source_url=download.url,
                ),
            )

        return dropper.transcript(download, size)

    async def _ftp_response(
        self, session_id: str, interaction_type: str, data: dict, templates: dict
    ) -> str:
        if interaction_type == "welcome":
            return templates["ftp_welcome"]

        elif interaction_type == "user":
            return templates["ftp_login_ok"]

        elif interaction_type == "pass":
            username = data.get("username", "anonymous")
            password = data.get("password", "")
            await session_manager.record_auth_attempt(
                session_id, username, password, True
            )
            return templates["ftp_success"]

        elif interaction_type == "list":
            result = (
                "150 Here comes the directory listing.\n"
                "drwxr-xr-x    2 0        0            4096 Jan 15 10:30 pub\n"
                "drwxr-xr-x    2 0        0            4096 Jan 15 10:30 incoming\n"
                "-rw-r--r--    1 0        0             120 Jan 15 10:30 readme.txt\n"
                "-rw-r--r--    1 0        0            2048 Jan 15 10:30 config.bak\n"
                "226 Directory send OK.\n"
            )
            return result

        elif interaction_type == "get":
            filename = data.get("filename", "unknown")
            await session_manager.record_command(
                session_id, f"RETR {filename}", f"150 Opening BINARY mode data connection for {filename}.\n226 Transfer complete.\n"
            )
            return f"150 Opening BINARY mode data connection for {filename}.\n226 Transfer complete.\n"

        elif interaction_type == "put":
            filename = data.get("filename", "unknown")
            content = data.get("content", b"")
            if isinstance(content, str):
                content = content.encode()
            await session_manager.record_file_upload(
                session_id, filename, content, f"/incoming/{filename}"
            )
            return f"150 Ok to send data.\n226 Transfer complete.\n"

        elif interaction_type == "cwd":
            path = data.get("path", "/")
            return f'250 Directory successfully changed to "{path}".\n'

        elif interaction_type == "pwd":
            return f'257 "{data.get("path", "/")}" is the current directory\n'

        elif interaction_type == "quit":
            return "221 Goodbye.\n"

        return "500 Unknown command.\n"

    async def _http_response(
        self, session_id: str, interaction_type: str, data: dict, templates: dict
    ) -> str:
        if interaction_type == "request":
            method = data.get("method", "GET")
            path = data.get("path", "/")
            headers = data.get("headers", {})
            body = data.get("body", "")

            await session_manager.record_network_event(
                session_id,
                "http_request",
                {
                    "method": method,
                    "path": path,
                    "headers": dict(headers),
                    "body_preview": body[:500] if body else "",
                },
            )

            if path == "/" or path == "/index.html":
                return self._build_http_response(
                    200, "OK", templates["http_200"].format(
                        server=fingerprint_engine.get_http_server_header(),
                        host=headers.get("Host", "localhost"),
                        port=config.http_port,
                    )
                )
            elif path in ("/admin", "/login", "/wp-admin", "/phpmyadmin"):
                return self._build_http_response(
                    200,
                    "OK",
                    f"<!DOCTYPE html><html><head><title>Login</title></head><body>"
                    f"<h1>Authentication Required</h1>"
                    f'<form method="POST" action="/login">'
                    f'<input type="text" name="username" placeholder="Username"><br>'
                    f'<input type="password" name="password" placeholder="Password"><br>'
                    f'<input type="submit" value="Login">'
                    f"</form></body></html>\n",
                )
            elif path.endswith((".php", ".asp", ".aspx", ".jsp")):
                return self._build_http_response(
                    404,
                    "Not Found",
                    templates["http_404"].format(
                        server=fingerprint_engine.get_http_server_header(),
                        host=headers.get("Host", "localhost"),
                        port=config.http_port,
                    ),
                )
            else:
                return self._build_http_response(
                    404,
                    "Not Found",
                    templates["http_404"].format(
                        server=fingerprint_engine.get_http_server_header(),
                        host=headers.get("Host", "localhost"),
                        port=config.http_port,
                    ),
                )

        elif interaction_type == "post":
            path = data.get("path", "/")
            body = data.get("body", "")

            await session_manager.record_network_event(
                session_id,
                "http_post",
                {
                    "path": path,
                    "body": body[:1000] if body else "",
                    "content_type": data.get("content_type", ""),
                },
            )

            if path == "/login":
                return self._build_http_response(
                    302,
                    "Found",
                    "",
                    {"Location": "/dashboard"},
                )
            elif path == "/upload":
                return self._build_http_response(
                    200, "OK", '{"status": "uploaded", "path": "/uploads/file"}\n'
                )

            return self._build_http_response(
                404, "Not Found", '{"error": "not found"}\n'
            )

        return self._build_http_response(400, "Bad Request", "")

    def _build_http_response(
        self,
        status_code: int,
        status_text: str,
        body: str,
        extra_headers: Optional[dict] = None,
    ) -> str:
        headers = {
            "Server": fingerprint_engine.get_http_server_header(),
            "Content-Type": "text/html; charset=UTF-8",
            "Content-Length": str(len(body.encode())),
            "Connection": "close",
        }
        # Only a PHP stack sends X-Powered-By, and only on a page it served —
        # never on a 404. nginx and static responses send none.
        powered_by = fingerprint_engine.get_x_powered_by()
        if powered_by and status_code < 400:
            headers["X-Powered-By"] = powered_by
        if extra_headers:
            headers.update(extra_headers)

        response = f"HTTP/1.1 {status_code} {status_text}\r\n"
        for key, value in headers.items():
            response += f"{key}: {value}\r\n"
        response += "\r\n"
        response += body
        return response


mode_handler = ModeHandler()
