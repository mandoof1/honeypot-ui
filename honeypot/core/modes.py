import asyncio
import random
from enum import Enum
from typing import Any, Optional

from honeypot.core.config import OperationalMode, config
from honeypot.core.session import session_manager


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
                "http_404": "<!DOCTYPE HTML PUBLIC \"-//IETF//DTD HTML 2.0//EN\">\n<html><head>\n<title>404 Not Found</title>\n</head><body>\n<h1>Not Found</h1>\n<p>The requested URL was not found on this server.</p>\n<hr>\n<address>Apache/2.4.52 (Ubuntu) Server at {host} Port {port}</address>\n</body></html>\n",
                "http_200": "<!DOCTYPE html>\n<html>\n<head><title>Default Page</title></head>\n<body>\n<h1>It works!</h1>\n<p>This is the default web page for this server.</p>\n<hr>\n<address>Apache/2.4.52 (Ubuntu) Server at {host} Port {port}</address>\n</body>\n</html>\n",
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
        if interaction_type == "command":
            await session_manager.record_command(
                session_id, data.get("command", ""), "", 0
            )
        elif interaction_type == "auth":
            await session_manager.record_auth_attempt(
                session_id,
                data.get("username", ""),
                data.get("password", ""),
                False,
            )
        elif interaction_type == "file_upload":
            content = data.get("content", b"")
            if isinstance(content, str):
                content = content.encode()
            await session_manager.record_file_upload(
                session_id,
                data.get("filename", "unknown"),
                content,
                data.get("path", ""),
            )
        elif interaction_type == "network":
            await session_manager.record_network_event(
                session_id, data.get("event_type", "unknown"), data
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

    async def _ssh_response(
        self, session_id: str, interaction_type: str, data: dict, templates: dict
    ) -> str:
        if interaction_type == "welcome":
            from datetime import datetime, timezone

            return templates["ssh_welcome"].format(
                login_time=datetime.now(timezone.utc).strftime("%a %b %d %H:%M:%S %Y"),
                source_ip=data.get("source_ip", "0.0.0.0"),
            )

        elif interaction_type == "prompt":
            is_root = data.get("is_root", False)
            hostname = data.get("hostname", "honeypot")
            cwd = data.get("cwd", "~")
            prompt_char = "#" if is_root else "$"
            return f"{data.get('username', 'user')}@{hostname}:{cwd}{prompt_char} "

        elif interaction_type == "command":
            cmd = data.get("command", "").strip().lower()
            return await self._execute_emulated_command(session_id, cmd, data)

        elif interaction_type == "auth_success":
            return templates["ssh_welcome"].format(
                login_time=datetime.now(timezone.utc).strftime("%a %b %d %H:%M:%S %Y"),
                source_ip=data.get("source_ip", "0.0.0.0"),
            )

        return ""

    async def _execute_emulated_command(
        self, session_id: str, cmd: str, data: dict
    ) -> str:
        from datetime import datetime, timezone

        fake_fs = {
            "/": ["bin", "etc", "home", "opt", "root", "tmp", "usr", "var", "srv"],
            "/home": ["admin", "user"],
            "/etc": [
                "passwd",
                "shadow",
                "ssh",
                "cron.d",
                "hosts",
                "hostname",
                "resolv.conf",
            ],
            "/tmp": [],
            "/opt": [],
        }

        fake_files = {
            "/etc/passwd": "root:x:0:0:root:/root:/bin/bash\n"
            "daemon:x:1:1:daemon:/usr/sbin:/usr/sbin/nologin\n"
            "bin:x:2:2:bin:/bin:/usr/sbin/nologin\n"
            "user:x:1000:1000:User:/home/user:/bin/bash\n",
            "/etc/hostname": "honeypot\n",
            "/etc/hosts": "127.0.0.1\tlocalhost\n"
            "::1\tlocalhost ip6-localhost ip6-loopback\n"
            "10.0.0.5\thoneypot\n",
        }

        if cmd == "ls" or cmd.startswith("ls "):
            path = cmd[3:].strip() if len(cmd) > 3 else "."
            if path == "-la" or path == "-al":
                path = "."
            entries = fake_fs.get(path, ["file1.txt", "file2.log", "config.yml"])
            result = ""
            for entry in entries:
                is_dir = entry not in ("file1.txt", "file2.log", "config.yml")
                perms = "drwxr-xr-x" if is_dir else "-rw-r--r--"
                size = "4096" if is_dir else str(random.randint(100, 50000))
                date = datetime.now(timezone.utc).strftime("%b %d %H:%M")
                result += f"{perms} 1 root root {size:>6} {date} {entry}\n"
            await session_manager.record_command(session_id, cmd, result)
            return result

        elif cmd == "pwd":
            result = data.get("cwd", "/home/user") + "\n"
            await session_manager.record_command(session_id, cmd, result)
            return result

        elif cmd == "whoami":
            result = data.get("username", "user") + "\n"
            await session_manager.record_command(session_id, cmd, result)
            return result

        elif cmd == "id":
            uid = 0 if data.get("is_root") else 1000
            result = f"uid={uid}({data.get('username', 'user')}) gid={uid}({data.get('username', 'user')}) groups={uid}({data.get('username', 'user')})\n"
            await session_manager.record_command(session_id, cmd, result)
            return result

        elif cmd == "uname" or cmd == "uname -a":
            result = "Linux honeypot 5.15.0-91-generic #101-Ubuntu SMP Tue Nov 14 13:30:08 UTC 2023 x86_64 x86_64 x86_64 GNU/Linux\n"
            await session_manager.record_command(session_id, cmd, result)
            return result

        elif cmd == "cat /etc/passwd":
            result = fake_files["/etc/passwd"]
            await session_manager.record_command(session_id, cmd, result)
            return result

        elif cmd == "cat /etc/hostname":
            result = fake_files["/etc/hostname"]
            await session_manager.record_command(session_id, cmd, result)
            return result

        elif cmd == "cat /etc/hosts":
            result = fake_files["/etc/hosts"]
            await session_manager.record_command(session_id, cmd, result)
            return result

        elif cmd == "hostname":
            result = "honeypot\n"
            await session_manager.record_command(session_id, cmd, result)
            return result

        elif cmd == "ifconfig" or cmd == "ip addr":
            result = (
                "eth0: flags=4163<UP,BROADCAST,RUNNING,MULTICAST>  mtu 1500\n"
                "        inet 10.0.0.5  netmask 255.255.255.0  broadcast 10.0.0.255\n"
                "        inet6 fe80::1  prefixlen 64  scopeid 0x20<link>\n"
                "        ether 02:42:0a:00:00:05  txqueuelen 0  (Ethernet)\n"
                "        RX packets 1234  bytes 123456 (123.4 KB)\n"
                "        TX packets 5678  bytes 567890 (567.8 KB)\n"
                "lo: flags=73<UP,LOOPBACK,RUNNING>  mtu 65536\n"
                "        inet 127.0.0.1  netmask 255.0.0.0\n"
            )
            await session_manager.record_command(session_id, cmd, result)
            return result

        elif cmd == "ps aux" or cmd == "ps -ef":
            result = (
                "USER         PID %CPU %MEM    VSZ   RSS TTY      STAT START   TIME COMMAND\n"
                "root           1  0.0  0.1  18504  3072 ?        Ss   00:00   0:00 /sbin/init\n"
                "root         102  0.0  0.1  72308  5632 ?        Ss   00:00   0:00 /usr/sbin/sshd -D\n"
                "root         234  0.0  0.0  12340  2048 ?        Ss   00:00   0:00 /usr/sbin/cron -f\n"
                "root         456  0.0  0.1  25600  4096 ?        Ss   00:00   0:00 /usr/sbin/apache2 -k start\n"
                "www-data     457  0.0  0.2  35840  8192 ?        S    00:00   0:00 /usr/sbin/apache2 -k start\n"
                "user         789  0.0  0.1  10240  2560 pts/0    Ss   00:01   0:00 -bash\n"
            )
            await session_manager.record_command(session_id, cmd, result)
            return result

        elif cmd == "netstat -tlnp" or cmd == "ss -tlnp":
            result = (
                "Proto Recv-Q Send-Q Local Address           Foreign Address         State       PID/Program name\n"
                "tcp        0      0 0.0.0.0:22              0.0.0.0:*               LISTEN      102/sshd\n"
                "tcp        0      0 0.0.0.0:80              0.0.0.0:*               LISTEN      456/apache2\n"
                "tcp        0      0 0.0.0.0:443             0.0.0.0:*               LISTEN      456/apache2\n"
                "tcp        0      0 0.0.0.0:21              0.0.0.0:*               LISTEN      345/vsftpd\n"
            )
            await session_manager.record_command(session_id, cmd, result)
            return result

        elif cmd == "wget" or cmd.startswith("wget ") or cmd == "curl" or cmd.startswith("curl "):
            result = f"bash: {cmd.split()[0]}: command not found\n"
            await session_manager.record_command(session_id, cmd, result, 127)
            return result

        elif cmd.startswith("cd "):
            return ""

        elif cmd == "exit" or cmd == "logout":
            return ""

        elif cmd == "help":
            result = (
                "GNU bash, version 5.1.16(1)-release (x86_64-pc-linux-gnu)\n"
                "These shell commands are defined internally.  Type `help' to see this list.\n"
            )
            await session_manager.record_command(session_id, cmd, result)
            return result

        elif cmd.startswith("echo "):
            result = cmd[5:] + "\n"
            await session_manager.record_command(session_id, cmd, result)
            return result

        elif cmd.startswith("python") or cmd.startswith("perl") or cmd.startswith("ruby"):
            result = f"bash: {cmd.split()[0]}: command not found\n"
            await session_manager.record_command(session_id, cmd, result, 127)
            return result

        elif any(
            tool in cmd
            for tool in [
                "nmap",
                "masscan",
                "nikto",
                "sqlmap",
                "metasploit",
                "msfconsole",
                "hydra",
                "john",
                "hashcat",
            ]
        ):
            result = f"bash: {cmd.split()[0]}: command not found\n"
            await session_manager.record_command(session_id, cmd, result, 127)
            return result

        elif cmd.startswith("chmod") or cmd.startswith("chown"):
            result = ""
            await session_manager.record_command(session_id, cmd, result)
            return result

        elif cmd.startswith("rm ") or cmd.startswith("mkdir ") or cmd.startswith("touch "):
            result = ""
            await session_manager.record_command(session_id, cmd, result)
            return result

        elif cmd == "history":
            result = "    1  ls -la\n    2  cat /etc/passwd\n    3  whoami\n"
            await session_manager.record_command(session_id, cmd, result)
            return result

        elif cmd == "env" or cmd == "printenv":
            result = (
                "PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin\n"
                "HOME=/home/user\n"
                "SHELL=/bin/bash\n"
                "USER=user\n"
                "LANG=en_US.UTF-8\n"
                "TERM=xterm-256color\n"
            )
            await session_manager.record_command(session_id, cmd, result)
            return result

        else:
            result = f"bash: {cmd.split()[0] if cmd else 'command'}: command not found\n"
            await session_manager.record_command(session_id, cmd, result, 127)
            return result

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
            await session_manager.record_command(session_id, "LIST", result)
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
                        host=headers.get("Host", "localhost"),
                        port=config.http_port,
                    ),
                )
            else:
                return self._build_http_response(
                    404,
                    "Not Found",
                    templates["http_404"].format(
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
            "Server": "Apache/2.4.52 (Ubuntu)",
            "Content-Type": "text/html; charset=UTF-8",
            "Content-Length": str(len(body.encode())),
            "Connection": "close",
            "X-Powered-By": "PHP/8.1.2",
        }
        if extra_headers:
            headers.update(extra_headers)

        response = f"HTTP/1.1 {status_code} {status_text}\r\n"
        for key, value in headers.items():
            response += f"{key}: {value}\r\n"
        response += "\r\n"
        response += body
        return response


mode_handler = ModeHandler()
