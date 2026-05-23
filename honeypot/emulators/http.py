import asyncio
import logging
import random
import time
from typing import Optional
from urllib.parse import parse_qs, urlparse

from honeypot.core.config import config
from honeypot.core.session import session_manager
from honeypot.core.modes import mode_handler
from honeypot.emulators.base import BaseEmulator
from honeypot.adaptive.fingerprint import fingerprint_engine
from honeypot.adaptive.response import adaptive_engine

logger = logging.getLogger(__name__)


class HTTPHoneypot(BaseEmulator):
    def __init__(self, use_tls: bool = False):
        protocol = "https" if use_tls else "http"
        port = config.https_port if use_tls else config.http_port
        super().__init__(protocol, port)
        self.use_tls = use_tls
        self._vulnerable_endpoints = {
            "/admin": "admin_panel",
            "/login": "login_form",
            "/wp-admin": "wordpress_admin",
            "/wp-login.php": "wordpress_login",
            "/phpmyadmin": "phpmyadmin",
            "/manager/html": "tomcat_manager",
            "/.env": "env_file",
            "/config.php": "config_file",
            "/api/v1/users": "api_users",
            "/api/v1/admin": "api_admin",
            "/upload": "upload_form",
            "/shell": "web_shell",
            "/cmd": "command_endpoint",
            "/eval": "eval_endpoint",
            "/debug": "debug_panel",
            "/console": "console_panel",
            "/actuator": "spring_actuator",
            "/actuator/env": "spring_env",
            "/actuator/health": "spring_health",
        }
        self._fake_files = {
            "/robots.txt": "User-agent: *\nDisallow: /admin/\nDisallow: /config/\nDisallow: /backup/\n",
            "/sitemap.xml": '<?xml version="1.0" encoding="UTF-8"?>\n<urlset xmlns="http://www.sitemaps.org/schemas/sitemap/0.9">\n<url><loc>http://localhost/</loc></url>\n</urlset>\n',
            "/.env": "DB_HOST=localhost\nDB_USER=root\nDB_PASS=supersecretpassword123\nAPI_KEY=sk-1234567890abcdef\n",
            "/config.php": "<?php\n$db_host = 'localhost';\n$db_user = 'root';\n$db_pass = 'admin123';\n$db_name = 'production';\n?>\n",
            "/wp-config.php": "<?php\ndefine('DB_NAME', 'wordpress');\ndefine('DB_USER', 'wp_user');\ndefine('DB_PASSWORD', 'wp_pass_2024');\ndefine('DB_HOST', 'localhost');\n?>\n",
        }

    def get_banner(self) -> str:
        return fingerprint_engine.get_http_server_header()

    async def handle_client(
        self, reader: asyncio.StreamReader, writer: asyncio.StreamWriter
    ):
        source_ip, source_port = self._get_peer_info(writer)
        logger.info(f"HTTP connection from {source_ip}:{source_port}")

        if not await self._check_rate_limit(source_ip):
            logger.warning(f"Rate limit exceeded for {source_ip}")
            writer.close()
            await writer.wait_closed()
            return

        session_id = await session_manager.create_session(
            self.protocol, source_ip, source_port
        )

        try:
            while True:
                try:
                    request_line = await asyncio.wait_for(
                        reader.readline(), timeout=60
                    )
                    if not request_line:
                        break

                    request_str = request_line.decode("utf-8", errors="replace").strip()
                    if not request_str:
                        continue

                    headers = await self._read_headers(reader)
                    content_length = int(headers.get("content-length", 0))
                    body = ""
                    if content_length > 0:
                        body_bytes = await asyncio.wait_for(
                            reader.readexactly(content_length), timeout=30
                        )
                        body = body_bytes.decode("utf-8", errors="replace")

                    response = await self._handle_request(
                        session_id, request_str, headers, body, source_ip, writer
                    )
                    await self._send_response(writer, response)

                    if headers.get("connection", "").lower() == "close":
                        break

                except asyncio.TimeoutError:
                    break
                except Exception:
                    break

        except (ConnectionResetError, BrokenPipeError, asyncio.CancelledError):
            pass
        except Exception as e:
            logger.error(f"HTTP session error: {e}")
        finally:
            await session_manager.end_session(session_id)
            writer.close()
            try:
                await writer.wait_closed()
            except Exception:
                pass

    async def _read_headers(
        self, reader: asyncio.StreamReader
    ) -> dict[str, str]:
        headers = {}
        try:
            while True:
                line = await asyncio.wait_for(reader.readline(), timeout=10)
                line_str = line.decode("utf-8", errors="replace").strip()
                if not line_str:
                    break
                if ":" in line_str:
                    key, value = line_str.split(":", 1)
                    headers[key.strip().lower()] = value.strip()
        except asyncio.TimeoutError:
            pass
        return headers

    async def _handle_request(
        self,
        session_id: str,
        request_line: str,
        headers: dict,
        body: str,
        source_ip: str,
        writer: asyncio.StreamWriter,
    ) -> str:
        parts = request_line.split()
        if len(parts) < 2:
            return self._build_response(400, "Bad Request", "Invalid request")

        method = parts[0].upper()
        full_path = parts[1]
        parsed = urlparse(full_path)
        path = parsed.path
        query = parse_qs(parsed.query)

        await session_manager.record_network_event(
            session_id,
            "http_request",
            {
                "method": method,
                "path": full_path,
                "headers": dict(headers),
                "body_preview": body[:500] if body else "",
                "source_ip": source_ip,
            },
        )

        await adaptive_engine.profile_actor(session_id, source_ip, {
            "http_method": method,
            "http_path": path,
        })

        if method == "GET":
            return await self._handle_get(session_id, path, query, headers, source_ip)
        elif method == "POST":
            return await self._handle_post(session_id, path, body, headers, source_ip)
        elif method == "HEAD":
            return await self._handle_head(session_id, path, headers)
        elif method == "OPTIONS":
            return self._handle_options()
        elif method == "PUT":
            return await self._handle_put(session_id, path, body, headers, source_ip)
        elif method == "DELETE":
            return await self._handle_delete(session_id, path, headers, source_ip)
        else:
            return self._build_response(
                501, "Not Implemented", f"Method {method} not supported"
            )

    async def _handle_get(
        self,
        session_id: str,
        path: str,
        query: dict,
        headers: dict,
        source_ip: str,
    ) -> str:
        if path in self._fake_files:
            content = self._fake_files[path]
            content_type = self._get_content_type(path)
            return self._build_response(
                200, "OK", content,
                {"Content-Type": content_type, "Content-Length": str(len(content))},
            )

        if path in self._vulnerable_endpoints:
            endpoint_type = self._vulnerable_endpoints[path]
            content = await self._generate_vulnerable_page(endpoint_type, path, headers)
            return self._build_response(
                200, "OK", content,
                {"Content-Type": "text/html; charset=UTF-8"},
            )

        if path.startswith("/wp-content/") or path.startswith("/wp-includes/"):
            return self._build_response(
                200, "OK", "<!-- WordPress asset placeholder -->\n",
                {"Content-Type": "text/html"},
            )

        attack_indicators = [
            ("../", "path_traversal"),
            ("etc/passwd", "etc_passwd_probe"),
            ("etc/shadow", "etc_shadow_probe"),
            ("/proc/", "proc_probe"),
            ("<script>", "xss_attempt"),
            ("javascript:", "xss_attempt"),
            ("union+select", "sql_injection"),
            ("union%20select", "sql_injection"),
            ("1=1", "sql_injection"),
            ("1' OR '1'='1", "sql_injection"),
            ("${jndi:", "log4shell_attempt"),
            ("${env:", "log4shell_attempt"),
            ("cmd=", "command_injection"),
            ("exec(", "command_injection"),
            ("shell_exec", "command_injection"),
            ("/etc/passwd", "lfi_attempt"),
            ("php://filter", "lfi_attempt"),
            ("php://input", "lfi_attempt"),
            ("data://", "lfi_attempt"),
            ("expect://", "lfi_attempt"),
        ]

        for indicator, attack_type in attack_indicators:
            if indicator.lower() in path.lower():
                await session_manager.record_network_event(
                    session_id, "attack_detected", {
                        "type": attack_type,
                        "path": path,
                        "source_ip": source_ip,
                    }
                )
                await adaptive_engine.profile_actor(session_id, source_ip, {
                    "attack_type": attack_type,
                })
                break

        return self._build_response(
            404, "Not Found",
            f'<!DOCTYPE HTML PUBLIC "-//IETF//DTD HTML 2.0//EN">\n'
            f"<html><head>\n<title>404 Not Found</title>\n</head><body>\n"
            f"<h1>Not Found</h1>\n"
            f"<p>The requested URL {path} was not found on this server.</p>\n"
            f"<hr>\n"
            f"<address>Apache/2.4.52 (Ubuntu) Server at "
            f"{headers.get('host', 'localhost')} Port {self.port}</address>\n"
            f"</body></html>\n",
            {"Content-Type": "text/html; charset=UTF-8"},
        )

    async def _handle_post(
        self,
        session_id: str,
        path: str,
        body: str,
        headers: dict,
        source_ip: str,
    ) -> str:
        await session_manager.record_network_event(
            session_id, "http_post", {
                "path": path,
                "body": body[:1000] if body else "",
                "content_type": headers.get("content-type", ""),
            }
        )

        if path == "/login" or path == "/wp-login.php":
            return self._build_response(
                302, "Found", "",
                {"Location": "/dashboard", "Set-Cookie": "session=abc123; Path=/"},
            )

        if path == "/upload":
            return self._build_response(
                200, "OK",
                '{"status": "success", "message": "File uploaded", "path": "/uploads/file"}\n',
                {"Content-Type": "application/json"},
            )

        if path in ("/shell", "/cmd", "/eval"):
            await session_manager.record_network_event(
                session_id, "command_execution_attempt", {
                    "path": path,
                    "body": body,
                }
            )
            return self._build_response(
                200, "OK",
                "uid=33(www-data) gid=33(www-data) groups=33(www-data)\n"
                "Linux honeypot 5.15.0-91-generic #101-Ubuntu SMP x86_64\n",
                {"Content-Type": "text/plain"},
            )

        attack_indicators = [
            ("<?php", "php_injection"),
            ("<script>", "xss_attempt"),
            ("union select", "sql_injection"),
            ("${jndi:", "log4shell_attempt"),
            ("cmd=", "command_injection"),
        ]

        for indicator, attack_type in attack_indicators:
            if indicator.lower() in body.lower():
                await session_manager.record_network_event(
                    session_id, "attack_detected", {
                        "type": attack_type,
                        "path": path,
                        "body_preview": body[:200],
                    }
                )
                await adaptive_engine.profile_actor(session_id, source_ip, {
                    "attack_type": attack_type,
                })
                break

        return self._build_response(
            200, "OK",
            '{"status": "ok"}\n',
            {"Content-Type": "application/json"},
        )

    async def _handle_head(
        self, session_id: str, path: str, headers: dict
    ) -> str:
        return self._build_response(
            200, "OK", "",
            {
                "Content-Type": "text/html; charset=UTF-8",
                "Content-Length": "0",
                "Server": self.get_banner(),
            },
        )

    def _handle_options(self) -> str:
        return self._build_response(
            200, "OK", "",
            {
                "Allow": "GET, POST, HEAD, OPTIONS, PUT, DELETE",
                "Content-Length": "0",
            },
        )

    async def _handle_put(
        self, session_id: str, path: str, body: str, headers: dict, source_ip: str
    ) -> str:
        await session_manager.record_network_event(
            session_id, "http_put", {
                "path": path,
                "body_preview": body[:500],
            }
        )
        return self._build_response(
            201, "Created",
            '{"status": "created"}\n',
            {"Content-Type": "application/json"},
        )

    async def _handle_delete(
        self, session_id: str, path: str, headers: dict, source_ip: str
    ) -> str:
        await session_manager.record_network_event(
            session_id, "http_delete", {"path": path}
        )
        return self._build_response(
            200, "OK",
            '{"status": "deleted"}\n',
            {"Content-Type": "application/json"},
        )

    async def _generate_vulnerable_page(
        self, endpoint_type: str, path: str, headers: dict
    ) -> str:
        pages = {
            "admin_panel": (
                '<!DOCTYPE html><html><head><title>Admin Panel</title></head><body>'
                '<h1>Administration Panel</h1>'
                '<form method="POST" action="/admin/login">'
                '<label>Username:</label><br>'
                '<input type="text" name="username"><br>'
                '<label>Password:</label><br>'
                '<input type="password" name="password"><br><br>'
                '<input type="submit" value="Login">'
                "</form></body></html>\n"
            ),
            "login_form": (
                '<!DOCTYPE html><html><head><title>Login</title></head><body>'
                '<h1>Login</h1>'
                '<form method="POST" action="/login">'
                '<input type="text" name="username" placeholder="Username"><br>'
                '<input type="password" name="password" placeholder="Password"><br>'
                '<input type="submit" value="Sign In">'
                "</form></body></html>\n"
            ),
            "wordpress_admin": (
                '<!DOCTYPE html><html><head><title>WordPress &rsaquo; Log In</title></head><body>'
                '<div id="login"><h1><a href="https://wordpress.org/">Powered by WordPress</a></h1>'
                '<form name="loginform" id="loginform" action="/wp-login.php" method="post">'
                '<p><label>Username or Email Address<br>'
                '<input type="text" name="log" id="user_login" class="input"></label></p>'
                '<p><label>Password<br>'
                '<input type="password" name="pwd" id="user_pass" class="input"></label></p>'
                '<p class="submit"><input type="submit" name="wp-submit" value="Log In"></p>'
                "</form></div></body></html>\n"
            ),
            "phpmyadmin": (
                '<!DOCTYPE html><html><head><title>phpMyAdmin</title></head><body>'
                '<h1>phpMyAdmin</h1>'
                '<form method="post" action="/phpmyadmin/index.php">'
                '<label>Username: <input type="text" name="pma_username"></label><br>'
                '<label>Password: <input type="password" name="pma_password"></label><br>'
                '<input type="submit" value="Go">'
                "</form></body></html>\n"
            ),
            "tomcat_manager": (
                '<!DOCTYPE html><html><head><title>Apache Tomcat Manager</title></head><body>'
                '<h1>Tomcat Manager Application</h1>'
                '<form method="get" action="/manager/html">'
                '<input type="submit" value="Login to Manager">'
                "</form></body></html>\n"
            ),
            "env_file": self._fake_files.get("/.env", ""),
            "config_file": self._fake_files.get("/config.php", ""),
            "api_users": '{"users": [{"id": 1, "username": "admin", "role": "administrator"}, {"id": 2, "username": "user", "role": "user"}]}\n',
            "api_admin": '{"status": "ok", "version": "1.0.0", "debug": true}\n',
            "upload_form": (
                '<!DOCTYPE html><html><head><title>Upload</title></head><body>'
                '<h1>File Upload</h1>'
                '<form method="POST" action="/upload" enctype="multipart/form-data">'
                '<input type="file" name="file"><br>'
                '<input type="submit" value="Upload">'
                "</form></body></html>\n"
            ),
            "web_shell": (
                '<!DOCTYPE html><html><head><title>Shell</title></head><body>'
                '<h1>Web Shell</h1>'
                '<form method="POST" action="/shell">'
                '<input type="text" name="cmd" placeholder="Command">'
                '<input type="submit" value="Execute">'
                "</form></body></html>\n"
            ),
            "command_endpoint": '{"output": "uid=33(www-data) gid=33(www-data) groups=33(www-data)"}\n',
            "eval_endpoint": '{"result": "evaluated"}\n',
            "debug_panel": (
                '<!DOCTYPE html><html><head><title>Debug</title></head><body>'
                '<h1>Debug Panel</h1>'
                '<pre>PHP Version: 8.1.2\n'
                'Server: Apache/2.4.52\n'
                'Document Root: /var/www/html\n'
                "Database: MySQL 8.0.35\n"
                'Debug Mode: ENABLED</pre>'
                "</body></html>\n"
            ),
            "console_panel": (
                '<!DOCTYPE html><html><head><title>Console</title></head><body>'
                '<h1>Spring Boot Admin Console</h1>'
                '<p>Application is running.</p>'
                "</body></html>\n"
            ),
            "spring_actuator": '{"_links": {"self": {"href": "/actuator"}, "health": {"href": "/actuator/health"}, "env": {"href": "/actuator/env"}, "beans": {"href": "/actuator/beans"}}}\n',
            "spring_env": '{"propertySources": [{"name": "applicationConfig", "properties": {"spring.datasource.url": {"value": "jdbc:mysql://localhost:3306/app"}, "spring.datasource.username": {"value": "root"}, "spring.datasource.password": {"value": "dbpass123"}}}]}\n',
            "spring_health": '{"status": "UP", "components": {"diskSpace": {"status": "UP"}, "db": {"status": "UP"}, "ping": {"status": "UP"}}}\n',
        }

        return pages.get(endpoint_type, "<html><body>OK</body></html>\n")

    def _build_response(
        self,
        status_code: int,
        status_text: str,
        body: str,
        extra_headers: Optional[dict] = None,
    ) -> str:
        headers = {
            "Server": self.get_banner(),
            "Date": time.strftime("%a, %d %b %Y %H:%M:%S GMT", time.gmtime()),
            "Connection": "close",
            "X-Powered-By": fingerprint_engine.get_x_powered_by(),
        }
        if extra_headers:
            headers.update(extra_headers)

        body_bytes = body.encode("utf-8") if body else b""
        headers["Content-Length"] = str(len(body_bytes))

        response = f"HTTP/1.1 {status_code} {status_text}\r\n"
        for key, value in headers.items():
            response += f"{key}: {value}\r\n"
        response += "\r\n"
        if body:
            response += body
        return response

    def _get_content_type(self, path: str) -> str:
        types = {
            ".txt": "text/plain",
            ".html": "text/html",
            ".php": "application/x-httpd-php",
            ".xml": "application/xml",
            ".json": "application/json",
            ".css": "text/css",
            ".js": "application/javascript",
            ".png": "image/png",
            ".jpg": "image/jpeg",
            ".gif": "image/gif",
            ".ico": "image/x-icon",
        }
        ext = "." + path.rsplit(".", 1)[-1] if "." in path else ""
        return types.get(ext, "application/octet-stream")
