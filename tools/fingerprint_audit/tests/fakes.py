"""Small in-process servers on loopback for the probe tests.

Each one speaks just enough of its protocol, in the style of a real daemon,
for a probe set to run against it from start to finish. They exist so the
audit can be tested without any reference container; they are not models
of any particular product and nothing measured against them means anything.
"""

from __future__ import annotations

import asyncio
import os
import socket
import struct
import threading
import time

from tools.fingerprint_audit import sshwire, telnetwire
from tools.fingerprint_audit.net import Target

TOO_LONG = object()


class FakeServer:
    """Runs ``handler(connection)`` in a thread for every connection."""

    def __init__(self, handler) -> None:
        self._handler = handler
        self._listener = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self._listener.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self._listener.bind(("127.0.0.1", 0))
        self._listener.listen(8)
        self.target = Target("127.0.0.1", self._listener.getsockname()[1])
        threading.Thread(target=self._accept, daemon=True).start()

    def _accept(self) -> None:
        while True:
            try:
                connection, _ = self._listener.accept()
            except OSError:
                return
            threading.Thread(target=self._serve, args=(connection,), daemon=True).start()

    def _serve(self, connection: socket.socket) -> None:
        try:
            self._handler(connection)
        except OSError:
            pass
        finally:
            connection.close()

    def close(self) -> None:
        try:
            self._listener.shutdown(socket.SHUT_RDWR)
        except OSError:
            pass
        self._listener.close()


def read_line(connection: socket.socket, buffer: bytes, limit: int):
    """(line, rest). line is None at end of stream, TOO_LONG past the limit
    (after swallowing the rest of the line, so the reply is not lost to a
    reset)."""
    too_long = False
    while b"\n" not in buffer:
        if len(buffer) > limit:
            too_long = True
            buffer = buffer[-1:]
        data = connection.recv(65536)
        if not data:
            return None, b""
        buffer += data
    line, _, rest = buffer.partition(b"\n")
    return (TOO_LONG if too_long or len(line) > limit else line + b"\n"), rest


# ----------------------------------------------------------------------- FTP

def ftp_handler(greeting: bytes = b"220 (fakeFTPd 1.0)\r\n", unknown: bytes = b"500 Unknown command.\r\n"):
    def handle(connection: socket.socket) -> None:
        connection.sendall(greeting)
        user, logged_in, failures, buffer = None, False, 0, b""
        while True:
            line, buffer = read_line(connection, buffer, 4096)
            if line is None:
                return
            if line is TOO_LONG:
                connection.sendall(b"500 Input line too long.\r\n")
                return
            verb, _, argument = line.strip().partition(b" ")
            verb = verb.upper()
            if verb == b"USER":
                user = argument
                connection.sendall(b"331 Please specify the password.\r\n")
            elif verb == b"PASS":
                if user is None:
                    connection.sendall(b"503 Login with USER first.\r\n")
                elif (user, argument) == (b"test", b"test"):
                    logged_in = True
                    connection.sendall(b"230 Login successful.\r\n")
                else:
                    failures += 1
                    connection.sendall(b"530 Login incorrect.\r\n")
                    if failures >= 3:
                        return
            elif verb == b"QUIT":
                connection.sendall(b"221 Goodbye.\r\n")
                return
            elif verb == b"FEAT":
                connection.sendall(b"211-Features:\r\n PASV\r\n SIZE\r\n211 End\r\n")
            elif not logged_in:
                connection.sendall(b"530 Please login with USER and PASS.\r\n")
            elif verb == b"SYST":
                connection.sendall(b"215 UNIX Type: L8\r\n")
            elif verb == b"HELP":
                connection.sendall(b"214-Commands:\r\n USER PASS QUIT\r\n214 Help OK.\r\n")
            elif verb == b"STAT":
                connection.sendall(b"211-Status:\r\n     Connected to 127.0.0.1\r\n211 End of status\r\n")
            elif verb == b"NOOP":
                connection.sendall(b"200 NOOP ok.\r\n")
            elif verb == b"PASV":
                connection.sendall(b"227 Entering Passive Mode (127,0,0,1,195,80).\r\n")
            else:
                connection.sendall(unknown)

    return handle


# ---------------------------------------------------------------------- HTTP

def http_handler(
    server: bytes = b"FakeHTTPd/1.0",
    order: tuple = (b"Date", b"Server", b"Content-Length", b"Content-Type"),
    not_found: bytes = b"<h1>Not Found</h1>\n",
):
    def respond(connection, status: bytes, body: bytes, head: bool, close: bool, extra: tuple = ()) -> None:
        values = {
            b"Date": time.strftime("%a, %d %b %Y %H:%M:%S GMT", time.gmtime()).encode(),
            b"Server": server,
            b"Content-Length": str(len(body)).encode(),
            b"Content-Type": b"text/html",
        }
        lines = [b"HTTP/1.1 " + status] + [name + b": " + values[name] for name in order]
        lines += list(extra)
        if close:
            lines.append(b"Connection: close")
        connection.sendall(b"\r\n".join(lines) + b"\r\n\r\n" + (b"" if head else body))

    def handle(connection: socket.socket) -> None:
        buffer = b""
        while True:
            line, buffer = read_line(connection, buffer, 8190)
            if line is None:
                return
            if line is TOO_LONG:
                respond(connection, b"414 Request-URI Too Long", b"<h1>Too long</h1>\n", False, True)
                return
            headers = {}
            while True:
                header, buffer = read_line(connection, buffer, 8190)
                if header is None or header is TOO_LONG:
                    return
                if not header.strip():
                    break
                name, _, value = header.partition(b":")
                headers[name.strip().lower()] = value.strip()
            parts = line.split()
            bad = len(parts) != 3 or not parts[2].startswith(b"HTTP/1.")
            if bad or (parts[2] == b"HTTP/1.1" and b"host" not in headers):
                respond(connection, b"400 Bad Request", b"<h1>Bad Request</h1>\n", False, True)
                return
            method, path, version = parts
            close = version == b"HTTP/1.0" or headers.get(b"connection", b"").lower() == b"close"
            if method == b"OPTIONS":
                respond(connection, b"200 OK", b"", False, close, (b"Allow: GET,HEAD,OPTIONS",))
            elif method not in (b"GET", b"HEAD"):
                respond(connection, b"405 Method Not Allowed", b"<h1>Not Allowed</h1>\n", False, close)
            elif path == b"/":
                respond(connection, b"200 OK", b"<html>It works</html>\n", method == b"HEAD", close)
            else:
                respond(connection, b"404 Not Found", not_found, method == b"HEAD", close)
            if close:
                return

    return handle


# -------------------------------------------------------------------- Telnet

def telnet_handler(hostname: bytes = b"box1", eager: bool = False, max_tries: int = 3):
    """``eager`` sends the banner at once; otherwise the server asks for two
    options first and waits for both answers, as an inetd telnetd does."""
    IAC, DO, DONT, WONT, WILL = 255, 253, 254, 252, 251
    wanted = (24, 31)
    banner = b"Fake OS 1.0\r\n" + hostname + b" login: "

    def handle(connection: socket.socket) -> None:
        if eager:
            connection.sendall(bytes([IAC, WILL, 1, IAC, WILL, 3]) + banner)
        else:
            connection.sendall(b"".join(bytes([IAC, DO, option]) for option in wanted))
        answered, banner_sent = set(), eager
        partial, text, expecting_password, tries = b"", b"", False, 0
        while True:
            data = connection.recv(4096)
            if not data:
                return
            tokens, partial = telnetwire.tokenize(partial + data)
            for token in tokens:
                if token.kind == "data":
                    text += token.data
                elif token.kind == "negotiation" and token.option == 99:
                    reply = DONT if token.verb == "WILL" else WONT
                    connection.sendall(bytes([IAC, reply, 99]))
                elif token.kind == "negotiation":
                    answered.add(token.option)
            if not banner_sent and answered >= set(wanted):
                connection.sendall(banner)
                banner_sent = True
            while b"\r\n" in text:
                _line, _, text = text.partition(b"\r\n")
                if not expecting_password:
                    connection.sendall(b"Password: ")
                    expecting_password = True
                    continue
                expecting_password = False
                tries += 1
                if tries >= max_tries:
                    connection.sendall(b"\r\nLogin incorrect\r\n")
                    return
                connection.sendall(b"\r\nLogin incorrect\r\n" + hostname + b" login: ")

    return handle


# ----------------------------------------------------------------------- SSH

KEX_LISTS = {
    "kex_algorithms": ["curve25519-sha256", "diffie-hellman-group14-sha256"],
    "server_host_key_algorithms": ["ssh-ed25519"],
    "encryption_client_to_server": ["aes128-ctr", "aes256-ctr"],
    "encryption_server_to_client": ["aes128-ctr", "aes256-ctr"],
    "mac_client_to_server": ["hmac-sha2-256"],
    "mac_server_to_client": ["hmac-sha2-256"],
    "compression_client_to_server": ["none"],
    "compression_server_to_client": ["none"],
    "languages_client_to_server": [],
    "languages_server_to_client": [],
}


def kexinit_payload(lists: dict = KEX_LISTS, cookie: bytes = b"") -> bytes:
    payload = bytes([sshwire.MSG_KEXINIT]) + (cookie or os.urandom(16))
    for name in sshwire.KEXINIT_LISTS:
        joined = ",".join(lists[name]).encode()
        payload += struct.pack(">I", len(joined)) + joined
    return payload + b"\x00" + struct.pack(">I", 0)


def _string(data: bytes) -> bytes:
    return struct.pack(">I", len(data)) + data


def ssh_text_handler(ident: bytes = b"SSH-2.0-FakeSSH_1.0\r\n"):
    """Clear-text half of an SSH server that answers bad input the way
    OpenSSH does: a line of text for a bad identification, a DISCONNECT
    packet for a bad packet. It cannot exchange keys."""

    def handle(connection: socket.socket) -> None:
        connection.sendall(ident)
        line, rest = read_line(connection, b"", 8192)
        if line is None:
            return
        if line is TOO_LONG or not line.startswith(b"SSH-") or line.count(b"-") < 2:
            connection.sendall(b"Invalid SSH identification string.\r\n")
            return
        if not line.startswith(b"SSH-2.0-"):
            connection.sendall(b"Protocol major versions differ.\r\n")
            return
        connection.sendall(sshwire.build_packet(kexinit_payload()))
        buffer = rest
        while True:
            try:
                parsed = sshwire.read_packet(buffer)
            except sshwire.WireError:
                disconnect = bytes([sshwire.MSG_DISCONNECT]) + struct.pack(">I", 2)
                connection.sendall(sshwire.build_packet(disconnect + _string(b"Packet corrupt") + _string(b"")))
                return
            if parsed is not None:
                _packet, buffer = parsed
                unimplemented = bytes([sshwire.MSG_UNIMPLEMENTED]) + struct.pack(">I", 0)
                connection.sendall(sshwire.build_packet(unimplemented))
                continue
            data = connection.recv(65536)
            if not data:
                return
            buffer += data

    return handle


class AsyncsshServer:
    """A real SSH server (asyncssh) that rejects every password, for the
    probes that need a completed key exchange."""

    def __init__(self) -> None:
        import asyncssh

        class RejectAll(asyncssh.SSHServer):
            def begin_auth(self, username: str) -> bool:
                return True

            def password_auth_supported(self) -> bool:
                return True

            def validate_password(self, username: str, password: str) -> bool:
                return False

        self._loop = asyncio.new_event_loop()
        ready = threading.Event()

        async def start() -> None:
            key = asyncssh.generate_private_key("ssh-ed25519")
            acceptor = await asyncssh.listen(
                "127.0.0.1", 0, server_factory=RejectAll, server_host_keys=[key]
            )
            self.target = Target("127.0.0.1", acceptor.get_port())
            ready.set()

        def run() -> None:
            asyncio.set_event_loop(self._loop)
            self._loop.run_until_complete(start())
            self._loop.run_forever()

        threading.Thread(target=run, daemon=True).start()
        if not ready.wait(10):
            raise RuntimeError("asyncssh test server did not start")

    def close(self) -> None:
        self._loop.call_soon_threadsafe(self._loop.stop)
