"""Minimal control/status API for the honeypot engine.

The backend's ``/api/v1/honeypot/*`` routes expect to reach the engine over
HTTP, but the engine never served anything, so every one of those routes fell
back to hardcoded placeholder data. This exposes the real engine state.

It is intentionally a hand-rolled asyncio server rather than a web framework:
this process is the internet-facing component, and every dependency added here
is attack surface. It binds to the internal management address only and
requires the shared ingest token on every request.
"""

from __future__ import annotations

import asyncio
import json
import logging
import secrets
from typing import Awaitable, Callable, Optional

from honeypot.core.config import config

logger = logging.getLogger(__name__)

Handler = Callable[[dict], Awaitable[dict]]


class ControlAPI:
    MAX_REQUEST_BYTES = 64 * 1024

    def __init__(self, host: str, port: int, token: str):
        self._host = host
        self._port = port
        self._token = token
        self._routes: dict[tuple[str, str], Handler] = {}
        self._server: Optional[asyncio.AbstractServer] = None

    def route(self, method: str, path: str):
        def decorator(func: Handler) -> Handler:
            self._routes[(method.upper(), path)] = func
            return func

        return decorator

    async def start(self):
        self._server = await asyncio.start_server(
            self._handle, self._host, self._port
        )
        logger.info(f"Control API listening on {self._host}:{self._port}")

    async def stop(self):
        if self._server:
            self._server.close()
            await self._server.wait_closed()

    async def _handle(
        self, reader: asyncio.StreamReader, writer: asyncio.StreamWriter
    ):
        try:
            request_line = await asyncio.wait_for(reader.readline(), timeout=10)
            if not request_line:
                return
            parts = request_line.decode("latin-1").split()
            if len(parts) < 2:
                await self._respond(writer, 400, {"detail": "Malformed request"})
                return
            method, path = parts[0].upper(), parts[1].split("?", 1)[0]

            headers: dict[str, str] = {}
            while True:
                line = await asyncio.wait_for(reader.readline(), timeout=10)
                if not line or line in (b"\r\n", b"\n"):
                    break
                if b":" in line:
                    key, value = line.decode("latin-1").split(":", 1)
                    headers[key.strip().lower()] = value.strip()

            try:
                length = int(headers.get("content-length", 0))
            except ValueError:
                length = 0
            if length > self.MAX_REQUEST_BYTES:
                await self._respond(writer, 413, {"detail": "Body too large"})
                return
            raw_body = await reader.readexactly(length) if length else b""

            supplied = headers.get("x-honeypot-token", "")
            if not secrets.compare_digest(supplied, self._token):
                await self._respond(writer, 401, {"detail": "Invalid token"})
                return

            handler = self._routes.get((method, path))
            if handler is None:
                await self._respond(writer, 404, {"detail": "Not found"})
                return

            body = json.loads(raw_body) if raw_body else {}
            result = await handler(body)
            await self._respond(writer, 200, result)

        except (asyncio.TimeoutError, asyncio.IncompleteReadError):
            pass
        except json.JSONDecodeError:
            await self._respond(writer, 400, {"detail": "Invalid JSON body"})
        except Exception as exc:
            logger.error(f"Control API error: {exc}")
            await self._respond(writer, 500, {"detail": "Internal error"})
        finally:
            writer.close()
            try:
                await writer.wait_closed()
            except Exception:
                pass

    @staticmethod
    async def _respond(writer: asyncio.StreamWriter, status: int, payload: dict):
        body = json.dumps(payload).encode()
        reason = {
            200: "OK",
            400: "Bad Request",
            401: "Unauthorized",
            404: "Not Found",
            413: "Payload Too Large",
            500: "Internal Server Error",
        }.get(status, "OK")
        writer.write(
            f"HTTP/1.1 {status} {reason}\r\n"
            "Content-Type: application/json\r\n"
            f"Content-Length: {len(body)}\r\n"
            "Connection: close\r\n\r\n".encode()
            + body
        )
        await writer.drain()


def build_control_api(service) -> ControlAPI:
    from honeypot.adaptive.response import adaptive_engine
    from honeypot.core.modes import mode_handler
    from honeypot.core.session import session_manager
    from honeypot.security.breakout import breakout_prevention
    from honeypot.security.egress_filter import egress_filter
    from honeypot.security.rate_limiter import rate_limiter

    api = ControlAPI(
        config.control_bind_address, config.control_port, config.ingest_token
    )

    @api.route("GET", "/status")
    async def status(_body: dict) -> dict:
        return await service.get_status()

    @api.route("GET", "/security-status")
    async def security_status(_body: dict) -> dict:
        # The sweep includes a blocking egress probe; keep it off the event
        # loop the emulators run on.
        return await asyncio.to_thread(breakout_prevention.verify_isolation)

    @api.route("GET", "/blocked-ips")
    async def blocked_ips(_body: dict) -> dict:
        return {"blocked_ips": await rate_limiter.get_blocked_ips()}

    @api.route("GET", "/denied-connections")
    async def denied_connections(_body: dict) -> dict:
        return {"denied_connections": egress_filter.get_denied_connections()}

    @api.route("GET", "/threat-actors")
    async def threat_actors(_body: dict) -> dict:
        return {"actors": await adaptive_engine.serialize_profiles()}

    @api.route("GET", "/sessions/active")
    async def active_sessions(_body: dict) -> dict:
        sessions = await session_manager.get_active_sessions()
        return {
            "active_sessions": [
                {
                    "session_id": s.session_id,
                    "protocol": s.protocol,
                    "source_ip": s.source_ip,
                    "started_at": s.start_datetime,
                    "duration_seconds": round(s.duration, 2),
                    "command_count": len(s.commands),
                }
                for s in sessions
            ]
        }

    @api.route("POST", "/mode")
    async def set_mode(body: dict) -> dict:
        from honeypot.core.config import OperationalMode

        mode = OperationalMode(body["mode"])
        mode_handler.mode = mode
        logger.info(f"Operational mode changed to {mode.value}")
        return {"status": "ok", "mode": mode.value}

    @api.route("POST", "/block-ip")
    async def block_ip(body: dict) -> dict:
        await rate_limiter.block_ip(body["ip"])
        return {"status": "blocked", "ip": body["ip"]}

    @api.route("POST", "/unblock-ip")
    async def unblock_ip(body: dict) -> dict:
        await rate_limiter.unblock_ip(body["ip"])
        return {"status": "unblocked", "ip": body["ip"]}

    return api
