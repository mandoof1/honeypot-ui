"""Refuse oversized request bodies before anything parses them.

Nothing capped the size of a request, so an unauthenticated client could post
12 MB to /auth/login and the API read and parsed all of it (8 s) before
answering 422. Every user-facing body is small JSON; this rejects anything
over MAX_REQUEST_BODY_BYTES with 413, checking Content-Length up front and
counting the bytes as they arrive for bodies sent without one.

The engine's routes (paths ending in ``-internal``) carry captured files of
several megabytes, so they get their own, larger limit rather than the user
one. They used to have none at all, and FastAPI reads and JSON-decodes a body
*before* it runs a route's dependencies, the token check included: anyone who
could reach the ingest service could make it buffer and parse a body of any
size without holding a token. So for those paths the engine token is checked
here, from the request headers, before a single body byte is read.
"""

from __future__ import annotations

import json
from typing import Callable, Optional


class BodySizeLimit:
    def __init__(
        self,
        app,
        max_bytes: int,
        internal_max_bytes: int = 0,
        internal_gate: Optional[Callable[[list], bool]] = None,
        exempt_suffix: str = "-internal",
    ) -> None:
        self.app = app
        self.max_bytes = max_bytes
        #: Limit for the engine's routes; 0 means "no limit".
        self.internal_max_bytes = internal_max_bytes
        #: Given the raw ASGI headers, says whether the request carries a
        #: valid engine token. None skips the early check.
        self.internal_gate = internal_gate
        self.exempt_suffix = exempt_suffix

    async def __call__(self, scope, receive, send):
        if scope["type"] != "http":
            await self.app(scope, receive, send)
            return

        limit = self.max_bytes
        if scope["path"].rstrip("/").endswith(self.exempt_suffix):
            if self.internal_gate is not None and not self.internal_gate(
                scope.get("headers", [])
            ):
                await self._reject(send, 401, "Invalid honeypot token")
                return
            limit = self.internal_max_bytes

        if limit <= 0:
            await self.app(scope, receive, send)
            return

        for name, value in scope.get("headers", []):
            if name == b"content-length":
                try:
                    declared = int(value)
                except ValueError:
                    declared = 0
                if declared > limit:
                    await self._reject(send, 413, "Request body too large")
                    return

        # Read the body here, up to the limit, then hand it to the app in one
        # piece. Raising from inside the app's receive does not work: FastAPI
        # turns any error while reading a body into a 400, and a chunked
        # upload with no Content-Length would still be read past the limit.
        chunks = []
        total = 0
        more = True
        while more:
            message = await receive()
            if message["type"] == "http.disconnect":
                return
            if message["type"] != "http.request":
                continue
            body = message.get("body", b"")
            total += len(body)
            if total > limit:
                await self._reject(send, 413, "Request body too large")
                return
            chunks.append(body)
            more = message.get("more_body", False)

        delivered = False

        async def replay():
            nonlocal delivered
            if not delivered:
                delivered = True
                return {"type": "http.request", "body": b"".join(chunks), "more_body": False}
            # Afterwards, only a disconnect can arrive.
            return await receive()

        await self.app(scope, replay, send)

    async def _reject(self, send, status: int, detail: str) -> None:
        body = json.dumps({"detail": detail}).encode()
        await send({
            "type": "http.response.start",
            "status": status,
            "headers": [
                (b"content-type", b"application/json"),
                (b"content-length", str(len(body)).encode()),
                (b"connection", b"close"),
            ],
        })
        await send({"type": "http.response.body", "body": body})
