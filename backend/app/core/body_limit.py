"""Refuse oversized request bodies before anything parses them.

Nothing capped the size of a request, so an unauthenticated client could post
12 MB to /auth/login and the API read and parsed all of it (8 s) before
answering 422. Every user-facing body is small JSON; this rejects anything
over MAX_REQUEST_BODY_BYTES with 413, checking Content-Length up front and
counting the bytes as they arrive for bodies sent without one.

The engine's routes (paths ending in ``-internal``) are exempt: a session can
carry captured files of several megabytes, those routes need the ingest
token, and the public proxy never forwards them.
"""

from __future__ import annotations

import json


class BodySizeLimit:
    def __init__(self, app, max_bytes: int, exempt_suffix: str = "-internal") -> None:
        self.app = app
        self.max_bytes = max_bytes
        self.exempt_suffix = exempt_suffix

    async def __call__(self, scope, receive, send):
        if (
            scope["type"] != "http"
            or self.max_bytes <= 0
            or scope["path"].rstrip("/").endswith(self.exempt_suffix)
        ):
            await self.app(scope, receive, send)
            return

        for name, value in scope.get("headers", []):
            if name == b"content-length":
                try:
                    declared = int(value)
                except ValueError:
                    declared = 0
                if declared > self.max_bytes:
                    await self._reject(send)
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
            if total > self.max_bytes:
                await self._reject(send)
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

    async def _reject(self, send) -> None:
        body = json.dumps({"detail": "Request body too large"}).encode()
        await send({
            "type": "http.response.start",
            "status": 413,
            "headers": [
                (b"content-type", b"application/json"),
                (b"content-length", str(len(body)).encode()),
                (b"connection", b"close"),
            ],
        })
        await send({"type": "http.response.body", "body": body})
