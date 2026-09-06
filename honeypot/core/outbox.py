"""Crash-persistent, at-least-once delivery of completed captures.

Only one worker sends at a time. SQLite holds the backlog on disk; a worker
loads one payload at a time and removes it only after a matching receipt.
The API's unique capture UUID makes an ambiguous timeout safe to retry.
"""

import asyncio
import json
import logging
import os
import random
import sqlite3
import time
from pathlib import Path

import httpx

logger = logging.getLogger(__name__)


class DeliveryOutbox:
    def __init__(self, path, api_url, token):
        self.path = Path(path)
        self.api_url = api_url.rstrip("/")
        self.token = token
        self._lock = asyncio.Lock()
        self._wake = asyncio.Event()
        self._task = None
        self._ready = False
        self._compatible = False
        self._paused_until = 0.0
        self.last_error = None

    async def _db(self, operation):
        # Keep filesystem work off the protocol event loop. One connection per
        # transaction avoids sharing sqlite connections across worker threads.
        async with self._lock:
            return await asyncio.to_thread(self._transaction, operation)

    def _transaction(self, operation):
        if not self._ready:
            self.path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
            fd = os.open(self.path, os.O_CREAT | os.O_WRONLY, 0o600)
            os.close(fd)
            self.path.chmod(0o600)
        db = sqlite3.connect(self.path, timeout=10)
        db.row_factory = sqlite3.Row
        try:
            db.execute("PRAGMA synchronous=FULL")
            db.execute("""CREATE TABLE IF NOT EXISTS deliveries (
                capture_id TEXT PRIMARY KEY, payload TEXT NOT NULL,
                node_id INTEGER, created_at REAL NOT NULL,
                attempts INTEGER NOT NULL DEFAULT 0,
                next_attempt REAL NOT NULL DEFAULT 0, last_error TEXT
            )""")
            db.execute("CREATE INDEX IF NOT EXISTS due_delivery ON deliveries(next_attempt, created_at)")
            self._ready = True
            with db:
                return operation(db)
        finally:
            db.close()

    async def enqueue(self, payload, node_id=None):
        encoded = json.dumps(payload, ensure_ascii=True, allow_nan=False)
        await self._db(lambda db: db.execute(
            "INSERT OR IGNORE INTO deliveries(capture_id,payload,node_id,created_at) VALUES(?,?,?,?)",
            (payload["capture_id"], encoded, node_id, time.time()),
        ).rowcount)
        self._wake.set()

    async def start(self, register_node):
        await self._db(lambda db: None)
        if self._task is None or self._task.done():
            self._task = asyncio.create_task(self._run(register_node))

    async def stop(self):
        # Cancelling a send can leave its outcome unknown. Its durable entry
        # survives, and the next process asks the API for the same capture.
        if self._task:
            self._task.cancel()
            await asyncio.gather(self._task, return_exceptions=True)
            self._task = None

    async def stats(self):
        try:
            return await self._stats()
        except (OSError, sqlite3.Error):
            return {"available": False, "pending": None, "retrying": 0,
                    "last_error": "Delivery storage unavailable; check capture volume"}

    async def _stats(self):
        row = await self._db(lambda db: dict(db.execute(
            "SELECT COUNT(*) AS pending, COALESCE(SUM(attempts > 0),0) AS retrying, "
            "MIN(created_at) AS oldest, MAX(attempts) AS max_attempts FROM deliveries"
        ).fetchone()))
        error = await self._db(lambda db: db.execute(
            "SELECT last_error FROM deliveries WHERE last_error IS NOT NULL "
            "ORDER BY next_attempt DESC LIMIT 1"
        ).fetchone())
        return {
            "available": True,
            "pending": row["pending"], "retrying": row["retrying"],
            "oldest_pending_seconds": max(0, round(time.time() - row["oldest"])) if row["oldest"] else 0,
            "max_attempts": row["max_attempts"] or 0,
            "last_error": self.last_error or (error[0] if error else None),
        }

    async def deliver_one(self, client, register_node):
        """Send the oldest due item. Return False when there is no due work."""
        if time.time() < self._paused_until:
            return False
        row = await self._db(lambda db: db.execute(
            "SELECT * FROM deliveries WHERE next_attempt <= ? "
            "ORDER BY next_attempt, created_at, capture_id LIMIT 1", (time.time(),),
        ).fetchone())
        if row is None:
            return False
        error = None
        pause = False
        delay = min(300, 2 ** min(row["attempts"] + 1, 9)) * random.uniform(0.8, 1.2)
        if not self._compatible:
            try:
                response = await client.get(
                    f"{self.api_url}/sessions/ingest-capabilities",
                    headers={"X-Honeypot-Token": self.token}, timeout=10,
                )
                capabilities = response.json() if response.status_code == 200 else {}
                self._compatible = isinstance(capabilities, dict) and capabilities.get("idempotent_capture") is True
            except (httpx.HTTPError, ValueError):
                pass
            if not self._compatible:
                # Older APIs ignore capture_id and would create a duplicate
                # on every retry. Refuse to send until the API is upgraded.
                error = "Idempotent ingest unavailable; check API version and token"
                delay = 300
                pause = True
        node_id = row["node_id"]
        if error is None and node_id is None:
            node_id = await register_node()
            if node_id is not None:
                # Pin the destination before sending. A restart must not
                # attribute already-attempted evidence to a different node.
                await self._db(lambda db: db.execute(
                    "UPDATE deliveries SET node_id=? WHERE capture_id=?",
                    (node_id, row["capture_id"]),
                ).rowcount)
            else:
                error = "Node registration unavailable"
                delay = max(delay, 30)
                pause = True
        if error is None:
            try:
                response = await client.post(
                    f"{self.api_url}/sessions/ingest-internal",
                    content=row["payload"], params={"node_id": node_id},
                    headers={"X-Honeypot-Token": self.token, "Content-Type": "application/json"},
                    timeout=15,
                )
                if response.status_code == 200:
                    receipt = response.json()
                    if isinstance(receipt, dict) and receipt.get("session_uuid") == row["capture_id"]:
                        await self._db(lambda db: db.execute(
                            "DELETE FROM deliveries WHERE capture_id=?", (row["capture_id"],),
                        ).rowcount)
                        self.last_error = None
                        return True
                    error = "API receipt did not match capture UUID; upgrade the backend first"
                    delay = 300
                    pause = True
                else:
                    # Never persist response bodies: they can echo credentials.
                    error = f"Ingest HTTP {response.status_code}"
                    pause = response.status_code in (408, 429) or response.status_code >= 500
                    if 400 <= response.status_code < 500 and response.status_code not in (408, 429):
                        delay = 300
                    retry_after = response.headers.get("Retry-After", "")
                    if retry_after.isdigit():
                        delay = max(delay, min(int(retry_after), 3600))
            except (httpx.HTTPError, ValueError):
                error = "Ingest transport or response error"
                pause = True
        if pause:
            # During an outage, one failed request pauses the sender. A large
            # backlog must not hammer the same unavailable API once per row.
            self._paused_until = time.time() + delay
        await self._db(lambda db: db.execute(
            "UPDATE deliveries SET attempts=attempts+1,next_attempt=?,last_error=? WHERE capture_id=?",
            (time.time() + delay, error, row["capture_id"]),
        ).rowcount)
        self.last_error = error
        logger.warning("Capture %s queued for retry: %s", row["capture_id"], error)
        return True

    async def _run(self, register_node):
        async with httpx.AsyncClient() as client:
            while True:
                self._wake.clear()
                try:
                    if await self.deliver_one(client, register_node):
                        continue
                except (OSError, sqlite3.Error):
                    self.last_error = "Delivery storage unavailable; check capture volume"
                    logger.exception("Delivery storage unavailable")
                try:
                    await asyncio.wait_for(self._wake.wait(), timeout=2)
                except asyncio.TimeoutError:
                    pass
