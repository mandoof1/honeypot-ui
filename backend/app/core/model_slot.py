"""One turn at a time on the local language model.

The language model is a single llama.cpp server running one request at a
time on the CPU. Two things in the backend process call it: the background
enrichment worker, continuously, and investigation reports, when an analyst
asks for one. Left to queue inside the model server they hurt each other: an
enrichment call sent while a report was being written sat there until its
own HTTP timeout expired, was recorded as "model unavailable", and put the
worker into its back-off; a report sent behind an enrichment call spent an
unknown share of its timeout waiting.

Both now take this slot around a model call. ``asyncio.Lock`` hands the lock
to waiters in arrival order, so the two alternate when both want it: a
report waits for at most the one enrichment call already in progress, and the
worker gets its next turn as soon as that report is written, even if further
reports are queued. Neither side's HTTP timeout runs while it is waiting.

In-process only, like the report jobs themselves: it coordinates the single
backend process that runs the workers. The ingest service makes no model
calls.
"""

from __future__ import annotations

import asyncio
import time
from contextlib import asynccontextmanager
from typing import Optional


class ModelBusy(Exception):
    """The slot did not come free within the caller's wait limit."""


class ModelSlot:
    def __init__(self) -> None:
        self._lock: Optional[asyncio.Lock] = None
        self._loop: Optional[asyncio.AbstractEventLoop] = None
        self._holder: Optional[str] = None
        self._since: float = 0.0

    def _current_lock(self) -> asyncio.Lock:
        # An asyncio lock belongs to the loop that first waited on it. The
        # application has one loop for its lifetime; the test suite starts a
        # new one per test, and a lock carried over would refuse to be used.
        loop = asyncio.get_running_loop()
        if self._lock is None or self._loop is not loop:
            self._lock = asyncio.Lock()
            self._loop = loop
            self._holder = None
        return self._lock

    @property
    def holder(self) -> Optional[str]:
        """Who has the model now ("enrichment", "report"), or None."""
        return self._holder

    def held_seconds(self) -> float:
        return time.monotonic() - self._since if self._holder else 0.0

    @asynccontextmanager
    async def hold(self, purpose: str, wait: Optional[float] = None):
        """Take the model for one call.

        ``wait`` bounds how long to queue for it; ModelBusy is raised when it
        runs out. None waits as long as it takes, which is right for the
        background worker and wrong for anything a person is waiting on.
        """
        lock = self._current_lock()
        try:
            await asyncio.wait_for(lock.acquire(), timeout=wait)
        except asyncio.TimeoutError as exc:
            raise ModelBusy(
                f"the model was still busy with {self._holder or 'another task'} "
                f"after {wait:.0f}s"
            ) from exc
        self._holder = purpose
        self._since = time.monotonic()
        try:
            yield
        finally:
            self._holder = None
            lock.release()


model_slot = ModelSlot()
