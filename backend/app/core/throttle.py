"""Counting recent failures per key, in memory.

Used to slow password and code guessing from one source against one account.
The account-wide lock cannot do that job any more: it used to refuse every
sign-in once an account had ten failures, which stopped the guessing but also
let anyone keep an administrator out by failing on purpose. What stops a
guessing run now is that the *source* doing it runs out of attempts.

In memory and per process, like the request rate limiter. The dashboard API
is deployed as a single process for exactly that reason; a restart forgets
the counts, which costs an attacker one restart's worth of extra guesses.
"""

from __future__ import annotations

import time
from collections import OrderedDict, deque
from typing import Deque, Hashable


class FailureThrottle:
    def __init__(self, max_keys: int = 20_000) -> None:
        #: key -> times of its recent failures, oldest first. Ordered by last
        #: use so the least recently touched key is the one dropped when full.
        self._failures: "OrderedDict[Hashable, Deque[float]]" = OrderedDict()
        self._max_keys = max_keys

    def _recent(self, key: Hashable, window: float, now: float) -> Deque[float]:
        times = self._failures.get(key)
        if times is None:
            return deque()
        while times and times[0] <= now - window:
            times.popleft()
        if not times:
            del self._failures[key]
        return times

    def count(self, key: Hashable, window: float) -> int:
        """Failures recorded for ``key`` in the last ``window`` seconds."""
        return len(self._recent(key, window, time.monotonic()))

    def blocked(self, key: Hashable, limit: int, window: float) -> bool:
        """Whether ``key`` has used up its failures. A limit of 0 never blocks."""
        return limit > 0 and self.count(key, window) >= limit

    def record(self, key: Hashable, window: float) -> int:
        """Note one failure for ``key``; returns its count inside the window."""
        now = time.monotonic()
        times = self._recent(key, window, now)
        times.append(now)
        self._failures[key] = times
        self._failures.move_to_end(key)
        # Bounded: keys are built from client-supplied values (an email
        # address as typed), so the table must not grow with the guesses.
        while len(self._failures) > self._max_keys:
            self._failures.popitem(last=False)
        return len(times)

    def reset(self, key: Hashable) -> None:
        self._failures.pop(key, None)

    def clear(self) -> None:
        self._failures.clear()


#: Failed sign-ins and second-factor attempts, keyed by (purpose, source, account).
sign_in_failures = FailureThrottle()
