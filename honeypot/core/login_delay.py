"""The pause a real daemon makes before it refuses a login.

sshd, login(1) behind telnetd and vsftpd do not answer a wrong password at
once: the first comparison with the real daemons (docs/evaluation/
fingerprint/baseline) timed them at 2.2, 2.9 and 3.0 seconds, and the decoys
at a millisecond. A client only has to time one refusal to tell them apart.

The pause is a sleep on the task that serves the connection, so nothing else
waits on it and a connection can have one pending at most. Two bounds keep it
from becoming a way to load the engine:

* a setting cannot ask for more than ``MAX_DELAY_SECONDS``, so a mistyped
  value cannot park every failed login for an hour;
* only ``HONEYPOT_FAIL_DELAY_MAX_PENDING`` refusals may be waiting at one
  moment across all protocols. Past that the refusal goes out without the
  pause: under a flood of guesses, answering as a real daemon would matters
  less than not holding a timer for every one of them.
"""

from __future__ import annotations

import asyncio
import logging

from honeypot.core.config import config

logger = logging.getLogger(__name__)

#: Longest pause any setting can produce, in seconds.
MAX_DELAY_SECONDS = 30.0


class LoginDelay:
    def __init__(self) -> None:
        #: Refusals waiting out their pause right now.
        self.pending = 0
        self._cap_reported = False

    @staticmethod
    def seconds(configured: float) -> float:
        """The pause a configured value comes to, within the bounds.

        Zero when anti-fingerprinting is switched off, which is also how the
        tests that are not about timing run.
        """
        if not config.enable_anti_fingerprinting:
            return 0.0
        # Written so that a NaN from the environment comes out as zero.
        return max(0.0, min(configured, MAX_DELAY_SECONDS))

    async def pause(self, configured: float) -> bool:
        """Wait before a refusal; False when no pause was made."""
        seconds = self.seconds(configured)
        if seconds <= 0:
            return False
        if self.pending >= config.fail_delay_max_pending:
            if not self._cap_reported:
                self._cap_reported = True
                logger.warning(
                    "%s failed logins are already waiting out their delay; "
                    "further refusals are sent without one until some finish",
                    self.pending,
                )
            return False
        self._cap_reported = False
        self.pending += 1
        try:
            await asyncio.sleep(seconds)
        finally:
            # Also when the connection is closed or cancelled mid-pause.
            self.pending -= 1
        return True


login_delay = LoginDelay()
