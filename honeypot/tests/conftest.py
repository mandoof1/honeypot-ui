"""Fixtures for the engine tests.

The engine had no tests. Its emulation is the part of the system an attacker
actually touches, and the part where a wrong answer costs intelligence rather
than raising an exception — a shell that replies "command not found" to wget
does not fail, it just quietly stops learning anything.
"""

import os
import sys

import pytest_asyncio

ROOT = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
sys.path.insert(0, ROOT)

import pytest  # noqa: E402

from honeypot.core.session import session_manager  # noqa: E402
from honeypot.core.shell_state import shell_states  # noqa: E402
from honeypot.security.rate_limiter import rate_limiter  # noqa: E402


@pytest.fixture(autouse=True)
def _fresh_rate_limiter():
    """Admission state is process-wide; every test connects from loopback,
    so without this a long run blocks 127.0.0.1 partway through the suite."""
    rate_limiter.reset()
    yield
    rate_limiter.reset()


@pytest_asyncio.fixture
async def session():
    """A live session id, with its shell state torn down afterwards."""
    session_id = await session_manager.create_session("ssh", "203.0.113.77", 44321)
    yield session_id
    shell_states.drop(session_id)
