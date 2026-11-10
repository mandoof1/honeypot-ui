"""Small process-level hardening calls, through prctl(2).

Pure standard library and free of application imports, because the payload
analysis child uses it too and must not load settings.

Both calls are Linux-only and best-effort: on another platform, or in a
sandbox that filters prctl, they return False and the caller carries on.
"""

from __future__ import annotations

import ctypes
import sys

# From <linux/prctl.h>.
_PR_SET_DUMPABLE = 4
_PR_GET_DUMPABLE = 3
_PR_SET_NO_NEW_PRIVS = 38
_PR_GET_NO_NEW_PRIVS = 39


def _prctl(option: int, value: int) -> int:
    """Call prctl; returns its result, or -1 when it cannot be called."""
    if not sys.platform.startswith("linux"):
        return -1
    try:
        # The C library is already loaded into the interpreter; asking for
        # the process's own symbols finds prctl there. ctypes.util's
        # find_library would run ldconfig or a compiler to locate it, and the
        # analysis child is not allowed to start a process.
        libc = ctypes.CDLL(None, use_errno=True)
        return int(libc.prctl(option, value, 0, 0, 0))
    except (OSError, AttributeError, TypeError, ValueError):
        return -1


def make_non_dumpable() -> bool:
    """Stop other processes of the same user reading this one's memory.

    A process that is not "dumpable" has its /proc/<pid>/ entries (environ,
    mem, maps, fd) owned by root and cannot be attached to with ptrace by an
    unprivileged process, same user or not. The API process holds the
    database password, the signing key and the encryption key in its
    environment and memory; the payload analysis child runs as the same user
    and would otherwise be able to read them from /proc if a parser bug gave
    an uploaded file control of it. Also disables core dumps, which would
    write the same secrets to disk.

    The flag is reset by execve, so it does not carry over to children; that
    is why the child cannot simply be started non-dumpable from here.
    """
    return _prctl(_PR_SET_DUMPABLE, 0) == 0


def is_dumpable() -> bool:
    """True when the flag is set, or cannot be read."""
    return _prctl(_PR_GET_DUMPABLE, 0) != 0


def set_no_new_privs() -> bool:
    """Give up, irreversibly, gaining privileges through execve.

    After this a set-uid or file-capability binary run by the process (or any
    descendant) executes without the extra privilege, so a compromised
    analyser cannot climb through one.
    """
    return _prctl(_PR_SET_NO_NEW_PRIVS, 1) == 0


def has_no_new_privs() -> bool:
    return _prctl(_PR_GET_NO_NEW_PRIVS, 0) == 1
