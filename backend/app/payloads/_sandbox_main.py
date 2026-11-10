"""The subprocess entry point for payload analysis.

Started as ``python -s -m app.payloads._sandbox_main <path>`` with an
environment the parent builds from scratch (see ``sandbox``). It takes its
own stdout out of reach of library code, applies the limits it can, reads the
sample, runs the analyser, and writes one framed JSON result.

It imports nothing from the application beyond the pure ``payloads`` package
and ``app.core.hardening`` (standard library only): no settings, no database,
so it is never handed the API's secrets. What does and does not separate it
from the API process is set out at the top of ``sandbox``; in short, limits
and a clean environment, not a different user, filesystem or network.
"""

from __future__ import annotations

import os
import sys


def _private_stdout() -> int:
    """Reserve the real stdout for the result frame.

    The parent reads the frame from the first byte of stdout, so nothing else
    may be written there. A library that prints a banner on import would
    corrupt it; pointing file descriptor 1 at stderr sends any such output
    where it is only ever used for diagnosis.
    """
    result_fd = os.dup(1)
    os.dup2(2, 1)
    return result_fd


def _apply_limits() -> None:
    try:
        import resource
    except ImportError:  # not POSIX; the wall-clock timeout in the parent still applies
        return

    # RLIMIT_AS bounds *virtual* address space, and numpy plus the parser
    # libraries reserve well over half a gigabyte of it before doing any real
    # work — a mismatch that segfaults the C extensions rather than raising
    # MemoryError. Floor it so a conservative config value cannot make analysis
    # fail spuriously; the cap still stops a decompression bomb.
    memory_mb = max(1024, int(os.environ.get("PAYLOAD_MEMORY_MB", "2048")))
    cpu_seconds = int(os.environ.get("PAYLOAD_CPU_SECONDS", "60"))

    limits = [
        (resource.RLIMIT_AS, memory_mb * 1024 * 1024),
        (resource.RLIMIT_CPU, cpu_seconds),
        (resource.RLIMIT_FSIZE, 0),        # the analyser writes no files
        (resource.RLIMIT_NOFILE, 64),
        (resource.RLIMIT_CORE, 0),         # a core dump would be the sample, on disk
    ]
    # No child processes and no threads: the analyser is single-threaded and
    # runs nothing. The kernel counts every task of this user against the
    # limit, so zero means "none from here on". (It is not enforced for root;
    # the container runs as an unprivileged user.)
    if hasattr(resource, "RLIMIT_NPROC"):
        limits.append((resource.RLIMIT_NPROC, 0))

    for what, wanted in limits:
        try:
            hard = resource.getrlimit(what)[1]
            ceiling = wanted if hard == resource.RLIM_INFINITY else min(wanted, hard)
            # Soft and hard together. With only the soft limit lowered, code
            # running in this process could simply raise it back to the hard
            # one; lowering the hard limit cannot be undone without privilege.
            resource.setrlimit(what, (ceiling, ceiling))
        except (ValueError, OSError):
            pass


def main() -> int:
    if len(sys.argv) != 2:
        print("usage: _sandbox_main <sample-path>", file=sys.stderr)
        return 2
    result_fd = _private_stdout()

    from app.core import hardening

    hardening.set_no_new_privs()
    _apply_limits()

    try:
        with open(sys.argv[1], "rb") as handle:
            data = handle.read()
    except OSError as exc:
        print(f"could not read sample: {exc}", file=sys.stderr)
        return 3

    # Imported only after the limits are set, so even import-time work is bounded.
    from app.payloads import analyzer, sandbox

    report = analyzer.analyse(data)

    frame = sandbox.frame(report)
    with os.fdopen(result_fd, "wb") as raw:
        raw.write(frame)
        raw.flush()
    return 0


if __name__ == "__main__":
    sys.exit(main())
