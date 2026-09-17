"""The subprocess entry point for payload analysis.

Started as ``python -I -m app.payloads._sandbox_main <path>``. It applies the
resource limits it can, reads the sample, runs the analyser, and writes one
framed result to stdout. It imports nothing from the application beyond the
pure ``payloads`` package — no settings, no database — so it holds none of the
API's secrets even if a parser it calls is compromised.
"""

from __future__ import annotations

import os
import sys


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
    limits = memory_mb * 1024 * 1024

    for what, soft in (
        (resource.RLIMIT_AS, limits),
        (resource.RLIMIT_CPU, cpu_seconds),
        (resource.RLIMIT_FSIZE, 0),        # the analyser writes no files
        (resource.RLIMIT_NOFILE, 64),
    ):
        try:
            hard = resource.getrlimit(what)[1]
            ceiling = soft if hard == resource.RLIM_INFINITY else min(soft, hard)
            resource.setrlimit(what, (ceiling, hard))
        except (ValueError, OSError):
            pass


def main() -> int:
    if len(sys.argv) != 2:
        print("usage: _sandbox_main <sample-path>", file=sys.stderr)
        return 2
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
    with os.fdopen(sys.stdout.fileno(), "wb", closefd=False) as raw:
        raw.write(frame)
        raw.flush()
    return 0


if __name__ == "__main__":
    sys.exit(main())
