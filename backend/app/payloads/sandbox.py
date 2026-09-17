"""Run the analyser in a locked-down subprocess.

The analysers are careful, but they parse attacker-chosen bytes with a stack
of libraries (pyelftools, pefile, the archive modules), and a parser fed
hostile input is exactly where a hang, a runaway allocation or a crash lives.
So analysis runs in a separate process with a wall-clock timeout, a CPU-time
limit and an address-space cap, started clean rather than forked so it carries
none of the API's memory — or its secrets. If it exceeds a limit or dies, the
sample is marked ``failed`` and nothing else is affected.

``run(data)`` is the only entry point. It works on any platform; the resource
limits apply where the OS supports them (Linux, where this deploys) and are
skipped elsewhere so the tests still run.
"""

from __future__ import annotations

import asyncio
import json
import logging
import os
import pathlib
import pickle
import struct
import sys
import tempfile

logger = logging.getLogger(__name__)

_CHILD_MAIN = "app.payloads._sandbox_main"


async def run(data: bytes, timeout: float, memory_mb: int) -> dict:
    """Analyse ``data`` in a subprocess. Never raises; returns a status dict."""
    # The sample goes to the child through a temp file, not argv or a pipe the
    # parent must keep writing: the child is the only reader, it is removed
    # immediately, and a multi-megabyte payload never sits in an argument list.
    fd, path = tempfile.mkstemp(prefix="payload-", suffix=".bin")
    try:
        with os.fdopen(fd, "wb") as handle:
            handle.write(data)
        return await _run_child(path, timeout, memory_mb)
    finally:
        try:
            os.unlink(path)
        except OSError:
            pass


async def _run_child(path: str, timeout: float, memory_mb: int) -> dict:
    # The child starts in a temp dir, so every path it needs must be absolute.
    # The backend root (the parent of the `app` package) is derived from this
    # file's own location rather than from cwd or a relative sys.path entry.
    backend_root = str(pathlib.Path(__file__).resolve().parents[2])
    search = [backend_root] + [
        str(pathlib.Path(entry).resolve()) for entry in sys.path if entry
    ]
    env = {
        "PATH": os.environ.get("PATH", "/usr/bin:/bin"),
        "PYTHONPATH": os.pathsep.join(dict.fromkeys(search)),
        "PAYLOAD_MEMORY_MB": str(memory_mb),
        "PAYLOAD_CPU_SECONDS": str(int(timeout) + 1),
        # No network for the child: nothing it does should reach out, and this
        # makes that structural rather than trusted.
        "PYTHONDONTWRITEBYTECODE": "1",
    }
    try:
        # "-s" drops the user site-packages dir but, unlike "-I", still honours
        # the curated PYTHONPATH above, which is how the child finds the app.
        process = await asyncio.create_subprocess_exec(
            sys.executable, "-s", "-m", _CHILD_MAIN, path,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
            env=env,
            cwd=tempfile.gettempdir(),
            start_new_session=True,  # its own process group, so timeout kills the tree
        )
    except OSError as exc:
        return {"status": "failed", "error": f"could not start analyser: {exc}"[:200]}

    try:
        stdout, stderr = await asyncio.wait_for(process.communicate(), timeout=timeout)
    except asyncio.TimeoutError:
        _terminate(process)
        await _reap(process)
        return {"status": "failed", "error": f"analysis exceeded {timeout:.0f}s and was killed"}

    if process.returncode != 0:
        detail = stderr.decode("utf-8", errors="replace").strip().splitlines()[-1:] or ["no output"]
        # A memory or CPU limit shows up as the kernel's signal, not a clean exit.
        signal = -process.returncode if process.returncode < 0 else None
        reason = f"killed by signal {signal}" if signal else f"exit {process.returncode}: {detail[0]}"
        return {"status": "failed", "error": f"analyser {reason}"[:300]}

    return _decode(stdout)


def _decode(stdout: bytes) -> dict:
    # The child frames its result: 4-byte length, then pickle. Anything it
    # printed to stdout on its own (a library banner) sits before the frame
    # and is skipped by scanning for the marker.
    marker = stdout.rfind(_FRAME_MAGIC)
    if marker == -1:
        return {"status": "failed", "error": "analyser produced no result frame"}
    try:
        (length,) = struct.unpack(">I", stdout[marker + 4:marker + 8])
        payload = stdout[marker + 8:marker + 8 + length]
        report = pickle.loads(payload)
    except (struct.error, pickle.UnpicklingError, EOFError) as exc:
        return {"status": "failed", "error": f"could not read analyser result: {exc}"[:200]}
    return {"status": "complete", "report": report}


def _terminate(process) -> None:
    try:
        os.killpg(os.getpgid(process.pid), 9)
    except (ProcessLookupError, PermissionError):
        process.kill()


async def _reap(process) -> None:
    try:
        await asyncio.wait_for(process.wait(), timeout=5)
    except asyncio.TimeoutError:
        pass


_FRAME_MAGIC = b"PLD\x00"


def frame(report: dict) -> bytes:
    """Serialise a report the way the child writes it and the parent reads it."""
    payload = pickle.dumps(report, protocol=pickle.HIGHEST_PROTOCOL)
    return _FRAME_MAGIC + struct.pack(">I", len(payload)) + payload
