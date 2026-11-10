"""Run the analyser in a separate, resource-limited process.

The analysers are careful, but they parse attacker-chosen bytes with a stack
of libraries (pyelftools, pefile, the archive modules), and a parser fed
hostile input is exactly where a hang, a runaway allocation or a crash lives.
So analysis runs in a child process, and the parent treats everything that
child sends back as untrusted.

What the isolation is, precisely:

* A separate process started with ``exec`` rather than forked, so it shares
  none of the API's memory, and given a minimal environment of its own
  (PATH, PYTHONPATH and its limits) rather than the API's, which holds the
  database password and the keys.
* Hard resource limits, set by the child before it reads the sample and
  impossible for it to raise again: address space, CPU seconds, no file
  writes, few file descriptors, no new processes or threads, no core dump.
  The parent adds a wall-clock timeout and kills the whole process group.
* ``no_new_privs``, so nothing the child executes can gain privileges.
* The API process marks itself non-dumpable at startup (``app.main``), so
  the child cannot read the API's environment or memory through /proc or
  attach to it with ptrace, although both run as the same user.

What it is not: the child runs as the same user as the API, sees the same
filesystem, and is in the same network namespace. Nothing here stops it
opening a socket. That it cannot reach anything is a property of the
deployment (the backend containers sit on internal Docker networks with no
route out), not of this module. A multi-worker ``uvicorn`` supervisor is a
separate process that this code never runs in, so it stays dumpable; see the
deployment notes.

The result comes back as JSON in one length-prefixed frame at the very start
of the child's stdout. It used to be a pickle located by searching stdout for
a four-byte marker, and the report quotes strings taken from the sample: an
uploaded file could contain the marker followed by bytes of its choosing, and
the API process would unpickle them, which is code execution in the process
that holds every secret. JSON can only ever produce data, the frame is taken
from offset zero rather than searched for, and its length must account for
every byte the child wrote.

``run(data)`` is the only entry point. It works on any platform; the limits
apply where the OS supports them (Linux, where this deploys) and are skipped
elsewhere so the tests still run.
"""

from __future__ import annotations

import asyncio
import json
import logging
import math
import os
import pathlib
import struct
import sys
import tempfile
from typing import Any

logger = logging.getLogger(__name__)

_CHILD_MAIN = "app.payloads._sandbox_main"

#: Identifies the frame format. Checked at offset zero only.
_FRAME_MAGIC = b"HSR1"
_HEADER = struct.Struct(">4sI")

#: Largest report accepted from the child. A real report is tens of
#: kilobytes; this bounds what a misbehaving child can make the API buffer.
MAX_REPORT_BYTES = 8 * 1024 * 1024
#: The child's stderr is only ever used for one line of diagnosis.
_MAX_STDERR_BYTES = 64 * 1024


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


def _child_environment(memory_mb: int, timeout: float) -> dict:
    """The whole environment the child gets. Nothing is inherited."""
    # The child starts in a temp dir, so every path it needs must be absolute.
    # The backend root (the parent of the `app` package) is derived from this
    # file's own location rather than from cwd or a relative sys.path entry.
    backend_root = str(pathlib.Path(__file__).resolve().parents[2])
    search = [backend_root] + [
        str(pathlib.Path(entry).resolve()) for entry in sys.path if entry
    ]
    return {
        "PATH": os.environ.get("PATH", "/usr/bin:/bin"),
        "PYTHONPATH": os.pathsep.join(dict.fromkeys(search)),
        "PAYLOAD_MEMORY_MB": str(memory_mb),
        "PAYLOAD_CPU_SECONDS": str(int(timeout) + 1),
        "PYTHONDONTWRITEBYTECODE": "1",
        # The child may not create threads (RLIMIT_NPROC), and numpy's BLAS
        # starts a pool of them on import unless told to stay single-threaded.
        "OPENBLAS_NUM_THREADS": "1",
        "OMP_NUM_THREADS": "1",
        "MKL_NUM_THREADS": "1",
        "NUMEXPR_NUM_THREADS": "1",
    }


async def _run_child(path: str, timeout: float, memory_mb: int) -> dict:
    try:
        # "-s" drops the user site-packages dir but, unlike "-I", still honours
        # the curated PYTHONPATH above, which is how the child finds the app.
        process = await asyncio.create_subprocess_exec(
            sys.executable, "-s", "-m", _CHILD_MAIN, path,
            stdin=asyncio.subprocess.DEVNULL,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
            env=_child_environment(memory_mb, timeout),
            cwd=tempfile.gettempdir(),
            start_new_session=True,  # its own process group, so timeout kills the tree
        )
    except OSError as exc:
        return {"status": "failed", "error": f"could not start analyser: {exc}"[:200]}

    try:
        stdout, stderr, overflow = await asyncio.wait_for(
            _collect(process), timeout=timeout
        )
    except asyncio.TimeoutError:
        _terminate(process)
        await _reap(process)
        return {"status": "failed", "error": f"analysis exceeded {timeout:.0f}s and was killed"}

    if overflow:
        return {"status": "failed", "error": "analyser output exceeded the report size limit"}

    if process.returncode != 0:
        detail = stderr.decode("utf-8", errors="replace").strip().splitlines()[-1:] or ["no output"]
        # A memory or CPU limit shows up as the kernel's signal, not a clean exit.
        signal = -process.returncode if process.returncode < 0 else None
        reason = f"killed by signal {signal}" if signal else f"exit {process.returncode}: {detail[0]}"
        return {"status": "failed", "error": f"analyser {reason}"[:300]}

    return _decode(stdout)


async def _collect(process) -> tuple[bytes, bytes, bool]:
    """Read the child's output without letting it fill the parent's memory.

    ``communicate()`` buffers whatever the child writes, without limit. The
    child is the untrusted side, so stdout is read up to one maximal frame
    and stderr is kept only as a tail.
    """
    limit = _HEADER.size + MAX_REPORT_BYTES

    async def read_stdout() -> tuple[bytes, bool]:
        chunks: list[bytes] = []
        total = 0
        while True:
            chunk = await process.stdout.read(65536)
            if not chunk:
                return b"".join(chunks), False
            total += len(chunk)
            if total > limit:
                return b"", True
            chunks.append(chunk)

    async def read_stderr() -> bytes:
        tail = b""
        while True:
            chunk = await process.stderr.read(65536)
            if not chunk:
                return tail
            tail = (tail + chunk)[-_MAX_STDERR_BYTES:]

    stderr_task = asyncio.ensure_future(read_stderr())
    try:
        stdout, overflow = await read_stdout()
        if overflow:
            _terminate(process)
        stderr = await stderr_task
        await process.wait()
    except BaseException:
        stderr_task.cancel()
        raise
    return stdout, stderr, overflow


def _decode(stdout: bytes) -> dict:
    """Parse the child's single result frame.

    The frame must start at the first byte and its declared length must cover
    everything that follows; anything before or after it is refused rather
    than skipped. The payload is JSON and must be an object.
    """
    if len(stdout) < _HEADER.size:
        return {"status": "failed", "error": "analyser produced no result frame"}
    magic, length = _HEADER.unpack_from(stdout, 0)
    if magic != _FRAME_MAGIC:
        return {"status": "failed", "error": "analyser produced no result frame"}
    if length > MAX_REPORT_BYTES or len(stdout) != _HEADER.size + length:
        return {"status": "failed", "error": "analyser result frame has the wrong length"}
    try:
        report = json.loads(stdout[_HEADER.size:].decode("utf-8"))
    except (UnicodeDecodeError, ValueError, RecursionError) as exc:
        return {"status": "failed", "error": f"could not read analyser result: {exc}"[:200]}
    if not isinstance(report, dict):
        return {"status": "failed", "error": "analyser result is not a report"}
    return {"status": "complete", "report": report}


def _terminate(process) -> None:
    try:
        os.killpg(os.getpgid(process.pid), 9)
    except (ProcessLookupError, PermissionError):
        try:
            process.kill()
        except ProcessLookupError:
            pass


async def _reap(process) -> None:
    try:
        await asyncio.wait_for(process.wait(), timeout=5)
    except asyncio.TimeoutError:
        pass


def to_jsonable(value: Any, _depth: int = 0) -> Any:
    """Reduce an analyser result to what JSON can carry.

    The analysers return plain dicts, lists, strings and numbers, but they are
    built on parser libraries that hand back bytes, tuples and sets in places,
    and pickle used to carry those across silently. Anything JSON has no form
    for is converted here, on the child's side, so one stray value cannot
    cost the whole report.
    """
    if _depth > 32:
        return "[nested too deeply]"
    if value is None or isinstance(value, (bool, int, str)):
        return value
    if isinstance(value, float):
        return value if math.isfinite(value) else None
    if isinstance(value, (bytes, bytearray, memoryview)):
        return bytes(value).decode("latin-1")
    if isinstance(value, dict):
        return {str(key): to_jsonable(item, _depth + 1) for key, item in value.items()}
    if isinstance(value, (list, tuple)):
        return [to_jsonable(item, _depth + 1) for item in value]
    if isinstance(value, (set, frozenset)):
        return sorted((to_jsonable(item, _depth + 1) for item in value), key=str)
    # numpy scalars are not Python numbers, but they know how to become one.
    as_python = getattr(value, "item", None)
    if callable(as_python):
        try:
            return to_jsonable(as_python(), _depth + 1)
        except (TypeError, ValueError):
            pass
    return str(value)


def frame(report: dict) -> bytes:
    """Serialise a report the way the child writes it and the parent reads it."""
    payload = json.dumps(
        to_jsonable(report), ensure_ascii=True, allow_nan=False, separators=(",", ":")
    ).encode("ascii")
    return _HEADER.pack(_FRAME_MAGIC, len(payload)) + payload
