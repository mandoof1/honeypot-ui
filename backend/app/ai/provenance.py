"""Where a model file or an evaluation number came from.

Every training and evaluation output records the code revision that
produced it and how it was invoked, so a figure quoted in the report can be
traced to a commit and reproduced. Model files are written atomically and
watched for change, so a process that did not fit a model still notices one.
"""

from __future__ import annotations

import os
import pickle
import subprocess
import sys
import tempfile
from datetime import datetime, timezone
from typing import Callable, Dict, List, Optional, Tuple

_BACKEND_DIR = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))


def git_revision() -> str:
    """The commit of the running code, or "unknown".

    A container image has no ``.git``; the build can pass the commit in as
    ``GIT_REVISION`` instead. A dirty tree is marked, because a number from
    uncommitted code cannot be reproduced from the commit alone.
    """
    from_env = os.environ.get("GIT_REVISION", "").strip()
    if from_env:
        return from_env
    try:
        commit = subprocess.run(
            ["git", "rev-parse", "HEAD"], cwd=_BACKEND_DIR, capture_output=True, text=True, timeout=5,
        )
        if commit.returncode != 0:
            return "unknown"
        dirty = subprocess.run(
            ["git", "status", "--porcelain", "--untracked-files=no"],
            cwd=_BACKEND_DIR, capture_output=True, text=True, timeout=5,
        )
        suffix = "-dirty" if dirty.returncode == 0 and dirty.stdout.strip() else ""
        return commit.stdout.strip() + suffix
    except (OSError, subprocess.SubprocessError):
        return "unknown"


def run_metadata(tool: str, argv: Optional[List[str]] = None) -> Dict:
    """The fields every evidence file starts with."""
    now = datetime.now(timezone.utc)
    return {
        "tool": tool,
        "arguments": list(sys.argv[1:] if argv is None else argv),
        "git_revision": git_revision(),
        "measured": now.date().isoformat(),
        "generated_at": now.isoformat(),
    }


def write_atomically(path: str, write: Callable) -> None:
    """Write a file so a reader sees the old one or the new one, never half.

    The four ingest workers load model files while the backend process may
    be replacing them.
    """
    directory = os.path.dirname(os.path.abspath(path))
    os.makedirs(directory, exist_ok=True)
    handle, temporary = tempfile.mkstemp(prefix=".tmp-", dir=directory)
    try:
        with os.fdopen(handle, "wb") as stream:
            write(stream)
        os.replace(temporary, path)
    except BaseException:
        try:
            os.unlink(temporary)
        except OSError:
            pass
        raise


def dump_pickle(path: str, payload) -> None:
    write_atomically(path, lambda stream: pickle.dump(payload, stream))


def file_stamp(path: str) -> Optional[Tuple[int, int]]:
    """Identity of a file's current content, cheap enough to check per call."""
    try:
        status = os.stat(path)
    except OSError:
        return None
    return status.st_mtime_ns, status.st_size
