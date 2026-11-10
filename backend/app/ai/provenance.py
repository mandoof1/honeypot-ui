"""Where a model file or an evaluation number came from.

Every training and evaluation output records the code revision that
produced it and how it was invoked, so a figure quoted in the report can be
traced to a commit and reproduced. Model files are written atomically and
watched for change, so a process that did not fit a model still notices one.
"""

from __future__ import annotations

import hashlib
import hmac
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


#: First line of a signed model file: this tag, a space, the hex MAC of the
#: pickle that follows.
_SIGNED_TAG = b"hs-model-v1 "


class UntrustedModel(Exception):
    """A model file that is unsigned, or whose signature does not match."""


def _model_key() -> bytes:
    from app.core.config import get_settings

    secret = get_settings().SECRET_KEY or ""
    return hashlib.sha256(b"honeysentinel model store\0" + secret.encode("utf-8")).digest()


def _signed(data: bytes) -> bytes:
    mac = hmac.new(_model_key(), data, hashlib.sha256).hexdigest().encode("ascii")
    return _SIGNED_TAG + mac + b"\n" + data


def dump_pickle(path: str, payload) -> None:
    """Write a model file, signed, in one atomic replace."""
    data = pickle.dumps(payload)
    write_atomically(path, lambda stream: stream.write(_signed(data)))


def load_pickle(path: str):
    """Load a model file this deployment signed; refuse any other.

    Unpickling runs whatever the file says to run, and the model directory
    is writable by the process that also starts the payload-analysis child,
    which parses attacker files. A child that had been taken over could
    replace a model (the file-size limit on it does not stop a rename), and
    the next reload would unpickle its bytes inside the API. The signature
    is an HMAC under a key derived from SECRET_KEY, which the child does not
    have: its environment is scrubbed and its parent is not readable to it.
    """
    with open(path, "rb") as handle:
        blob = handle.read()
    if not blob.startswith(_SIGNED_TAG):
        raise UntrustedModel(
            f"{path} is not signed; if you trust it, run `python -m app.ai.provenance sign {path}`"
        )
    header, separator, data = blob.partition(b"\n")
    claimed = header[len(_SIGNED_TAG):].decode("ascii", "replace")
    expected = hmac.new(_model_key(), data, hashlib.sha256).hexdigest()
    if not separator or not hmac.compare_digest(claimed, expected):
        raise UntrustedModel(f"{path} does not carry this deployment's signature and was not loaded")
    return pickle.loads(data)


def sign_file(path: str) -> str:
    """Sign a model file in place, whatever it carried before. Returns its SHA-256.

    For an operator, about a file they have reason to trust: one trained
    offline, or one written before model files were signed.
    """
    with open(path, "rb") as handle:
        blob = handle.read()
    if blob.startswith(_SIGNED_TAG):
        blob = blob.partition(b"\n")[2]
    write_atomically(path, lambda stream: stream.write(_signed(blob)))
    return hashlib.sha256(blob).hexdigest()


def file_stamp(path: str) -> Optional[Tuple[int, int]]:
    """Identity of a file's current content, cheap enough to check per call."""
    try:
        status = os.stat(path)
    except OSError:
        return None
    return status.st_mtime_ns, status.st_size


def _main(argv: List[str]) -> int:
    if len(argv) < 2 or argv[0] != "sign":
        print("usage: python -m app.ai.provenance sign <model file> [...]", file=sys.stderr)
        return 2
    for path in argv[1:]:
        try:
            print(f"signed {path} (sha256 of the model: {sign_file(path)})")
        except OSError as exc:
            print(f"could not sign {path}: {exc}", file=sys.stderr)
            return 1
    return 0


if __name__ == "__main__":
    sys.exit(_main(sys.argv[1:]))
