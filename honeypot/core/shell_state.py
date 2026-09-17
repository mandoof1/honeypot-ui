"""Per-session shell state for the SSH emulator.

Every emulated command was previously answered from a dictionary rebuilt on
each call, so the shell had no memory: ``cd /tmp`` printed nothing and changed
nothing, and a file an attacker downloaded did not exist a command later. An
attacker who checks — and a dropper script that checks by running the thing it
just fetched — sees the emulation immediately.

This holds the small amount of state that makes a session self-consistent: the
working directory, and the files the attacker believes they created. Nothing
here touches the real filesystem.

Files written through the shell — ``echo -ne … >> .s``, ``base64 -d > x``,
heredocs — also keep their *content*, assembled across commands, because that
content is the payload. It lives only in memory until the session closes, when
it is handed to the session manager as a captured upload.
"""

from __future__ import annotations

import posixpath
import time
from dataclasses import dataclass, field

#: Sessions tracked at once. A honeypot under a mass scan opens and abandons
#: connections continuously, so this is bounded and evicted oldest-first.
MAX_TRACKED_SESSIONS = 2048

#: Files remembered per session. A dropper writes a handful; anything writing
#: thousands is trying to exhaust memory rather than attack the host.
MAX_FILES_PER_SESSION = 64

#: Content retained for one written file, and for all of a session's files.
#: An echoloader assembles a binary of a few hundred kilobytes; these bounds
#: are well above that and well below what would let one session exhaust the
#: engine's memory.
MAX_CONTENT_PER_FILE = 16 * 1024 * 1024
MAX_CONTENT_PER_SESSION = 64 * 1024 * 1024


@dataclass
class DroppedFile:
    """A file the attacker believes they put on the box."""

    name: str
    size: int
    executable: bool = False
    source_url: str | None = None
    created_at: float = field(default_factory=time.time)


@dataclass
class ShellState:
    """What one SSH session thinks the machine looks like."""

    cwd: str = "/home/user"
    files: dict[str, DroppedFile] = field(default_factory=dict)
    last_used: float = field(default_factory=time.time)
    #: Bytes written through the shell, by path.
    contents: dict[str, bytearray] = field(default_factory=dict)
    #: How each path's bytes arrived — echo, base64, heredoc — in order.
    methods: dict[str, list[str]] = field(default_factory=dict)

    def add_file(self, path: str, file: DroppedFile) -> None:
        if len(self.files) >= MAX_FILES_PER_SESSION:
            return
        self.files[path] = file

    def read_content(self, path: str) -> bytes | None:
        content = self.contents.get(path)
        return bytes(content) if content is not None else None

    def write_content(self, path: str, data: bytes, append: bool, method: str) -> bool:
        """Apply one shell write. Returns False when a bound refused it."""
        existing = self.contents.get(path)
        if existing is None and len(self.contents) >= MAX_FILES_PER_SESSION:
            return False
        stored = sum(len(c) for c in self.contents.values())
        previous = len(existing) if existing is not None else 0
        new_length = previous + len(data) if append else len(data)
        if new_length > MAX_CONTENT_PER_FILE:
            return False
        if stored - previous + new_length > MAX_CONTENT_PER_SESSION:
            return False

        if existing is None or not append:
            self.contents[path] = bytearray(data)
            self.methods[path] = [method]
        else:
            existing += data
            if method not in self.methods[path]:
                self.methods[path].append(method)

        file = self.files.get(path)
        if file is None:
            self.add_file(path, DroppedFile(name=posixpath.basename(path) or path, size=new_length))
        else:
            file.size = new_length
        return True

    def captured(self) -> list[tuple[str, bytes, list[str]]]:
        """Every written file with its final content, for the session record."""
        return [
            (path, bytes(content), list(self.methods.get(path, [])))
            for path, content in self.contents.items()
            if content
        ]

    def display_cwd(self, home: str = "/home/user") -> str:
        """The prompt form: ``~`` for home, ``~/x`` beneath it."""
        if self.cwd == home:
            return "~"
        if self.cwd.startswith(home + "/"):
            return "~/" + self.cwd[len(home) + 1:]
        return self.cwd


def resolve_path(cwd: str, arg: str, home: str = "/home/user") -> str:
    """Resolve a shell path argument the way a shell would.

    Handles ``~``, relative segments and ``..``. ``posixpath.normpath``
    collapses ``..`` textually, which is what a shell does for a path that has
    no symlinks in it — and this filesystem has none.
    """
    arg = (arg or "").strip().strip("'\"")
    if not arg or arg == "~":
        return home
    if arg.startswith("~/"):
        arg = posixpath.join(home, arg[2:])
    if not arg.startswith("/"):
        arg = posixpath.join(cwd, arg)
    resolved = posixpath.normpath(arg)
    return resolved if resolved.startswith("/") else "/"


class ShellStateStore:
    """Session id -> ShellState, bounded."""

    def __init__(self) -> None:
        self._states: dict[str, ShellState] = {}

    def get(self, session_id: str) -> ShellState:
        state = self._states.get(session_id)
        if state is None:
            self._evict()
            state = ShellState()
            self._states[session_id] = state
        state.last_used = time.time()
        return state

    def drop(self, session_id: str) -> None:
        self._states.pop(session_id, None)

    def pop(self, session_id: str) -> ShellState | None:
        """Remove and return a session's state, without creating one."""
        return self._states.pop(session_id, None)

    def _evict(self) -> None:
        if len(self._states) < MAX_TRACKED_SESSIONS:
            return
        stale = sorted(self._states.items(), key=lambda kv: kv[1].last_used)
        for session_id, _ in stale[: len(self._states) - MAX_TRACKED_SESSIONS + 1]:
            self._states.pop(session_id, None)


shell_states = ShellStateStore()
