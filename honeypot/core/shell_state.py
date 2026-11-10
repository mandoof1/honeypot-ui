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

The seeded filesystem every session starts from is in ``core/vfs.py``; what is
here is laid over it by ``FsView``.
"""

from __future__ import annotations

import posixpath
import time
from dataclasses import dataclass, field

from honeypot.core.shell_syntax import resolve_path  # noqa: F401 - imported from here by callers

#: Sessions tracked at once. A honeypot under a mass scan opens and abandons
#: connections continuously, so this is bounded and evicted oldest-first.
MAX_TRACKED_SESSIONS = 2048

#: Files remembered per session. A dropper writes a handful; anything writing
#: thousands is trying to exhaust memory rather than attack the host.
MAX_FILES_PER_SESSION = 64

#: Directories one session may create or remove.
MAX_DIRS_PER_SESSION = 256

#: Content retained for one written file, and for all of a session's files.
#: An echoloader assembles a binary of a few hundred kilobytes; these bounds
#: are well above that and well below what would let one session exhaust the
#: engine's memory.
MAX_CONTENT_PER_FILE = 16 * 1024 * 1024
MAX_CONTENT_PER_SESSION = 64 * 1024 * 1024

#: ``history`` keeps this many lines, each cut to this length. Uncut, five
#: hundred 256 KiB command lines sat in memory for the life of the session
#: and came back in full every time the attacker typed ``history``.
MAX_HISTORY_LINES = 500
MAX_HISTORY_LINE_CHARS = 1024


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
    #: The logged-in user's home, so ``~`` and the prompt agree with the
    #: account that authenticated rather than always meaning /home/user.
    home: str = "/home/user"
    #: Directories the attacker created with mkdir, so ``mkdir d && cd d``
    #: works; and paths they removed, so the seeded tree stops showing them.
    dirs: set[str] = field(default_factory=set)
    dir_times: dict[str, float] = field(default_factory=dict)
    removed: set[str] = field(default_factory=set)
    previous_cwd: str | None = None
    #: Command lines in order, for ``history``.
    history: list[str] = field(default_factory=list)
    #: Exit status of the last command, for ``$?``.
    last_status: int = 0
    #: Environment the attacker exported this session, and every shell
    #: variable they set (``X=1`` sets a variable without exporting it).
    env: dict[str, str] = field(default_factory=dict)
    variables: dict[str, str] = field(default_factory=dict)
    #: Bytes written through the shell, by path.
    contents: dict[str, bytearray] = field(default_factory=dict)
    #: How each path's bytes arrived — echo, base64, heredoc — in order.
    methods: dict[str, list[str]] = field(default_factory=dict)
    #: Paths whose content is already in the session record, with the length
    #: it had then: an SFTP upload is recorded when its handle closes, and a
    #: file restored for a returning source was recorded by an earlier
    #: session. Neither is recorded again unless it has changed since.
    recorded: dict[str, int] = field(default_factory=dict)
    #: Who the shell belongs to and where they came from, for ``w``, ``who``,
    #: ``ps`` and the socket tables.
    username: str = "root"
    client_ip: str = ""
    client_port: int = 0
    login_time: float = field(default_factory=time.time)
    #: Process id of the session's shell, stable for its lifetime.
    pid: int = 0
    #: Nested shells started with a bare ``bash`` or ``sh``; ``exit`` leaves
    #: one of these before it ends the session.
    subshells: int = 0

    def add_file(self, path: str, file: DroppedFile) -> None:
        if path not in self.files and len(self.files) >= MAX_FILES_PER_SESSION:
            return
        self.files[path] = file
        self.removed.discard(path)

    def add_dir(self, path: str) -> bool:
        if path in self.dirs:
            return True
        if len(self.dirs) >= MAX_DIRS_PER_SESSION:
            return False
        self.dirs.add(path)
        self.dir_times[path] = time.time()
        self.removed.discard(path)
        return True

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
            # In place: appending never copies what is already there.
            existing += data
            if method not in self.methods[path]:
                self.methods[path].append(method)

        file = self.files.get(path)
        if file is None:
            self.add_file(path, DroppedFile(name=posixpath.basename(path) or path, size=new_length))
        else:
            file.size = new_length
        self.removed.discard(path)
        return True

    def captured(self) -> list[tuple[str, bytes, list[str]]]:
        """Every written file with its final content, for the session record.

        Leaves out what the record already holds unchanged; see ``recorded``.
        """
        return [
            (path, bytes(content), list(self.methods.get(path, [])))
            for path, content in self.contents.items()
            if content and self.recorded.get(path) != len(content)
        ]

    def remember(self, command: str) -> None:
        if len(self.history) >= MAX_HISTORY_LINES:
            del self.history[: len(self.history) - MAX_HISTORY_LINES + 1]
        self.history.append(command[:MAX_HISTORY_LINE_CHARS])

    def remove_path(self, path: str, recursive: bool) -> None:
        """Forget a file, or with ``recursive`` everything beneath a directory."""
        self.files.pop(path, None)
        self.contents.pop(path, None)
        self.methods.pop(path, None)
        self.recorded.pop(path, None)
        if recursive:
            prefix = path.rstrip("/") + "/"
            for store in (self.files, self.contents, self.methods, self.recorded):
                for key in [k for k in store if k.startswith(prefix)]:
                    store.pop(key, None)
            self.dirs = {d for d in self.dirs if d != path and not d.startswith(prefix)}
        self.dirs.discard(path)
        self.dir_times.pop(path, None)
        # Hide it in the seeded tree too, within a bound.
        if len(self.removed) < MAX_DIRS_PER_SESSION:
            self.removed.add(path)

    def display_cwd(self, home: str | None = None) -> str:
        """The prompt form: ``~`` for home, ``~/x`` beneath it."""
        home = home or self.home
        if self.cwd == home:
            return "~"
        if self.cwd.startswith(home + "/"):
            return "~/" + self.cwd[len(home) + 1:]
        return self.cwd


class ShellStateStore:
    """Session id -> ShellState, bounded."""

    def __init__(self) -> None:
        self._states: dict[str, ShellState] = {}

    def get(self, session_id: str) -> ShellState:
        state = self._states.get(session_id)
        if state is None:
            self._evict()
            state = ShellState()
            # Derived from the session id so it is stable for the session
            # and different between sessions, like a real shell's pid.
            state.pid = 1400 + (hash(session_id) & 0x3FFF) * 2
            self._states[session_id] = state
        state.last_used = time.time()
        return state

    def peek(self, session_id: str) -> ShellState | None:
        """A session's state if it has one; never creates it."""
        return self._states.get(session_id)

    def drop(self, session_id: str) -> None:
        self._states.pop(session_id, None)

    def pop(self, session_id: str) -> ShellState | None:
        """Remove and return a session's state, without creating one."""
        return self._states.pop(session_id, None)

    def __len__(self) -> int:
        return len(self._states)

    def _evict(self) -> None:
        if len(self._states) < MAX_TRACKED_SESSIONS:
            return
        stale = sorted(self._states.items(), key=lambda kv: kv[1].last_used)
        for session_id, _ in stale[: len(self._states) - MAX_TRACKED_SESSIONS + 1]:
            self._states.pop(session_id, None)


shell_states = ShellStateStore()
