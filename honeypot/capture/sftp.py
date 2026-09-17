"""An in-memory SFTP and SCP endpoint that keeps what attackers upload.

The SSH emulator refused every subsystem request, so ``scp bot root@host:/tmp``
and ``sftp put`` failed at the first step, and a real OpenSSH server does not
refuse them. asyncssh routes both through one ``SFTPServer`` object — SCP is
implemented on top of the same file operations — so one class serves both.

The important property is what this does *not* do. asyncssh's default
``SFTPServer`` maps every operation onto the real local filesystem; an
override that missed one method would hand an attacker ``readlink``,
``symlink`` or ``remove`` against the container. So every filesystem method
is implemented here against a per-connection dictionary, and the operations
there is no reason to model are refused outright. No path an attacker sends
is ever given to the operating system.

A file is recorded when it is closed — which asyncssh also does for every
handle still open when the connection drops, so an upload cut off halfway is
captured as far as it got.
"""

from __future__ import annotations

import asyncio
import logging
import posixpath
import stat
import time
from dataclasses import dataclass
from typing import AsyncIterator, Optional

import asyncssh

from honeypot.core.session import session_manager

logger = logging.getLogger(__name__)

#: Bounds per connection. An upload bigger than the engine's capture cap is
#: refused with an out-of-space error, which is what a full disk would say.
MAX_FILE_BYTES = 16 * 1024 * 1024
MAX_TOTAL_BYTES = 64 * 1024 * 1024
MAX_FILES = 64
MAX_DIRS = 256

#: Directories an ordinary Ubuntu host has, so uploads to the usual drop
#: locations succeed.
SEED_DIRS = frozenset({
    "/", "/bin", "/dev", "/dev/shm", "/etc", "/etc/cron.d", "/home",
    "/home/user", "/home/user/.ssh", "/mnt", "/opt", "/root", "/root/.ssh",
    "/run", "/sbin", "/srv", "/tmp", "/usr", "/usr/bin", "/usr/local",
    "/usr/local/bin", "/var", "/var/run", "/var/tmp",
})

_EPOCH = int(time.time())

#: SFTP/SCP channels still running, per session. When a connection drops,
#: asyncssh closes the channel's open handles in a task of its own, while the
#: SSH server schedules the session's end in another; nothing orders the two.
#: The session close waits on these so an interrupted upload is recorded
#: before the session is finalised, rather than whenever the race allows.
_active_transfers: dict[str, set[asyncio.Event]] = {}


async def wait_for_transfers(session_id: str, timeout: float = 5.0) -> None:
    events = list(_active_transfers.get(session_id, ()))
    if not events:
        return
    try:
        await asyncio.wait_for(
            asyncio.gather(*(event.wait() for event in events)), timeout=timeout
        )
    except asyncio.TimeoutError:
        logger.warning("SFTP channel for %s did not exit in time", session_id)


@dataclass
class _Handle:
    path: str
    writable: bool
    dirty: bool = False


class DecoySFTPServer(asyncssh.SFTPServer):
    def __init__(self, chan: asyncssh.SSHServerChannel) -> None:
        # No chroot: the base class's path mapping is never used, because no
        # method below falls through to it.
        super().__init__(chan)
        server = chan.get_connection().get_extra_info("honeypot_server")
        state = getattr(server, "state", None)
        self._session_id: Optional[str] = getattr(state, "session_id", None)
        self._home = "/root" if getattr(state, "is_root", False) else "/home/user"
        command = chan.get_command() or ""
        self._source = "scp" if command.startswith("scp ") else "sftp"
        self._dirs: set[str] = set(SEED_DIRS)
        self._files: dict[str, bytearray] = {}
        self._total = 0
        self._done = asyncio.Event()
        if self._session_id is not None:
            _active_transfers.setdefault(self._session_id, set()).add(self._done)

    # -- paths --------------------------------------------------------------

    def _path(self, raw: bytes) -> str:
        path = raw.decode("utf-8", errors="surrogateescape") or "."
        if not path.startswith("/"):
            path = posixpath.join(self._home, path)
        normalised = posixpath.normpath(path)
        return "/" if normalised.startswith("//") else normalised

    def map_path(self, path: bytes) -> bytes:  # pragma: no cover - never reached
        raise asyncssh.SFTPPermissionDenied("Permission denied")

    def reverse_map_path(self, path: bytes) -> bytes:  # pragma: no cover
        raise asyncssh.SFTPPermissionDenied("Permission denied")

    def realpath(self, path: bytes) -> bytes:
        return self._path(path).encode("utf-8", errors="surrogateescape")

    # -- attributes ---------------------------------------------------------

    def _attrs(self, path: str) -> asyncssh.SFTPAttrs:
        if path in self._dirs:
            return asyncssh.SFTPAttrs(
                type=asyncssh.FILEXFER_TYPE_DIRECTORY, size=4096, uid=0, gid=0,
                permissions=stat.S_IFDIR | 0o755, atime=_EPOCH, mtime=_EPOCH, nlink=2,
            )
        if path in self._files:
            return asyncssh.SFTPAttrs(
                type=asyncssh.FILEXFER_TYPE_REGULAR, size=len(self._files[path]),
                uid=0, gid=0, permissions=stat.S_IFREG | 0o644,
                atime=int(time.time()), mtime=int(time.time()), nlink=1,
            )
        raise asyncssh.SFTPNoSuchFile("No such file")

    def stat(self, path: bytes) -> asyncssh.SFTPAttrs:
        return self._attrs(self._path(path))

    def lstat(self, path: bytes) -> asyncssh.SFTPAttrs:
        return self._attrs(self._path(path))

    def fstat(self, file_obj: _Handle) -> asyncssh.SFTPAttrs:
        return self._attrs(file_obj.path)

    def setstat(self, path: bytes, attrs: asyncssh.SFTPAttrs) -> None:
        self._attrs(self._path(path))  # exists, or raises

    def lsetstat(self, path: bytes, attrs: asyncssh.SFTPAttrs) -> None:
        self._attrs(self._path(path))

    def fsetstat(self, file_obj: _Handle, attrs: asyncssh.SFTPAttrs) -> None:
        return None

    def format_user(self, uid: Optional[int]) -> str:
        # The default looks the uid up in the real /etc/passwd.
        return "root"

    def format_group(self, gid: Optional[int]) -> str:
        return "root"

    # -- files --------------------------------------------------------------

    def open(self, path: bytes, pflags: int, attrs: asyncssh.SFTPAttrs) -> _Handle:
        target = self._path(path)
        if target in self._dirs:
            raise asyncssh.SFTPFailure("Is a directory")
        writable = bool(pflags & (asyncssh.FXF_WRITE | asyncssh.FXF_APPEND))
        if not writable:
            if target not in self._files:
                raise asyncssh.SFTPNoSuchFile("No such file")
            return _Handle(target, writable=False)

        if posixpath.dirname(target) not in self._dirs:
            raise asyncssh.SFTPNoSuchFile("No such file")
        if target not in self._files:
            if len(self._files) >= MAX_FILES:
                raise asyncssh.SFTPPermissionDenied("Permission denied")
            self._files[target] = bytearray()
        elif pflags & asyncssh.FXF_TRUNC:
            self._total -= len(self._files[target])
            self._files[target] = bytearray()
        return _Handle(target, writable=True)

    def read(self, file_obj: _Handle, offset: int, size: int) -> bytes:
        content = self._files.get(file_obj.path, bytearray())
        return bytes(content[offset:offset + size])

    def write(self, file_obj: _Handle, offset: int, data: bytes) -> int:
        if not file_obj.writable:
            raise asyncssh.SFTPPermissionDenied("Permission denied")
        content = self._files.get(file_obj.path)
        if content is None:
            raise asyncssh.SFTPNoSuchFile("No such file")
        end = offset + len(data)
        growth = max(0, end - len(content))
        if end > MAX_FILE_BYTES or self._total + growth > MAX_TOTAL_BYTES:
            raise asyncssh.SFTPFailure("No space left on device")
        if offset > len(content):
            content.extend(b"\x00" * (offset - len(content)))
        content[offset:end] = data
        self._total += growth
        file_obj.dirty = True
        return len(data)

    async def close(self, file_obj: _Handle) -> None:
        if not file_obj.dirty or self._session_id is None:
            return
        file_obj.dirty = False
        content = bytes(self._files.get(file_obj.path, b""))
        if content:
            await session_manager.record_file_upload(
                self._session_id,
                posixpath.basename(file_obj.path) or file_obj.path,
                content,
                remote_path=file_obj.path,
                source=self._source,
            )

    def fsync(self, file_obj: _Handle) -> None:
        return None

    # -- directories --------------------------------------------------------

    async def scandir(self, path: bytes) -> AsyncIterator[asyncssh.SFTPName]:
        directory = self._path(path)
        if directory not in self._dirs:
            raise asyncssh.SFTPNoSuchFile("No such file")
        children = sorted(
            {posixpath.basename(p) for p in self._dirs | set(self._files)
             if p != "/" and posixpath.dirname(p) == directory}
        )
        for name in [".", ".."] + children:
            full = directory if name in (".", "..") else posixpath.join(directory, name)
            entry = asyncssh.SFTPName(name.encode(), b"", self._attrs(full))
            self.format_longname(entry)
            yield entry

    def mkdir(self, path: bytes, attrs: asyncssh.SFTPAttrs) -> None:
        target = self._path(path)
        if target in self._dirs or target in self._files:
            raise asyncssh.SFTPFailure("File exists")
        if posixpath.dirname(target) not in self._dirs:
            raise asyncssh.SFTPNoSuchFile("No such file")
        if len(self._dirs) >= MAX_DIRS:
            raise asyncssh.SFTPPermissionDenied("Permission denied")
        self._dirs.add(target)

    def rmdir(self, path: bytes) -> None:
        target = self._path(path)
        if target in SEED_DIRS:
            raise asyncssh.SFTPPermissionDenied("Permission denied")
        if target not in self._dirs:
            raise asyncssh.SFTPNoSuchFile("No such file")
        if any(posixpath.dirname(p) == target for p in self._dirs | set(self._files)):
            raise asyncssh.SFTPFailure("Directory not empty")
        self._dirs.discard(target)

    def remove(self, path: bytes) -> None:
        # The content was already recorded when it was closed; removing it
        # here changes what the attacker sees, not what was captured.
        target = self._path(path)
        if target not in self._files:
            raise asyncssh.SFTPNoSuchFile("No such file")
        self._total -= len(self._files.pop(target))

    def rename(self, oldpath: bytes, newpath: bytes) -> None:
        old, new = self._path(oldpath), self._path(newpath)
        if old not in self._files:
            raise asyncssh.SFTPNoSuchFile("No such file")
        if posixpath.dirname(new) not in self._dirs or new in self._dirs:
            raise asyncssh.SFTPFailure("Failure")
        if new in self._files:
            self._total -= len(self._files[new])
        self._files[new] = self._files.pop(old)

    def posix_rename(self, oldpath: bytes, newpath: bytes) -> None:
        self.rename(oldpath, newpath)

    # -- refused ------------------------------------------------------------
    # Everything below would touch the real filesystem in the base class, and
    # none of it moves a file onto the host, so none of it is modelled.

    def readlink(self, path: bytes) -> bytes:
        raise asyncssh.SFTPNoSuchFile("No such file")

    def symlink(self, oldpath: bytes, newpath: bytes) -> None:
        raise asyncssh.SFTPPermissionDenied("Permission denied")

    def link(self, oldpath: bytes, newpath: bytes) -> None:
        raise asyncssh.SFTPPermissionDenied("Permission denied")

    def statvfs(self, path: bytes):
        raise asyncssh.SFTPOpUnsupported("statvfs not supported")

    def fstatvfs(self, file_obj: _Handle):
        raise asyncssh.SFTPOpUnsupported("fstatvfs not supported")

    def open56(self, path: bytes, desired_access: int, flags: int, attrs):
        raise asyncssh.SFTPOpUnsupported("Unsupported")

    def lock(self, file_obj: _Handle, offset: int, length: int, flags: int) -> None:
        raise asyncssh.SFTPOpUnsupported("Unsupported")

    def unlock(self, file_obj: _Handle, offset: int, length: int) -> None:
        raise asyncssh.SFTPOpUnsupported("Unsupported")

    async def exit(self) -> None:
        try:
            if self._session_id is not None:
                await session_manager.record_network_event(
                    self._session_id,
                    "ssh_file_transfer",
                    {"mode": self._source, "files": len(self._files)},
                )
        finally:
            self._done.set()
            waiting = _active_transfers.get(self._session_id or "", set())
            waiting.discard(self._done)
            if not waiting:
                _active_transfers.pop(self._session_id or "", None)
