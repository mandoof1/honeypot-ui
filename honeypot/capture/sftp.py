"""An in-memory SFTP and SCP endpoint that keeps what attackers upload.

The SSH emulator refused every subsystem request, so ``scp bot root@host:/tmp``
and ``sftp put`` failed at the first step, and a real OpenSSH server does not
refuse them. asyncssh routes both through one ``SFTPServer`` object — SCP is
implemented on top of the same file operations — so one class serves both.

The important property is what this does *not* do. asyncssh's default
``SFTPServer`` maps every operation onto the real local filesystem; an
override that missed one method would hand an attacker ``readlink``,
``symlink`` or ``remove`` against the container. So every filesystem method
is implemented here against the decoy's virtual filesystem, and the operations
there is no reason to model are refused outright. No path an attacker sends
is ever given to the operating system.

What a client sees is the same tree the shell shows (``core/vfs.py``), for
the same user: ``ls`` over SFTP and ``ls`` in the shell list the same names
with the same sizes and dates, a file can be downloaded if ``cat`` could read
it, and an upload appears in the shell of the same connection. It used to be
a separate, mostly empty tree of two dozen directories.

A file is recorded when it is closed — which asyncssh also does for every
handle still open when the connection drops, so an upload cut off halfway is
captured as far as it got.
"""

from __future__ import annotations

import asyncio
import errno
import logging
import os
import posixpath
import stat
import time
from dataclasses import dataclass
from typing import AsyncIterator, Optional

import asyncssh

from honeypot.core.session import session_manager
from honeypot.core.shell_state import ShellState, shell_states
from honeypot.core.vfs import Entry, FsView

logger = logging.getLogger(__name__)

#: Bounds per connection. An upload bigger than the engine's capture cap is
#: refused with an out-of-space error, which is what a full disk would say.
MAX_FILE_BYTES = 16 * 1024 * 1024
MAX_TOTAL_BYTES = 64 * 1024 * 1024
MAX_FILES = 64
MAX_DIRS = 256

#: SFTP/SCP channels still running, per session. When a connection drops,
#: asyncssh closes the channel's open handles in a task of its own, while the
#: SSH server schedules the session's end in another; nothing orders the two.
#: The session close waits on these so an interrupted upload is recorded
#: before the session is finalised, rather than whenever the race allows.
_active_transfers: dict[str, set[asyncio.Event]] = {}

_FILE_TYPES = {
    "dir": (asyncssh.FILEXFER_TYPE_DIRECTORY, stat.S_IFDIR),
    "file": (asyncssh.FILEXFER_TYPE_REGULAR, stat.S_IFREG),
    "link": (asyncssh.FILEXFER_TYPE_SYMLINK, stat.S_IFLNK),
    "char": (asyncssh.FILEXFER_TYPE_CHAR_DEVICE, stat.S_IFCHR),
    "block": (asyncssh.FILEXFER_TYPE_BLOCK_DEVICE, stat.S_IFBLK),
}


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
    #: Length of the file when it was opened for reading.
    size: int = 0

    def seek(self, offset: int, whence: int = os.SEEK_SET) -> int:
        """Answer asyncssh's sparse-file probe: the file is one run of data.

        An asyncssh client asks where the data and the holes are before it
        downloads, and the library's handler does that by seeking on the
        open file object. This is not a file; it says "data from here to the
        end", and nothing is ever sought on the real filesystem.
        """
        if whence == getattr(os, "SEEK_DATA", 3):
            if offset >= self.size:
                raise OSError(errno.ENXIO, "No data past the end")
            return offset
        if whence == getattr(os, "SEEK_HOLE", 4):
            return max(offset, self.size)
        return offset


class DecoySFTPServer(asyncssh.SFTPServer):
    def __init__(self, chan: asyncssh.SSHServerChannel) -> None:
        # No chroot: the base class's path mapping is never used, because no
        # method below falls through to it.
        super().__init__(chan)
        server = chan.get_connection().get_extra_info("honeypot_server")
        state = getattr(server, "state", None)
        self._session_id: Optional[str] = getattr(state, "session_id", None)
        is_root = bool(getattr(state, "is_root", False))
        username = getattr(state, "username", None) or ("root" if is_root else "user")
        command = chan.get_command() or ""
        self._source = "scp" if command.startswith("scp ") else "sftp"
        # The connection's shell state, so what is uploaded here is there
        # when a shell on the same connection looks, and the other way round.
        self._shell: ShellState = (
            shell_states.get(self._session_id) if self._session_id is not None else ShellState()
        )
        self._view = FsView(self._shell, username, is_root)
        self._home = self._shell.home if self._session_id is not None else "/root"
        #: Files this channel has written, complete or still arriving.
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

    def _is_dir(self, path: str) -> bool:
        return path not in self._files and self._view.is_dir(path)

    # -- attributes ---------------------------------------------------------

    def _uid(self, name: str) -> int:
        if name == "root":
            return 0
        return self._view.vfs.identity.uid_for(name) if name == self._view.username else 1000

    def _entry_attrs(self, entry: Entry) -> asyncssh.SFTPAttrs:
        kind, mode_bits = _FILE_TYPES[entry.kind]
        when = int(entry.when())
        return asyncssh.SFTPAttrs(
            type=kind, size=entry.size, uid=self._uid(entry.owner), gid=self._uid(entry.group),
            permissions=mode_bits | (entry.mode & 0o7777), atime=when, mtime=when, nlink=entry.nlink,
        )

    def _attrs(self, path: str, follow: bool = True) -> asyncssh.SFTPAttrs:
        if path in self._files:
            return asyncssh.SFTPAttrs(
                type=asyncssh.FILEXFER_TYPE_REGULAR, size=len(self._files[path]),
                uid=0, gid=0, permissions=stat.S_IFREG | 0o644,
                atime=int(time.time()), mtime=int(time.time()), nlink=1,
            )
        entry = self._view.lookup(path, follow=follow)
        if entry is None:
            raise asyncssh.SFTPNoSuchFile("No such file")
        return self._entry_attrs(entry)

    def stat(self, path: bytes) -> asyncssh.SFTPAttrs:
        return self._attrs(self._path(path))

    def lstat(self, path: bytes) -> asyncssh.SFTPAttrs:
        return self._attrs(self._path(path), follow=False)

    def fstat(self, file_obj: _Handle) -> asyncssh.SFTPAttrs:
        return self._attrs(file_obj.path)

    def setstat(self, path: bytes, attrs: asyncssh.SFTPAttrs) -> None:
        target = self._path(path)
        self._attrs(target)  # exists, or raises
        # `chmod +x` over SFTP, as scp -p and most upload scripts do.
        file = self._shell.files.get(target)
        if file is not None and attrs.permissions is not None:
            file.executable = bool(attrs.permissions & 0o111)

    def lsetstat(self, path: bytes, attrs: asyncssh.SFTPAttrs) -> None:
        self._attrs(self._path(path))

    def fsetstat(self, file_obj: _Handle, attrs: asyncssh.SFTPAttrs) -> None:
        return None

    def format_user(self, uid: Optional[int]) -> str:
        # The default looks the uid up in the real /etc/passwd.
        return "root" if not uid else self._view.username

    def format_group(self, gid: Optional[int]) -> str:
        return "root" if not gid else self._view.username

    # -- files --------------------------------------------------------------

    def open(self, path: bytes, pflags: int, attrs: asyncssh.SFTPAttrs) -> _Handle:
        target = self._path(path)
        if self._is_dir(target):
            raise asyncssh.SFTPFailure("Is a directory")
        writable = bool(pflags & (asyncssh.FXF_WRITE | asyncssh.FXF_APPEND))
        if not writable:
            if target in self._files:
                return _Handle(target, writable=False, size=len(self._files[target]))
            entry = self._view.lookup(target)
            if entry is None:
                raise asyncssh.SFTPNoSuchFile("No such file")
            if not self._view.can_read(entry) or entry.kind == "block":
                raise asyncssh.SFTPPermissionDenied("Permission denied")
            return _Handle(target, writable=False, size=len(self._view.read(target) or b""))

        if not self._is_dir(posixpath.dirname(target)):
            raise asyncssh.SFTPNoSuchFile("No such file")
        if not self._view.can_write(target):
            raise asyncssh.SFTPPermissionDenied("Permission denied")
        if target not in self._files:
            if len(self._files) >= MAX_FILES:
                raise asyncssh.SFTPPermissionDenied("Permission denied")
            self._files[target] = bytearray()
        elif pflags & asyncssh.FXF_TRUNC:
            self._total -= len(self._files[target])
            self._files[target] = bytearray()
        return _Handle(target, writable=True)

    def read(self, file_obj: _Handle, offset: int, size: int) -> bytes:
        content = self._files.get(file_obj.path)
        if content is None:
            content = self._view.read(file_obj.path) or b""
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
            # Now in the session record; put it in the shell's filesystem as
            # well, marked so the close of the session does not record the
            # same bytes a second time.
            if self._shell.write_content(file_obj.path, content, False, self._source):
                self._shell.recorded[file_obj.path] = len(content)

    def fsync(self, file_obj: _Handle) -> None:
        return None

    # -- directories --------------------------------------------------------

    async def scandir(self, path: bytes) -> AsyncIterator[asyncssh.SFTPName]:
        directory = self._path(path)
        if not self._is_dir(directory):
            raise asyncssh.SFTPNoSuchFile("No such file")
        listed = self._view.lookup(directory)
        if listed is not None and not self._view.can_list(listed):
            raise asyncssh.SFTPPermissionDenied("Permission denied")
        children = {name for name, _entry in self._view.listdir(directory)}
        children |= {posixpath.basename(p) for p in self._files if posixpath.dirname(p) == directory}
        for name in [".", ".."] + sorted(children):
            if name == ".":
                full = directory
            elif name == "..":
                full = posixpath.dirname(directory)
            else:
                full = posixpath.join(directory, name)
            try:
                attrs = self._attrs(full, follow=False)
            except asyncssh.SFTPNoSuchFile:
                continue
            entry = asyncssh.SFTPName(name.encode("utf-8", "surrogateescape"), b"", attrs)
            self.format_longname(entry)
            yield entry

    def mkdir(self, path: bytes, attrs: asyncssh.SFTPAttrs) -> None:
        target = self._path(path)
        if target in self._files or self._view.exists(target):
            raise asyncssh.SFTPFailure("File exists")
        if not self._is_dir(posixpath.dirname(target)):
            raise asyncssh.SFTPNoSuchFile("No such file")
        if not self._view.can_write(target) or not self._shell.add_dir(target):
            raise asyncssh.SFTPPermissionDenied("Permission denied")

    def rmdir(self, path: bytes) -> None:
        target = self._path(path)
        if not self._view.exists(target):
            raise asyncssh.SFTPNoSuchFile("No such file")
        if target not in self._shell.dirs:
            # Part of the host, not something this session made.
            raise asyncssh.SFTPPermissionDenied("Permission denied")
        if self._view.listdir(target) or any(posixpath.dirname(p) == target for p in self._files):
            raise asyncssh.SFTPFailure("Directory not empty")
        self._shell.remove_path(target, False)

    def remove(self, path: bytes) -> None:
        # The content was already recorded when it was closed; removing it
        # here changes what the attacker sees, not what was captured.
        target = self._path(path)
        if target in self._files:
            self._total -= len(self._files.pop(target))
            self._shell.remove_path(target, False)
            return
        entry = self._view.lookup(target, follow=False)
        if entry is None:
            raise asyncssh.SFTPNoSuchFile("No such file")
        if not entry.session:
            raise asyncssh.SFTPPermissionDenied("Permission denied")
        self._shell.remove_path(target, False)

    def rename(self, oldpath: bytes, newpath: bytes) -> None:
        old, new = self._path(oldpath), self._path(newpath)
        if old not in self._files:
            if self._view.exists(old):
                raise asyncssh.SFTPPermissionDenied("Permission denied")
            raise asyncssh.SFTPNoSuchFile("No such file")
        if not self._is_dir(posixpath.dirname(new)) or self._is_dir(new):
            raise asyncssh.SFTPFailure("Failure")
        if new in self._files:
            self._total -= len(self._files[new])
        self._files[new] = self._files.pop(old)
        # Keep the shell's copy under the same name.
        moved = self._shell.contents.get(old)
        if moved is not None:
            executable = bool(self._shell.files.get(old) and self._shell.files[old].executable)
            if self._shell.write_content(new, bytes(moved), False, self._source):
                self._shell.recorded[new] = len(moved)
                self._shell.files[new].executable = executable
            self._shell.remove_path(old, False)
            self._shell.removed.discard(old)

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
