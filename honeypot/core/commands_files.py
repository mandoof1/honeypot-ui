"""Commands that read the filesystem or rework text.

Every handler here reads through ``self.fs`` — the seeded tree with the
session's own files over it — so ``ls``, ``cat``, ``stat``, ``find``,
``head`` and ``grep <file>`` cannot disagree about what exists, how big it
is or when it changed. The text tools take their input from the files named
on the command line or, when there are none, from ``self.stdin``; that is
all a "pipe filter" is, and treating the two cases as one command is what
lets ``grep root /etc/passwd`` and ``cat /etc/passwd | grep root`` give the
same answer.

Patterns go through :mod:`honeypot.core.textfilters`, which is where the
protection against a hostile regular expression lives.
"""

from __future__ import annotations

import base64 as _base64
import hashlib
import posixpath
import time
import zlib
from datetime import datetime, timezone
from typing import Optional

from honeypot.core import textfilters
from honeypot.core.shell_state import resolve_path
from honeypot.core.textfilters import SafePattern, join_lines, split_lines
from honeypot.core.vfs import Entry

#: Entries one ``find`` walks before it stops.
MAX_FIND_VISITS = 4000


def to_text(data: bytes) -> str:
    """Bytes as shell text; undecodable bytes survive the round trip."""
    return data.decode("utf-8", errors="surrogateescape")


def to_bytes(text: str) -> bytes:
    return text.encode("utf-8", errors="surrogateescape")


def human_size(size: int, si: bool = False) -> str:
    """``ls -h`` / ``du -h`` style: 4.0K, 1.2M, 3.4G."""
    if size < 1024:
        return str(size)
    value = float(size)
    for unit in "KMGTP":
        value /= 1024
        if value < 1024:
            break
    if value < 10:
        # GNU rounds up to one decimal place.
        rounded = int(value * 10 + 0.999) / 10
        return f"{rounded:.1f}{unit}"
    return f"{int(value + 0.999)}{unit}"


def columns(names: list[str], width: int = 80) -> str:
    """Lay names out the way ``ls`` does on a terminal: down, then across."""
    if not names:
        return ""
    for rows in range(1, len(names) + 1):
        cols = [names[i:i + rows] for i in range(0, len(names), rows)]
        widths = [max(len(n) for n in col) + 2 for col in cols]
        if sum(widths) - 2 <= width or rows == len(names):
            lines = []
            for row in range(rows):
                cells = []
                for index, col in enumerate(cols):
                    if row < len(col):
                        last = index == len(cols) - 1 or row >= len(cols[index + 1])
                        cells.append(col[row] if last else col[row].ljust(widths[index]))
                lines.append("".join(cells))
            return "\n".join(lines) + "\n"
    return "\n".join(names) + "\n"


class FileCommands:
    """Mixin: filesystem and text commands. See the module docstring."""

    # -- shared helpers ----------------------------------------------------

    def _path(self, arg: str) -> str:
        return resolve_path(self.shell.cwd, arg, self.shell.home)

    def _tz(self):
        """The host's time zone, falling back to UTC where it is unknown."""
        try:
            from zoneinfo import ZoneInfo

            return ZoneInfo(self.identity.timezone)
        except Exception:
            return timezone.utc

    def _now(self) -> datetime:
        return datetime.now(self._tz())

    def _open(self, verb: str, arg: str) -> tuple[Optional[str], Optional[str]]:
        """A file's text, or the error the real command prints for it."""
        path = self._path(arg)
        entry = self.fs.lookup(path)
        if entry is None:
            return None, f"{verb}: {arg}: No such file or directory"
        if entry.kind == "dir":
            return None, f"{verb}: {arg}: Is a directory"
        if not self.fs.can_read(entry):
            return None, f"{verb}: {arg}: Permission denied"
        return to_text(self.fs.read(path) or b""), None

    def _inputs(self, verb: str, files: list[str]) -> tuple[list[tuple[str, str]], list[str]]:
        """(name, text) for every input, and the errors for those unreadable.

        With no files the one input is standard input, named ``-``; when
        there is no standard input either the list is empty and the caller
        knows the command would have waited at the terminal.
        """
        if not files:
            text = self._stdin_text()
            return ([("-", text)] if text is not None else []), []
        inputs, errors = [], []
        for name in files[:64]:
            if name == "-":
                inputs.append(("-", self._stdin_text() or ""))
                continue
            text, error = self._open(verb, name)
            if error:
                errors.append(error)
            else:
                inputs.append((name, text))
        return inputs, errors

    @staticmethod
    def _split_flags(args: list[str], with_value: str = "") -> tuple[str, dict[str, str], list[str]]:
        """Short flags, the values of those that take one, and the operands."""
        flags, values, operands = "", {}, []
        i = 0
        while i < len(args):
            arg = args[i]
            if arg == "--":
                operands.extend(args[i + 1:])
                break
            if arg.startswith("--") or not arg.startswith("-") or arg == "-":
                if not arg.startswith("--"):
                    operands.append(arg)
                i += 1
                continue
            cluster = arg[1:]
            for position, flag in enumerate(cluster):
                if flag in with_value:
                    rest = cluster[position + 1:]
                    if rest:
                        values[flag] = rest
                    elif i + 1 < len(args):
                        values[flag] = args[i + 1]
                        i += 1
                    break
                flags += flag
            i += 1
        return flags, values, operands

    # -- ls ----------------------------------------------------------------

    def _ls_time(self, when: float) -> str:
        stamp = datetime.fromtimestamp(when, self._tz())
        # ls shows the year instead of the time once a file is six months old.
        if abs(time.time() - when) > 182 * 86400:
            return stamp.strftime("%b %e  %Y")
        return stamp.strftime("%b %e %H:%M")

    def _ls_long(self, rows: list[tuple[str, Entry]], human: bool, numeric: bool) -> list[str]:
        cells = []
        for name, entry in rows:
            if entry.kind in ("char", "block"):
                size = f"{entry.rdev[0]}, {entry.rdev[1]:>3}"
            elif human:
                size = human_size(entry.size)
            else:
                size = str(entry.size)
            shown = name + (f" -> {entry.target}" if entry.kind == "link" else "")
            owner = entry.owner if not numeric else str(self._uid_of(entry.owner))
            group = entry.group if not numeric else str(self._uid_of(entry.group))
            cells.append((entry.mode_string(), str(entry.nlink), owner, group, size,
                          self._ls_time(entry.when()), shown))
        widths = [max((len(c[i]) for c in cells), default=0) for i in range(5)]
        return [
            f"{c[0]} {c[1]:>{widths[1]}} {c[2]:<{widths[2]}} {c[3]:<{widths[3]}} "
            f"{c[4]:>{widths[4]}} {c[5]} {c[6]}"
            for c in cells
        ]

    def _uid_of(self, name: str) -> int:
        if name == "root":
            return 0
        for account, uid, _home, _shell in self._accounts():
            if account == name:
                return uid
        return {"www-data": 33, "syslog": 104, "mysql": 112, "shadow": 42, "adm": 4,
                "tty": 5, "disk": 6, "crontab": 105, "ssl-cert": 116, "ftp": 113,
                "systemd-journal": 101}.get(name, 1000)

    @staticmethod
    def _ls_key(name: str) -> tuple[str, str]:
        # The en_US collation Ubuntu ships with: case and leading dots do
        # not decide the order.
        return name.lstrip(".").lower(), name

    def _cmd_ls(self, args, shell, username, is_root):
        flags, _values, operands = self._split_flags(args)
        long = "l" in flags or "n" in flags or "g" in flags
        show_all = "a" in flags
        almost_all = "A" in flags
        one_per_line = "1" in flags or not self.terminal
        errors: list[str] = []
        files: list[tuple[str, Entry]] = []
        directories: list[tuple[str, str, Entry]] = []
        for operand in operands or ["."]:
            path = self._path(operand)
            entry = self.fs.lookup(path, follow=not long or operand.endswith("/"))
            if entry is None:
                errors.append(f"ls: cannot access '{operand}': No such file or directory")
            elif entry.kind == "dir" and "d" not in flags:
                directories.append((operand, path, entry))
            else:
                files.append((operand, entry))

        def render(rows: list[tuple[str, Entry]]) -> str:
            if "t" in flags:
                rows = sorted(rows, key=lambda r: -r[1].when())
            elif "S" in flags:
                rows = sorted(rows, key=lambda r: -r[1].size)
            if "r" in flags:
                rows = rows[::-1]
            if long:
                return "".join(line + "\n" for line in self._ls_long(rows, "h" in flags, "n" in flags))
            names = [name + ("/" if "F" in flags and entry.kind == "dir" else "") for name, entry in rows]
            return "".join(n + "\n" for n in names) if one_per_line else columns(names)

        sections: list[str] = []
        if files:
            sections.append(render(sorted(files, key=lambda r: self._ls_key(r[0]))))
        heading = len(directories) + len(files) + len(errors) > 1
        for operand, path, entry in directories:
            if not self.fs.can_list(entry):
                errors.append(f"ls: cannot open directory '{operand}': Permission denied")
                continue
            rows = sorted(self.fs.listdir(path), key=lambda r: self._ls_key(r[0]))
            if not (show_all or almost_all):
                rows = [r for r in rows if not r[0].startswith(".")]
            if show_all:
                parent = self.fs.lookup(posixpath.dirname(path)) or entry
                rows = [(".", entry), ("..", parent)] + rows
            body = ""
            if long:
                blocks = sum(((e.size + 4095) // 4096) * 4 for _n, e in rows if e.kind in ("file", "dir"))
                body = f"total {blocks}\n"
            body += render(rows)
            sections.append((f"{operand}:\n" if heading else "") + body)
        text = "".join(e + "\n" for e in errors) + "\n".join(sections)
        return text, 2 if errors else 0

    def _cmd_dir(self, args, shell, username, is_root):
        return self._cmd_ls(args, shell, username, is_root)

    def _cmd_vdir(self, args, shell, username, is_root):
        return self._cmd_ls(["-l"] + list(args), shell, username, is_root)

    def _cmd_ll(self, args, shell, username, is_root):
        return self._cmd_ls(["-alF"] + list(args), shell, username, is_root)

    # -- reading files -----------------------------------------------------

    def _cmd_cat(self, args, shell, username, is_root):
        flags, _values, files = self._split_flags(args)
        inputs, errors = self._inputs("cat", files)
        if not inputs and not errors:
            return None, 0  # cat with nothing to read waits at the terminal
        out: list[str] = []
        size = 0
        for _name, text in inputs:
            # Stop reading once there is more than will be sent: `cat f f f …`
            # with thousands of arguments must not build it all first.
            if size > textfilters.MAX_OUTPUT_CHARS:
                break
            out.append(text)
            size += len(text)
        text = "".join(out)
        if "n" in flags:
            text = "".join(f"{i + 1:6d}\t{line}\n" for i, line in enumerate(split_lines(text)))
        if errors:
            text += "".join(e + "\n" for e in errors)
        return text, 1 if errors else 0

    def _cmd_tac(self, args, shell, username, is_root):
        inputs, errors = self._inputs("tac", [a for a in args if not a.startswith("-")])
        if not inputs and not errors:
            return None, 0
        lines: list[str] = []
        for _name, text in inputs:
            lines.extend(split_lines(text)[::-1])
        return join_lines(lines) + "".join(e + "\n" for e in errors), 1 if errors else 0

    def _count(self, args: list[str], default: int = 10) -> tuple[int, Optional[int], list[str], bool]:
        """Parse ``head``/``tail`` options: (lines, bytes, files, from-start)."""
        lines, nbytes, files, from_start = default, None, [], False
        i = 0
        while i < len(args):
            arg = args[i]
            value = None
            if arg in ("-n", "-c") and i + 1 < len(args):
                value, kind = args[i + 1], arg[1]
                i += 1
            elif arg[:2] in ("-n", "-c") and len(arg) > 2:
                value, kind = arg[2:], arg[1]
            elif arg.startswith("-") and arg[1:].isdigit():
                value, kind = arg[1:], "n"
            elif arg.startswith("-") and len(arg) > 1:
                i += 1
                continue
            else:
                files.append(arg)
                i += 1
                continue
            from_start = value.startswith("+")
            try:
                number = abs(int(value.lstrip("+")[:12]))
            except ValueError:
                number = default
            if kind == "n":
                lines = number
            else:
                nbytes = number
            i += 1
        return lines, nbytes, files, from_start

    def _head_tail(self, args, verb: str):
        count, nbytes, files, from_start = self._count(args)
        inputs, errors = self._inputs(verb, files)
        if not inputs and not errors:
            return None, 0
        errors = [e.replace(f"{verb}: ", f"{verb}: cannot open '", 1).replace(": No such", "' for reading: No such", 1)
                  if ": No such" in e else e for e in errors]
        out: list[str] = []
        for name, text in inputs:
            if len(inputs) + len(errors) > 1:
                out.append(f"==> {'standard input' if name == '-' else name} <==\n")
            if nbytes is not None:
                raw = to_bytes(text)
                out.append(to_text(raw[:nbytes] if verb == "head" else raw[len(raw) - nbytes:] if nbytes else b""))
                continue
            lines = text.split("\n")
            trailing = lines and lines[-1] == ""
            if trailing:
                lines.pop()
            if verb == "head":
                chosen = lines[:count]
            elif from_start:
                chosen = lines[max(0, count - 1):]
            else:
                chosen = lines[len(lines) - count:] if count else []
            out.append("\n".join(chosen) + ("\n" if chosen and (trailing or len(chosen) < len(lines) or verb == "head") else ""))
        return "".join(out) + "".join(e + "\n" for e in errors), 1 if errors else 0

    def _cmd_head(self, args, shell, username, is_root):
        return self._head_tail(args, "head")

    def _cmd_tail(self, args, shell, username, is_root):
        return self._head_tail([a for a in args if a not in ("-f", "-F", "--follow")], "tail")

    def _cmd_less(self, args, shell, username, is_root):
        return self._cmd_cat([a for a in args if not a.startswith("-")], shell, username, is_root)

    def _cmd_more(self, args, shell, username, is_root):
        return self._cmd_less(args, shell, username, is_root)

    def _cmd_wc(self, args, shell, username, is_root):
        flags, _values, files = self._split_flags(args)
        inputs, errors = self._inputs("wc", files)
        if not inputs and not errors:
            return None, 0
        rows = []
        for name, text in inputs:
            counts = (text.count("\n"), len(text.split()), len(to_bytes(text)))
            rows.append((counts, "" if name == "-" and not files else name))
        if len(rows) > 1:
            rows.append((tuple(sum(r[0][i] for r in rows) for i in range(3)), "total"))
        picked = [i for i, flag in enumerate("lwc") if flag in flags] or [0, 1, 2]
        if "m" in flags and 2 not in picked:
            picked.append(2)
        # wc pads to the widest number when it knows the sizes up front, and
        # to seven columns when it is reading a pipe.
        width = 7 if not files else max(len(str(c)) for counts, _n in rows for c in counts)
        lines = []
        for counts, name in rows:
            if len(picked) == 1 and len(rows) == 1 and not name:
                lines.append(str(counts[picked[0]]))
            elif len(picked) == 1:
                lines.append(f"{counts[picked[0]]} {name}".rstrip())
            else:
                lines.append((" ".join(f"{counts[i]:>{width}}" for i in picked) + f" {name}").rstrip())
        return "".join(l + "\n" for l in lines) + "".join(e + "\n" for e in errors), 1 if errors else 0

    def _cmd_stat(self, args, shell, username, is_root):
        out, code = [], 0
        for arg in (a for a in args if not a.startswith("-")):
            path = self._path(arg)
            entry = self.fs.lookup(path, follow=False)
            if entry is None:
                out.append(f"stat: cannot stat '{arg}': No such file or directory")
                code = 1
                continue
            kind = {"dir": "directory", "file": "regular file" if entry.size else "regular empty file",
                    "link": "symbolic link", "char": "character special file", "block": "block special file"}[entry.kind]
            inode = 131072 + zlib.crc32(f"{self.identity.seed}:{path}".encode()) % 2_400_000
            when = datetime.fromtimestamp(entry.when(), self._tz()).strftime("%Y-%m-%d %H:%M:%S.000000000 %z")
            shown = f"{arg} -> {entry.target}" if entry.kind == "link" else arg
            out.append(
                f"  File: {shown}\n"
                f"  Size: {entry.size:<10}\tBlocks: {((entry.size + 4095) // 4096) * 8:<10} IO Block: 4096   {kind}\n"
                f"Device: fc01h/64513d\tInode: {inode:<11} Links: {entry.nlink}\n"
                f"Access: ({entry.mode & 0o7777:04o}/{entry.mode_string()})  "
                f"Uid: ({self._uid_of(entry.owner):5d}/{entry.owner:>8})   Gid: ({self._uid_of(entry.group):5d}/{entry.group:>8})\n"
                f"Access: {when}\nModify: {when}\nChange: {when}\n Birth: -"
            )
        if not out:
            return "stat: missing operand\nTry 'stat --help' for more information.\n", 1
        return "\n".join(out) + "\n", code

    def _cmd_file(self, args, shell, username, is_root):
        out = []
        for arg in (a for a in args if not a.startswith("-")):
            path = self._path(arg)
            entry = self.fs.lookup(path, follow=False)
            if entry is None:
                out.append(f"{arg}: cannot open `{arg}' (No such file or directory)")
            elif entry.kind == "dir":
                out.append(f"{arg}: directory")
            elif entry.kind == "link":
                out.append(f"{arg}: symbolic link to {entry.target}")
            elif entry.kind in ("char", "block"):
                out.append(f"{arg}: {'character' if entry.kind == 'char' else 'block'} special ({entry.rdev[0]}/{entry.rdev[1]})")
            elif entry.size == 0:
                out.append(f"{arg}: empty")
            else:
                head = (self.fs.read(path, 64) or b"")[:64]
                if head.startswith(b"\x7fELF"):
                    out.append(f"{arg}: ELF 64-bit LSB shared object, x86-64, version 1 (SYSV), dynamically linked, "
                               "interpreter /lib64/ld-linux-x86-64.so.2, for GNU/Linux 3.2.0, stripped")
                elif head.startswith(b"#!"):
                    interpreter = head.split(b"\n", 1)[0][2:].decode("ascii", "replace").strip()
                    out.append(f"{arg}: {posixpath.basename(interpreter.split()[0]) if interpreter else 'script'} script, ASCII text executable")
                elif all(32 <= b < 127 or b in (9, 10, 13) for b in head):
                    out.append(f"{arg}: ASCII text")
                else:
                    out.append(f"{arg}: data")
        return "\n".join(out) + ("\n" if out else ""), 0

    def _cmd_readlink(self, args, shell, username, is_root):
        for arg in (a for a in args if not a.startswith("-")):
            entry = self.fs.lookup(self._path(arg), follow=False)
            if entry is not None and entry.kind == "link":
                return entry.target + "\n", 0
            if "-f" in args and entry is not None:
                return self.fs.vfs.canonical(self._path(arg)) + "\n", 0
        return "", 1

    def _cmd_realpath(self, args, shell, username, is_root):
        out, code = [], 0
        for arg in (a for a in args if not a.startswith("-")):
            path = self.fs.vfs.canonical(self._path(arg))
            if self.fs.exists(path):
                out.append(path)
            else:
                out.append(f"realpath: {arg}: No such file or directory")
                code = 1
        return "\n".join(out) + ("\n" if out else ""), code

    def _cmd_basename(self, args, shell, username, is_root):
        if not args:
            return "basename: missing operand\n", 1
        name = posixpath.basename(args[0].rstrip("/")) or "/"
        if len(args) > 1 and name.endswith(args[1]) and name != args[1]:
            name = name[: -len(args[1])]
        return name + "\n", 0

    def _cmd_dirname(self, args, shell, username, is_root):
        if not args:
            return "dirname: missing operand\n", 1
        return (posixpath.dirname(args[0].rstrip("/")) or ("/" if args[0].startswith("/") else ".")) + "\n", 0

    # -- find and du -------------------------------------------------------

    def _walk(self, top: str, shown: str, max_depth: int):
        """Yield (shown path, real path, entry, depth), parents first."""
        budget = MAX_FIND_VISITS
        stack = [(shown, top, 0)]
        while stack and budget > 0:
            label, path, depth = stack.pop()
            entry = self.fs.lookup(path, follow=depth == 0)
            if entry is None:
                continue
            budget -= 1
            yield label, path, entry, depth
            if entry.kind == "dir" and depth < max_depth and self.fs.can_list(entry):
                children = self.fs.listdir(path)
                for name, _child in reversed(children):
                    stack.append((label.rstrip("/") + "/" + name, posixpath.join(path, name), depth + 1))

    def _cmd_find(self, args, shell, username, is_root):
        from honeypot.core.shell_syntax import glob_match

        tops, i = [], 0
        while i < len(args) and not args[i].startswith(("-", "(", "!")):
            tops.append(args[i])
            i += 1
        name = kind = None
        insensitive = False
        max_depth = 64
        setuid = False
        while i < len(args):
            arg = args[i]
            value = args[i + 1] if i + 1 < len(args) else ""
            if arg in ("-name", "-iname"):
                name, insensitive = value, arg == "-iname"
                i += 1
            elif arg == "-type":
                kind = value[:1]
                i += 1
            elif arg == "-maxdepth":
                try:
                    max_depth = max(0, int(value[:4]))
                except ValueError:
                    pass
                i += 1
            elif arg == "-perm":
                setuid = "4000" in value or "u=s" in value or "u+s" in value or "6000" in value
                i += 1
            elif arg in ("-exec", "-execdir", "-ok"):
                while i < len(args) and args[i] not in (";", "+"):
                    i += 1
            elif arg in ("-mtime", "-mmin", "-atime", "-ctime", "-size", "-user", "-group",
                         "-newer", "-path", "-regex", "-uid", "-gid", "-mindepth"):
                i += 1
            i += 1
        out, errors = [], []
        for top in tops or ["."]:
            start = self._path(top)
            if not self.fs.exists(start):
                errors.append(f"find: ‘{top}’: No such file or directory")
                continue
            for label, _path, entry, _depth in self._walk(start, top, max_depth):
                base = posixpath.basename(label.rstrip("/")) or label
                if name is not None:
                    pattern, candidate = (name.lower(), base.lower()) if insensitive else (name, base)
                    if not glob_match(pattern, candidate):
                        continue
                if kind and {"f": "file", "d": "dir", "l": "link", "c": "char", "b": "block"}.get(kind) != entry.kind:
                    continue
                if setuid and not entry.mode & 0o4000:
                    continue
                out.append(label)
                if len(out) >= MAX_FIND_VISITS:
                    break
        return join_lines(out) + "".join(e + "\n" for e in errors), 1 if errors else 0

    def _cmd_du(self, args, shell, username, is_root):
        flags, _values, operands = self._split_flags(args, "d")
        out = []
        for operand in operands or ["."]:
            start = self._path(operand)
            if not self.fs.exists(start):
                out.append(f"du: cannot access '{operand}': No such file or directory")
                continue
            total = sum(((entry.size + 4095) // 4096) * 4 for _l, _p, entry, _d in self._walk(start, operand, 64))
            out.append(f"{human_size(total * 1024) if 'h' in flags else total}\t{operand}")
        return "\n".join(out) + ("\n" if out else ""), 0

    # -- pattern tools -----------------------------------------------------

    def _grep(self, args, extended: bool, fixed: bool):
        flags, values, operands = self._split_flags(args, "emABCf")
        if "E" in flags:
            extended = True
        if "F" in flags:
            fixed = True
        pattern_text = values.get("e")
        if pattern_text is None:
            if not operands:
                return "Usage: grep [OPTION]... PATTERNS [FILE]...\nTry 'grep --help' for more information.\n", 2
            pattern_text, operands = operands[0], operands[1:]
        pattern = SafePattern(
            pattern_text, self.budget, extended=extended, fixed=fixed,
            ignore_case="i" in flags, whole_word="w" in flags,
        )
        recursive = "r" in flags or "R" in flags
        if recursive:
            expanded = []
            for operand in operands or ["."]:
                start = self._path(operand)
                for label, _p, entry, _d in self._walk(start, operand, 8):
                    if entry.kind == "file" and len(expanded) < 256:
                        expanded.append(label)
            operands = expanded
            if not operands:
                return "", 1
        inputs, errors = self._inputs("grep", operands)
        if not inputs and not errors:
            return None, 0
        if "s" in flags:
            errors = []
        show_names = (len(inputs) + len(errors) > 1 or recursive or "H" in flags) and "h" not in flags
        try:
            limit = int(values.get("m", "0")[:9] or 0)
        except ValueError:
            limit = 0
        invert = "v" in flags
        out: list[str] = []
        matched_any = False
        for name, text in inputs:
            count = 0
            for number, line in enumerate(split_lines(text), start=1):
                span = pattern.search(line)
                if (span is not None) == invert:
                    continue
                count += 1
                matched_any = True
                if "c" not in flags and "q" not in flags and "l" not in flags:
                    shown = line[span[0]:span[1]] if ("o" in flags and span) else line
                    prefix = (f"{name}:" if show_names else "") + (f"{number}:" if "n" in flags else "")
                    out.append(prefix + shown)
                if limit and count >= limit:
                    break
            if "c" in flags:
                out.append((f"{name}:" if show_names else "") + str(count))
            elif "l" in flags and count:
                out.append(name)
        if "q" in flags:
            return "", 0 if matched_any else 1
        text = join_lines(out) + "".join(e + "\n" for e in errors)
        return text, 0 if matched_any else (2 if errors else 1)

    def _cmd_grep(self, args, shell, username, is_root):
        return self._grep(args, extended=False, fixed=False)

    def _cmd_egrep(self, args, shell, username, is_root):
        return self._grep(args, extended=True, fixed=False)

    def _cmd_fgrep(self, args, shell, username, is_root):
        return self._grep(args, extended=False, fixed=True)

    def _cmd_sed(self, args, shell, username, is_root):
        scripts: list[str] = []
        files: list[str] = []
        quiet = extended = in_place = False
        i = 0
        while i < len(args):
            arg = args[i]
            if arg == "-e" and i + 1 < len(args):
                scripts.append(args[i + 1])
                i += 1
            elif arg in ("-n", "--quiet", "--silent"):
                quiet = True
            elif arg in ("-E", "-r", "--regexp-extended"):
                extended = True
            elif arg.startswith("-i") or arg == "--in-place":
                in_place = True
            elif arg.startswith("-") and len(arg) > 1 and not arg.startswith("--"):
                quiet = quiet or "n" in arg
                extended = extended or "E" in arg or "r" in arg
                in_place = in_place or "i" in arg
            elif not scripts and not arg.startswith("-"):
                scripts.append(arg)
            else:
                files.append(arg)
            i += 1
        if not scripts:
            return "Usage: sed [OPTION]... {script-only-if-no-other-script} [input-file]...\n", 1
        program = textfilters.SedProgram(scripts, self.budget, extended, quiet)
        inputs, errors = self._inputs("sed", files)
        errors = [e.replace("sed: ", "sed: can't read ", 1) for e in errors]
        if not inputs and not errors:
            return None, 0
        if in_place:
            # Editing in place prints nothing. The file is left as it was:
            # rewriting captured content here would change the evidence.
            return "".join(e + "\n" for e in errors), 2 if errors else 0
        lines: list[str] = []
        for _name, text in inputs:
            lines.extend(split_lines(text))
        return join_lines(program.run(lines[:textfilters.MAX_LINES])) + "".join(e + "\n" for e in errors), 2 if errors else 0

    def _cmd_awk(self, args, shell, username, is_root):
        separator = None
        program_text = None
        files: list[str] = []
        i = 0
        while i < len(args):
            arg = args[i]
            if arg == "-F" and i + 1 < len(args):
                separator = args[i + 1]
                i += 1
            elif arg.startswith("-F") and len(arg) > 2:
                separator = arg[2:]
            elif arg == "-v" and i + 1 < len(args):
                i += 1
            elif arg.startswith("-") and len(arg) > 1 and program_text is None:
                pass
            elif program_text is None:
                program_text = arg
            else:
                files.append(arg)
            i += 1
        if program_text is None:
            return "Usage: mawk [Options] [Program] [file ...]\n", 2
        program = textfilters.AwkProgram(program_text, separator, self.budget)
        only_begin = program.supported and all(rule[0][0] == "BEGIN" for rule in program.rules)
        inputs, errors = ([], []) if only_begin else self._inputs("awk", files)
        errors = [e.replace("awk: ", "awk: cannot open ", 1).replace(": No such", " (No such", 1) + ")"
                  if ": No such" in e else e for e in errors]
        if not inputs and not errors and not only_begin:
            return None, 0
        lines: list[str] = []
        for _name, text in inputs:
            lines.extend(split_lines(text))
        produced = program.run(lines)
        # A program outside the supported subset prints nothing: silence is
        # a possible answer from awk, an invented line is not.
        return join_lines(produced or []) + "".join(e + "\n" for e in errors), 2 if errors else 0

    def _cmd_mawk(self, args, shell, username, is_root):
        return self._cmd_awk(args, shell, username, is_root)

    def _cmd_gawk(self, args, shell, username, is_root):
        return self._cmd_awk(args, shell, username, is_root)

    def _cmd_cut(self, args, shell, username, is_root):
        files = []
        skip = False
        for index, arg in enumerate(args):
            if skip:
                skip = False
            elif arg in ("-d", "-f", "-c", "-b"):
                skip = True
            elif not arg.startswith("-"):
                files.append(arg)
        inputs, errors = self._inputs("cut", files)
        if not inputs and not errors:
            return None, 0
        lines: list[str] = []
        for _name, text in inputs:
            lines.extend(split_lines(text))
        produced = textfilters.cut(list(args), lines)
        if produced is None:
            return "cut: you must specify a list of bytes, characters, or fields\nTry 'cut --help' for more information.\n", 1
        return join_lines(produced) + "".join(e + "\n" for e in errors), 1 if errors else 0

    def _cmd_tr(self, args, shell, username, is_root):
        text = self._stdin_text()
        if text is None:
            return None, 0
        if not [a for a in args if not (a.startswith("-") and len(a) > 1)]:
            return "tr: missing operand\nTry 'tr --help' for more information.\n", 1
        return textfilters.tr(list(args), text[:textfilters.MAX_OUTPUT_CHARS]), 0

    def _lines_of(self, verb: str, args) -> tuple[Optional[list[str]], list[str]]:
        inputs, errors = self._inputs(verb, [a for a in args if not a.startswith("-")])
        if not inputs and not errors:
            return None, []
        lines: list[str] = []
        for _name, text in inputs:
            lines.extend(split_lines(text))
        return lines, errors

    def _cmd_sort(self, args, shell, username, is_root):
        flags, _values, operands = self._split_flags(args, "kto")
        lines, errors = self._lines_of("sort", operands)
        if lines is None:
            return None, 0
        if "n" in flags:
            def key(line: str):
                head = line.strip().split(None, 1)[0] if line.strip() else ""
                try:
                    return (0, float(head[:32]))
                except ValueError:
                    return (0, 0.0)
            lines = sorted(lines, key=key)
        else:
            lines = sorted(lines)
        if "r" in flags:
            lines = lines[::-1]
        if "u" in flags:
            lines = [l for i, l in enumerate(lines) if i == 0 or l != lines[i - 1]]
        return join_lines(lines) + "".join(e + "\n" for e in errors), 2 if errors else 0

    def _cmd_uniq(self, args, shell, username, is_root):
        flags, _values, operands = self._split_flags(args)
        lines, errors = self._lines_of("uniq", operands)
        if lines is None:
            return None, 0
        groups: list[list] = []
        for line in lines:
            if groups and groups[-1][0] == line:
                groups[-1][1] += 1
            else:
                groups.append([line, 1])
        if "d" in flags:
            groups = [g for g in groups if g[1] > 1]
        if "u" in flags:
            groups = [g for g in groups if g[1] == 1]
        out = [f"{count:7d} {line}" if "c" in flags else line for line, count in groups]
        return join_lines(out) + "".join(e + "\n" for e in errors), 1 if errors else 0

    def _cmd_rev(self, args, shell, username, is_root):
        lines, errors = self._lines_of("rev", args)
        if lines is None:
            return None, 0
        return join_lines([l[::-1] for l in lines]), 0

    def _cmd_nl(self, args, shell, username, is_root):
        lines, errors = self._lines_of("nl", args)
        if lines is None:
            return None, 0
        return join_lines([f"{i + 1:6d}\t{line}" for i, line in enumerate(lines)]), 0

    def _cmd_tee(self, args, shell, username, is_root):
        # The copies to the named files are made by the capture layer; this
        # is the copy that carries on down the pipe.
        return self._stdin_text() or "", 0

    def _cmd_xargs(self, args, shell, username, is_root):
        text = self._stdin_text()
        command = [a for a in args if not a.startswith("-")]
        if text is None:
            return None, 0
        words = text.split()[:256]
        if not command or command[0] == "echo":
            return " ".join(command[1:] + words) + "\n", 0
        if not self.can_run(command[0]) or command[0] in ("xargs", "sh", "bash"):
            return "", 0
        return self.run(command + words, shell, username, is_root, None)

    def _cmd_strings(self, args, shell, username, is_root):
        inputs, errors = self._inputs("strings", [a for a in args if not a.startswith("-")])
        if not inputs and not errors:
            return None, 0
        out: list[str] = []
        for _name, text in inputs:
            run = []
            for ch in text[:textfilters.MAX_OUTPUT_CHARS]:
                if " " <= ch <= "~" or ch == "\t":
                    run.append(ch)
                    continue
                if len(run) >= 4:
                    out.append("".join(run))
                run = []
            if len(run) >= 4:
                out.append("".join(run))
        return join_lines(out) + "".join(e + "\n" for e in errors), 1 if errors else 0

    # -- encoders and digests ----------------------------------------------

    def _one_input(self, verb: str, args) -> tuple[Optional[bytes], Optional[str], str]:
        """Bytes of the single input a digest-style tool reads, and its name."""
        files = [a for a in args if not a.startswith("-")]
        if not files:
            return self.stdin, None, "-"
        text, error = self._open(verb, files[0])
        return (to_bytes(text) if text is not None else None), error, files[0]

    def _cmd_base64(self, args, shell, username, is_root):
        data, error, _name = self._one_input("base64", args)
        if error:
            return error + "\n", 1
        if data is None:
            return None, 0
        if any(a in ("-d", "--decode", "-D") or (a.startswith("-") and not a.startswith("--") and "d" in a) for a in args):
            cleaned = b"".join(data.split())
            try:
                return to_text(_base64.b64decode(cleaned + b"=" * (-len(cleaned) % 4))), 0
            except Exception:
                return "base64: invalid input\n", 1
        encoded = _base64.b64encode(data[:192 * 1024]).decode("ascii")
        if any(a in ("-w0", "--wrap=0") for a in args) or ("-w" in args and "0" in args):
            return encoded + "\n", 0
        return "".join(encoded[i:i + 76] + "\n" for i in range(0, len(encoded), 76)), 0

    def _digest(self, verb: str, algorithm, args):
        files = [a for a in args if not a.startswith("-")]
        if not files:
            if self.stdin is None:
                return None, 0
            return f"{algorithm(self.stdin).hexdigest()}  -\n", 0
        out, code = [], 0
        for name in files[:32]:
            text, error = self._open(verb, name)
            if error:
                out.append(error)
                code = 1
            else:
                out.append(f"{algorithm(to_bytes(text)).hexdigest()}  {name}")
        return "\n".join(out) + "\n", code

    def _cmd_md5sum(self, args, shell, username, is_root):
        return self._digest("md5sum", hashlib.md5, args)

    def _cmd_sha1sum(self, args, shell, username, is_root):
        return self._digest("sha1sum", hashlib.sha1, args)

    def _cmd_sha256sum(self, args, shell, username, is_root):
        return self._digest("sha256sum", hashlib.sha256, args)

    def _cmd_sha512sum(self, args, shell, username, is_root):
        return self._digest("sha512sum", hashlib.sha512, args)

    def _cmd_dd(self, args, shell, username, is_root):
        options = dict(a.split("=", 1) for a in args if "=" in a)

        def number(text: str, default: int) -> int:
            scale = {"k": 1024, "K": 1024, "M": 1024 ** 2, "G": 1024 ** 3}.get(text[-1:], 1)
            try:
                return int(text.rstrip("kKMGB")[:9]) * scale
            except ValueError:
                return default

        block = max(1, number(options.get("bs", "512"), 512))
        count = number(options["count"], 0) if "count" in options else None
        skip = number(options.get("skip", "0"), 0)
        if "if" in options:
            text, error = self._open("dd", options["if"])
            if error:
                return error.replace("dd: ", "dd: failed to open '", 1).replace(": No such", "': No such", 1) + "\n", 1
            data = to_bytes(text)
        else:
            data = self.stdin or b""
        data = data[skip * block:]
        if count is not None:
            data = data[:count * block]
        full, partial = divmod(len(data), block)
        stats = (
            f"{full}+{1 if partial else 0} records in\n{full}+{1 if partial else 0} records out\n"
            f"{len(data)} bytes copied, {0.0001 + len(data) / 9e8:.6g} s, {max(1, len(data) // 1024)} kB/s\n"
        )
        # Without of=, the data goes to stdout and the statistics to stderr;
        # both arrive on the one channel, data first.
        if "of" in options:
            return stats, 0
        return to_text(data) + stats, 0

    def _cmd_seq(self, args, shell, username, is_root):
        try:
            numbers = [int(a[:9]) for a in args if not a.startswith("-") or a[1:].isdigit()]
        except ValueError:
            return f"seq: invalid floating point argument: ‘{args[0]}’\n", 1
        if not numbers:
            return "seq: missing operand\n", 1
        first, step, last = (1, 1, numbers[0]) if len(numbers) == 1 else (
            (numbers[0], 1, numbers[1]) if len(numbers) == 2 else (numbers[0], numbers[1] or 1, numbers[2]))
        out = []
        value = first
        while (value <= last if step > 0 else value >= last) and len(out) < 10000:
            out.append(str(value))
            value += step
        return join_lines(out), 0

    def _cmd_expr(self, args, shell, username, is_root):
        from honeypot.core.shell_syntax import evaluate_arithmetic

        if len(args) == 3 and args[1] in ("=", "!="):
            result = int((args[0] == args[2]) == (args[1] == "="))
            return f"{result}\n", 0 if result else 1
        value = evaluate_arithmetic(" ".join(args), lambda _name: None)
        if value is None:
            return "expr: syntax error\n", 2
        return f"{value}\n", 0 if value else 1

    # -- archives ----------------------------------------------------------

    def _archive(self, verb: str, args):
        files = [a for a in args if not a.startswith("-") and "=" not in a]
        if verb == "tar":
            flags = args[0] if args else ""
            # The first operand after the options is the archive itself.
            files = [a for a in args[1:] if not a.startswith("-")][:1] if "f" in flags else []
        for name in files:
            if not self.fs.exists(self._path(name)):
                if verb == "tar":
                    return (f"tar: {name}: Cannot open: No such file or directory\n"
                            "tar: Error is not recoverable: exiting now\n"), 2
                return f"{verb}: {name}: No such file or directory\n", 1
        return "", 0

    def _cmd_tar(self, args, shell, username, is_root):
        return self._archive("tar", args)

    def _cmd_gzip(self, args, shell, username, is_root):
        return self._archive("gzip", args)

    def _cmd_gunzip(self, args, shell, username, is_root):
        return self._archive("gzip", args)

    def _cmd_unzip(self, args, shell, username, is_root):
        return self._archive("unzip", args)

    def _cmd_bzip2(self, args, shell, username, is_root):
        return self._archive("bzip2", args)

    def _cmd_xz(self, args, shell, username, is_root):
        return self._archive("xz", args)
