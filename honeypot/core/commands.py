"""A read-only emulation of the commands an SSH visitor runs.

Nothing here executes anything. Each handler returns the text a real command
would have printed, rendered from the session's :class:`HostIdentity` so that
``uname``, ``hostname``, ``free``, ``cat /proc/cpuinfo`` and the shell prompt
all describe one consistent machine, and from the per-session shell state so
that a file the attacker wrote a moment ago is there when they look for it.

The point is to keep the session going. A loader that runs ``uname -m`` to
pick an architecture, or checks ``nproc`` before starting a miner, or reads
``/proc/cpuinfo`` to decide whether the box is worth keeping, stops the moment
it gets ``command not found`` — and the C2 host, the second stage and the
objective go unrecorded. Answering plausibly is what buys the rest of the
transcript.

A handler returns ``(stdout, exit_code)``. Output destined for stderr is
returned in the same string (the SSH channel folds them), but the exit code is
tracked so ``&&`` / ``||`` and ``$?`` behave.

The handlers are split by subject: the filesystem and text tools are in
``commands_files.py``, the machine, its processes and its network in
``commands_system.py``, and the shell's own builtins here. All of them read
the filesystem through one :class:`~honeypot.core.vfs.FsView` and take their
standard input from ``self.stdin``, so a command behaves the same at the head
of a pipeline, in the middle of one, and inside ``$(…)``.
"""

from __future__ import annotations

import posixpath
import random
from typing import Optional

from honeypot.capture import shell_writes
from honeypot.core import canary
from honeypot.core.commands_files import FileCommands
from honeypot.core.commands_system import SystemCommands
from honeypot.core.identity import HostIdentity
from honeypot.core.shell_state import DroppedFile, ShellState, resolve_path
from honeypot.core.shell_syntax import ASSIGNMENT, MAX_VARIABLE_CHARS
from honeypot.core.textfilters import RegexBudget
from honeypot.core.vfs import PROGRAMS, FsView

#: Most text one command may return. A real ``cat`` of a large file would
#: send all of it; this sends enough to be convincing and stops, because the
#: alternative is letting ``cat f f f f …`` build gigabytes in memory.
MAX_OUTPUT_CHARS = 256 * 1024

#: Shell builtins — ``which x`` fails for these on a real system, ``type`` names them.
_BUILTINS = {"cd", "echo", "pwd", "export", "alias", "unalias", "set", "unset",
             "source", ".", "exit", "logout", "history", "type", "umask", "read",
             "test", "[", "true", "false", "jobs", "fg", "bg", "wait", "kill", "help",
             "printf", "eval", "exec", "trap", "shopt", "ulimit", "local", "declare",
             "command", ":"}

_DEFAULT_PATH = "/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin:/usr/games:/usr/local/games:/snap/bin"


def to_text(data: bytes) -> str:
    """Bytes as shell text; undecodable bytes survive the round trip."""
    return data.decode("utf-8", errors="surrogateescape")


def to_bytes(text: str) -> bytes:
    return text.encode("utf-8", errors="surrogateescape")


def base_environment(shell: ShellState, identity: HostIdentity, username: str, is_root: bool) -> dict[str, str]:
    """What ``env`` prints in a fresh login shell on this host."""
    user = username or ("root" if is_root else "user")
    uid = 0 if is_root else identity.uid_for(user)
    env = {
        "SHELL": "/bin/bash",
        "PWD": shell.cwd,
        "LOGNAME": user,
        "XDG_SESSION_TYPE": "tty",
        "MOTD_SHOWN": "pam",
        "HOME": shell.home,
        "LANG": "en_US.UTF-8",
        "USER": user,
        "SHLVL": str(1 + shell.subshells),
        "XDG_SESSION_CLASS": "user",
        "TERM": "xterm-256color",
        "XDG_RUNTIME_DIR": f"/run/user/{uid}",
        "PATH": _DEFAULT_PATH,
    }
    if shell.client_ip:
        env["SSH_CLIENT"] = f"{shell.client_ip} {shell.client_port} 22"
        env["SSH_CONNECTION"] = f"{shell.client_ip} {shell.client_port} {identity.ip} 22"
        env["SSH_TTY"] = "/dev/pts/0"
    return env


def lookup_variable(shell: ShellState, identity: HostIdentity, username: str, is_root: bool, name: str) -> Optional[str]:
    """The value ``$name`` expands to in this session, or None when unset."""
    if name in shell.variables:
        return shell.variables[name]
    if name in shell.env:
        return shell.env[name]
    if name == "?":
        return str(shell.last_status)
    if name == "$":
        return str(shell.pid)
    if name == "#":
        return "0"
    if name == "0":
        return "-bash"
    if name == "RANDOM":
        return str(random.randint(0, 32767))
    if name in ("UID", "EUID"):
        return str(0 if is_root else identity.uid_for(username or "user"))
    if name == "HOSTNAME":
        return identity.hostname
    if name == "OLDPWD":
        return shell.previous_cwd
    if name == "PPID":
        return str(max(2, shell.pid - 1))
    return base_environment(shell, identity, username, is_root).get(name)


class CommandEmulator(FileCommands, SystemCommands):
    """Answer one command segment against a session's shell and identity."""

    def __init__(self, identity: HostIdentity, budget: Optional[RegexBudget] = None,
                 terminal: bool = True) -> None:
        self.identity = identity
        #: Shared by every pattern on the command line; see textfilters.
        self.budget = budget or RegexBudget()
        #: Whether output is going to a terminal. ``ls`` prints columns to one
        #: and a name per line to a pipe, as the real one does.
        self.terminal = terminal
        self.stdin: Optional[bytes] = None
        self.shell: Optional[ShellState] = None
        self.fs: Optional[FsView] = None
        #: Details for an ``ai_canary_triggered`` event, when the last command
        #: was the marker. The caller records it; this module has no session.
        self.canary_hit: Optional[dict] = None

    def can_run(self, name: str) -> bool:
        """Whether ``name`` is a command this emulator has an answer for."""
        return self._handler(posixpath.basename(name)) is not None

    def _handler(self, base: str):
        attribute = "_cmd_" + base.replace("-", "_").replace(".", "_")
        if base == "[":
            attribute = "_cmd_test"
        elif base == ":":
            attribute = "_cmd_true"
        elif base == ".":
            attribute = "_cmd_source"
        return getattr(self, attribute, None)

    def run(self, argv: list[str], shell: ShellState, username: str,
            is_root: bool, stdin: Optional[bytes], to_terminal: Optional[bool] = None) -> tuple[Optional[str], int]:
        """Return (text, exit_code); text is None when stdout is unknowable."""
        if not argv:
            return "", 0
        name = argv[0]
        base = posixpath.basename(name)
        handler = self._handler(base)
        if handler is None:
            # A path that is not a known program: ./x, /tmp/x, ../x.
            if name.startswith(("./", "/", "../")) or name.startswith("~"):
                return None, 127  # caller handles execution of dropped files
            return self._not_found(base), 127
        previous = (self.stdin, self.shell, self.fs, self.terminal)
        self.stdin, self.shell = stdin, shell
        self.fs = FsView(shell, username or ("root" if is_root else "user"), is_root)
        if to_terminal is not None:
            self.terminal = to_terminal
        try:
            text, status = handler(argv[1:], shell, username, is_root)
        finally:
            self.stdin, self.shell, self.fs, self.terminal = previous
        if text is not None and len(text) > MAX_OUTPUT_CHARS:
            text = text[:MAX_OUTPUT_CHARS]
        return text, status

    # -- shared helpers ----------------------------------------------------

    def _stdin_text(self) -> Optional[str]:
        return None if self.stdin is None else to_text(self.stdin)

    def _env(self, shell, username, is_root) -> dict[str, str]:
        env = base_environment(shell, self.identity, username, is_root)
        env.update(shell.env)
        return env

    # -- users -----------------------------------------------------------

    def _cmd_whoami(self, args, shell, username, is_root):
        return ("root" if is_root else (username or "user")) + "\n", 0

    def _cmd_id(self, args, shell, username, is_root):
        target = next((a for a in args if not a.startswith("-")), None)
        name = target or ("root" if is_root else (username or "user"))
        known = {"root"} | {account[0] for account in self._accounts()}
        if target and target not in known:
            return f"id: ‘{target}’: no such user\n", 1
        uid = 0 if name == "root" else self.identity.uid_for(name)
        flags = "".join(a[1:] for a in args if a.startswith("-"))
        if "u" in flags:
            return (name if "n" in flags else str(uid)) + "\n", 0
        if "g" in flags and "G" not in flags:
            return (name if "n" in flags else str(uid)) + "\n", 0
        if uid == 0:
            return "uid=0(root) gid=0(root) groups=0(root)\n", 0
        admin = self.identity.users[0][0] if self.identity.users else ""
        extra = ",4(adm),24(cdrom),27(sudo),30(dip),46(plugdev)" if name == admin else ""
        return f"uid={uid}({name}) gid={uid}({name}) groups={uid}({name}){extra}\n", 0

    def _accounts(self):
        from honeypot.core.hostfacts import login_accounts

        return login_accounts(self.identity)

    def _cmd_groups(self, args, shell, username, is_root):
        if is_root:
            return "root\n", 0
        name = username or "user"
        admin = self.identity.users[0][0] if self.identity.users else ""
        return (f"{name} adm cdrom sudo dip plugdev\n" if name == admin else f"{name}\n"), 0

    def _cmd_sudo(self, args, shell, username, is_root):
        # `sudo <command>` is unwrapped before it reaches here (see modes);
        # what arrives is sudo on its own or with only flags.
        if any(a in ("-l", "--list") for a in args):
            name = "root" if is_root else (username or "user")
            return (
                f"Matching Defaults entries for {name} on {self.identity.hostname}:\n"
                "    env_reset, mail_badpass,\n"
                "    secure_path=/usr/local/sbin\\:/usr/local/bin\\:/usr/sbin\\:/usr/bin\\:/sbin\\:/bin\\:/snap/bin\n\n"
                f"User {name} may run the following commands on {self.identity.hostname}:\n"
                "    (ALL : ALL) ALL\n"
            ), 0
        if not args or all(a.startswith("-") for a in args):
            if any(a in ("-i", "-s") or a.startswith("-u") for a in args):
                return "", 0
            if any(a in ("-n", "-v", "-k", "-K") for a in args):
                return "", 0
            return "usage: sudo -h | -K | -k | -V\nusage: sudo -v [-AknS] [-g group] [-h host] [-p prompt] [-u user]\n", 1
        return "", 0

    def _cmd_su(self, args, shell, username, is_root):
        if is_root:
            return "", 0
        # No terminal to ask for a password on, and no password would be
        # right: fail the way su does when authentication does.
        return "su: Authentication failure\n", 1

    def _cmd_passwd(self, args, shell, username, is_root):
        name = next((a for a in args if not a.startswith("-")), "root" if is_root else (username or "user"))
        if not is_root and name != (username or "user"):
            return f"passwd: You may not view or modify password information for {name}.\n", 1
        if self.stdin:
            return "New password: Retype new password: passwd: password updated successfully\n", 0
        return "passwd: Authentication token manipulation error\npasswd: password unchanged\n", 10

    def _cmd_chpasswd(self, args, shell, username, is_root):
        if not is_root:
            return "chpasswd: (user root) pam_chauthtok() failed, error:\nAuthentication token manipulation error\nchpasswd: (line 1, user root) password not changed\n", 1
        return "", 0

    def _account_tool(self, args, shell, username, is_root, tool):
        if not is_root:
            return f"{tool}: Permission denied.\n{tool}: cannot lock /etc/passwd; try again later.\n", 1
        return "", 0

    def _cmd_useradd(self, args, shell, username, is_root):
        return self._account_tool(args, shell, username, is_root, "useradd")

    def _cmd_usermod(self, args, shell, username, is_root):
        return self._account_tool(args, shell, username, is_root, "usermod")

    def _cmd_userdel(self, args, shell, username, is_root):
        return self._account_tool(args, shell, username, is_root, "userdel")

    def _cmd_groupadd(self, args, shell, username, is_root):
        return self._account_tool(args, shell, username, is_root, "groupadd")

    def _cmd_adduser(self, args, shell, username, is_root):
        if not is_root:
            return "adduser: Only root may add a user or group to the system.\n", 1
        return "", 0

    # -- the shell's own -------------------------------------------------

    def _cmd_pwd(self, args, shell, username, is_root):
        return shell.cwd + "\n", 0

    def _cmd_echo(self, args, shell, username, is_root):
        # The same function the capture interpreter uses, so what an
        # attacker sees printed and what `> file` stores cannot differ.
        return to_text(shell_writes._echo(list(args))), 0

    def _cmd_printf(self, args, shell, username, is_root):
        if not args:
            return "printf: usage: printf [-v var] format [arguments]\n", 2
        produced = shell_writes._printf(list(args))
        return to_text((produced or b"")[:MAX_OUTPUT_CHARS]), 0

    def _cmd_true(self, args, shell, username, is_root):
        return "", 0

    def _cmd_false(self, args, shell, username, is_root):
        return "", 1

    def _cmd_test(self, args, shell, username, is_root):
        args = list(args)
        if args and args[-1] == "]":
            args.pop()
        return "", 0 if self._test(args, shell) else 1

    def _test(self, args: list[str], shell: ShellState) -> bool:
        """``test`` / ``[``: the file, string and integer checks."""
        if not args:
            return False
        if args[0] == "!":
            return not self._test(args[1:], shell)
        for joiner in ("-o", "-a"):
            if joiner in args[1:-1]:
                index = args.index(joiner, 1)
                left, right = self._test(args[:index], shell), self._test(args[index + 1:], shell)
                return (left or right) if joiner == "-o" else (left and right)
        if len(args) == 1:
            return args[0] != ""
        if len(args) == 2:
            flag, operand = args
            if flag == "-z":
                return operand == ""
            if flag == "-n":
                return operand != ""
            entry = self.fs.lookup(resolve_path(shell.cwd, operand, shell.home))
            if flag in ("-e", "-a"):
                return entry is not None
            if flag == "-f":
                return entry is not None and entry.kind == "file"
            if flag == "-d":
                return entry is not None and entry.kind == "dir"
            if flag in ("-L", "-h"):
                link = self.fs.lookup(resolve_path(shell.cwd, operand, shell.home), follow=False)
                return link is not None and link.kind == "link"
            if flag == "-x":
                return entry is not None and (entry.executable or entry.kind == "dir")
            if flag == "-s":
                return entry is not None and entry.size > 0
            if flag in ("-r", "-w"):
                return entry is not None and (self.fs.can_read(entry) if flag == "-r" else self.fs.can_write(operand))
            return False
        if len(args) == 3:
            left, operator, right = args
            if operator in ("=", "=="):
                return left == right
            if operator == "!=":
                return left != right
            try:
                a, b = int(left[:19]), int(right[:19])
            except ValueError:
                return False
            return {
                "-eq": a == b, "-ne": a != b, "-lt": a < b,
                "-le": a <= b, "-gt": a > b, "-ge": a >= b,
            }.get(operator, False)
        return False

    def _cmd_which(self, args, shell, username, is_root):
        out, code = [], 0
        for a in args:
            if a.startswith("-"):
                continue
            path = PROGRAMS.get(a)
            # `which` is a program: it finds builtins only where a binary of
            # the same name exists on the PATH.
            if path and (a not in _BUILTINS or a in ("echo", "pwd", "kill", "test", "true", "false", "printf")):
                out.append(path)
            else:
                code = 1
        return ("\n".join(out) + "\n") if out else "", code

    def _cmd_whereis(self, args, shell, username, is_root):
        out = []
        for a in args:
            if a.startswith("-"):
                continue
            path = PROGRAMS.get(a)
            out.append(f"{a}: {path}" if path else f"{a}:")
        return "\n".join(out) + ("\n" if out else ""), 0

    def _cmd_command(self, args, shell, username, is_root):
        if args and args[0] in ("-v", "-V") and len(args) > 1:
            name = args[1]
            if name in _BUILTINS:
                return name + "\n", 0
            path = PROGRAMS.get(name)
            return (path + "\n", 0) if path else ("", 1)
        if args:
            return self.run(list(args), shell, username, is_root, self.stdin)
        return "", 0

    def _cmd_type(self, args, shell, username, is_root):
        out, code = [], 0
        for a in args:
            if a.startswith("-"):
                continue
            if a in _BUILTINS:
                out.append(f"{a} is a shell builtin")
            elif a in PROGRAMS:
                out.append(f"{a} is {PROGRAMS[a]}")
            else:
                out.append(f"-bash: type: {a}: not found")
                code = 1
        return "\n".join(out) + ("\n" if out else ""), code

    def _cmd_env(self, args, shell, username, is_root):
        # `env NAME=value command` is unwrapped by the caller; here it lists.
        env = self._env(shell, username, is_root)
        env["_"] = "/usr/bin/env"
        return "".join(f"{k}={v}\n" for k, v in env.items())[:MAX_OUTPUT_CHARS], 0

    def _cmd_printenv(self, args, shell, username, is_root):
        env = self._env(shell, username, is_root)
        names = [a for a in args if not a.startswith("-")]
        if names:
            found = [env[name] for name in names if name in env]
            return "".join(v + "\n" for v in found), 0 if len(found) == len(names) else 1
        env["_"] = "/usr/bin/printenv"
        return "".join(f"{k}={v}\n" for k, v in env.items())[:MAX_OUTPUT_CHARS], 0

    def _cmd_export(self, args, shell, username, is_root):
        if not args or args == ["-p"]:
            env = self._env(shell, username, is_root)
            return "".join(f'declare -x {k}="{v}"\n' for k, v in sorted(env.items()))[:MAX_OUTPUT_CHARS], 0
        for a in args:
            if a.startswith("-"):
                continue
            match = ASSIGNMENT.match(a)
            if match:
                name, value = match.group(1), match.group(2)[:MAX_VARIABLE_CHARS]
                shell.variables[name] = value
            else:
                name, value = a, shell.variables.get(a)
            if value is not None and (name in shell.env or len(shell.env) < 256):
                shell.env[name] = value
        return "", 0

    def _cmd_declare(self, args, shell, username, is_root):
        for a in args:
            match = ASSIGNMENT.match(a)
            if match and (match.group(1) in shell.variables or len(shell.variables) < 256):
                shell.variables[match.group(1)] = match.group(2)[:MAX_VARIABLE_CHARS]
        return "", 0

    def _cmd_local(self, args, shell, username, is_root):
        return self._cmd_declare(args, shell, username, is_root)

    def _cmd_readonly(self, args, shell, username, is_root):
        return self._cmd_declare(args, shell, username, is_root)

    def _cmd_unset(self, args, shell, username, is_root):
        for a in args:
            shell.env.pop(a, None)
            shell.variables.pop(a, None)
        return "", 0

    def _cmd_read(self, args, shell, username, is_root):
        names = [a for a in args if not a.startswith("-")] or ["REPLY"]
        text = self._stdin_text()
        if not text:
            return "", 1
        line = text.split("\n", 1)[0]
        fields = line.split(None, len(names) - 1) if len(names) > 1 else [line]
        for index, name in enumerate(names[:16]):
            if name in shell.variables or len(shell.variables) < 256:
                shell.variables[name] = (fields[index] if index < len(fields) else "")[:MAX_VARIABLE_CHARS]
        return "", 0

    def _cmd_history(self, args, shell, username, is_root):
        if args and args[0] == "-c":
            shell.history.clear()
            return "", 0
        lines = [f"{idx + 1:5d}  {cmd}" for idx, cmd in enumerate(shell.history)]
        return "\n".join(lines) + ("\n" if lines else ""), 0

    def _cmd_set(self, args, shell, username, is_root):
        if args:
            return "", 0
        merged = dict(self._env(shell, username, is_root))
        merged.update(shell.variables)
        return "".join(f"{k}={v}\n" for k, v in sorted(merged.items()))[:MAX_OUTPUT_CHARS], 0

    def _cmd_umask(self, args, shell, username, is_root):
        return "" if args else "0022\n", 0

    def _cmd_ulimit(self, args, shell, username, is_root):
        if "-n" in args:
            return "1024\n", 0
        if "-u" in args:
            return f"{self.identity.mem_kb // 256}\n", 0
        if "-a" in args:
            return (
                "core file size          (blocks, -c) 0\n"
                "data seg size           (kbytes, -d) unlimited\n"
                "file size               (blocks, -f) unlimited\n"
                f"max locked memory       (kbytes, -l) {self.identity.mem_kb // 8}\n"
                "open files                      (-n) 1024\n"
                "stack size              (kbytes, -s) 8192\n"
                f"max user processes              (-u) {self.identity.mem_kb // 256}\n"
                "virtual memory          (kbytes, -v) unlimited\n"
            ), 0
        return "unlimited\n" if not any(a.lstrip("-").isdigit() or a == "unlimited" for a in args) else "", 0

    def _cmd_alias(self, args, shell, username, is_root):
        if args:
            return "", 0
        return "alias l='ls -CF'\nalias la='ls -A'\nalias ll='ls -alF'\nalias ls='ls --color=auto'\n", 0

    def _cmd_unalias(self, args, shell, username, is_root):
        return "", 0

    def _cmd_shopt(self, args, shell, username, is_root):
        return "", 0

    def _cmd_trap(self, args, shell, username, is_root):
        return "", 0

    def _cmd_wait(self, args, shell, username, is_root):
        return "", 0

    def _cmd_jobs(self, args, shell, username, is_root):
        return "", 0

    def _cmd_bg(self, args, shell, username, is_root):
        return "-bash: bg: current: no such job\n", 1

    def _cmd_fg(self, args, shell, username, is_root):
        return "-bash: fg: current: no such job\n", 1

    def _cmd_source(self, args, shell, username, is_root):
        if not args:
            return "-bash: source: filename argument required\nsource: usage: source filename [arguments]\n", 2
        if not self.fs.exists(resolve_path(shell.cwd, args[0], shell.home)):
            return f"-bash: {args[0]}: No such file or directory\n", 1
        return "", 0

    def _cmd_help(self, args, shell, username, is_root):
        return (
            "GNU bash, version 5.0.17(1)-release (x86_64-pc-linux-gnu)\n"
            "These shell commands are defined internally.  Type `help' to see this list.\n"
            "Type `help name' to find out more about the function `name'.\n"
        ), 0

    def _cmd_clear(self, args, shell, username, is_root):
        return "\x1b[H\x1b[2J\x1b[3J", 0

    def _cmd_reset(self, args, shell, username, is_root):
        return "\x1bc", 0

    def _cmd_tty(self, args, shell, username, is_root):
        return ("/dev/pts/0\n", 0) if self.terminal else ("not a tty\n", 1)

    def _cmd_stty(self, args, shell, username, is_root):
        if "size" in args:
            return "24 80\n", 0
        return "", 0

    # -- the canary --------------------------------------------------------

    def _cmd_ops_session(self, args, shell, username, is_root):
        if not canary.enabled():
            return self._not_found(canary.MARKER_PROGRAM), 127
        self.canary_hit = canary.check([canary.MARKER_PROGRAM] + list(args), self.identity)
        if "--register" in args and len(args) >= 2:
            return "ops-session: registered\n", 0
        return "usage: ops-session --register TOKEN\n", 2

    # -- writes the capture layer does not model -----------------------------

    def _cmd_touch(self, args, shell, username, is_root):
        for a in args:
            if a.startswith("-"):
                continue
            path = resolve_path(shell.cwd, a, shell.home)
            if self.fs.exists(path):
                continue
            if not self.fs.is_dir(posixpath.dirname(path)):
                return f"touch: cannot touch '{a}': No such file or directory\n", 1
            if not self.fs.can_write(path):
                return f"touch: cannot touch '{a}': Permission denied\n", 1
            shell.add_file(path, DroppedFile(name=posixpath.basename(path), size=0))
        return "", 0

    def _cmd_mkdir(self, args, shell, username, is_root):
        parents = any(a.startswith("-") and "p" in a for a in args)
        out, code = [], 0
        for a in args:
            if a.startswith("-"):
                continue
            path = resolve_path(shell.cwd, a, shell.home)
            if self.fs.exists(path):
                if not parents:
                    out.append(f"mkdir: cannot create directory ‘{a}’: File exists")
                    code = 1
                continue
            missing = []
            walk = path
            while walk != "/" and not self.fs.exists(walk):
                missing.append(walk)
                walk = posixpath.dirname(walk)
            if len(missing) > 1 and not parents:
                out.append(f"mkdir: cannot create directory ‘{a}’: No such file or directory")
                code = 1
                continue
            if not self.fs.is_dir(walk):
                out.append(f"mkdir: cannot create directory ‘{a}’: Not a directory")
                code = 1
                continue
            if not self.fs.can_write(missing[-1]):
                out.append(f"mkdir: cannot create directory ‘{a}’: Permission denied")
                code = 1
                continue
            for made in reversed(missing):
                shell.add_dir(made)
        return "\n".join(out) + ("\n" if out else ""), code

    def _cmd_rm(self, args, shell, username, is_root):
        flags = "".join(a[1:] for a in args if a.startswith("-") and not a.startswith("--"))
        recursive = "r" in flags or "R" in flags or "--recursive" in args
        force = "f" in flags or "--force" in args
        out, code = [], 0
        for a in args:
            if a.startswith("-"):
                continue
            path = resolve_path(shell.cwd, a, shell.home)
            entry = self.fs.lookup(path, follow=False)
            if entry is None:
                if not force:
                    out.append(f"rm: cannot remove '{a}': No such file or directory")
                    code = 1
                continue
            if entry.kind == "dir" and not recursive:
                out.append(f"rm: cannot remove '{a}': Is a directory")
                code = 1
                continue
            if not self.fs.can_write(path) or (not is_root and not entry.session and entry.owner != username):
                out.append(f"rm: cannot remove '{a}': Permission denied")
                code = 1
                continue
            shell.remove_path(path, recursive)
        return "\n".join(out) + ("\n" if out else ""), code

    def _cmd_rmdir(self, args, shell, username, is_root):
        out, code = [], 0
        for a in args:
            if a.startswith("-"):
                continue
            path = resolve_path(shell.cwd, a, shell.home)
            if not self.fs.exists(path):
                out.append(f"rmdir: failed to remove '{a}': No such file or directory")
                code = 1
            elif not self.fs.is_dir(path):
                out.append(f"rmdir: failed to remove '{a}': Not a directory")
                code = 1
            elif self.fs.listdir(path):
                out.append(f"rmdir: failed to remove '{a}': Directory not empty")
                code = 1
            else:
                shell.remove_path(path, False)
        return "\n".join(out) + ("\n" if out else ""), code

    def _copy(self, args, shell, username, is_root, verb: str, move: bool):
        operands = [a for a in args if not a.startswith("-")]
        if len(operands) < 2:
            missing = f"missing destination file operand after '{operands[0]}'" if operands else "missing file operand"
            return f"{verb}: {missing}\nTry '{verb} --help' for more information.\n", 1
        *sources, destination = operands
        target_dir = resolve_path(shell.cwd, destination, shell.home)
        into_directory = self.fs.is_dir(target_dir)
        out, code = [], 0
        for source in sources[:32]:
            path = resolve_path(shell.cwd, source, shell.home)
            entry = self.fs.lookup(path)
            if entry is None:
                out.append(f"{verb}: cannot stat '{source}': No such file or directory")
                code = 1
                continue
            if entry.kind == "dir":
                if move:
                    continue
                out.append(f"cp: -r not specified; omitting directory '{source}'")
                code = 1
                continue
            target = posixpath.join(target_dir, posixpath.basename(path)) if into_directory else target_dir
            if not self.fs.is_dir(posixpath.dirname(target)):
                out.append(f"{verb}: cannot create regular file '{destination}': No such file or directory")
                code = 1
                continue
            content = self.fs.read(path) if entry.size <= 4 * 1024 * 1024 else None
            known = shell.contents.get(path) is not None or not entry.session
            if content is not None and known:
                shell.write_content(target, content, False, verb)
            else:
                shell.add_file(target, DroppedFile(
                    name=posixpath.basename(target), size=entry.size,
                    source_url=entry.source_url,
                ))
            copied = shell.files.get(target)
            if copied is not None:
                copied.executable = entry.executable
                copied.source_url = entry.source_url
            if move:
                shell.remove_path(path, False)
        return "\n".join(out) + ("\n" if out else ""), code

    def _cmd_cp(self, args, shell, username, is_root):
        return self._copy(args, shell, username, is_root, "cp", move=False)

    def _cmd_mv(self, args, shell, username, is_root):
        return self._copy(args, shell, username, is_root, "mv", move=True)

    def _cmd_ln(self, args, shell, username, is_root):
        return "", 0

    def _cmd_chmod(self, args, shell, username, is_root):
        operands = [a for a in args if not a.startswith("-") or a[1:2] in "rwxXst"]
        if len(operands) < 2:
            return "chmod: missing operand\nTry 'chmod --help' for more information.\n", 1
        mode, *targets = operands
        executable = None
        if mode.isdigit():
            try:
                executable = bool(int(mode[-3:], 8) & 0o111)
            except ValueError:
                executable = None
        elif "x" in mode:
            executable = "-" not in mode
        out, code = [], 0
        for target in targets:
            path = resolve_path(shell.cwd, target, shell.home)
            entry = self.fs.lookup(path)
            if entry is None:
                out.append(f"chmod: cannot access '{target}': No such file or directory")
                code = 1
                continue
            file = shell.files.get(path)
            if file is not None and executable is not None:
                file.executable = executable
            elif file is None and not is_root and entry.owner != username:
                out.append(f"chmod: changing permissions of '{target}': Operation not permitted")
                code = 1
        return "\n".join(out) + ("\n" if out else ""), code

    def _cmd_chown(self, args, shell, username, is_root):
        operands = [a for a in args if not a.startswith("-")]
        out, code = [], 0
        for target in operands[1:]:
            if not self.fs.exists(resolve_path(shell.cwd, target, shell.home)):
                out.append(f"chown: cannot access '{target}': No such file or directory")
                code = 1
            elif not is_root:
                out.append(f"chown: changing ownership of '{target}': Operation not permitted")
                code = 1
        return "\n".join(out) + ("\n" if out else ""), code

    def _cmd_chgrp(self, args, shell, username, is_root):
        return self._cmd_chown(args, shell, username, is_root)

    def _cmd_chattr(self, args, shell, username, is_root):
        return ("", 0) if is_root else ("chattr: Operation not permitted while setting flags\n", 1)

    # -- not-found -------------------------------------------------------

    def _not_found(self, base: str) -> str:
        return f"{base}: command not found\n"
