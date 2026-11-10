"""Commands that describe the machine: what it is, what runs on it, who it talks to.

All of it is rendered from the host identity and the tables in
``core/hostfacts.py``. ``ps``, ``top``, ``pgrep``, ``netstat`` and ``ss`` show
one process table and one set of sockets; ``free``, ``top`` and
``/proc/meminfo`` one memory figure; ``lscpu`` and ``/proc/cpuinfo`` one
processor. A visitor comparing any two of them finds the same host.

Commands that would need the network (``ping``, ``ssh``, ``nslookup``) answer
from the same invented resolver ``wget`` uses, so a name resolves to the same
address whichever tool asks. Nothing here opens a socket.
"""

from __future__ import annotations

import posixpath
import random
from datetime import datetime, timezone
from typing import Optional

from honeypot.core import dropper, hostfacts
from honeypot.core.hostfacts import Process

_SERVICES = {21: "ftp", 22: "ssh", 23: "telnet", 53: "domain", 68: "bootpc",
             80: "http", 443: "https", 3306: "mysql"}

#: Units ``systemctl status`` knows, by the name an operator would type.
_UNITS = {
    "ssh": ("ssh.service", "OpenBSD Secure Shell server", "sshd"),
    "sshd": ("ssh.service", "OpenBSD Secure Shell server", "sshd"),
    "cron": ("cron.service", "Regular background program processing daemon", "cron"),
    "rsyslog": ("rsyslog.service", "System Logging Service", "rsyslogd"),
    "mysql": ("mysql.service", "MySQL Community Server", "mysqld"),
    "nginx": ("nginx.service", "A high performance web server and a reverse proxy server", "nginx"),
    "apache2": ("apache2.service", "The Apache HTTP Server", "apache2"),
    "vsftpd": ("vsftpd.service", "vsftpd FTP server", "vsftpd"),
    "proftpd": ("proftpd.service", "ProFTPD FTP Server", "proftpd"),
}


def table(rows: list[list[str]], left: tuple[int, ...] = (0,)) -> str:
    """Rows as aligned columns: the listed ones flush left, the rest right."""
    if not rows:
        return ""
    widths = [max(len(row[i]) for row in rows if i < len(row)) for i in range(len(rows[0]))]
    lines = []
    for row in rows:
        cells = []
        for index, cell in enumerate(row):
            last = index == len(row) - 1
            if index in left:
                cells.append(cell if last else cell.ljust(widths[index]))
            else:
                cells.append(cell.rjust(widths[index]))
        lines.append(" ".join(cells).rstrip())
    return "\n".join(lines) + "\n"


class SystemCommands:
    """Mixin: identity, process and network commands."""

    # -- identity ----------------------------------------------------------

    def _cmd_uname(self, args, shell, username, is_root):
        i = self.identity
        if not args or args == ["-s"]:
            return "Linux\n", 0
        flags = "".join(a[1:] for a in args if a.startswith("-") and not a.startswith("--"))
        if "a" in flags or "--all" in args:
            return i.uname_a + "\n", 0
        parts = []
        if "s" in flags:
            parts.append("Linux")
        if "n" in flags:
            parts.append(i.hostname)
        if "r" in flags:
            parts.append(i.kernel)
        if "v" in flags:
            parts.append(i.kernel_build)
        if "m" in flags or "p" in flags or "i" in flags:
            parts.append(i.arch)
        if "o" in flags:
            parts.append("GNU/Linux")
        return (" ".join(parts) if parts else "Linux") + "\n", 0

    def _cmd_hostname(self, args, shell, username, is_root):
        if args and args[0] in ("-f", "--fqdn"):
            return self.identity.fqdn + "\n", 0
        if args and args[0] in ("-I", "--all-ip-addresses", "-i"):
            return self.identity.ip + (" \n" if args[0] != "-i" else "\n"), 0
        if args and args[0] in ("-d", "--domain"):
            return self.identity.domain + "\n", 0
        if args and not args[0].startswith("-"):
            if not is_root:
                return "hostname: you must be root to change the host name\n", 1
            return "", 0
        return self.identity.hostname + "\n", 0

    def _cmd_hostnamectl(self, args, shell, username, is_root):
        i = self.identity
        _product, _vendor, hypervisor = hostfacts.platform_facts(i)
        return (
            f"   Static hostname: {i.hostname}\n"
            "         Icon name: computer-vm\n"
            "           Chassis: vm\n"
            f"        Machine ID: {i.machine_id}\n"
            f"           Boot ID: {hostfacts.seeded_uuid(i, f'boot-id:{int(i.boot_time)}').replace('-', '')}\n"
            f"    Virtualization: {hypervisor.lower()}\n"
            f"  Operating System: Ubuntu {i.os_version} LTS\n"
            f"            Kernel: Linux {i.kernel}\n"
            "      Architecture: x86-64\n"
        ), 0

    def _cmd_arch(self, args, shell, username, is_root):
        return self.identity.arch + "\n", 0

    def _cmd_nproc(self, args, shell, username, is_root):
        return f"{self.identity.cpu_cores}\n", 0

    def _cmd_lscpu(self, args, shell, username, is_root):
        return hostfacts.lscpu(self.identity), 0

    def _cmd_lsb_release(self, args, shell, username, is_root):
        i = self.identity
        flags = "".join(a.lstrip("-") for a in args)
        short = "s" in flags
        fields = [
            ("i", "Distributor ID", "Ubuntu"),
            ("d", "Description", f"Ubuntu {i.os_version} LTS"),
            ("r", "Release", "20.04"),
            ("c", "Codename", "focal"),
        ]
        wanted = [f for f in fields if f[0] in flags or "a" in flags or "all" in flags]
        if not wanted:
            return "No LSB modules are available.\n", 0
        head = "No LSB modules are available.\n" if "a" in flags and not short else ""
        return head + "".join((value if short else f"{label}:\t{value}") + "\n" for _f, label, value in wanted), 0

    # -- memory, disk, time ------------------------------------------------

    @staticmethod
    def _free_human(kb: int) -> str:
        value = float(kb)
        for unit in ("Ki", "Mi", "Gi", "Ti"):
            if value < 1024 or unit == "Ti":
                break
            value /= 1024
        return f"{value:.1f}{unit}" if value < 10 else f"{value:.0f}{unit}"

    def _cmd_free(self, args, shell, username, is_root):
        m = hostfacts.memory(self.identity)
        flags = "".join(a.lstrip("-") for a in args if a.startswith("-"))
        if "h" in flags or "human" in flags:
            convert = self._free_human
        else:
            divisor = 1
            if "b" in flags and "bytes" not in flags:
                convert = lambda kb: str(kb * 1024)  # noqa: E731
            else:
                if "m" in flags or "mebi" in flags:
                    divisor = 1024
                elif "g" in flags or "gibi" in flags:
                    divisor = 1024 * 1024
                convert = lambda kb: str(kb // divisor)  # noqa: E731
        memory = [m.total, m.used, m.free, m.shared, m.buff_cache, m.available]
        swap = [m.swap_total, m.swap_used, m.swap_total - m.swap_used]
        lines = [
            "              total        used        free      shared  buff/cache   available",
            "Mem:" + f"{convert(memory[0]):>15}" + "".join(f"{convert(v):>12}" for v in memory[1:]),
            "Swap:" + f"{convert(swap[0]):>14}" + "".join(f"{convert(v):>12}" for v in swap[1:]),
        ]
        if "t" in flags:
            total = [m.total + m.swap_total, m.used + m.swap_used, m.free + m.swap_total - m.swap_used]
            lines.append("Total:" + f"{convert(total[0]):>13}" + "".join(f"{convert(v):>12}" for v in total[1:]))
        return "\n".join(lines) + "\n", 0

    def _cmd_df(self, args, shell, username, is_root):
        from honeypot.core.commands_files import human_size

        i = self.identity
        flags = "".join(a[1:] for a in args if a.startswith("-") and not a.startswith("--"))
        human = "h" in flags
        # ext4 keeps five percent back for root, so Used + Avail < Size.
        reserved = int(i.disk_total_kb * 0.05)
        run = i.mem_kb // 10
        run_used = 900 + hostfacts.seeded(i, "df").randint(0, 900)
        filesystems = [
            ("udev", "devtmpfs", i.mem_kb // 2, 0, i.mem_kb // 2, "/dev"),
            ("tmpfs", "tmpfs", run, run_used, run - run_used, "/run"),
            ("/dev/vda1", "ext4", i.disk_total_kb, i.disk_used_kb, i.disk_total_kb - i.disk_used_kb - reserved, "/"),
            ("tmpfs", "tmpfs", i.mem_kb // 2, 0, i.mem_kb // 2, "/dev/shm"),
            ("tmpfs", "tmpfs", 5120, 0, 5120, "/run/lock"),
            ("tmpfs", "tmpfs", i.mem_kb // 2, 0, i.mem_kb // 2, "/sys/fs/cgroup"),
        ]
        operands = [a for a in args if not a.startswith("-")]
        if operands:
            # Asked about a path: the filesystem that holds it.
            path = self._path(operands[0])
            if not self.fs.exists(path):
                return f"df: {operands[0]}: No such file or directory\n", 1
            best = max((f for f in filesystems if path == f[5] or path.startswith(f[5].rstrip("/") + "/")),
                       key=lambda f: len(f[5]))
            filesystems = [best]

        def size(kb: int) -> str:
            return (human_size(kb * 1024) if kb else "0") if human else str(kb)

        header = ["Filesystem"] + (["Type"] if "T" in flags else []) + (
            ["Size", "Used", "Avail", "Use%", "Mounted on"] if human else
            ["1K-blocks", "Used", "Available", "Use%", "Mounted on"])
        rows = [header]
        for name, kind, total, used, available, mount in filesystems:
            percent = f"{-(-used * 100 // (used + available)) if used else 0}%"
            rows.append([name] + ([kind] if "T" in flags else []) + [size(total), size(used), size(available), percent, mount])
        last = len(header) - 1
        return table(rows, left=(0, 1, last) if "T" in flags else (0, last)), 0

    def _uptime_line(self) -> str:
        secs = int(self.identity.uptime_seconds)
        days, rest = divmod(secs, 86400)
        hours, minutes = rest // 3600, (rest % 3600) // 60
        if days:
            up = f"{days} day{'s' if days != 1 else ''}, {hours:2d}:{minutes:02d}"
        elif hours:
            up = f"{hours:2d}:{minutes:02d}"
        else:
            up = f"{minutes} min"
        load = hostfacts.load_average(self.identity)
        return (f" {self._now().strftime('%H:%M:%S')} up {up},  1 user,  "
                f"load average: {load[0]:.2f}, {load[1]:.2f}, {load[2]:.2f}\n")

    def _cmd_uptime(self, args, shell, username, is_root):
        if "-s" in args:
            return datetime.fromtimestamp(self.identity.boot_time, self._tz()).strftime("%Y-%m-%d %H:%M:%S") + "\n", 0
        return self._uptime_line(), 0

    def _login_origin(self, shell) -> str:
        return shell.client_ip or self.identity.last_login_ip

    def _cmd_w(self, args, shell, username, is_root):
        name = ("root" if is_root else (username or "user"))[:8]
        login = datetime.fromtimestamp(shell.login_time, self._tz()).strftime("%H:%M")
        return (
            self._uptime_line()
            + "USER     TTY      FROM             LOGIN@   IDLE   JCPU   PCPU WHAT\n"
            + f"{name:<8} pts/0    {self._login_origin(shell)[:16]:<16} {login}    0.00s  0.03s  0.00s w\n"
        ), 0

    def _cmd_who(self, args, shell, username, is_root):
        name = "root" if is_root else (username or "user")
        when = datetime.fromtimestamp(shell.login_time, self._tz()).strftime("%Y-%m-%d %H:%M")
        return f"{name:<8} pts/0        {when} ({self._login_origin(shell)})\n", 0

    def _cmd_last(self, args, shell, username, is_root):
        name = ("root" if is_root else (username or "user"))[:8]
        when = datetime.fromtimestamp(shell.login_time, self._tz())
        boot = datetime.fromtimestamp(self.identity.boot_time, self._tz())
        return (
            f"{name:<8} pts/0        {self._login_origin(shell)[:16]:<16} {when.strftime('%a %b %e %H:%M')}   still logged in\n"
            f"reboot   system boot  {self.identity.kernel[:16]:<16} {boot.strftime('%a %b %e %H:%M')}   still running\n"
            f"\nwtmp begins {boot.strftime('%a %b %e %H:%M:%S %Y')}\n"
        ), 0

    def _cmd_date(self, args, shell, username, is_root):
        now = datetime.now(timezone.utc) if ("-u" in args or "--utc" in args) else self._now()
        if any(a in ("-s", "--set") or a.startswith("--set=") for a in args) and not is_root:
            return "date: cannot set date: Operation not permitted\n", 1
        formats = [a for a in args if a.startswith("+")]
        if formats:
            wanted = formats[0][1:129]
            try:
                return now.strftime(wanted.replace("%s", str(int(now.timestamp())))) + "\n", 0
            except (ValueError, OverflowError):
                return f"date: invalid date ‘{wanted}’\n", 1
        return now.strftime("%a %b %e %H:%M:%S %Z %Y") + "\n", 0

    # -- processes ---------------------------------------------------------

    def _session_processes(self, shell, username, is_root, command: str) -> list[Process]:
        """The visitor's own processes: the login chain, the shell, the command."""
        name = "root" if is_root else (username or "user")
        listener = hostfacts.process_named(self.identity, "sshd")
        parent = listener.pid if listener else 1
        own = shell.pid + 12 + len(shell.history)
        rows = [
            Process(shell.pid - 2, parent, "root", f"sshd: {name} [priv]", "sshd", 13920, 9068, stat="Ss"),
            Process(shell.pid, shell.pid - 1 if not is_root else shell.pid - 2, name, "-bash", "bash", 10048, 5128, tty="pts/0", stat="Ss"),
            Process(own, shell.pid, name, command, command.split()[0], 10624, 3284, tty="pts/0", stat="R+"),
        ]
        if not is_root:
            rows.insert(1, Process(shell.pid - 1, shell.pid - 2, name, f"sshd: {name}@pts/0", "sshd", 14052, 6012, stat="S"))
        else:
            rows[0] = Process(shell.pid - 2, parent, "root", "sshd: root@pts/0", "sshd", 13920, 9068, stat="Ss")
        return rows

    def _all_processes(self, shell, username, is_root, command: str) -> list[Process]:
        killed = getattr(shell, "killed", set())
        daemons = [p for p in hostfacts.processes(self.identity) if p.pid not in killed]
        return daemons + self._session_processes(shell, username, is_root, command)

    @staticmethod
    def _ps_user(name: str) -> str:
        return name if len(name) <= 8 else name[:7] + "+"

    def _start_column(self, session: bool, shell) -> str:
        when = shell.login_time if session else self.identity.boot_time
        stamp = datetime.fromtimestamp(when, self._tz())
        if self._now().timestamp() - when < 86400:
            return stamp.strftime("%H:%M")
        return stamp.strftime("%b%d")

    def _cmd_ps(self, args, shell, username, is_root):
        joined = "".join(args)
        command = "ps " + " ".join(args) if args else "ps"
        table_rows = self._all_processes(shell, username, is_root, command)
        own_pids = {p.pid for p in table_rows[-4:] if p.tty == "pts/0"}
        everything = any(flag in joined for flag in ("a", "e", "A", "x")) and bool(args)
        if not everything:
            lines = ["    PID TTY          TIME CMD"]
            for proc in table_rows:
                if proc.tty == "pts/0":
                    lines.append(f"{proc.pid:>7} {proc.tty:<8} 00:00:00 {proc.name}")
            return "\n".join(lines) + "\n", 0
        total_kb = self.identity.mem_kb
        if "u" in joined and "-" not in args[0][:1] or joined in ("aux", "-aux", "auxf", "auxw", "auxww", "axu", "-auxww"):
            lines = ["USER         PID %CPU %MEM    VSZ   RSS TTY      STAT START   TIME COMMAND"]
            for proc in table_rows:
                session = proc.pid in own_pids or proc.command.startswith("sshd: ") and "listener" not in proc.command
                lines.append(
                    f"{self._ps_user(proc.user):<8} {proc.pid:>7} {0.0:4.1f} {proc.rss * 100 / total_kb:4.1f} "
                    f"{proc.vsz:>6} {proc.rss:>5} {proc.tty:<8} {proc.stat:<4} "
                    f"{self._start_column(session, shell):>5}   0:0{(proc.pid * 7) % 4} {proc.command}"
                )
            return "\n".join(lines) + "\n", 0
        if "f" in joined or "l" in joined:
            lines = ["UID          PID    PPID  C STIME TTY          TIME CMD"]
            for proc in table_rows:
                session = proc.pid in own_pids
                lines.append(
                    f"{self._ps_user(proc.user):<8} {proc.pid:>7} {proc.ppid:>7}  0 "
                    f"{self._start_column(session, shell):>5} {proc.tty:<8} 00:00:0{(proc.pid * 7) % 4} {proc.command}"
                )
            return "\n".join(lines) + "\n", 0
        lines = ["    PID TTY          TIME CMD"]
        for proc in table_rows:
            lines.append(f"{proc.pid:>7} {proc.tty:<8} 00:00:0{(proc.pid * 7) % 4} {proc.name}")
        return "\n".join(lines) + "\n", 0

    def _cmd_top(self, args, shell, username, is_root):
        i = self.identity
        m = hostfacts.memory(i)
        rows = self._all_processes(shell, username, is_root, "top")
        userland = [p for p in rows if not p.kernel]
        running = 1
        mib = 1024.0
        out = [
            "top -" + self._uptime_line().rstrip("\n"),
            f"Tasks: {len(rows):3d} total, {running:3d} running, {len(rows) - running:3d} sleeping,   0 stopped,   0 zombie",
            "%Cpu(s):  0.3 us,  0.2 sy,  0.0 ni, 99.5 id,  0.0 wa,  0.0 hi,  0.0 si,  0.0 st",
            f"MiB Mem : {m.total / mib:8.1f} total, {m.free / mib:8.1f} free, {m.used / mib:8.1f} used, {m.buff_cache / mib:8.1f} buff/cache",
            f"MiB Swap: {m.swap_total / mib:8.1f} total, {(m.swap_total - m.swap_used) / mib:8.1f} free, {m.swap_used / mib:8.1f} used. {m.available / mib:8.1f} avail Mem ",
            "",
            "    PID USER      PR  NI    VIRT    RES    SHR S  %CPU  %MEM     TIME+ COMMAND",
        ]
        ordered = sorted(userland, key=lambda p: -p.rss) + [p for p in rows if p.kernel]
        for proc in ordered[:60]:
            state = "R" if proc.name == "top" else ("I" if proc.kernel and proc.stat.startswith("I") else "S")
            out.append(
                f"{proc.pid:>7} {self._ps_user(proc.user):<8}  20   0 {proc.vsz:>7} {proc.rss:>6} {proc.rss * 2 // 3:>6} {state} "
                f"{0.0:5.1f} {proc.rss * 100 / i.mem_kb:5.1f} {0:>3}:0{(proc.pid * 7) % 6}.{(proc.pid * 13) % 100:02d} {proc.name[:15]}"
            )
        return "\n".join(out) + "\n", 0

    def _matching(self, shell, username, is_root, patterns: list[str], full: bool, exact: bool) -> list[Process]:
        found = []
        for proc in self._all_processes(shell, username, is_root, "pgrep")[:-1]:
            subject = proc.command if full else proc.name
            for pattern in patterns:
                if (subject == pattern) if exact else (pattern in subject):
                    found.append(proc)
                    break
        return found

    def _cmd_pgrep(self, args, shell, username, is_root):
        flags, _values, patterns = self._split_flags(args, "uUGgPts")
        if not patterns:
            return "pgrep: no matching criteria specified\nTry `pgrep --help' for more information.\n", 2
        found = self._matching(shell, username, is_root, patterns, "f" in flags, "x" in flags)
        if "c" in flags:
            return f"{len(found)}\n", 0 if found else 1
        lines = [f"{p.pid} {p.name}" if "l" in flags else (f"{p.pid} {p.command}" if "a" in flags else str(p.pid)) for p in found]
        return "\n".join(lines) + ("\n" if lines else ""), 0 if found else 1

    def _cmd_pidof(self, args, shell, username, is_root):
        names = [a for a in args if not a.startswith("-")]
        found = self._matching(shell, username, is_root, names, False, True)
        return (" ".join(str(p.pid) for p in reversed(found)) + "\n", 0) if found else ("\n", 1)

    def _kill(self, shell, is_root, victims: list[Process]) -> None:
        killed = getattr(shell, "killed", None)
        if killed is None:
            killed = shell.killed = set()
        for proc in victims:
            if (is_root or proc.user == shell.username) and len(killed) < 512:
                killed.add(proc.pid)

    def _cmd_kill(self, args, shell, username, is_root):
        if "-l" in args:
            return (" 1) SIGHUP\t 2) SIGINT\t 3) SIGQUIT\t 4) SIGILL\t 5) SIGTRAP\n"
                    " 6) SIGABRT\t 7) SIGBUS\t 8) SIGFPE\t 9) SIGKILL\t10) SIGUSR1\n"
                    "11) SIGSEGV\t12) SIGUSR2\t13) SIGPIPE\t14) SIGALRM\t15) SIGTERM\n"), 0
        targets = [a for a in args if not a.startswith("-") or a[1:].isdigit() and args.index(a) > 0 and False]
        if not targets:
            return "kill: usage: kill [-s sigspec | -n signum | -sigspec] pid | jobspec ... or kill -l [sigspec]\n", 2
        known = {p.pid: p for p in self._all_processes(shell, username, is_root, "kill")}
        out, code = [], 0
        for target in targets:
            if not target.lstrip("%").isdigit():
                out.append(f"-bash: kill: {target}: arguments must be process or job IDs")
                code = 1
                continue
            proc = known.get(int(target[:9]))
            if proc is None:
                out.append(f"-bash: kill: ({target}) - No such process")
                code = 1
            elif not is_root and proc.user != (username or "user"):
                out.append(f"-bash: kill: ({target}) - Operation not permitted")
                code = 1
            else:
                self._kill(shell, is_root, [proc])
        return "\n".join(out) + ("\n" if out else ""), code

    def _cmd_pkill(self, args, shell, username, is_root):
        flags, _values, patterns = self._split_flags(args, "uUGgPts")
        patterns = [p for p in patterns if not p.isdigit() or len(patterns) == 1]
        if not patterns:
            return "pkill: no matching criteria specified\nTry `pkill --help' for more information.\n", 2
        found = self._matching(shell, username, is_root, patterns, "f" in flags, "x" in flags)
        self._kill(shell, is_root, found)
        return "", 0 if found else 1

    def _cmd_killall(self, args, shell, username, is_root):
        names = [a for a in args if not a.startswith("-")]
        if not names:
            return "Usage: killall [OPTION]... [--] NAME...\n", 1
        out, code = [], 0
        for name in names:
            found = self._matching(shell, username, is_root, [name], False, True)
            if not found:
                out.append(f"{name}: no process found")
                code = 1
            self._kill(shell, is_root, found)
        return "\n".join(out) + ("\n" if out else ""), code

    # -- network -----------------------------------------------------------

    def _cmd_ifconfig(self, args, shell, username, is_root):
        i = self.identity
        rx_bytes, rx, tx_bytes, tx = hostfacts.interface_counters(i)
        mac = i.mac.split(":")
        link_local = f"fe80::{int(mac[0], 16) ^ 2:x}{mac[1]}:{mac[2]}ff:fe{mac[3]}:{mac[4]}{mac[5]}"
        return (
            "eth0: flags=4163<UP,BROADCAST,RUNNING,MULTICAST>  mtu 1500\n"
            f"        inet {i.ip}  netmask {i.netmask}  broadcast {i.gateway.rsplit('.', 1)[0]}.255\n"
            f"        inet6 {link_local}  prefixlen 64  scopeid 0x20<link>\n"
            f"        ether {i.mac}  txqueuelen 1000  (Ethernet)\n"
            f"        RX packets {rx}  bytes {rx_bytes} ({rx_bytes / 1e6:.1f} MB)\n"
            "        RX errors 0  dropped 0  overruns 0  frame 0\n"
            f"        TX packets {tx}  bytes {tx_bytes} ({tx_bytes / 1e6:.1f} MB)\n"
            "        TX errors 0  dropped 0 overruns 0  carrier 0  collisions 0\n\n"
            "lo: flags=73<UP,LOOPBACK,RUNNING>  mtu 65536\n"
            "        inet 127.0.0.1  netmask 255.0.0.0\n"
            "        inet6 ::1  prefixlen 128  scopeid 0x10<host>\n"
            "        loop  txqueuelen 1000  (Local Loopback)\n"
            "        RX packets 2104  bytes 184320 (184.3 KB)\n"
            "        RX errors 0  dropped 0  overruns 0  frame 0\n"
            "        TX packets 2104  bytes 184320 (184.3 KB)\n"
            "        TX errors 0  dropped 0 overruns 0  carrier 0  collisions 0\n\n"
        ), 0

    def _cmd_ip(self, args, shell, username, is_root):
        i = self.identity
        words = [a for a in args if not a.startswith("-")]
        brief = any(a in ("-br", "-brief") for a in args)
        subject = words[0] if words else ""
        prefix = i.ip.rsplit(".", 1)[0]
        if subject.startswith("a"):
            if brief:
                return f"lo               UNKNOWN        127.0.0.1/8 ::1/128 \neth0             UP             {i.ip}/24 \n", 0
            return (
                "1: lo: <LOOPBACK,UP,LOWER_UP> mtu 65536 qdisc noqueue state UNKNOWN group default qlen 1000\n"
                "    link/loopback 00:00:00:00:00:00 brd 00:00:00:00:00:00\n"
                "    inet 127.0.0.1/8 scope host lo\n       valid_lft forever preferred_lft forever\n"
                "    inet6 ::1/128 scope host \n       valid_lft forever preferred_lft forever\n"
                "2: eth0: <BROADCAST,MULTICAST,UP,LOWER_UP> mtu 1500 qdisc fq_codel state UP group default qlen 1000\n"
                f"    link/ether {i.mac} brd ff:ff:ff:ff:ff:ff\n"
                f"    inet {i.ip}/24 brd {prefix}.255 scope global eth0\n"
                "       valid_lft forever preferred_lft forever\n"
            ), 0
        if subject.startswith("r"):
            return (
                f"default via {i.gateway} dev eth0 proto static \n"
                f"{prefix}.0/24 dev eth0 proto kernel scope link src {i.ip} \n"
            ), 0
        if subject.startswith("l"):
            return (
                "1: lo: <LOOPBACK,UP,LOWER_UP> mtu 65536 qdisc noqueue state UNKNOWN mode DEFAULT group default qlen 1000\n"
                "    link/loopback 00:00:00:00:00:00 brd 00:00:00:00:00:00\n"
                "2: eth0: <BROADCAST,MULTICAST,UP,LOWER_UP> mtu 1500 qdisc fq_codel state UP mode DEFAULT group default qlen 1000\n"
                f"    link/ether {i.mac} brd ff:ff:ff:ff:ff:ff\n"
            ), 0
        if subject.startswith("n"):
            return f"{i.gateway} dev eth0 lladdr {i.mac[:9]}00:00:01 REACHABLE\n", 0
        return ("Usage: ip [ OPTIONS ] OBJECT { COMMAND | help }\n"
                "where  OBJECT := { link | address | route | neigh | rule | netns }\n"), 255

    def _cmd_route(self, args, shell, username, is_root):
        i = self.identity
        prefix = i.ip.rsplit(".", 1)[0]
        return (
            "Kernel IP routing table\n"
            "Destination     Gateway         Genmask         Flags Metric Ref    Use Iface\n"
            f"{'0.0.0.0' if '-n' in args else 'default':<15} {i.gateway:<15} 0.0.0.0         UG    0      0        0 eth0\n"
            f"{prefix + '.0':<15} 0.0.0.0         255.255.255.0   U     0      0        0 eth0\n"
        ), 0

    def _connections(self, shell) -> list[tuple[str, str, int, str, int]]:
        """Established connections: the visitor's own."""
        if not shell.client_ip:
            return []
        return [("tcp", self.identity.ip, 22, shell.client_ip, shell.client_port or 40000)]

    @staticmethod
    def _socket_flags(args: list[str]) -> str:
        return "".join(a[1:] for a in args if a.startswith("-") and not a.startswith("--"))

    def _cmd_netstat(self, args, shell, username, is_root):
        flags = self._socket_flags(args)
        if "r" in flags:
            return self._cmd_route(["-n"] if "n" in flags else [], shell, username, is_root)
        if "i" in flags:
            _rxb, rx, _txb, tx = hostfacts.interface_counters(self.identity)
            return (
                "Kernel Interface table\n"
                "Iface      MTU    RX-OK RX-ERR RX-DRP RX-OVR    TX-OK TX-ERR TX-DRP TX-OVR Flg\n"
                f"eth0      1500 {rx:>8}      0      0 0      {tx:>8}      0      0      0 BMRU\n"
                "lo       65536     2104      0      0 0          2104      0      0      0 LRU\n"
            ), 0
        numeric = "n" in flags
        listening = "l" in flags or "a" in flags
        established = "l" not in flags
        want_tcp = "t" in flags or "u" not in flags
        want_udp = "u" in flags or "t" not in flags
        programs = "p" in flags

        def endpoint(address: str, port: int) -> str:
            host = address
            if not numeric:
                host = {"127.0.0.1": "localhost", "127.0.0.53": "localhost", "::": "[::]"}.get(address, address)
            service = str(port) if numeric else _SERVICES.get(port, str(port))
            return f"{':::' if address == '::' and numeric else host + ':'}{service}"

        title = "(only servers)" if "l" in flags else ("(servers and established)" if "a" in flags else "(w/o servers)")
        lines = [f"Active Internet connections {title}"]
        header = "Proto Recv-Q Send-Q Local Address           Foreign Address         State      "
        lines.append(header + (" PID/Program name    " if programs else ""))
        rows = []
        if established and want_tcp:
            for proto, local, lport, remote, rport in self._connections(shell):
                rows.append((proto, f"{local}:{'ssh' if not numeric else lport}", f"{remote}:{rport}", "ESTABLISHED",
                             f"{shell.pid - 2}/sshd: root@pts"))
        if listening:
            for sock in hostfacts.listeners(self.identity):
                if (sock.proto == "tcp" and not want_tcp) or (sock.proto == "udp" and not want_udp):
                    continue
                proto = sock.proto + ("6" if sock.address == "::" else "")
                peer = ":::*" if sock.address == "::" else "0.0.0.0:*"
                owner = f"{sock.pid}/{sock.program}" if (is_root or sock.pid == 0) else "-"
                rows.append((proto, endpoint(sock.address, sock.port), peer,
                             "LISTEN" if sock.proto == "tcp" else "", owner))
        for proto, local, peer, state, owner in rows:
            line = f"{proto:<5} {0:>6} {0:>6} {local:<23} {peer:<23} {state:<11}"
            lines.append(line + (f" {owner[:19]:<19}" if programs else ""))
        return "\n".join(l.rstrip() if not programs else l for l in lines) + "\n", 0

    def _cmd_ss(self, args, shell, username, is_root):
        flags = self._socket_flags(args)
        if "s" in flags and len(flags.replace("s", "")) == 0:
            listeners = hostfacts.listeners(self.identity)
            tcp = sum(1 for s in listeners if s.proto == "tcp")
            return (
                f"Total: {140 + len(listeners)}\n"
                f"TCP:   {tcp + 1} (estab 1, closed 0, orphaned 0, timewait 0)\n\n"
                "Transport Total     IP        IPv6\nRAW\t  0         0         0        \n"
                f"UDP\t  {len(listeners) - tcp}         {len(listeners) - tcp}         0        \n"
                f"TCP\t  {tcp + 1}         {tcp}         1        \nINET\t  {len(listeners) + 1}         {len(listeners)}         1        \n"
                "FRAG\t  0         0         0        \n\n"
            ), 0
        listening = "l" in flags or "a" in flags
        established = "l" not in flags
        want_tcp = "t" in flags or "u" not in flags
        want_udp = "u" in flags or "t" not in flags
        programs = "p" in flags
        rows: list[list[str]] = []
        if "H" not in flags:
            rows.append(["Netid", "State", "Recv-Q", "Send-Q", "Local Address:Port", "Peer Address:Port", "Process"])
        if listening:
            # The same sockets netstat lists, in ss's notation.
            for sock in hostfacts.listeners(self.identity):
                if (sock.proto == "tcp" and not want_tcp) or (sock.proto == "udp" and not want_udp):
                    continue
                if sock.address == "::":
                    local, peer = f"[::]:{sock.port}", "[::]:*"
                elif sock.address == "127.0.0.53":
                    local, peer = f"127.0.0.53%lo:{sock.port}", "0.0.0.0:*"
                else:
                    local, peer = f"{sock.address}:{sock.port}", "0.0.0.0:*"
                owner = f'users:(("{sock.program}",pid={sock.pid},fd={3 + sock.port % 9}))' if (programs and is_root) else ""
                rows.append([sock.proto, "LISTEN" if sock.proto == "tcp" else "UNCONN", "0", str(sock.backlog), local, peer, owner])
        if established and want_tcp:
            for proto, local, lport, remote, rport in self._connections(shell):
                owner = f'users:(("sshd",pid={shell.pid - 2},fd=4))' if (programs and is_root) else ""
                rows.append([proto, "ESTAB", "0", "0", f"{local}:{lport}", f"{remote}:{rport}", owner])
        return table(rows, left=(0, 1, 6)), 0

    def _resolve_host(self, host: str) -> str:
        return host if dropper.is_ip_literal(host) else dropper.resolved_address(host, self.identity.seed)

    def _cmd_ping(self, args, shell, username, is_root):
        flags, values, operands = self._split_flags(args, "cisWwtIq")
        if not operands:
            return "ping: usage error: Destination address required\n", 1
        host = operands[0][:253]
        address = self._resolve_host(host)
        try:
            count = max(1, min(4, int(values.get("c", "4")[:4])))
        except ValueError:
            count = 4
        rng = random.Random(f"{self.identity.seed}:ping:{address}")
        base = rng.uniform(0.9, 48.0)
        times = [base + rng.uniform(-0.4, 0.6) for _ in range(count)]
        ttl = rng.choice([52, 54, 56, 57, 115, 117, 118])
        lines = [f"PING {host} ({address}) 56(84) bytes of data."]
        for index, elapsed in enumerate(times, start=1):
            lines.append(f"64 bytes from {address}: icmp_seq={index} ttl={ttl} time={elapsed:.2f} ms" if elapsed < 10
                         else f"64 bytes from {address}: icmp_seq={index} ttl={ttl} time={elapsed:.1f} ms")
        mean = sum(times) / count
        deviation = (sum((t - mean) ** 2 for t in times) / count) ** 0.5
        lines += [
            "", f"--- {host} ping statistics ---",
            f"{count} packets transmitted, {count} received, 0% packet loss, time {(count - 1) * 1001}ms",
            f"rtt min/avg/max/mdev = {min(times):.3f}/{mean:.3f}/{max(times):.3f}/{deviation:.3f} ms",
        ]
        return "\n".join(lines) + "\n", 0

    def _cmd_nslookup(self, args, shell, username, is_root):
        names = [a for a in args if not a.startswith("-")]
        if not names:
            return "", 0
        return (
            "Server:\t\t127.0.0.53\nAddress:\t127.0.0.53#53\n\n"
            f"Non-authoritative answer:\nName:\t{names[0][:253]}\nAddress: {self._resolve_host(names[0][:253])}\n\n"
        ), 0

    def _cmd_host(self, args, shell, username, is_root):
        names = [a for a in args if not a.startswith("-")]
        if not names:
            return "Usage: host [-aCdilrTvVw] [-c class] [-N ndots] [-t type] [-W time]\n            [-R number] [-m flag] hostname [server]\n", 1
        return f"{names[0][:253]} has address {self._resolve_host(names[0][:253])}\n", 0

    def _unreachable(self, tool: str, args, port: int):
        hosts = [a for a in args if not a.startswith("-")]
        if not hosts:
            return None
        host = hosts[0].rsplit("@", 1)[-1].split(":", 1)[0][:253]
        return host

    def _cmd_ssh(self, args, shell, username, is_root):
        host = self._unreachable("ssh", args, 22)
        if host is None:
            return ("usage: ssh [-46AaCfGgKkMNnqsTtVvXxYy] [-B bind_interface]\n"
                    "           [-b bind_address] [-c cipher_spec] [-D [bind_address:]port]\n"
                    "           destination [command]\n"), 255
        return f"ssh: connect to host {host} port 22: Connection timed out\n", 255

    def _cmd_scp(self, args, shell, username, is_root):
        remote = next((a for a in args if ":" in a and not a.startswith("-")), None)
        if remote is None:
            return "usage: scp [-346BCpqrTv] [-c cipher] [-F ssh_config] [-i identity_file]\n            [-J destination] [-l limit] [-o ssh_option] [-P port]\n            [-S program] source ... target\n", 1
        host = remote.split(":", 1)[0].rsplit("@", 1)[-1][:253]
        return f"ssh: connect to host {host} port 22: Connection timed out\nlost connection\n", 1

    def _cmd_telnet(self, args, shell, username, is_root):
        hosts = [a for a in args if not a.startswith("-")]
        if not hosts:
            return "", 0
        address = self._resolve_host(hosts[0][:253])
        return f"Trying {address}...\ntelnet: Unable to connect to remote host: Connection timed out\n", 1

    def _cmd_nc(self, args, shell, username, is_root):
        if not [a for a in args if not a.startswith("-")]:
            return ("usage: nc [-46CDdFhklNnrStUuvZz] [-I length] [-i interval] [-M ttl]\n"
                    "\t  [-m minttl] [-O length] [-P proxy_username] [-p source_port]\n"
                    "\t  [-q seconds] [-s source] [-T keyword] [-V rtable] [-W recvlimit] [-w timeout]\n"
                    "\t  [-X proxy_protocol] [-x proxy_address[:port]] \t  [destination] [port]\n"), 1
        return "", 1

    def _cmd_netcat(self, args, shell, username, is_root):
        return self._cmd_nc(args, shell, username, is_root)

    def _cmd_iptables(self, args, shell, username, is_root):
        if not is_root:
            return "iptables v1.8.4 (legacy): can't initialize iptables table `filter': Permission denied (you must be root)\nPerhaps iptables or your kernel needs to be upgraded.\n", 3
        if any(a in ("-L", "--list") for a in args):
            return ("Chain INPUT (policy ACCEPT)\ntarget     prot opt source               destination         \n\n"
                    "Chain FORWARD (policy ACCEPT)\ntarget     prot opt source               destination         \n\n"
                    "Chain OUTPUT (policy ACCEPT)\ntarget     prot opt source               destination         \n"), 0
        if any(a in ("-S", "--list-rules") for a in args):
            return "-P INPUT ACCEPT\n-P FORWARD ACCEPT\n-P OUTPUT ACCEPT\n", 0
        return "", 0

    def _cmd_ufw(self, args, shell, username, is_root):
        if not is_root:
            return "ERROR: You need to be root to run this script\n", 1
        return ("Status: inactive\n", 0) if "status" in args else ("", 0)

    # -- storage and kernel ------------------------------------------------

    def _cmd_lsblk(self, args, shell, username, is_root):
        size = f"{self.identity.disk_total_kb // (1024 * 1024)}G"
        return (
            "NAME   MAJ:MIN RM  SIZE RO TYPE MOUNTPOINT\n"
            f"vda    252:0    0 {size:>4}  0 disk \n"
            f"└─vda1 252:1    0 {size:>4}  0 part /\n"
        ), 0

    def _cmd_mount(self, args, shell, username, is_root):
        if args:
            return ("", 0) if is_root else ("mount: only root can do that\n", 1)
        lines = []
        for row in hostfacts.mounts(self.identity).splitlines():
            device, where, kind, options = row.split()[:4]
            lines.append(f"{device} on {where} type {kind} ({options})")
        return "\n".join(lines) + "\n", 0

    def _cmd_umount(self, args, shell, username, is_root):
        return ("", 0) if is_root else ("umount: only root can do that\n", 1)

    def _cmd_dmesg(self, args, shell, username, is_root):
        i = self.identity
        product, vendor, hypervisor = hostfacts.platform_facts(i)
        return (
            f"[    0.000000] Linux version {i.kernel} (buildd@lcy02-amd64-045) (gcc version 9.4.0 (Ubuntu 9.4.0-1ubuntu1~20.04.1)) {i.kernel_build}\n"
            f"[    0.000000] Command line: BOOT_IMAGE=/boot/vmlinuz-{i.kernel} root=UUID={hostfacts.root_uuid(i)} ro console=tty1 console=ttyS0\n"
            f"[    0.000000] DMI: {vendor} {product}\n"
            f"[    0.000000] Hypervisor detected: {hypervisor}\n"
            f"[    0.004000] Memory: {i.mem_kb - 90000}K/{i.mem_kb + 60000}K available\n"
            f"[    0.250000] smp: Brought up 1 node, {i.cpu_cores} CPU{'s' if i.cpu_cores > 1 else ''}\n"
            "[    1.412000] EXT4-fs (vda1): mounted filesystem with ordered data mode. Opts: (null)\n"
            "[    2.960000] systemd[1]: Detected virtualization %s.\n" % hypervisor.lower()
            + f"[    2.961000] systemd[1]: Set hostname to <{i.hostname}>.\n"
        ), 0

    def _cmd_lsmod(self, args, shell, username, is_root):
        rows = [("Module", "Size", "Used by"), ("virtio_net", "53248", "0"), ("net_failover", "20480", "1 virtio_net"),
                ("virtio_blk", "20480", "2"), ("crc32_pclmul", "16384", "0"), ("psmouse", "155648", "0"),
                ("floppy", "81920", "0"), ("failover", "16384", "1 net_failover")]
        return "".join(f"{name:<22} {size:>6}  {used}\n" for name, size, used in rows), 0

    def _cmd_sysctl(self, args, shell, username, is_root):
        i = self.identity
        values = {
            "kernel.hostname": i.hostname, "kernel.osrelease": i.kernel, "kernel.ostype": "Linux",
            "kernel.version": i.kernel_build, "vm.swappiness": "60", "net.ipv4.ip_forward": "0",
            "kernel.pid_max": "4194304", "fs.file-max": "9223372036854775807",
        }
        names = [a for a in args if not a.startswith("-")]
        if "-a" in args or not names:
            return "".join(f"{k} = {v}\n" for k, v in sorted(values.items())), 0
        out, code = [], 0
        for name in names:
            key = name.split("=", 1)[0]
            if "=" in name:
                if not is_root:
                    out.append(f"sysctl: permission denied on key '{key}'")
                    code = 255
                else:
                    out.append(f"{key} = {name.split('=', 1)[1]}")
            elif key in values:
                out.append(f"{key} = {values[key]}")
            else:
                out.append(f"sysctl: cannot stat /proc/sys/{key.replace('.', '/')}: No such file or directory")
                code = 255
        return "\n".join(out) + "\n", code

    def _cmd_getent(self, args, shell, username, is_root):
        if not args:
            return "Usage: getent [OPTION...] database [key ...]\n", 1
        source = {"passwd": hostfacts.passwd, "group": hostfacts.group}.get(args[0])
        if source is None:
            return ("", 2) if args[0] != "hosts" else (f"127.0.0.1       localhost\n", 0)
        rows = source(self.identity).splitlines()
        if len(args) > 1:
            rows = [r for r in rows if r.split(":", 1)[0] in args[1:]]
        return "\n".join(rows) + ("\n" if rows else ""), 0 if rows else 2

    # -- services and packages ---------------------------------------------

    def _unit(self, name: str):
        key = name[:-8] if name.endswith(".service") else name
        unit = _UNITS.get(key)
        if unit is None:
            return None
        proc = hostfacts.process_named(self.identity, unit[2])
        return (unit[0], unit[1], proc) if proc is not None else None

    def _unit_status(self, name: str) -> tuple[str, int]:
        unit = self._unit(name)
        if unit is None:
            shown = name if name.endswith(".service") else name + ".service"
            return f"Unit {shown} could not be found.\n", 4
        unit_name, description, proc = unit
        since = datetime.fromtimestamp(self.identity.boot_time + 9, self._tz())
        days = int(self.identity.uptime_seconds // 86400)
        ago = f"{days} day{'s' if days != 1 else ''} ago" if days else "today"
        return (
            f"● {unit_name} - {description}\n"
            f"     Loaded: loaded (/lib/systemd/system/{unit_name}; enabled; vendor preset: enabled)\n"
            f"     Active: active (running) since {since.strftime('%a %Y-%m-%d %H:%M:%S %Z')}; {ago}\n"
            f"   Main PID: {proc.pid} ({proc.name})\n"
            f"      Tasks: 1 (limit: {self.identity.mem_kb // 860})\n"
            f"     Memory: {proc.rss / 1024:.1f}M\n"
            f"     CGroup: /system.slice/{unit_name}\n"
            f"             └─{proc.pid} {proc.command}\n"
        ), 0

    def _cmd_systemctl(self, args, shell, username, is_root):
        words = [a for a in args if not a.startswith("-")]
        if not words:
            return "", 0
        verb, units = words[0], words[1:]
        if verb == "status":
            if not units:
                return f"● {self.identity.hostname}\n    State: running\n     Jobs: 0 queued\n   Failed: 0 units\n", 0
            return self._unit_status(units[0])
        if verb in ("is-active", "is-enabled"):
            known = bool(units) and self._unit(units[0]) is not None
            answer = ("active" if known else "inactive") if verb == "is-active" else ("enabled" if known else "disabled")
            return answer + "\n", 0 if known else (3 if verb == "is-active" else 1)
        if verb in ("start", "stop", "restart", "reload", "enable", "disable", "mask", "unmask", "daemon-reload", "kill"):
            if not is_root:
                return (f"Failed to {verb} {units[0] if units else ''}: Interactive authentication required.\n"
                        "See system logs and 'systemctl status' for details.\n"), 1
            return "", 0
        return "", 0

    def _cmd_service(self, args, shell, username, is_root):
        if len(args) >= 2 and args[1] == "status":
            return self._unit_status(args[0])
        if "--status-all" in args:
            return "".join(f" [ + ]  {name}\n" for name in ("cron", "mysql", "rsyslog", "ssh", "udev")), 0
        return ("", 0) if is_root or len(args) < 2 else (f"Failed to {args[1]} {args[0]}.service: Interactive authentication required.\n", 1)

    def _cmd_journalctl(self, args, shell, username, is_root):
        return "-- Logs begin at %s. --\n" % datetime.fromtimestamp(self.identity.boot_time, self._tz()).strftime("%a %Y-%m-%d %H:%M:%S %Z"), 0

    def _cmd_crontab(self, args, shell, username, is_root):
        if "-l" in args:
            return "no crontab for " + ("root" if is_root else (username or "user")) + "\n", 1
        return "", 0

    def _apt(self, args, shell, username, is_root):
        from honeypot.core.vfs import PROGRAMS

        words = [a for a in args if not a.startswith("-")]
        verb = words[0] if words else ""
        if verb in ("install", "remove", "purge", "upgrade", "dist-upgrade", "update", "autoremove", "full-upgrade") and not is_root:
            if verb == "update":
                return ("Reading package lists... Done\n"
                        "E: Could not open lock file /var/lib/apt/lists/lock - open (13: Permission denied)\n"
                        "E: Unable to lock directory /var/lib/apt/lists/\n"), 100
            return ("E: Could not open lock file /var/lib/dpkg/lock-frontend - open (13: Permission denied)\n"
                    "E: Unable to acquire the dpkg frontend lock (/var/lib/dpkg/lock-frontend), are you root?\n"), 100
        if verb == "update":
            return ("Hit:1 http://archive.ubuntu.com/ubuntu focal InRelease\n"
                    "Hit:2 http://archive.ubuntu.com/ubuntu focal-updates InRelease\n"
                    "Hit:3 http://security.ubuntu.com/ubuntu focal-security InRelease\n"
                    "Reading package lists... Done\n"), 0
        preamble = "Reading package lists... Done\nBuilding dependency tree       \nReading state information... Done\n"
        if verb == "install":
            lines = [preamble.rstrip("\n")]
            for package in words[1:8]:
                if package not in PROGRAMS and package not in ("net-tools", "openssh-server", "cron", "coreutils"):
                    return preamble + f"E: Unable to locate package {package[:64]}\n", 100
                lines.append(f"{package} is already the newest version.")
            lines.append("0 upgraded, 0 newly installed, 0 to remove and 0 not upgraded.")
            return "\n".join(lines) + "\n", 0
        if verb in ("upgrade", "dist-upgrade", "full-upgrade", "autoremove", "remove", "purge"):
            return preamble + "0 upgraded, 0 newly installed, 0 to remove and 0 not upgraded.\n", 0
        return "", 0

    def _cmd_apt(self, args, shell, username, is_root):
        return self._apt(args, shell, username, is_root)

    def _cmd_apt_get(self, args, shell, username, is_root):
        return self._apt(args, shell, username, is_root)

    def _cmd_dpkg(self, args, shell, username, is_root):
        if "--print-architecture" in args:
            return "amd64\n", 0
        return "", 0

    # -- interpreters and editors ------------------------------------------

    def _cmd_python3(self, args, shell, username, is_root):
        if args and args[0] in ("-V", "--version"):
            return "Python 3.8.10\n", 0
        # What a program prints cannot be known without running it.
        return "", 0

    def _cmd_perl(self, args, shell, username, is_root):
        return "", 0

    def _cmd_mysql(self, args, shell, username, is_root):
        user = "root"
        for index, arg in enumerate(args):
            if arg == "-u" and index + 1 < len(args):
                user = args[index + 1]
            elif arg.startswith("-u") and len(arg) > 2:
                user = arg[2:]
            elif arg.startswith("--user="):
                user = arg.split("=", 1)[1]
        password = any(a.startswith("-p") or a.startswith("--password") for a in args)
        return (f"ERROR 1045 (28000): Access denied for user '{user[:32]}'@'localhost' "
                f"(using password: {'YES' if password else 'NO'})\n"), 1

    def _editor(self, args, shell, username, is_root):
        return "", 0

    _cmd_vi = _cmd_vim = _cmd_nano = _editor

    def _cmd_logger(self, args, shell, username, is_root):
        return "", 0

    def _cmd_sync(self, args, shell, username, is_root):
        return "", 0

    def _cmd_nice(self, args, shell, username, is_root):
        return "0\n", 0

    def _cmd_modprobe(self, args, shell, username, is_root):
        return ("", 0) if is_root else ("modprobe: ERROR: could not insert module: Operation not permitted\n", 1)

    def _power(self, args, shell, username, is_root):
        # A reboot that never happens would be noticed; refusing it is not.
        if not is_root:
            return "Failed to set wall message, ignoring: Interactive authentication required.\nFailed to reboot system via logind: Interactive authentication required.\n", 1
        return "", 0

    _cmd_reboot = _cmd_shutdown = _cmd_halt = _cmd_poweroff = _power
