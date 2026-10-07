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
"""

from __future__ import annotations

import posixpath
import random
from datetime import datetime, timedelta, timezone
from typing import Optional

from honeypot.core.identity import HostIdentity
from honeypot.core.shell_state import DroppedFile, ShellState, resolve_path

#: Where common programs live, for ``which`` / ``type`` / ``command -v``.
_BIN = "/usr/bin/"
_SBIN = "/usr/sbin/"
_PATHS = {}
for _n in (
    "awk sed grep egrep fgrep cat tac head tail cut sort uniq wc tr tee less more "
    "ls cp mv rm mkdir rmdir touch ln find xargs chmod chown chgrp stat file du df "
    "date uptime who whoami id groups env printenv export tty hostname uname arch "
    "ps top kill pkill pgrep nohup nice sleep watch crontab at bash sh dash "
    "wget curl scp sftp ssh nc ncat socat ftp tftp ping traceroute dig host "
    "tar gzip gunzip bzip2 xz zip unzip base64 md5sum sha1sum sha256sum openssl "
    "python3 perl awk vi vim nano apt apt-get dpkg systemctl service "
    "ifconfig route netstat ss ip iptables lscpu nproc free lsblk lsb_release"
).split():
    _PATHS[_n] = (_SBIN if _n in {"ifconfig", "route", "iptables", "service", "ssh", "sshd"} else _BIN) + _n
_PATHS.update({"sudo": "/usr/bin/sudo", "su": "/bin/su", "cd": "", "echo": "", "pwd": "",
               "which": "/usr/bin/which", "clear": "/usr/bin/clear", "ps": "/usr/bin/ps",
               "ip": "/usr/sbin/ip", "ss": "/usr/bin/ss", "mount": "/usr/bin/mount"})

#: Shell builtins — ``which x`` fails for these on a real system, ``type`` names them.
_BUILTINS = {"cd", "echo", "pwd", "export", "alias", "unalias", "set", "unset",
             "source", ".", "exit", "logout", "history", "type", "umask", "read",
             "test", "[", "true", "false", "jobs", "fg", "bg", "wait", "kill", "help"}


def _fmt_size(kb: int) -> str:
    if kb >= 1024 * 1024:
        return f"{kb / 1024 / 1024:.0f}G"
    if kb >= 1024:
        return f"{kb / 1024:.0f}M"
    return f"{kb}K"


def _passwd(identity: HostIdentity) -> str:
    rows = [
        ("root", 0, 0, "root", "/root", "/bin/bash"),
        ("daemon", 1, 1, "daemon", "/usr/sbin", "/usr/sbin/nologin"),
        ("bin", 2, 2, "bin", "/bin", "/usr/sbin/nologin"),
        ("sys", 3, 3, "sys", "/dev", "/usr/sbin/nologin"),
        ("sync", 4, 65534, "sync", "/bin", "/bin/sync"),
        ("www-data", 33, 33, "www-data", "/var/www", "/usr/sbin/nologin"),
        ("sshd", 110, 65534, "", "/run/sshd", "/usr/sbin/nologin"),
        ("systemd-network", 100, 102, "", "/run/systemd", "/usr/sbin/nologin"),
    ]
    lines = [f"{n}:x:{u}:{g}:{gecos}:{h}:{s}" for n, u, g, gecos, h, s in rows]
    for name, uid, home, shell in identity.users:
        lines.append(f"{name}:x:{uid}:{uid}:{name.title()},,,:{home}:{shell}")
    return "\n".join(lines) + "\n"


def _cpuinfo(identity: HostIdentity) -> str:
    blocks = []
    for n in range(identity.cpu_cores):
        blocks.append(
            f"processor\t: {n}\n"
            "vendor_id\t: GenuineIntel\n"
            "cpu family\t: 6\n"
            "model\t\t: 85\n"
            f"model name\t: {identity.cpu_model}\n"
            "stepping\t: 7\n"
            f"cpu MHz\t\t: {identity.cpu_mhz:.3f}\n"
            "cache size\t: 25344 KB\n"
            f"physical id\t: 0\ncore id\t\t: {n}\ncpu cores\t: {identity.cpu_cores}\n"
            "fpu\t\t: yes\n"
            "flags\t\t: fpu vme de pse tsc msr pae mce cx8 apic sep mtrr pge mca "
            "cmov pat pse36 clflush mmx fxsr sse sse2 ss ht syscall nx pdpe1gb "
            "rdtscp lm constant_tsc rep_good nopl xtopology nonstop_tsc cpuid "
            "pni pclmulqdq ssse3 fma cx16 pcid sse4_1 sse4_2 x2apic movbe popcnt "
            "aes xsave avx f16c rdrand hypervisor lahf_lm abm 3dnowprefetch "
            "invpcid_single pti fsgsbase bmi1 avx2 smep bmi2 erms invpcid\n"
            f"bogomips\t: {identity.cpu_mhz * 2:.2f}\n"
            "clflush size\t: 64\ncache_alignment\t: 64\n"
            "address sizes\t: 46 bits physical, 48 bits virtual\n"
        )
    return "\n".join(blocks) + "\n"


def _free(identity: HostIdentity) -> str:
    total = identity.mem_kb
    used = int(total * 0.32)
    free = int(total * 0.18)
    buff = total - used - free
    avail = free + int(buff * 0.7)
    sw = identity.swap_kb
    sw_used = int(sw * 0.05) if sw else 0
    return (
        "               total        used        free      shared  buff/cache   available\n"
        f"Mem:    {total:12d}{used:12d}{free:12d}{int(total*0.004):12d}{buff:12d}{avail:12d}\n"
        f"Swap:   {sw:12d}{sw_used:12d}{sw - sw_used:12d}\n"
    )


def _uptime(identity: HostIdentity) -> str:
    secs = int(identity.uptime_seconds)
    days = secs // 86400
    hm = secs % 86400
    hours, minutes = hm // 3600, (hm % 3600) // 60
    if days:
        up = f"{days} day{'s' if days != 1 else ''}, {hours:2d}:{minutes:02d}"
    else:
        up = f"{hours:2d}:{minutes:02d}"
    now = datetime.now(timezone.utc).strftime("%H:%M:%S")
    la = f"{random.uniform(0, 0.2):.2f}, {random.uniform(0, 0.2):.2f}, {random.uniform(0, 0.1):.2f}"
    return f" {now} up {up},  1 user,  load average: {la}\n"


def _df(identity: HostIdentity) -> str:
    total = identity.disk_total_kb
    used = identity.disk_used_kb
    avail = total - used
    pct = int(used / total * 100)
    return (
        "Filesystem     1K-blocks      Used Available Use% Mounted on\n"
        "udev            {u:9d}         0 {u:9d}   0% /dev\n".format(u=identity.mem_kb // 2)
        + f"tmpfs           {identity.mem_kb // 10:9d}      {random.randint(800, 1800):4d} {identity.mem_kb // 10 - 1200:9d}   1% /run\n"
        + f"/dev/vda1       {total:9d} {used:9d} {avail:9d} {pct:3d}% /\n"
        + "tmpfs           {m:9d}         0 {m:9d}   0% /dev/shm\n".format(m=identity.mem_kb // 2)
    )


def _os_release(identity: HostIdentity) -> str:
    v = identity.os_version
    return (
        'NAME="Ubuntu"\n'
        f'VERSION="{v} LTS (Focal Fossa)"\n'
        'ID=ubuntu\nID_LIKE=debian\n'
        f'PRETTY_NAME="Ubuntu {v} LTS"\n'
        'VERSION_ID="20.04"\n'
        'HOME_URL="https://www.ubuntu.com/"\n'
        'SUPPORT_URL="https://help.ubuntu.com/"\n'
        'BUG_REPORT_URL="https://bugs.launchpad.net/ubuntu/"\n'
        'VERSION_CODENAME=focal\nUBUNTU_CODENAME=focal\n'
    )


def _hosts(identity: HostIdentity) -> str:
    return (
        f"127.0.0.1\tlocalhost\n127.0.1.1\t{identity.hostname}\n\n"
        "# The following lines are desirable for IPv6 capable hosts\n"
        "::1     ip6-localhost ip6-loopback\nfe00::0 ip6-localnet\n"
        "ff00::0 ip6-mcastprefix\nff02::1 ip6-allnodes\nff02::2 ip6-allrouters\n"
    )


def _ifconfig(identity: HostIdentity) -> str:
    rx, tx = random.randint(40000, 900000), random.randint(40000, 900000)
    return (
        "eth0: flags=4163<UP,BROADCAST,RUNNING,MULTICAST>  mtu 1500\n"
        f"        inet {identity.ip}  netmask {identity.netmask}  broadcast {identity.gateway.rsplit('.',1)[0]}.255\n"
        "        inet6 fe80::{a}:{b}ff:fe{c}:{d}  prefixlen 64  scopeid 0x20<link>\n".format(
            a=identity.mac[0:2], b=identity.mac[3:5], c=identity.mac[9:11], d=identity.mac[12:14].replace(":", ""))
        + f"        ether {identity.mac}  txqueuelen 1000  (Ethernet)\n"
        f"        RX packets {rx}  bytes {rx * 86} ({rx * 86 // 1000} KB)\n"
        "        RX errors 0  dropped 0  overruns 0  frame 0\n"
        f"        TX packets {tx}  bytes {tx * 74} ({tx * 74 // 1000} KB)\n"
        "        TX errors 0  dropped 0 overruns 0  carrier 0  collisions 0\n\n"
        "lo: flags=73<UP,LOOPBACK,RUNNING>  mtu 65536\n"
        "        inet 127.0.0.1  netmask 255.0.0.0\n"
        "        inet6 ::1  prefixlen 128  scopeid 0x10<host>\n"
        "        loop  txqueuelen 1000  (Local Loopback)\n"
    )


def _ip_addr(identity: HostIdentity) -> str:
    return (
        "1: lo: <LOOPBACK,UP,LOWER_UP> mtu 65536 qdisc noqueue state UNKNOWN group default qlen 1000\n"
        "    link/loopback 00:00:00:00:00:00 brd 00:00:00:00:00:00\n"
        "    inet 127.0.0.1/8 scope host lo\n       valid_lft forever preferred_lft forever\n"
        "2: eth0: <BROADCAST,MULTICAST,UP,LOWER_UP> mtu 1500 qdisc fq_codel state UP group default qlen 1000\n"
        f"    link/ether {identity.mac} brd ff:ff:ff:ff:ff:ff\n"
        f"    inet {identity.ip}/24 brd {identity.gateway.rsplit('.',1)[0]}.255 scope global eth0\n"
        "       valid_lft forever preferred_lft forever\n"
    )


def _ps(identity: HostIdentity) -> str:
    rows = [
        ("root", 1, 0.0, 0.1, 169404, 11192, "?", "Ss", "/sbin/init"),
        ("root", 2, 0.0, 0.0, 0, 0, "?", "S", "[kthreadd]"),
        ("root", 102, 0.0, 0.0, 0, 0, "?", "I<", "[kworker/0:0H]"),
        ("root", 389, 0.0, 0.2, 102232, 19684, "?", "Ss", "/lib/systemd/systemd-journald"),
        ("root", 421, 0.0, 0.1, 21844, 5312, "?", "Ss", "/lib/systemd/systemd-udevd"),
        ("systemd+", 512, 0.0, 0.1, 90128, 6216, "?", "Ssl", "/lib/systemd/systemd-resolved"),
        ("root", 701, 0.0, 0.1, 72308, 6760, "?", "Ss", "/usr/sbin/sshd -D"),
        ("root", 712, 0.0, 0.1, 12176, 3456, "?", "Ss", "/usr/sbin/cron -f"),
        ("root", 744, 0.0, 0.3, 238512, 25460, "?", "Ssl", "/usr/sbin/apache2 -k start"),
        ("www-data", 801, 0.0, 0.2, 240100, 17840, "?", "S", "/usr/sbin/apache2 -k start"),
    ]
    out = ["USER         PID %CPU %MEM    VSZ   RSS TTY      STAT START   TIME COMMAND"]
    for u, pid, cpu, mem, vsz, rss, tty, stat, cmd in rows:
        out.append(f"{u:<8} {pid:6d} {cpu:4.1f} {mem:4.1f} {vsz:6d} {rss:5d} {tty:<8} {stat:<4} 00:00   0:00 {cmd}")
    bash_pid = random.randint(2000, 9000)
    out.append(f"root     {bash_pid:6d}  0.0  0.1  10048  3284 pts/0    Ss   00:01   0:00 -bash")
    out.append(f"root     {bash_pid+7:6d}  0.0  0.0   8892  1620 pts/0    R+   00:01   0:00 ps aux")
    return "\n".join(out) + "\n"


def _w(identity: HostIdentity) -> str:
    return (
        _uptime(identity)
        + "USER     TTY      FROM             LOGIN@   IDLE   JCPU   PCPU WHAT\n"
        + "root     pts/0    {ip:<15}  00:01    0.00s  0.03s  0.00s w\n".format(
            ip=identity.last_login_ip[:15])
    )


def _last_login_line(identity: HostIdentity) -> str:
    when = datetime.fromtimestamp(identity.last_login_time, tz=timezone.utc)
    return f"Last login: {when.strftime('%a %b %d %H:%M:%S %Y')} from {identity.last_login_ip}\n"


def _lscpu(identity: HostIdentity) -> str:
    return (
        "Architecture:                    x86_64\n"
        "CPU op-mode(s):                  32-bit, 64-bit\n"
        "Byte Order:                      Little Endian\n"
        f"CPU(s):                          {identity.cpu_cores}\n"
        f"On-line CPU(s) list:             0-{identity.cpu_cores - 1}\n"
        "Thread(s) per core:              1\n"
        f"Core(s) per socket:              {identity.cpu_cores}\n"
        "Socket(s):                       1\n"
        "Vendor ID:                       GenuineIntel\n"
        "CPU family:                      6\nModel:                           85\n"
        f"Model name:                      {identity.cpu_model}\n"
        f"CPU MHz:                         {identity.cpu_mhz:.3f}\n"
        "Hypervisor vendor:               KVM\nVirtualization type:             full\n"
    )


class CommandEmulator:
    """Answer one command segment against a session's shell and identity."""

    def __init__(self, identity: HostIdentity) -> None:
        self.identity = identity

    def run(self, argv: list[str], shell: ShellState, username: str,
            is_root: bool, stdin: Optional[bytes]) -> tuple[Optional[str], int]:
        """Return (text, exit_code); text is None when stdout is unknowable."""
        if not argv:
            return "", 0
        name = argv[0]
        base = posixpath.basename(name)
        handler = getattr(self, f"_cmd_{base}", None)
        if handler is None:
            # A path that is not a known program: ./x, /tmp/x, ../x.
            if name.startswith(("./", "/", "../")) or name.startswith("~"):
                return None, 127  # caller handles execution of dropped files
            return self._not_found(base), 127
        return handler(argv[1:], shell, username, is_root)

    # -- identity-driven system info -------------------------------------

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
        if args and args[0] in ("-I", "--all-ip-addresses"):
            return self.identity.ip + " \n", 0
        return self.identity.hostname + "\n", 0

    def _cmd_arch(self, args, shell, username, is_root):
        return self.identity.arch + "\n", 0

    def _cmd_nproc(self, args, shell, username, is_root):
        return f"{self.identity.cpu_cores}\n", 0

    def _cmd_lscpu(self, args, shell, username, is_root):
        return _lscpu(self.identity), 0

    def _cmd_free(self, args, shell, username, is_root):
        return _free(self.identity), 0

    def _cmd_df(self, args, shell, username, is_root):
        if args and "h" in "".join(a[1:] for a in args if a.startswith("-")):
            i = self.identity
            return (
                "Filesystem      Size  Used Avail Use% Mounted on\n"
                "udev            {d}     0  {d}   0% /dev\n".format(d=_fmt_size(i.mem_kb // 2))
                + f"tmpfs           {_fmt_size(i.mem_kb // 10)}  1.2M  {_fmt_size(i.mem_kb // 10)}   1% /run\n"
                + f"/dev/vda1       {_fmt_size(i.disk_total_kb)}  {_fmt_size(i.disk_used_kb)}  "
                f"{_fmt_size(i.disk_free_kb)} {int(i.disk_used_kb/i.disk_total_kb*100):3d}% /\n"
            ), 0
        return _df(self.identity), 0

    def _cmd_uptime(self, args, shell, username, is_root):
        return _uptime(self.identity), 0

    def _cmd_w(self, args, shell, username, is_root):
        return _w(self.identity), 0

    def _cmd_who(self, args, shell, username, is_root):
        i = self.identity
        when = datetime.fromtimestamp(i.last_login_time, tz=timezone.utc).strftime("%Y-%m-%d %H:%M")
        return f"root     pts/0        {when} ({i.last_login_ip})\n", 0

    def _cmd_lsb_release(self, args, shell, username, is_root):
        i = self.identity
        if args and args[0] in ("-a", "--all"):
            return (
                "Distributor ID:\tUbuntu\n"
                f"Description:\tUbuntu {i.os_version} LTS\n"
                "Release:\t20.04\nCodename:\tfocal\n"
            ), 0
        if args and args[0] in ("-d", "--description"):
            return f"Description:\tUbuntu {i.os_version} LTS\n", 0
        return "No LSB modules are available.\n", 0

    def _cmd_ifconfig(self, args, shell, username, is_root):
        return _ifconfig(self.identity), 0

    def _cmd_date(self, args, shell, username, is_root):
        now = datetime.now(timezone.utc)
        return now.strftime("%a %b %e %H:%M:%S UTC %Y") + "\n", 0

    def _cmd_ps(self, args, shell, username, is_root):
        return _ps(self.identity), 0

    def _cmd_ip(self, args, shell, username, is_root):
        if args and args[0].startswith(("a", "-a")):
            return _ip_addr(self.identity), 0
        if args and args[0].startswith("r"):
            i = self.identity
            return (
                f"default via {i.gateway} dev eth0 proto static\n"
                f"{i.ip.rsplit('.',1)[0]}.0/24 dev eth0 proto kernel scope link src {i.ip}\n"
            ), 0
        return "", 0

    # -- users -----------------------------------------------------------

    def _cmd_whoami(self, args, shell, username, is_root):
        return (username or "root") + "\n", 0

    def _cmd_id(self, args, shell, username, is_root):
        uid = 0 if is_root else self.identity.uid_for(username or "user")
        name = username or ("root" if is_root else "user")
        if uid == 0:
            return "uid=0(root) gid=0(root) groups=0(root)\n", 0
        return (f"uid={uid}({name}) gid={uid}({name}) "
                f"groups={uid}({name}),4(adm),24(cdrom),27(sudo),30(dip),46(plugdev)\n"), 0

    def _cmd_groups(self, args, shell, username, is_root):
        if is_root:
            return "root\n", 0
        name = username or "user"
        return f"{name} adm cdrom sudo dip plugdev lxd\n", 0

    def _cmd_sudo(self, args, shell, username, is_root):
        # Record intent upstream; here just answer the way a passwordless
        # sudoer would, so `sudo <cmd>` runs the inner command.
        if args and args[0] in ("-n", "-v"):
            return "", 0
        if args:
            inner, code = self.run(args, shell, "root", True, None)
            return inner, code
        return "usage: sudo -h | -K | -k | -V\n", 1

    # -- filesystem reads ------------------------------------------------

    def _cmd_cat(self, args, shell, username, is_root):
        files = [a for a in args if not a.startswith("-")]
        if not files:
            return None, 0  # cat with no args reads stdin; unknowable here
        out, code = [], 0
        for arg in files:
            path = resolve_path(shell.cwd, arg, shell.home)
            text = self._read_path(path, shell, is_root)
            if text is None:
                out.append(f"cat: {arg}: No such file or directory")
                code = 1
            else:
                out.append(text.rstrip("\n"))
        return "\n".join(out) + "\n", code

    def _cmd_head(self, args, shell, username, is_root):
        return self._head_tail(args, shell, is_root, head=True)

    def _cmd_tail(self, args, shell, username, is_root):
        return self._head_tail(args, shell, is_root, head=False)

    def _head_tail(self, args, shell, is_root, head):
        n = 10
        files = []
        skip = False
        for idx, a in enumerate(args):
            if skip:
                skip = False
                continue
            if a == "-n" and idx + 1 < len(args):
                try:
                    n = int(args[idx + 1].lstrip("+"))
                except ValueError:
                    n = 10
                skip = True
            elif a.startswith("-n"):
                try:
                    n = int(a[2:])
                except ValueError:
                    n = 10
            elif not a.startswith("-"):
                files.append(a)
        if not files:
            return None, 0
        path = resolve_path(shell.cwd, files[0], shell.home)
        text = self._read_path(path, shell, is_root)
        if text is None:
            verb = "head" if head else "tail"
            return f"{verb}: cannot open '{files[0]}' for reading: No such file or directory\n", 1
        lines = text.splitlines()
        chosen = lines[:n] if head else lines[-n:]
        return "\n".join(chosen) + ("\n" if chosen else ""), 0

    def _read_path(self, path: str, shell: ShellState, is_root: bool) -> Optional[str]:
        i = self.identity
        written = shell.read_content(path)
        if written is not None:
            return written.decode("utf-8", errors="replace")
        virtual = {
            "/etc/passwd": _passwd(i),
            "/etc/hostname": i.hostname + "\n",
            "/etc/hosts": _hosts(i),
            "/etc/os-release": _os_release(i),
            "/usr/lib/os-release": _os_release(i),
            "/etc/issue": f"Ubuntu {i.os_version} LTS \\n \\l\n\n",
            "/etc/issue.net": f"Ubuntu {i.os_version} LTS\n",
            "/etc/machine-id": i.machine_id + "\n",
            "/etc/resolv.conf": f"nameserver {i.nameserver}\nsearch {i.domain}\n",
            "/proc/cpuinfo": _cpuinfo(i),
            "/proc/version": (f"Linux version {i.kernel} (buildd@lcy02) "
                              f"(gcc version 9.4.0) {i.kernel_build}\n"),
            "/proc/uptime": f"{i.uptime_seconds:.2f} {i.uptime_seconds * i.cpu_cores * 0.6:.2f}\n",
            "/etc/timezone": i.timezone + "\n",
        }
        if path == "/etc/shadow" and not is_root:
            return None
        if path == "/etc/shadow":
            return "root:$6$" + "".join(random.choice("./0123456789abcdefghijklmnopqrstuvwxyz") for _ in range(86)) + ":19000:0:99999:7:::\n"
        if path == "/proc/meminfo":
            return f"MemTotal:       {i.mem_kb} kB\nMemFree:        {int(i.mem_kb*0.18)} kB\nMemAvailable:   {int(i.mem_kb*0.5)} kB\n"
        return virtual.get(path)

    # -- navigation ------------------------------------------------------

    def _cmd_pwd(self, args, shell, username, is_root):
        return shell.cwd + "\n", 0

    #: A plausible listing for the handful of directories a visitor inspects.
    _FS = {
        "/": ["bin", "boot", "dev", "etc", "home", "lib", "lib64", "media",
              "mnt", "opt", "proc", "root", "run", "sbin", "snap", "srv",
              "sys", "tmp", "usr", "var"],
        "/root": [".bashrc", ".profile", ".ssh", ".cache"],
        "/tmp": [],
        "/var": ["backups", "cache", "lib", "log", "mail", "opt", "run",
                 "spool", "tmp", "www"],
        "/var/www": ["html"],
        "/var/www/html": ["index.html"],
        "/etc": ["passwd", "shadow", "hostname", "hosts", "os-release",
                 "resolv.conf", "ssh", "cron.d", "apt", "network", "systemd"],
    }

    def _cmd_ls(self, args, shell, username, is_root):
        long = False
        show_all = False
        paths = []
        for a in args:
            if a.startswith("-") and len(a) > 1:
                long = long or "l" in a
                show_all = show_all or "a" in a
            else:
                paths.append(a)
        target = resolve_path(shell.cwd, paths[0], shell.home) if paths else shell.cwd
        home_entries = (
            [".bashrc", ".profile", ".bash_history", ".ssh", ".cache", ".local"]
            if target in (shell.home, "/home/" + (username or "user"))
            else None
        )
        entries = list(self._FS.get(target, home_entries if home_entries is not None else []))
        extra_dirs = sorted(
            posixpath.basename(d) for d in shell.dirs if posixpath.dirname(d) == target
        )
        dropped = {
            posixpath.basename(fp): f
            for fp, f in shell.files.items()
            if posixpath.dirname(fp) == target
        }
        names = entries + [d for d in extra_dirs if d not in entries]
        names += [n for n in sorted(dropped) if n not in names]
        if not long:
            visible = [n for n in names if show_all or not n.startswith(".")]
            if show_all:
                visible = [".", ".."] + visible
            return ("  ".join(visible) + "\n") if visible else "", 0
        lines = []
        if show_all:
            lines.append("total %d" % (len(names) + 2))
            lines.append(f"drwxr-xr-x  {len(names)+2:2d} root root 4096 {self._ls_date()} .")
            lines.append(f"drwxr-xr-x  22 root root 4096 {self._ls_date()} ..")
        else:
            lines.append("total %d" % max(4, len(names)))
        for name in names:
            file = dropped.get(name)
            if file is not None:
                perms = "-rwxr-xr-x" if file.executable else "-rw-r--r--"
                size = file.size
            elif name in (self._FS.get(target) or []) and name in self._FS:
                perms, size = "drwxr-xr-x", 4096
            elif name in extra_dirs or (target + "/" + name) in shell.dirs:
                perms, size = "drwxr-xr-x", 4096
            elif name.startswith(".") and name in (".ssh", ".cache", ".local"):
                perms, size = "drwx------", 4096
            elif name in self._FS.get("/", []) and target == "/":
                perms, size = "drwxr-xr-x", 4096
            else:
                perms, size = "-rw-r--r--", random.randint(180, 8200)
            owner = "root" if (is_root or target == "/" or target.startswith("/etc")) else (username or "user")
            lines.append(f"{perms}  1 {owner} {owner} {size:>6} {self._ls_date()} {name}")
        return "\n".join(lines) + "\n", 0

    @staticmethod
    def _ls_date() -> str:
        when = datetime.now(timezone.utc) - timedelta(days=random.randint(1, 120))
        return when.strftime("%b %e %H:%M")

    def _cmd_dir(self, args, shell, username, is_root):
        return self._cmd_ls(args, shell, username, is_root)

    def _cmd_vdir(self, args, shell, username, is_root):
        return self._cmd_ls(["-l"] + list(args), shell, username, is_root)

    def _cmd_echo(self, args, shell, username, is_root):
        # Variable expansion for the handful loaders rely on; everything else
        # is echoed literally, which is also what a real shell does for an
        # unset variable (empty) — here we keep the token to avoid lying about
        # content the attacker can check.
        env = {
            "HOME": shell.home, "USER": username or "root",
            "SHELL": "/bin/bash", "HOSTNAME": self.identity.hostname,
            "PWD": shell.cwd, "UID": str(0 if is_root else 1000),
            "PATH": "/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin",
            "?": str(shell.last_status), "$": str(random.randint(2000, 9000)),
        }
        env.update(shell.env)
        interpret_e = args and args[0] == "-e"
        if args and args[0] in ("-n", "-e", "-ne", "-en"):
            args = args[1:]
        out = []
        for tok in args:
            out.append(self._expand(tok, env))
        text = " ".join(out)
        if interpret_e:
            text = text.encode().decode("unicode_escape", errors="replace")
        return text + "\n", 0

    @staticmethod
    def _expand(token: str, env: dict) -> str:
        import re

        def repl(m):
            name = m.group(1) or m.group(2)
            return env.get(name, "")
        return re.sub(r"\$\{(\w+|\?|\$)\}|\$(\w+|\?|\$)", repl, token)

    def _cmd_which(self, args, shell, username, is_root):
        out, code = [], 0
        for a in args:
            if a.startswith("-"):
                continue
            if a in _BUILTINS:
                code = 1
                continue
            path = _PATHS.get(a)
            if path:
                out.append(path)
            else:
                code = 1
        return ("\n".join(out) + "\n") if out else "", code

    def _cmd_command(self, args, shell, username, is_root):
        if args and args[0] == "-v" and len(args) > 1:
            return self._cmd_which([args[1]], shell, username, is_root)
        if args:
            return self.run(args, shell, username, is_root, None)
        return "", 0

    def _cmd_type(self, args, shell, username, is_root):
        out, code = [], 0
        for a in args:
            if a.startswith("-"):
                continue
            if a in _BUILTINS:
                out.append(f"{a} is a shell builtin")
            elif a in _PATHS and _PATHS[a]:
                out.append(f"{a} is {_PATHS[a]}")
            else:
                out.append(f"bash: type: {a}: not found")
                code = 1
        return "\n".join(out) + ("\n" if out else ""), code

    def _cmd_env(self, args, shell, username, is_root):
        return self._cmd_printenv(args, shell, username, is_root)

    def _cmd_printenv(self, args, shell, username, is_root):
        env = {
            "SHELL": "/bin/bash",
            "PWD": shell.cwd,
            "LOGNAME": username or "root",
            "HOME": shell.home,
            "LANG": "en_US.UTF-8",
            "USER": username or "root",
            "SHLVL": "1",
            "PATH": "/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin:/usr/games",
            "_": "/usr/bin/printenv",
        }
        env.update(shell.env)
        return "".join(f"{k}={v}\n" for k, v in env.items()), 0

    def _cmd_export(self, args, shell, username, is_root):
        for a in args:
            if "=" in a:
                k, _, v = a.partition("=")
                shell.env[k] = v.strip("'\"")
        return "", 0

    def _cmd_history(self, args, shell, username, is_root):
        lines = [f"{idx + 1:5d}  {cmd}" for idx, cmd in enumerate(shell.history)]
        return "\n".join(lines) + ("\n" if lines else ""), 0

    def _cmd_mkdir(self, args, shell, username, is_root):
        made = [a for a in args if not a.startswith("-")]
        for a in made:
            shell.dirs.add(resolve_path(shell.cwd, a, shell.home))
        return "", 0

    def _cmd_touch(self, args, shell, username, is_root):
        for a in args:
            if a.startswith("-"):
                continue
            path = resolve_path(shell.cwd, a, shell.home)
            if path not in shell.files and shell.read_content(path) is None:
                shell.add_file(path, DroppedFile(name=posixpath.basename(path), size=0))
        return "", 0

    def _cmd_rm(self, args, shell, username, is_root):
        recursive = any(f.startswith("-") and ("r" in f or "R" in f) for f in args)
        force = any(f.startswith("-") and "f" in f for f in args)
        code = 0
        for a in args:
            if a.startswith("-"):
                continue
            path = resolve_path(shell.cwd, a, shell.home)
            existed = path in shell.files or shell.read_content(path) is not None or path in shell.dirs
            shell.remove_path(path, recursive)
            if not existed and not force:
                return f"rm: cannot remove '{a}': No such file or directory\n", 1
        return "", code

    def _cmd_rmdir(self, args, shell, username, is_root):
        for a in args:
            if not a.startswith("-"):
                shell.dirs.discard(resolve_path(shell.cwd, a, shell.home))
        return "", 0

    def _cmd_wc(self, args, shell, username, is_root):
        files = [a for a in args if not a.startswith("-")]
        if not files:
            return None, 0
        path = resolve_path(shell.cwd, files[0], shell.home)
        text = self._read_path(path, shell, is_root)
        if text is None:
            return f"wc: {files[0]}: No such file or directory\n", 1
        return f" {len(text.splitlines())} {len(text.split())} {len(text)} {files[0]}\n", 0

    # -- things that exist but print little ------------------------------

    def _cmd_clear(self, args, shell, username, is_root):
        return "\x1b[H\x1b[2J\x1b[3J", 0

    def _cmd_sleep(self, args, shell, username, is_root):
        return "", 0

    def _cmd_true(self, args, shell, username, is_root):
        return "", 0

    def _cmd_false(self, args, shell, username, is_root):
        return "", 1

    def _cmd_set(self, args, shell, username, is_root):
        return "", 0

    def _cmd_umask(self, args, shell, username, is_root):
        return "" if args else "0022\n", 0

    def _cmd_unset(self, args, shell, username, is_root):
        for a in args:
            shell.env.pop(a, None)
        return "", 0

    def _cmd_alias(self, args, shell, username, is_root):
        return "" if args else "", 0

    def _cmd_crontab(self, args, shell, username, is_root):
        if args and args[0] == "-l":
            return "no crontab for " + (username or "root") + "\n", 1
        return "", 0

    def _cmd_systemctl(self, args, shell, username, is_root):
        if args and args[0] in ("status",):
            return "", 3
        return "", 0

    def _cmd_service(self, args, shell, username, is_root):
        return "", 0

    def _cmd_kill(self, args, shell, username, is_root):
        return "", 0

    def _cmd_pkill(self, args, shell, username, is_root):
        return "", 0

    def _cmd_pgrep(self, args, shell, username, is_root):
        return "", 1

    # -- not-found -------------------------------------------------------

    def _not_found(self, base: str) -> str:
        return f"{base}: command not found\n"
