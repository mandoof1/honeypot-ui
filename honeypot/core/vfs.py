"""One filesystem for the whole decoy.

``ls`` used to print a hard-coded handful of names with a fresh random size
and date on every call, ``cat`` knew a separate list of about a dozen paths,
``cd`` accepted anything under a standard root whether or not ``ls`` showed
it, and the SFTP subsystem had a fourth idea of what existed. So ``ls /etc``
listed files ``cat`` could not open, the same file changed size between two
listings, and ``cd /etc/nonsense`` worked. Any one of those tells a visitor
the directory tree is being made up as it goes.

This module builds the tree once per deployment, from the host identity's
seed: every directory, every file with its owner, mode, size and date, and
the content each file returns. The same seed gives the same tree, so it is
identical across sessions and restarts. ``ls``, ``cat``, ``cd``, ``stat``,
``find`` and SFTP all read it through :class:`FsView`, which lays the files a
session has written or fetched over the top.

Two rules keep it honest with itself. A file that is listed can be read (or
is refused for a reason its mode explains), and its listed size is the
length of what a read returns. And nothing is real: no path here is ever
passed to the operating system.
"""

from __future__ import annotations

import posixpath
import random
import threading
import time
from dataclasses import dataclass
from typing import Callable, Optional, Union

from honeypot.core import canary, hostfacts
from honeypot.core.honeytokens import get_honeytokens
from honeypot.core.identity import HostIdentity, get_identity
from honeypot.core.shell_state import ShellState

Content = Union[bytes, Callable[[], bytes], None]

#: Most bytes a generated binary returns on a read, whatever size it lists.
#: Nothing sends more than this for one command anyway.
MAX_GENERATED_BYTES = 256 * 1024

_DAY = 86400.0


@dataclass
class Entry:
    kind: str                 # dir | file | link | char | block
    mode: int
    owner: str = "root"
    group: str = "root"
    size: int = 4096
    mtime: Union[float, Callable[[], float]] = 0.0
    nlink: int = 1
    #: Link target, as ``ls -l`` shows it.
    target: str = ""
    content: Content = None
    #: Device numbers for ``char`` and ``block`` entries.
    rdev: tuple[int, int] = (0, 0)
    #: Where a fetched file came from (session files only).
    source_url: Optional[str] = None
    #: True for something this session created.
    session: bool = False

    @property
    def is_dir(self) -> bool:
        return self.kind == "dir"

    @property
    def executable(self) -> bool:
        return bool(self.mode & 0o111)

    def when(self) -> float:
        return self.mtime() if callable(self.mtime) else self.mtime

    def mode_string(self) -> str:
        """``drwxr-xr-x`` and friends, with the sticky and setuid marks."""
        lead = {"dir": "d", "file": "-", "link": "l", "char": "c", "block": "b"}[self.kind]
        bits = ""
        for shift in (6, 3, 0):
            triple = (self.mode >> shift) & 7
            bits += ("r" if triple & 4 else "-") + ("w" if triple & 2 else "-") + ("x" if triple & 1 else "-")
        chars = list(bits)
        if self.mode & 0o4000:
            chars[2] = "s" if chars[2] == "x" else "S"
        if self.mode & 0o2000:
            chars[5] = "s" if chars[5] == "x" else "S"
        if self.mode & 0o1000:
            chars[8] = "t" if chars[8] == "x" else "T"
        return lead + "".join(chars)


#: Programs on the PATH: name -> directory. ``which``, ``type``, path
#: execution (``/bin/uname``) and the ``/usr/bin`` listing all read this.
_SBIN_PROGRAMS = (
    "ifconfig route arp iptables iptables-save ip6tables service sshd ip useradd usermod "
    "userdel groupadd chpasswd visudo cron sysctl shutdown reboot halt poweroff "
    "modprobe insmod rmmod lsmod fdisk mkfs.ext4 swapon swapoff ufw nologin "
    "netplan dhclient agetty logrotate rsyslogd chroot update-rc.d adduser "
    "deluser ethtool start-stop-daemon ldconfig blkid losetup fsck mysqld tcpdump"
).split()
_BIN_PROGRAMS = (
    "awk sed grep egrep fgrep cat tac head tail cut sort uniq wc tr tee less more "
    "ls cp mv rm mkdir rmdir touch ln find xargs chmod chown chgrp stat file du df "
    "date uptime who w whoami id groups env printenv tty hostname uname arch "
    "ps top kill killall pkill pgrep nohup nice sleep watch crontab at bash sh dash "
    "wget curl scp sftp ssh ssh-keygen nc netcat ftp telnet ping traceroute dig host nslookup "
    "tar gzip gunzip zcat bzip2 xz zip unzip base64 md5sum sha1sum sha256sum sha512sum "
    "openssl python3 python3.8 perl vi vim nano apt apt-get apt-cache dpkg systemctl journalctl "
    "netstat ss ip lscpu nproc free lsblk lsb_release mount umount su sudo passwd chsh "
    "which whereis clear reset busybox dd od xxd hexdump strings seq yes true false "
    "expr test dirname basename realpath readlink mktemp timeout tty stty "
    "last lastlog dmesg lsof strace screen tmux git make-first-existing-target "
    "mysql mysqldump logger getent locale hostnamectl timedatectl loginctl "
    "diff cmp rev nl paste join comm fold expand shuf tsort sync flock setsid "
    "ssh-copy-id ssh-add ssh-agent rsync gpg lsmem lspci lsusb lshw uptime vmstat "
    "iostat pidof pwdx renice chattr lsattr install printf echo pwd"
).split()
PROGRAMS: dict[str, str] = {}
for _name in _BIN_PROGRAMS:
    if _name != "make-first-existing-target":
        PROGRAMS[_name] = "/usr/bin/" + _name
for _name in _SBIN_PROGRAMS:
    PROGRAMS[_name] = "/usr/sbin/" + _name
PROGRAMS[canary.MARKER_PROGRAM] = canary.MARKER_PATH

#: Directories that are symlinks into /usr on a merged-/usr system.
_USR_LINKS = {"/bin": "usr/bin", "/sbin": "usr/sbin", "/lib": "usr/lib", "/lib64": "usr/lib64"}

_BASHRC_ROOT = (
    "# ~/.bashrc: executed by bash(1) for non-login shells.\n"
    "# see /usr/share/doc/bash/examples/startup-files (in the package bash-doc)\n"
    "# for examples\n\n"
    "# If not running interactively, don't do anything\n"
    "[ -z \"$PS1\" ] && return\n\n"
    "# don't put duplicate lines in the history. See bash(1) for more options\n"
    "HISTCONTROL=ignoredups:ignorespace\n\n"
    "# append to the history file, don't overwrite it\n"
    "shopt -s histappend\n\n"
    "# for setting history length see HISTSIZE and HISTFILESIZE in bash(1)\n"
    "HISTSIZE=1000\nHISTFILESIZE=2000\n\n"
    "# check the window size after each command and, if necessary,\n"
    "# update the values of LINES and COLUMNS.\n"
    "shopt -s checkwinsize\n\n"
    "# make less more friendly for non-text input files, see lesspipe(1)\n"
    "[ -x /usr/bin/lesspipe ] && eval \"$(SHELL=/bin/sh lesspipe)\"\n\n"
    "PS1='${debian_chroot:+($debian_chroot)}\\u@\\h:\\w\\$ '\n\n"
    "# enable color support of ls and also add handy aliases\n"
    "if [ -x /usr/bin/dircolors ]; then\n"
    "    test -r ~/.dircolors && eval \"$(dircolors -b ~/.dircolors)\" || eval \"$(dircolors -b)\"\n"
    "    alias ls='ls --color=auto'\n"
    "    alias grep='grep --color=auto'\n"
    "fi\n\n"
    "# some more ls aliases\n"
    "alias ll='ls -alF'\nalias la='ls -A'\nalias l='ls -CF'\n\n"
    "if [ -f ~/.bash_aliases ]; then\n    . ~/.bash_aliases\nfi\n"
)
_PROFILE_ROOT = (
    "# ~/.profile: executed by Bourne-compatible login shells.\n\n"
    "if [ \"$BASH\" ]; then\n  if [ -f ~/.bashrc ]; then\n    . ~/.bashrc\n  fi\nfi\n\n"
    "mesg n 2> /dev/null || true\n"
)
_PROFILE_USER = (
    "# ~/.profile: executed by the command interpreter for login shells.\n"
    "# This file is not read by bash(1), if ~/.bash_profile or ~/.bash_login\n"
    "# exists.\n\n"
    "# if running bash\n"
    "if [ -n \"$BASH_VERSION\" ]; then\n"
    "    # include .bashrc if it exists\n"
    "    if [ -f \"$HOME/.bashrc\" ]; then\n\t. \"$HOME/.bashrc\"\n    fi\nfi\n\n"
    "# set PATH so it includes user's private bin if it exists\n"
    "if [ -d \"$HOME/bin\" ] ; then\n    PATH=\"$HOME/bin:$PATH\"\nfi\n"
)
_BASH_LOGOUT = (
    "# ~/.bash_logout: executed by bash(1) when login shell exits.\n\n"
    "# when leaving the console clear the screen to increase privacy\n\n"
    "if [ \"$SHLVL\" = 1 ]; then\n"
    "    [ -x /usr/bin/clear_console ] && /usr/bin/clear_console -q\nfi\n"
)
_SSHD_CONFIG = (
    "#\t$OpenBSD: sshd_config,v 1.103 2018/04/09 20:41:22 tj Exp $\n\n"
    "# This is the sshd server system-wide configuration file.  See\n"
    "# sshd_config(5) for more information.\n\n"
    "Include /etc/ssh/sshd_config.d/*.conf\n\n"
    "#Port 22\n#AddressFamily any\n#ListenAddress 0.0.0.0\n#ListenAddress ::\n\n"
    "#HostKey /etc/ssh/ssh_host_rsa_key\n#HostKey /etc/ssh/ssh_host_ecdsa_key\n"
    "#HostKey /etc/ssh/ssh_host_ed25519_key\n\n"
    "# Authentication:\n\n#LoginGraceTime 2m\nPermitRootLogin yes\n#StrictModes yes\n"
    "#MaxAuthTries 6\n#MaxSessions 10\n\n#PubkeyAuthentication yes\n\n"
    "PasswordAuthentication yes\n#PermitEmptyPasswords no\n\n"
    "ChallengeResponseAuthentication no\n\nUsePAM yes\n\n"
    "X11Forwarding yes\nPrintMotd no\n\nAcceptEnv LANG LC_*\n\n"
    "Subsystem\tsftp\t/usr/lib/openssh/sftp-server\n"
)
_SNAP_README = (
    "This directory presents installed snap packages.\n\n"
    "It has the following structure:\n\n"
    "/snap/bin                   - Symlinks to snap applications.\n"
    "/snap/<snapname>/<revision> - Mountpoint for snap content.\n"
    "/snap/<snapname>/current    - Symlink to current revision, if enabled.\n"
)


def elf_blob(seed: int, path: str, size: int) -> bytes:
    """Bytes for a binary this host only pretends to have.

    A valid x86-64 ELF header — loaders read the first bytes of ``/bin/echo``
    to learn the architecture before choosing a payload — followed by filler
    that is the same on every read.
    """
    rng = random.Random(f"{seed}:elf:{path}")
    header = bytearray(64)
    header[0:16] = b"\x7fELF\x02\x01\x01\x00" + bytes(8)
    header[16:18] = (3).to_bytes(2, "little")        # ET_DYN
    header[18:20] = (62).to_bytes(2, "little")       # EM_X86_64
    header[20:24] = (1).to_bytes(4, "little")
    header[24:32] = (0x1000 + rng.randrange(0x400, 0x7000, 16)).to_bytes(8, "little")
    header[32:40] = (64).to_bytes(8, "little")
    header[40:48] = max(64, size - 64 * 29).to_bytes(8, "little")
    header[52:54] = (64).to_bytes(2, "little")
    header[54:56] = (56).to_bytes(2, "little")
    header[56:58] = (13).to_bytes(2, "little")
    header[58:60] = (64).to_bytes(2, "little")
    header[60:62] = (29).to_bytes(2, "little")
    header[62:64] = (28).to_bytes(2, "little")
    length = min(size, MAX_GENERATED_BYTES)
    if length <= 64:
        return bytes(header[:length])
    return bytes(header) + rng.randbytes(length - 64)


def data_blob(seed: int, path: str, size: int) -> bytes:
    """Stable filler for a file whose bytes nobody should need to trust."""
    return random.Random(f"{seed}:blob:{path}").randbytes(min(size, MAX_GENERATED_BYTES))


class VirtualFS:
    """The seeded tree. Immutable once built; sessions overlay it."""

    def __init__(self, identity: HostIdentity) -> None:
        self.identity = identity
        self.nodes: dict[str, Entry] = {}
        self.children: dict[str, set[str]] = {}
        seed_rng = hostfacts.seeded(identity, "vfs")
        #: When this machine was installed. Fixed by the seed, so a file's
        #: date is the same today and after any number of restarts.
        self.installed = 1_680_000_000 + seed_rng.randint(0, 270) * _DAY + seed_rng.randint(0, 86399)
        self._build()

    # -- construction ------------------------------------------------------

    def _stamp(self, path: str, earliest: float, latest: float) -> float:
        rng = random.Random(f"{self.identity.seed}:mtime:{path}")
        return earliest + rng.random() * max(1.0, latest - earliest)

    def _attach(self, path: str, entry: Entry) -> Entry:
        parent = posixpath.dirname(path)
        if path != "/" and parent not in self.nodes:
            self.dir(parent)
        self.nodes[path] = entry
        if path != "/":
            self.children.setdefault(parent, set()).add(posixpath.basename(path))
        return entry

    def dir(self, path: str, mode: int = 0o755, owner: str = "root", group: str = "",
            mtime: Union[float, Callable[[], float], None] = None) -> Entry:
        existing = self.nodes.get(path)
        if existing is not None:
            return existing
        when = mtime if mtime is not None else self._stamp(path, self.installed, self.installed + 400 * _DAY)
        self.children.setdefault(path, set())
        return self._attach(path, Entry("dir", mode, owner, group or owner, 4096, when, nlink=2))

    def file(self, path: str, content: Union[str, bytes, Callable[[], bytes]], mode: int = 0o644,
             owner: str = "root", group: str = "",
             mtime: Union[float, Callable[[], float], None] = None, size: Optional[int] = None) -> Entry:
        if isinstance(content, str):
            content = content.encode("utf-8")
        if size is None:
            size = len(content) if isinstance(content, bytes) else len(content())
        when = mtime if mtime is not None else self._stamp(path, self.installed, self.installed + 300 * _DAY)
        return self._attach(path, Entry("file", mode, owner, group or owner, size, when, content=content))

    def binary(self, path: str, size: Optional[int] = None, mode: int = 0o755) -> Entry:
        rng = random.Random(f"{self.identity.seed}:size:{path}")
        if size is None:
            size = rng.choice([14488, 18744, 22912, 30952, 35000, 39256, 43416, 51480, 59736, 72000, 88664, 109000, 142144, 199048])
        # Shipped by the distribution, so dated before this machine existed.
        when = self._stamp(path, self.installed - 1100 * _DAY, self.installed - 30 * _DAY)
        seed = self.identity.seed
        return self._attach(path, Entry(
            "file", mode, "root", "root", size, when,
            content=lambda: elf_blob(seed, path, size),
        ))

    def blob(self, path: str, size: int, mode: int = 0o644, owner: str = "root",
             mtime: Union[float, Callable[[], float], None] = None) -> Entry:
        seed = self.identity.seed
        when = mtime if mtime is not None else self._stamp(path, self.installed, self.installed + 300 * _DAY)
        return self._attach(path, Entry(
            "file", mode, owner, owner, size, when, content=lambda: data_blob(seed, path, size),
        ))

    def link(self, path: str, target: str) -> Entry:
        when = self._stamp(path, self.installed - 5 * _DAY, self.installed)
        return self._attach(path, Entry("link", 0o777, "root", "root", len(target), when, target=target))

    def device(self, path: str, kind: str, major: int, minor: int, mode: int = 0o666, group: str = "root") -> Entry:
        boot = self.identity.boot_time
        return self._attach(path, Entry(kind, mode, "root", group, 0, boot, rdev=(major, minor)))

    def script(self, path: str, purpose: str, mode: int = 0o755) -> Entry:
        return self.file(path, f"#!/bin/sh\n# {purpose}\nset -e\nexit 0\n", mode)

    # -- the tree ----------------------------------------------------------

    def _build(self) -> None:
        identity = self.identity
        self.dir("/", mtime=self.installed + 3 * _DAY).nlink = 20
        for name, target in _USR_LINKS.items():
            self.link(name, target)
        for name in ("/boot", "/dev", "/etc", "/home", "/media", "/mnt", "/opt", "/proc",
                     "/run", "/srv", "/sys", "/usr", "/var"):
            self.dir(name)
        self.dir("/root", 0o700)
        self.dir("/lost+found", 0o700)
        self.dir("/tmp", 0o1777, mtime=lambda: time.time() - time.time() % 600)
        if identity.swap_kb:
            self.blob("/swap.img", identity.swap_kb * 1024, 0o600)
        self._build_usr()
        self._build_etc()
        self._build_var()
        self._build_homes()
        self._build_kernel_views()
        self._build_misc()
        # Directory link counts: two, plus one per subdirectory.
        for path, names in self.children.items():
            node = self.nodes.get(path)
            if node is not None and node.kind == "dir":
                subdirs = sum(1 for n in names if self.nodes[posixpath.join(path, n)].kind == "dir")
                node.nlink = 2 + subdirs

    def _build_usr(self) -> None:
        identity = self.identity
        for name in ("/usr/bin", "/usr/sbin", "/usr/lib", "/usr/lib64", "/usr/include",
                     "/usr/games", "/usr/src", "/usr/libexec", "/usr/share",
                     "/usr/local/bin", "/usr/local/sbin", "/usr/local/lib",
                     "/usr/local/share", "/usr/local/etc", "/usr/local/games",
                     "/usr/local/include", "/usr/local/src", "/usr/share/doc",
                     "/usr/share/man", "/usr/share/zoneinfo", "/usr/share/keyrings",
                     "/usr/lib/x86_64-linux-gnu", "/usr/lib/systemd/system",
                     "/usr/lib/python3/dist-packages", "/usr/lib/openssh",
                     "/usr/lib/apt", "/usr/lib/modules/" + identity.kernel):
            self.dir(name)
        known_sizes = {"bash": 1183448, "busybox": 2139904, "python3.8": 5494584,
                       "perl": 3478464, "openssl": 849960, "vim": 2906824, "mysqld": 62651080}
        for name, path in PROGRAMS.items():
            if name in ("sh", "python3", "awk", "vi", "netcat", "nc", canary.MARKER_PROGRAM):
                continue
            self.binary(path, known_sizes.get(name))
        self.link("/usr/bin/sh", "dash")
        self.link("/usr/bin/python3", "python3.8")
        self.link("/usr/bin/awk", "/etc/alternatives/awk")
        self.link("/usr/bin/vi", "/etc/alternatives/vi")
        self.binary("/usr/bin/nc.openbsd", 35344)
        self.link("/usr/bin/nc", "/etc/alternatives/nc")
        self.link("/usr/bin/netcat", "/etc/alternatives/netcat")
        self.binary("/usr/bin/mawk", 121976)
        for mode_name in ("sudo", "su", "passwd", "mount", "umount", "chsh"):
            self.nodes["/usr/bin/" + mode_name].mode = 0o4755
        web = "nginx" if identity.http_family == "nginx" else "apache2"
        self.binary("/usr/sbin/" + web, 1195152 if web == "nginx" else 704520)
        self.binary("/usr/sbin/" + ("proftpd" if identity.ftp_family == "proftpd" else "vsftpd"), 176000)
        self.binary("/usr/lib/systemd/systemd", 1620224)
        self.link("/usr/sbin/init", "/lib/systemd/systemd")
        self.binary("/usr/lib/openssh/sftp-server", 109000)
        self.binary("/usr/lib/x86_64-linux-gnu/libc-2.31.so", 2029592)
        self.link("/usr/lib/x86_64-linux-gnu/libc.so.6", "libc-2.31.so")
        self.binary("/usr/lib/x86_64-linux-gnu/ld-2.31.so", 191504)
        self.link("/usr/lib64/ld-linux-x86-64.so.2", "/lib/x86_64-linux-gnu/ld-2.31.so")
        self.file("/usr/lib/os-release", hostfacts.os_release(identity))
        self.link("/usr/share/zoneinfo/localtime", "/etc/localtime")
        if canary.enabled():
            self.file(canary.MARKER_PATH, canary.marker_script(), 0o755,
                      mtime=self.installed + 200 * _DAY)

    def _build_etc(self) -> None:
        identity = self.identity
        self.file("/etc/passwd", hostfacts.passwd(identity))
        self.file("/etc/group", hostfacts.group(identity))
        self.file("/etc/shadow", hostfacts.shadow(identity), 0o640, "root", "shadow")
        self.file("/etc/gshadow", "root:*::\nsudo:*::%s\nshadow:*::\n" % identity.users[0][0], 0o640, "root", "shadow")
        self.file("/etc/hostname", identity.hostname + "\n")
        self.file("/etc/hosts", hostfacts.hosts(identity))
        self.link("/etc/os-release", "../usr/lib/os-release")
        self.file("/etc/lsb-release",
                  "DISTRIB_ID=Ubuntu\nDISTRIB_RELEASE=20.04\nDISTRIB_CODENAME=focal\n"
                  f'DISTRIB_DESCRIPTION="Ubuntu {identity.os_version} LTS"\n')
        self.file("/etc/issue", f"Ubuntu {identity.os_version} LTS \\n \\l\n\n")
        self.file("/etc/issue.net", f"Ubuntu {identity.os_version} LTS\n")
        self.file("/etc/debian_version", "bullseye/sid\n")
        self.file("/etc/machine-id", identity.machine_id + "\n", 0o444)
        self.link("/etc/resolv.conf", "../run/systemd/resolve/stub-resolv.conf")
        self.file("/etc/timezone", identity.timezone + "\n")
        self.link("/etc/localtime", "/usr/share/zoneinfo/" + identity.timezone)
        self.file("/etc/fstab", hostfacts.fstab(identity))
        self.link("/etc/mtab", "../proc/self/mounts")
        self.file("/etc/shells", "# /etc/shells: valid login shells\n/bin/sh\n/bin/bash\n/usr/bin/bash\n/bin/rbash\n/usr/bin/rbash\n/bin/dash\n/usr/bin/dash\n")
        self.file("/etc/environment", 'PATH="/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin:/usr/games:/usr/local/games:/snap/bin"\n')
        self.file("/etc/profile",
                  "# /etc/profile: system-wide .profile file for the Bourne shell (sh(1))\n"
                  "# and Bourne compatible shells (bash(1), ksh(1), ash(1), ...).\n\n"
                  "if [ -d /etc/profile.d ]; then\n  for i in /etc/profile.d/*.sh; do\n"
                  "    if [ -r $i ]; then\n      . $i\n    fi\n  done\n  unset i\nfi\n")
        self.file("/etc/bash.bashrc", "# System-wide .bashrc file for interactive bash(1) shells.\n\n[ -z \"$PS1\" ] && return\n\nshopt -s checkwinsize\n")
        self.file("/etc/sudoers",
                  "#\n# This file MUST be edited with the 'visudo' command as root.\n#\n"
                  "Defaults\tenv_reset\nDefaults\tmail_badpass\n"
                  'Defaults\tsecure_path="/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin:/snap/bin"\n\n'
                  "root\tALL=(ALL:ALL) ALL\n%admin ALL=(ALL) ALL\n%sudo\tALL=(ALL:ALL) ALL\n\n"
                  "#includedir /etc/sudoers.d\n", 0o440)
        self.file("/etc/nsswitch.conf",
                  "passwd:         files systemd\ngroup:          files systemd\nshadow:         files\n"
                  "gshadow:        files\n\nhosts:          files dns\nnetworks:       files\n\n"
                  "protocols:      db files\nservices:       db files\nethers:         db files\nrpc:            db files\n")
        self.file("/etc/host.conf", "# The \"order\" line is only used by old versions of the C library.\norder hosts,bind\nmulti on\n")
        self.file("/etc/hosts.allow", "# /etc/hosts.allow: list of hosts that are allowed to access the system.\n")
        self.file("/etc/hosts.deny", "# /etc/hosts.deny: list of hosts that are _not_ allowed to access the system.\n")
        self.file("/etc/ld.so.conf", "include /etc/ld.so.conf.d/*.conf\n\n")
        self.file("/etc/legal",
                  "\nThe programs included with the Ubuntu system are free software;\n"
                  "the exact distribution terms for each program are described in the\n"
                  "individual files in /usr/share/doc/*/copyright.\n\n"
                  "Ubuntu comes with ABSOLUTELY NO WARRANTY, to the extent permitted by\n"
                  "applicable law.\n\n")
        self.file("/etc/crontab",
                  "# /etc/crontab: system-wide crontab\n"
                  "SHELL=/bin/sh\nPATH=/usr/local/sbin:/usr/local/bin:/sbin:/bin:/usr/sbin:/usr/bin\n\n"
                  "# m h dom mon dow user\tcommand\n"
                  "17 *\t* * *\troot    cd / && run-parts --report /etc/cron.hourly\n"
                  "25 6\t* * *\troot\ttest -x /usr/sbin/anacron || ( cd / && run-parts --report /etc/cron.daily )\n"
                  "47 6\t* * 7\troot\ttest -x /usr/sbin/anacron || ( cd / && run-parts --report /etc/cron.weekly )\n"
                  "52 6\t1 * *\troot\ttest -x /usr/sbin/anacron || ( cd / && run-parts --report /etc/cron.monthly )\n#\n")
        self.file("/etc/sysctl.conf", "#\n# /etc/sysctl.conf - Configuration file for setting system variables\n# See /etc/sysctl.d/ for additional system variables.\n#\n\n#net.ipv4.ip_forward=1\n")
        self.file("/etc/rsyslog.conf", "# /etc/rsyslog.conf configuration file for rsyslog\n\nmodule(load=\"imuxsock\")\nmodule(load=\"imklog\" permitnonkernelfacility=\"on\")\n\n$FileOwner syslog\n$FileGroup adm\n$FileCreateMode 0640\n\n$IncludeConfig /etc/rsyslog.d/*.conf\n")
        self.file("/etc/logrotate.conf", "# see \"man logrotate\" for details\nweekly\nsu root adm\nrotate 4\ncreate\ninclude /etc/logrotate.d\n")
        self.file("/etc/services",
                  "# Network services, Internet style\n\nftp-data\t20/tcp\nftp\t\t21/tcp\nssh\t\t22/tcp\n"
                  "telnet\t\t23/tcp\nsmtp\t\t25/tcp\t\tmail\ndomain\t\t53/tcp\ndomain\t\t53/udp\n"
                  "http\t\t80/tcp\t\twww\npop3\t\t110/tcp\t\tpop-3\nntp\t\t123/udp\nimap2\t\t143/tcp\t\timap\n"
                  "https\t\t443/tcp\nmysql\t\t3306/tcp\n")
        self.file("/etc/apt/sources.list",
                  "deb http://archive.ubuntu.com/ubuntu focal main restricted universe multiverse\n"
                  "deb http://archive.ubuntu.com/ubuntu focal-updates main restricted universe multiverse\n"
                  "deb http://security.ubuntu.com/ubuntu focal-security main restricted universe multiverse\n")
        for name in ("/etc/apt/apt.conf.d", "/etc/apt/sources.list.d", "/etc/apt/trusted.gpg.d",
                     "/etc/cron.hourly", "/etc/cron.weekly", "/etc/cron.monthly",
                     "/etc/ld.so.conf.d", "/etc/profile.d", "/etc/rsyslog.d", "/etc/sudoers.d",
                     "/etc/sysctl.d", "/etc/systemd/system/multi-user.target.wants",
                     "/etc/systemd/network", "/etc/security", "/etc/skel", "/etc/opt",
                     "/etc/ssl/certs", "/etc/alternatives", "/etc/update-motd.d",
                     "/etc/logrotate.d", "/etc/modprobe.d", "/etc/network/if-up.d",
                     "/etc/ssh/sshd_config.d", "/etc/pam.d", "/etc/dpkg", "/etc/kernel"):
            self.dir(name)
        self.dir("/etc/ssl/private", 0o710, "root", "ssl-cert")
        self.file("/etc/skel/.bash_logout", _BASH_LOGOUT)
        self.file("/etc/skel/.bashrc", _BASHRC_ROOT)
        self.file("/etc/skel/.profile", _PROFILE_USER)
        self.link("/etc/alternatives/awk", "/usr/bin/mawk")
        self.link("/etc/alternatives/vi", "/usr/bin/vim")
        self.link("/etc/alternatives/nc", "/bin/nc.openbsd")
        self.link("/etc/alternatives/netcat", "/bin/nc.openbsd")
        self.file("/etc/sudoers.d/README", "#\n# As of Debian version 1.7.2p1-1, the default /etc/sudoers file created on\n# installation of the package now includes the directive:\n#\n#\t#includedir /etc/sudoers.d\n#\n", 0o440)
        self.file("/etc/cron.d/e2scrub_all", "30 3 * * 0 root test -e /run/systemd/system || SERVICE_MODE=1 /usr/lib/x86_64-linux-gnu/e2fsprogs/e2scrub_all_cron\n10 3 * * * root test -e /run/systemd/system || SERVICE_MODE=1 /sbin/e2scrub_all -A -r\n")
        for name in ("apt-compat", "dpkg", "logrotate", "man-db"):
            self.script("/etc/cron.daily/" + name, f"daily {name} housekeeping")
        self.file("/etc/default/ssh", "# Default settings for openssh-server. This file is sourced by /bin/sh from\n# /etc/init.d/ssh.\n\n# Options to pass to sshd\nSSHD_OPTS=\n")
        self.file("/etc/default/cron", "# This file has been deprecated. Please add custom options for cron to\n# /etc/init.d/cron or /etc/systemd/system/cron.service.d/override.conf\nEXTRA_OPTS=\"\"\n")
        self.file("/etc/default/locale", "LANG=en_US.UTF-8\n")
        self.file("/etc/default/grub", "GRUB_DEFAULT=0\nGRUB_TIMEOUT_STYLE=hidden\nGRUB_TIMEOUT=0\nGRUB_DISTRIBUTOR=`lsb_release -i -s 2> /dev/null || echo Debian`\nGRUB_CMDLINE_LINUX_DEFAULT=\"\"\nGRUB_CMDLINE_LINUX=\"\"\n")
        self.file("/etc/ssh/sshd_config", _SSHD_CONFIG)
        self.file("/etc/ssh/ssh_config", "Include /etc/ssh/ssh_config.d/*.conf\n\nHost *\n    SendEnv LANG LC_*\n    HashKnownHosts yes\n    GSSAPIAuthentication yes\n")
        self.dir("/etc/ssh/ssh_config.d")
        key_rng = hostfacts.seeded(identity, "ssh-host-keys")
        alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/"

        def fake_key(lines: int) -> str:
            body = "\n".join("".join(key_rng.choice(alphabet) for _ in range(70)) for _ in range(lines))
            return f"-----BEGIN OPENSSH PRIVATE KEY-----\n{body}\n-----END OPENSSH PRIVATE KEY-----\n"

        # Shaped like host keys so the directory looks right; they are not
        # the keys the decoy's own SSH transport uses.
        for kind, lines, prefix, length in (("rsa", 36, "AAAAB3NzaC1yc2EAAAADAQABAAABgQ", 500),
                                            ("ecdsa", 7, "AAAAE2VjZHNhLXNoYTItbmlzdHAyNTYAAAAIbmlzdHAyNTYAAABBB", 87),
                                            ("ed25519", 5, "AAAAC3NzaC1lZDI1NTE5AAAAI", 43)):
            self.file(f"/etc/ssh/ssh_host_{kind}_key", fake_key(lines), 0o600)
            public = prefix + "".join(key_rng.choice(alphabet) for _ in range(length))
            name = {"rsa": "ssh-rsa", "ecdsa": "ecdsa-sha2-nistp256", "ed25519": "ssh-ed25519"}[kind]
            self.file(f"/etc/ssh/ssh_host_{kind}_key.pub", f"{name} {public} root@{identity.hostname}\n")
        self.file("/etc/netplan/00-installer-config.yaml",
                  "# This is the network config written by 'subiquity'\nnetwork:\n  ethernets:\n    eth0:\n"
                  f"      addresses:\n      - {identity.ip}/24\n      gateway4: {identity.gateway}\n"
                  f"      nameservers:\n        addresses:\n        - {identity.nameserver}\n"
                  f"        search:\n        - {identity.domain}\n  version: 2\n")
        for name in ("ssh", "cron", "rsyslog", "mysql", "procps", "udev", "kmod"):
            self.script("/etc/init.d/" + name, f"init script for {name}")
        self.file("/etc/mysql/my.cnf", "#\n# The MySQL database server configuration file.\n#\n\n!includedir /etc/mysql/conf.d/\n!includedir /etc/mysql/mysql.conf.d/\n")
        self.file("/etc/mysql/mysql.conf.d/mysqld.cnf", "[mysqld]\nuser\t\t= mysql\nbind-address\t\t= 127.0.0.1\nmysqlx-bind-address\t= 127.0.0.1\nkey_buffer_size\t\t= 16M\nlog_error = /var/log/mysql/error.log\nmax_binlog_size   = 100M\n")
        self.dir("/etc/mysql/conf.d")
        if identity.http_family == "nginx":
            self.file("/etc/nginx/nginx.conf",
                      "user www-data;\nworker_processes auto;\npid /run/nginx.pid;\ninclude /etc/nginx/modules-enabled/*.conf;\n\n"
                      "events {\n\tworker_connections 768;\n}\n\nhttp {\n\tsendfile on;\n\ttcp_nopush on;\n\ttypes_hash_max_size 2048;\n\n"
                      "\tinclude /etc/nginx/mime.types;\n\tdefault_type application/octet-stream;\n\n"
                      "\taccess_log /var/log/nginx/access.log;\n\terror_log /var/log/nginx/error.log;\n\n"
                      "\tgzip on;\n\n\tinclude /etc/nginx/conf.d/*.conf;\n\tinclude /etc/nginx/sites-enabled/*;\n}\n")
            self.file("/etc/nginx/sites-available/default",
                      "server {\n\tlisten 80 default_server;\n\tlisten [::]:80 default_server;\n\n\troot /var/www/html;\n"
                      "\tindex index.html index.htm index.nginx-debian.html;\n\n\tserver_name _;\n\n"
                      "\tlocation / {\n\t\ttry_files $uri $uri/ =404;\n\t}\n}\n")
            self.link("/etc/nginx/sites-enabled/default", "/etc/nginx/sites-available/default")
            for name in ("/etc/nginx/conf.d", "/etc/nginx/modules-enabled", "/etc/nginx/snippets"):
                self.dir(name)
            self.script("/etc/init.d/nginx", "init script for nginx")
        else:
            self.file("/etc/apache2/apache2.conf",
                      "# This is the main Apache server configuration file.\n\nDefaultRuntimeDir ${APACHE_RUN_DIR}\n"
                      "PidFile ${APACHE_PID_FILE}\nTimeout 300\nKeepAlive On\nMaxKeepAliveRequests 100\nKeepAliveTimeout 5\n\n"
                      "User ${APACHE_RUN_USER}\nGroup ${APACHE_RUN_GROUP}\n\nErrorLog ${APACHE_LOG_DIR}/error.log\nLogLevel warn\n\n"
                      "IncludeOptional mods-enabled/*.load\nIncludeOptional mods-enabled/*.conf\nInclude ports.conf\n\n"
                      "<Directory /var/www/>\n\tOptions Indexes FollowSymLinks\n\tAllowOverride None\n\tRequire all granted\n</Directory>\n\n"
                      "IncludeOptional conf-enabled/*.conf\nIncludeOptional sites-enabled/*.conf\n")
            self.file("/etc/apache2/ports.conf", "Listen 80\n\n<IfModule ssl_module>\n\tListen 443\n</IfModule>\n")
            self.file("/etc/apache2/sites-available/000-default.conf",
                      "<VirtualHost *:80>\n\tServerAdmin webmaster@localhost\n\tDocumentRoot /var/www/html\n\n"
                      "\tErrorLog ${APACHE_LOG_DIR}/error.log\n\tCustomLog ${APACHE_LOG_DIR}/access.log combined\n</VirtualHost>\n")
            self.link("/etc/apache2/sites-enabled/000-default.conf", "../sites-available/000-default.conf")
            for name in ("/etc/apache2/mods-enabled", "/etc/apache2/conf-enabled", "/etc/apache2/mods-available"):
                self.dir(name)
            self.script("/etc/init.d/apache2", "init script for apache2")
        if identity.ftp_family == "proftpd":
            self.file("/etc/proftpd/proftpd.conf",
                      "Include /etc/proftpd/modules.conf\n\nUseIPv6 on\nServerName \"Debian\"\nServerType standalone\n"
                      "DefaultServer on\nPort 21\nUser proftpd\nGroup nogroup\nUmask 022 022\nTransferLog /var/log/proftpd/xferlog\n")
        else:
            self.file("/etc/vsftpd.conf",
                      "listen=NO\nlisten_ipv6=YES\nanonymous_enable=NO\nlocal_enable=YES\nwrite_enable=YES\n"
                      "dirmessage_enable=YES\nuse_localtime=YES\nxferlog_enable=YES\nconnect_from_port_20=YES\n"
                      "secure_chroot_dir=/var/run/vsftpd/empty\npam_service_name=vsftpd\nssl_enable=NO\n")
        for name in ("common-auth", "common-account", "common-password", "common-session", "sshd", "sudo", "login", "su"):
            self.file("/etc/pam.d/" + name, f"#\n# /etc/pam.d/{name}\n#\n@include common-auth\n@include common-account\n@include common-session\n"
                      if not name.startswith("common") else
                      f"#\n# /etc/pam.d/{name}\n#\n{name.split('-')[1]}\t[success=1 default=ignore]\tpam_unix.so\n{name.split('-')[1]}\trequisite\t\t\tpam_deny.so\n{name.split('-')[1]}\trequired\t\t\tpam_permit.so\n")

    def _build_var(self) -> None:
        identity = self.identity
        tokens = get_honeytokens()
        for name in ("/var/backups", "/var/cache/apt/archives", "/var/crash", "/var/lib/apt/lists",
                     "/var/lib/dpkg/info", "/var/lib/systemd", "/var/lib/cloud", "/var/local",
                     "/var/mail", "/var/opt", "/var/spool/rsyslog", "/var/www/html"):
            self.dir(name)
        self.dir("/var/tmp", 0o1777)
        self.dir("/var/lib/mysql", 0o700, "mysql", "mysql")
        self.dir("/var/spool/cron/crontabs", 0o1730, "root", "crontab")
        self.link("/var/run", "/run")
        self.link("/var/lock", "/run/lock")
        self.link("/var/spool/mail", "../mail")
        self.file("/var/lib/dpkg/status", "Package: adduser\nStatus: install ok installed\nPriority: important\nSection: admin\nInstalled-Size: 624\nArchitecture: all\nVersion: 3.118ubuntu2\n\n")
        # Planted: an old config beside the backups, and the application's
        # environment file in the web root.
        self.file("/var/backups/config.bak", tokens.config_backup(), 0o644,
                  mtime=self.installed + 140 * _DAY)
        self.blob("/var/backups/apt.extended_states.0", 3412)
        self.blob("/var/backups/dpkg.status.0", 652316)
        self.file("/var/www/html/.env", tokens.env_file(), 0o644, "www-data", "www-data",
                  mtime=self.installed + 188 * _DAY)
        if identity.http_family == "nginx":
            self.file("/var/www/html/index.nginx-debian.html",
                      "<!DOCTYPE html>\n<html>\n<head>\n<title>Welcome to nginx!</title>\n<style>\n"
                      "    body {\n        width: 35em;\n        margin: 0 auto;\n"
                      "        font-family: Tahoma, Verdana, Arial, sans-serif;\n    }\n</style>\n</head>\n<body>\n"
                      "<h1>Welcome to nginx!</h1>\n<p>If you see this page, the nginx web server is successfully installed and\n"
                      "working. Further configuration is required.</p>\n\n"
                      "<p>For online documentation and support please refer to\n<a href=\"http://nginx.org/\">nginx.org</a>.<br/>\n"
                      "Commercial support is available at\n<a href=\"http://nginx.com/\">nginx.com</a>.</p>\n\n"
                      "<p><em>Thank you for using nginx.</em></p>\n</body>\n</html>\n")
        else:
            self.file("/var/www/html/index.html",
                      "<!DOCTYPE html PUBLIC \"-//W3C//DTD XHTML 1.0 Transitional//EN\" \"http://www.w3.org/TR/xhtml1/DTD/xhtml1-transitional.dtd\">\n"
                      "<html xmlns=\"http://www.w3.org/1999/xhtml\">\n  <head>\n"
                      "    <meta http-equiv=\"Content-Type\" content=\"text/html; charset=UTF-8\" />\n"
                      "    <title>Apache2 Ubuntu Default Page: It works</title>\n  </head>\n  <body>\n"
                      "    <h1>Apache2 Ubuntu Default Page</h1>\n    <p>It works!</p>\n"
                      "    <p>This is the default welcome page used to test the correct operation of the\n"
                      "    Apache2 server after installation on Ubuntu systems.</p>\n  </body>\n</html>\n")
        if "ftp" in hostfacts._enabled_protocols():
            self.dir("/srv/ftp", 0o755, "root", "ftp")
        self._build_logs()

    def _build_logs(self) -> None:
        identity = self.identity
        recent = lambda: time.time() - time.time() % 60  # noqa: E731 - a clock, not a function worth naming
        self.dir("/var/log", 0o775, "root", "syslog", mtime=recent)
        self.dir("/var/log/apt")
        self.dir("/var/log/journal", 0o2755, "root", "systemd-journal")
        self.dir("/var/log/mysql", 0o750, "mysql", "adm")
        web = "nginx" if identity.http_family == "nginx" else "apache2"
        self.dir("/var/log/" + web, 0o755, "root", "adm")
        host = identity.hostname
        sshd = hostfacts.process_named(identity, "sshd")
        cron = hostfacts.process_named(identity, "cron")
        sshd_pid = sshd.pid if sshd else 700
        cron_pid = cron.pid if cron else 650

        def stamp(offset: float) -> str:
            return time.strftime("%b %e %H:%M:%S", time.gmtime(identity.last_login_time - offset))

        def auth_log() -> bytes:
            ip = identity.last_login_ip
            lines = [
                f"{stamp(4000)} {host} CRON[{cron_pid + 311}]: pam_unix(cron:session): session opened for user root by (uid=0)",
                f"{stamp(3999)} {host} CRON[{cron_pid + 311}]: pam_unix(cron:session): session closed for user root",
                f"{stamp(12)} {host} sshd[{sshd_pid + 870}]: Accepted password for root from {ip} port 52114 ssh2",
                f"{stamp(12)} {host} sshd[{sshd_pid + 870}]: pam_unix(sshd:session): session opened for user root by (uid=0)",
                f"{stamp(11)} {host} systemd-logind[{sshd_pid - 40}]: New session 214 of user root.",
            ]
            return ("\n".join(lines) + "\n").encode()

        def syslog() -> bytes:
            lines = [
                f"{stamp(7200)} {host} systemd[1]: Starting Daily apt download activities...",
                f"{stamp(7195)} {host} systemd[1]: apt-daily.service: Succeeded.",
                f"{stamp(7195)} {host} systemd[1]: Finished Daily apt download activities.",
                f"{stamp(3600)} {host} CRON[{cron_pid + 311}]: (root) CMD (   cd / && run-parts --report /etc/cron.hourly)",
                f"{stamp(600)} {host} systemd[1]: Starting Cleanup of Temporary Directories...",
                f"{stamp(599)} {host} systemd[1]: systemd-tmpfiles-clean.service: Succeeded.",
            ]
            return ("\n".join(lines) + "\n").encode()

        self.file("/var/log/auth.log", auth_log, 0o640, "syslog", "adm", mtime=recent)
        self.file("/var/log/syslog", syslog, 0o640, "syslog", "adm", mtime=recent)
        self.file("/var/log/kern.log", f"{stamp(90000)} {host} kernel: [    0.000000] Linux version {identity.kernel}\n",
                  0o640, "syslog", "adm")
        installed = time.strftime("%Y-%m-%d %H:%M:%S", time.gmtime(self.installed))
        self.file("/var/log/dpkg.log", f"{installed} startup archives unpack\n{installed} install base-passwd:amd64 <none> 3.5.47\n{installed} status half-installed base-passwd:amd64 3.5.47\n{installed} status unpacked base-passwd:amd64 3.5.47\n")
        self.file("/var/log/apt/history.log", f"\nStart-Date: {installed[:10]}  {installed[11:]}\nCommandline: apt-get install -y openssh-server\nInstall: openssh-server:amd64 (1:8.2p1-4ubuntu0.9)\nEnd-Date: {installed[:10]}  {installed[11:]}\n")
        self.blob("/var/log/wtmp", 23040, 0o664, mtime=recent)
        self.blob("/var/log/lastlog", 292292, 0o664, mtime=recent)
        self.blob("/var/log/btmp", 12672, 0o660, mtime=recent)
        self.file(f"/var/log/{web}/access.log", b"", 0o640, "www-data" if web == "nginx" else "root", "adm", mtime=recent)
        self.file(f"/var/log/{web}/error.log", b"", 0o640, "www-data" if web == "nginx" else "root", "adm")

    def _home(self, home: str, owner: str, root: bool = False) -> None:
        identity = self.identity
        self.dir(home, 0o700 if root else 0o755, owner)
        self.file(f"{home}/.bashrc", _BASHRC_ROOT, 0o644, owner)
        self.file(f"{home}/.profile", _PROFILE_ROOT if root else _PROFILE_USER, 0o644, owner)
        if not root:
            self.file(f"{home}/.bash_logout", _BASH_LOGOUT, 0o644, owner)
        self.dir(f"{home}/.cache", 0o700, owner)
        self.file(f"{home}/.cache/motd.legal-displayed", b"", 0o644, owner)
        if canary.enabled():
            self.file(f"{home}/{canary.BAIT_NAME}", canary.bait_text(identity), 0o644, owner,
                      mtime=self.installed + 201 * _DAY)

    def _build_homes(self) -> None:
        identity = self.identity
        tokens = get_honeytokens()
        self._home("/root", "root", root=True)
        self.dir("/root/.ssh", 0o700)
        key_rng = hostfacts.seeded(identity, "authorized-keys")
        alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/"
        public = "AAAAC3NzaC1lZDI1NTE5AAAAI" + "".join(key_rng.choice(alphabet) for _ in range(43))
        admin = identity.users[0][0] if identity.users else "admin"
        self.file("/root/.ssh/authorized_keys", f"ssh-ed25519 {public} {admin}@ops-laptop\n", 0o600)
        self.dir("/root/.aws", 0o755)
        self.file("/root/.aws/credentials", tokens.aws_credentials(), 0o600,
                  mtime=self.installed + 150 * _DAY)
        self.file("/root/.aws/config", "[default]\nregion = eu-west-1\noutput = json\n", 0o600)
        self.dir("/root/.local/share", 0o700)
        web = "nginx" if identity.http_family == "nginx" else "apache2"
        leaked = tokens.history_lines()
        history = [
            "apt update", "apt list --upgradable", f"systemctl status {web}",
            "df -h", "free -m", f"tail -n 50 /var/log/{web}/error.log",
            "cd /var/www/html", "ls -la", "cat .env", leaked[0], "exit",
            "journalctl -u ssh --since yesterday", "crontab -l",
            "cp /var/www/html/config.php /var/backups/config.bak",
            leaked[1], "aws s3 ls s3://portal-backups/", "uptime", "exit",
        ]
        self.file("/root/.bash_history", "\n".join(history) + "\n", 0o600,
                  mtime=lambda: identity.last_login_time)
        for name, _uid, home, _shell in hostfacts.login_accounts(identity):
            self._home(home, name)
        self.file(f"{identity.users[0][2]}/.sudo_as_admin_successful", b"", 0o644, admin)
        planted = f"/home/{tokens.username}"
        self.dir(f"{planted}/.ssh", 0o700, tokens.username)
        self.file(f"{planted}/.ssh/authorized_keys", f"ssh-ed25519 {public} {admin}@ops-laptop\n", 0o600, tokens.username)

    def _build_kernel_views(self) -> None:
        identity = self.identity
        boot = identity.boot_time
        now = time.time

        def proc_file(path: str, render: Callable[[], str], mode: int = 0o444) -> None:
            # /proc files have no stored size: they list as zero bytes.
            self.file(path, lambda: render().encode(), mode, mtime=now, size=0)

        self.nodes["/proc"].mode = 0o555
        self.nodes["/proc"].mtime = boot
        self.nodes["/sys"].mode = 0o555
        self.nodes["/sys"].mtime = boot
        proc_file("/proc/cpuinfo", lambda: hostfacts.cpuinfo(identity))
        proc_file("/proc/meminfo", lambda: hostfacts.meminfo(identity))
        proc_file("/proc/version", lambda: (
            f"Linux version {identity.kernel} (buildd@lcy02-amd64-045) "
            f"(gcc version 9.4.0 (Ubuntu 9.4.0-1ubuntu1~20.04.1)) {identity.kernel_build}\n"))
        proc_file("/proc/uptime", lambda: f"{identity.uptime_seconds:.2f} {identity.uptime_seconds * identity.cpu_cores * 0.97:.2f}\n")
        proc_file("/proc/loadavg", lambda: "%.2f %.2f %.2f 1/%d %d\n" % (
            *hostfacts.load_average(identity), 180 + identity.cpu_cores * 12, hostfacts.processes(identity)[-1].pid + 400))
        proc_file("/proc/cmdline", lambda: f"BOOT_IMAGE=/boot/vmlinuz-{identity.kernel} root=UUID={hostfacts.root_uuid(identity)} ro console=tty1 console=ttyS0\n")
        proc_file("/proc/filesystems", lambda: "nodev\tsysfs\nnodev\ttmpfs\nnodev\tbdev\nnodev\tproc\nnodev\tcgroup\nnodev\tcgroup2\nnodev\tdevtmpfs\nnodev\tdevpts\n\text3\n\text2\n\text4\n\tvfat\n")
        proc_file("/proc/swaps", lambda: "Filename\t\t\t\tType\t\tSize\tUsed\tPriority\n" + (
            f"/swap.img                               file\t\t{identity.swap_kb}\t{hostfacts.memory(identity).swap_used}\t-2\n" if identity.swap_kb else ""))
        proc_file("/proc/partitions", lambda: "major minor  #blocks  name\n\n 252        0  %d vda\n 252        1  %d vda1\n" % (
            identity.disk_total_kb + 1024, identity.disk_total_kb))
        proc_file("/proc/sys/kernel/hostname", lambda: identity.hostname + "\n", 0o644)
        proc_file("/proc/sys/kernel/osrelease", lambda: identity.kernel + "\n")
        proc_file("/proc/sys/kernel/ostype", lambda: "Linux\n")
        proc_file("/proc/sys/kernel/version", lambda: identity.kernel_build + "\n")
        proc_file("/proc/sys/kernel/random/boot_id", lambda: hostfacts.seeded_uuid(identity, f"boot-id:{int(identity.boot_time)}") + "\n")
        self.link("/proc/mounts", "self/mounts")
        self.link("/proc/net", "self/net")
        for proc in hostfacts.processes(identity):
            base = f"/proc/{proc.pid}"
            self.dir(base, 0o555, proc.user, mtime=boot)
            argv = "" if proc.kernel else proc.command.replace(" ", "\x00") + "\x00"
            proc_file(f"{base}/cmdline", lambda argv=argv: argv)
            proc_file(f"{base}/comm", lambda proc=proc: proc.name[:15] + "\n", 0o644)
            proc_file(f"{base}/cgroup", hostfacts.cgroup)
            proc_file(f"{base}/status", lambda proc=proc: (
                f"Name:\t{proc.name[:15]}\nUmask:\t0022\nState:\tS (sleeping)\nTgid:\t{proc.pid}\n"
                f"Pid:\t{proc.pid}\nPPid:\t{proc.ppid}\nUid:\t0\t0\t0\t0\nGid:\t0\t0\t0\t0\n"
                f"VmSize:\t{proc.vsz:8d} kB\nVmRSS:\t{proc.rss:8d} kB\nThreads:\t1\n"))
            if not proc.kernel:
                self.link(f"{base}/exe", proc.command.split()[0] if proc.command.startswith("/") else "/usr/sbin/" + proc.name)
        # The visiting shell's own entry. One fixed set of answers: which
        # process "self" is cannot be told apart from inside these files.
        self.dir("/proc/self", 0o555, mtime=now)
        proc_file("/proc/self/cgroup", hostfacts.cgroup)
        proc_file("/proc/self/mounts", lambda: hostfacts.mounts(identity))
        proc_file("/proc/self/cmdline", lambda: "-bash\x00")
        proc_file("/proc/self/comm", lambda: "bash\n", 0o644)
        proc_file("/proc/self/status", lambda: "Name:\tbash\nUmask:\t0022\nState:\tS (sleeping)\nUid:\t0\t0\t0\t0\nGid:\t0\t0\t0\t0\nThreads:\t1\n")
        proc_file("/proc/self/environ", lambda: "SHELL=/bin/bash\x00LANG=en_US.UTF-8\x00PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin\x00", 0o400)
        self.link("/proc/self/exe", "/usr/bin/bash")
        self.dir("/proc/self/net", 0o555, mtime=now)
        proc_file("/proc/self/net/dev", lambda: (
            "Inter-|   Receive                                                |  Transmit\n"
            " face |bytes    packets errs drop fifo frame compressed multicast|bytes    packets errs drop fifo colls carrier compressed\n"
            "    lo:  184320    2104    0    0    0     0          0         0   184320    2104    0    0    0     0       0          0\n"
            "  eth0: %d  %d    0    0    0     0          0         0 %d  %d    0    0    0     0       0          0\n"
            % hostfacts.interface_counters(identity)))

        product, vendor, _hypervisor = hostfacts.platform_facts(identity)
        for name in ("/sys/block", "/sys/bus", "/sys/class/net", "/sys/dev", "/sys/devices/system/cpu",
                     "/sys/devices/virtual/dmi/id", "/sys/firmware", "/sys/fs/cgroup", "/sys/kernel",
                     "/sys/module", "/sys/power"):
            self.dir(name, mtime=boot)
        self.link("/sys/class/net/eth0", "../../devices/virtual/net/eth0")
        self.dir("/sys/devices/virtual/net/eth0", mtime=boot)
        self.file("/sys/devices/virtual/net/eth0/address", identity.mac + "\n", 0o444, mtime=boot)
        self.file("/sys/devices/virtual/net/eth0/operstate", "up\n", 0o444, mtime=boot)
        self.file("/sys/devices/virtual/net/eth0/mtu", "1500\n", mtime=boot)
        self.link("/sys/class/dmi", "../devices/virtual/dmi")
        self.file("/sys/devices/virtual/dmi/id/product_name", product + "\n", 0o444, mtime=boot)
        self.file("/sys/devices/virtual/dmi/id/sys_vendor", vendor + "\n", 0o444, mtime=boot)
        self.file("/sys/devices/system/cpu/online", f"0-{identity.cpu_cores - 1}\n" if identity.cpu_cores > 1 else "0\n", 0o444, mtime=boot)

    def _build_misc(self) -> None:
        identity = self.identity
        boot = identity.boot_time
        self.nodes["/dev"].mtime = boot
        self.nodes["/run"].mtime = boot
        for name, major, minor, mode in (("null", 1, 3, 0o666), ("zero", 1, 5, 0o666), ("full", 1, 7, 0o666),
                                         ("random", 1, 8, 0o666), ("urandom", 1, 9, 0o666),
                                         ("tty", 5, 0, 0o666), ("console", 5, 1, 0o600), ("ptmx", 5, 2, 0o666),
                                         ("kmsg", 1, 11, 0o644), ("mem", 1, 1, 0o640)):
            self.device("/dev/" + name, "char", major, minor, mode)
        self.device("/dev/vda", "block", 252, 0, 0o660, "disk")
        self.device("/dev/vda1", "block", 252, 1, 0o660, "disk")
        self.dir("/dev/shm", 0o1777, mtime=boot)
        self.dir("/dev/pts", 0o755, mtime=boot)
        self.device("/dev/pts/0", "char", 136, 0, 0o620, "tty")
        self.link("/dev/stdin", "/proc/self/fd/0")
        self.link("/dev/stdout", "/proc/self/fd/1")
        self.link("/dev/stderr", "/proc/self/fd/2")
        self.link("/dev/fd", "/proc/self/fd")
        for name in ("/dev/disk", "/dev/net", "/dev/mapper", "/dev/hugepages", "/dev/mqueue"):
            self.dir(name, mtime=boot)

        self.dir("/run/lock", 0o1777, mtime=boot)
        self.dir("/run/sshd", mtime=boot)
        self.dir("/run/systemd/resolve", mtime=boot)
        self.dir("/run/user", mtime=boot)
        self.dir("/run/mysqld", 0o755, "mysql", "mysql", mtime=boot)
        self.file("/run/systemd/resolve/stub-resolv.conf",
                  "# This file is managed by man:systemd-resolved(8). Do not edit.\n"
                  f"nameserver 127.0.0.53\noptions edns0 trust-ad\nsearch {identity.domain}\n", mtime=boot)
        self.file("/run/systemd/resolve/resolv.conf",
                  f"nameserver {identity.nameserver}\nsearch {identity.domain}\n", mtime=boot)
        for name, pid_file in (("sshd", "/run/sshd.pid"), ("cron", "/run/crond.pid"),
                               ("mysqld", "/run/mysqld/mysqld.pid"), ("nginx", "/run/nginx.pid")):
            proc = hostfacts.process_named(identity, name)
            if proc is not None:
                self.file(pid_file, f"{proc.pid}\n", mtime=boot)
        self.blob("/run/utmp", 1920, 0o664, mtime=lambda: identity.last_login_time)

        kernel = identity.kernel
        kernel_time = self._stamp("/boot/kernel", self.installed + 20 * _DAY, self.installed + 320 * _DAY)
        self.blob(f"/boot/vmlinuz-{kernel}", 13660416, 0o600, mtime=kernel_time)
        self.blob(f"/boot/initrd.img-{kernel}", 84719360, 0o644, mtime=kernel_time + 40)
        self.blob(f"/boot/System.map-{kernel}", 4759520, 0o600, mtime=kernel_time)
        self.blob(f"/boot/config-{kernel}", 237884, 0o644, mtime=kernel_time)
        self.link("/boot/vmlinuz", f"vmlinuz-{kernel}")
        self.link("/boot/initrd.img", f"initrd.img-{kernel}")
        self.dir("/boot/grub", mtime=kernel_time + 60)
        self.file("/boot/grub/grubenv", "# GRUB Environment Block\n" + "#" * 999, mtime=kernel_time + 60)

        self.dir("/snap/bin")
        self.file("/snap/README", _SNAP_README)

        # What systemd leaves in /tmp on a server nobody is using.
        rng = hostfacts.seeded(identity, "tmp")
        for name in (".ICE-unix", ".Test-unix", ".X11-unix", ".XIM-unix", ".font-unix"):
            self.dir("/tmp/" + name, 0o1777, mtime=boot)
        token = "".join(rng.choice("0123456789abcdef") for _ in range(32))
        for service in ("systemd-logind", "systemd-resolved", "systemd-timesyncd"):
            suffix = "".join(rng.choice("ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789") for _ in range(6))
            self.dir(f"/tmp/systemd-private-{token}-{service}.service-{suffix}", 0o700, mtime=boot)
            self.dir(f"/var/tmp/systemd-private-{token}-{service}.service-{suffix}", 0o700, mtime=boot)

    # -- lookups -----------------------------------------------------------

    def canonical(self, path: str, follow_last: bool = True) -> str:
        """``path`` with the symlinks along it followed."""
        for _ in range(8):
            if path == "/":
                return path
            parts = path.strip("/").split("/")
            current = ""
            replaced = False
            for index, part in enumerate(parts):
                current += "/" + part
                node = self.nodes.get(current)
                if node is None or node.kind != "link":
                    continue
                if index == len(parts) - 1 and not follow_last:
                    continue
                target = node.target
                if not target.startswith("/"):
                    target = posixpath.join(posixpath.dirname(current), target)
                rest = "/".join(parts[index + 1:])
                path = posixpath.normpath(posixpath.join(target, rest) if rest else target)
                replaced = True
                break
            if not replaced:
                return path
        return path

    def get(self, path: str, follow: bool = True) -> Optional[Entry]:
        return self.nodes.get(self.canonical(path, follow))

    def names(self, path: str) -> list[str]:
        return sorted(self.children.get(self.canonical(path), ()))


# --------------------------------------------------------------------------
# The cached tree
# --------------------------------------------------------------------------

_lock = threading.Lock()
_cached: Optional[VirtualFS] = None
_cached_key: Optional[tuple] = None


def get_vfs() -> VirtualFS:
    """The tree for the current identity, built on first use."""
    global _cached, _cached_key
    identity = get_identity()
    key = (identity.seed, id(identity), canary.enabled(), tuple(sorted(hostfacts._enabled_protocols())))
    with _lock:
        if _cached is None or _cached_key != key:
            _cached = VirtualFS(identity)
            _cached_key = key
        return _cached


# --------------------------------------------------------------------------
# A session's view
# --------------------------------------------------------------------------


class FsView:
    """The seeded tree with one session's changes laid over it.

    Files the session wrote or fetched, directories it made and paths it
    removed live in its :class:`ShellState`; this answers every question
    about the filesystem from both together, for one user.
    """

    def __init__(self, shell: ShellState, username: str = "root", is_root: bool = True,
                 vfs: Optional[VirtualFS] = None) -> None:
        self.vfs = vfs or get_vfs()
        self.shell = shell
        self.username = username or ("root" if is_root else "user")
        self.is_root = is_root

    # -- session overlay ---------------------------------------------------

    def _session_entry(self, path: str) -> Optional[Entry]:
        shell = self.shell
        if path in shell.dirs:
            return Entry("dir", 0o755, self.username, self.username, 4096,
                         shell.dir_times.get(path, shell.last_used), nlink=2, session=True)
        file = shell.files.get(path)
        content = shell.contents.get(path)
        if file is None and content is None:
            return None
        size = len(content) if content is not None else file.size
        executable = bool(file and file.executable)
        return Entry(
            "file", 0o755 if executable else 0o644, self.username, self.username, size,
            file.created_at if file else shell.last_used,
            source_url=file.source_url if file else None, session=True,
        )

    def _hidden(self, path: str) -> bool:
        removed = self.shell.removed
        if not removed:
            return False
        if path in removed:
            return True
        return any(path.startswith(r.rstrip("/") + "/") for r in removed)

    def lookup(self, path: str, follow: bool = True) -> Optional[Entry]:
        """The entry at ``path``, or None when nothing is there."""
        entry = self._session_entry(path)
        if entry is not None:
            return entry
        canonical = self.vfs.canonical(path, follow)
        if canonical != path:
            entry = self._session_entry(canonical)
            if entry is not None:
                return entry
        if self._hidden(canonical):
            return None
        return self.vfs.nodes.get(canonical)

    def exists(self, path: str) -> bool:
        return self.lookup(path) is not None

    def is_dir(self, path: str) -> bool:
        entry = self.lookup(path)
        return entry is not None and entry.kind == "dir"

    def is_file(self, path: str) -> bool:
        entry = self.lookup(path)
        return entry is not None and entry.kind == "file"

    # -- permissions -------------------------------------------------------

    def _allowed(self, entry: Entry, bit: int) -> bool:
        if self.is_root:
            return True
        if entry.owner == self.username:
            return bool(entry.mode & (bit << 6))
        return bool(entry.mode & bit)

    def can_read(self, entry: Entry) -> bool:
        return self._allowed(entry, 4)

    def can_enter(self, path: str) -> bool:
        entry = self.lookup(path)
        return entry is not None and entry.kind == "dir" and self._allowed(entry, 1)

    def can_list(self, entry: Entry) -> bool:
        return self._allowed(entry, 4)

    def can_write(self, path: str) -> bool:
        """Whether this user could create or replace ``path``."""
        if self.is_root:
            return True
        entry = self.lookup(path)
        if entry is not None and entry.kind != "dir":
            return self._allowed(entry, 2)
        parent = self.lookup(posixpath.dirname(path))
        return parent is not None and parent.kind == "dir" and self._allowed(parent, 2)

    # -- reading -----------------------------------------------------------

    def listdir(self, path: str) -> list[tuple[str, Entry]]:
        """Children of a directory, sorted by name."""
        canonical = self.vfs.canonical(path)
        found: dict[str, Entry] = {}
        if not self._hidden(canonical):
            for name in self.vfs.children.get(canonical, ()):
                child = posixpath.join(canonical, name)
                if not self._hidden(child):
                    found[name] = self.vfs.nodes[child]
        shell = self.shell
        for candidate in list(shell.dirs) + list(shell.files) + list(shell.contents):
            if posixpath.dirname(candidate) in (path, canonical) and candidate not in ("/",):
                entry = self._session_entry(candidate)
                if entry is not None:
                    found[posixpath.basename(candidate)] = entry
        return sorted(found.items())

    def read(self, path: str, limit: int = MAX_GENERATED_BYTES) -> Optional[bytes]:
        """A file's bytes; None when there is no readable file at ``path``.

        Use :meth:`lookup` first to tell "missing" from "is a directory"
        from "permission denied"; this returns None for all three.
        """
        written = self.shell.contents.get(path)
        if written is None:
            canonical = self.vfs.canonical(path)
            written = self.shell.contents.get(canonical)
        if written is not None:
            return bytes(written[:limit])
        entry = self.lookup(path)
        if entry is None or entry.kind == "dir" or not self.can_read(entry):
            return None
        if entry.session:
            # Fetched with wget or curl: the engine never retrieved it, so
            # there is nothing true to show. A script-like name reads as
            # empty; anything else as an ELF binary of the size listed.
            if entry.size == 0 or posixpath.splitext(path)[1] in (".sh", ".py", ".pl", ".txt", ".php"):
                return b""
            return elf_blob(self.vfs.identity.seed, path, min(entry.size, limit))
        if entry.kind == "char":
            if path.endswith(("/urandom", "/random")):
                return random.randbytes(min(limit, 65536))
            if path.endswith("/zero"):
                return bytes(min(limit, 65536))
            return b""
        if entry.kind == "block":
            return None
        content = entry.content
        if content is None:
            return b""
        data = content() if callable(content) else content
        return data[:limit]

    def glob(self, pattern: str, cwd: str, home: str) -> list[str]:
        """Paths matching a pattern with wildcards in its last component(s)."""
        from honeypot.core.shell_syntax import glob_match, resolve_path

        if not any(ch in pattern for ch in "*?"):
            return []
        absolute = pattern.startswith(("/", "~"))
        parts = [p for p in resolve_path(cwd, pattern, home).split("/") if p]
        candidates = ["/"]
        for part in parts:
            matched: list[str] = []
            for base in candidates:
                if any(ch in part for ch in "*?"):
                    for name, _entry in self.listdir(base):
                        if name.startswith(".") and not part.startswith("."):
                            continue
                        if glob_match(part, name):
                            matched.append(posixpath.join(base, name))
                elif self.exists(posixpath.join(base, part)):
                    matched.append(posixpath.join(base, part))
                if len(matched) >= 512:
                    break
            candidates = matched[:512]
            if not candidates:
                return []
        if absolute:
            return candidates
        prefix = cwd.rstrip("/") + "/"
        return [c[len(prefix):] if c.startswith(prefix) else c for c in candidates]
