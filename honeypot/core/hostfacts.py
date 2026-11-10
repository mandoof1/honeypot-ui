"""Facts about the emulated host that more than one command reports.

``ps``, ``top``, ``pgrep``, ``netstat`` and ``ss`` all describe the same
processes and sockets; ``lscpu`` and ``/proc/cpuinfo`` the same processor;
``free`` and ``/proc/meminfo`` the same memory. Each of those used to be
written out separately, which is how the box came to report an AMD model name
under a ``GenuineIntel`` vendor line and ``apache2`` in ``ps`` while the HTTP
decoy called itself nginx. They are derived here, once, from the host
identity, and every command renders the same table.

They are also derived from the identity's *seed*. The process ids, the
shadow hashes and the socket owners used to be literals in the source, so
every deployment of this project answered ``ps aux`` identically — a
signature anyone could match after seeing one of them.
"""

from __future__ import annotations

import random
import time
from dataclasses import dataclass
from typing import Optional

from honeypot.core.identity import HostIdentity


def seeded(identity: HostIdentity, label: str) -> random.Random:
    """A generator that gives this deployment its own stable answers."""
    return random.Random(f"{identity.seed}:{label}")


# --------------------------------------------------------------------------
# Processor and memory
# --------------------------------------------------------------------------

_INTEL_FLAGS = (
    "fpu vme de pse tsc msr pae mce cx8 apic sep mtrr pge mca cmov pat pse36 "
    "clflush mmx fxsr sse sse2 ss ht syscall nx pdpe1gb rdtscp lm constant_tsc "
    "rep_good nopl xtopology nonstop_tsc cpuid pni pclmulqdq ssse3 fma cx16 "
    "pcid sse4_1 sse4_2 x2apic movbe popcnt aes xsave avx f16c rdrand "
    "hypervisor lahf_lm abm 3dnowprefetch invpcid_single pti fsgsbase bmi1 "
    "avx2 smep bmi2 erms invpcid"
)
_AMD_FLAGS = (
    "fpu vme de pse tsc msr pae mce cx8 apic sep mtrr pge mca cmov pat pse36 "
    "clflush mmx fxsr sse sse2 ht syscall nx mmxext fxsr_opt pdpe1gb rdtscp lm "
    "constant_tsc rep_good nopl nonstop_tsc cpuid extd_apicid tsc_known_freq "
    "pni pclmulqdq ssse3 fma cx16 sse4_1 sse4_2 x2apic movbe popcnt aes xsave "
    "avx f16c rdrand hypervisor lahf_lm cmp_legacy cr8_legacy abm sse4a "
    "misalignsse 3dnowprefetch topoext ssbd ibpb vmmcall fsgsbase bmi1 avx2 "
    "smep bmi2 rdseed adx smap clflushopt sha_ni xsaveopt xsavec xgetbv1 "
    "clzero xsaveerptr arat npt nrip_save"
)

#: Family, model, stepping and cache size for each processor an identity can
#: have, keyed by a fragment of its model name.
_CPU_DETAILS = (
    ("E5-2680 v4", "GenuineIntel", 6, 79, 1, 35840),
    ("Gold 6248", "GenuineIntel", 6, 85, 7, 28160),
    ("Platinum 8259CL", "GenuineIntel", 6, 85, 7, 36608),
    ("E5-2650 v2", "GenuineIntel", 6, 62, 4, 20480),
    ("E-2236", "GenuineIntel", 6, 158, 10, 12288),
    ("EPYC 7571", "AuthenticAMD", 23, 1, 2, 512),
    ("EPYC 7R32", "AuthenticAMD", 23, 49, 0, 512),
)


@dataclass(frozen=True)
class CpuFacts:
    vendor: str
    family: int
    model: int
    stepping: int
    cache_kb: int
    flags: str
    address_sizes: str


def cpu_facts(identity: HostIdentity) -> CpuFacts:
    """The vendor line that belongs with the identity's model name."""
    for fragment, vendor, family, model, stepping, cache_kb in _CPU_DETAILS:
        if fragment in identity.cpu_model:
            break
    else:
        amd = "AMD" in identity.cpu_model
        vendor = "AuthenticAMD" if amd else "GenuineIntel"
        family, model, stepping, cache_kb = (23, 1, 2, 512) if amd else (6, 85, 7, 25344)
    amd = vendor == "AuthenticAMD"
    return CpuFacts(
        vendor=vendor,
        family=family,
        model=model,
        stepping=stepping,
        cache_kb=cache_kb,
        flags=_AMD_FLAGS if amd else _INTEL_FLAGS,
        address_sizes="48 bits physical, 48 bits virtual" if amd else "46 bits physical, 48 bits virtual",
    )


def cpuinfo(identity: HostIdentity) -> str:
    cpu = cpu_facts(identity)
    blocks = []
    for n in range(identity.cpu_cores):
        blocks.append(
            f"processor\t: {n}\n"
            f"vendor_id\t: {cpu.vendor}\n"
            f"cpu family\t: {cpu.family}\n"
            f"model\t\t: {cpu.model}\n"
            f"model name\t: {identity.cpu_model}\n"
            f"stepping\t: {cpu.stepping}\n"
            f"cpu MHz\t\t: {identity.cpu_mhz:.3f}\n"
            f"cache size\t: {cpu.cache_kb} KB\n"
            f"physical id\t: 0\nsiblings\t: {identity.cpu_cores}\n"
            f"core id\t\t: {n}\ncpu cores\t: {identity.cpu_cores}\n"
            f"apicid\t\t: {n}\ninitial apicid\t: {n}\n"
            "fpu\t\t: yes\nfpu_exception\t: yes\ncpuid level\t: 13\nwp\t\t: yes\n"
            f"flags\t\t: {cpu.flags}\n"
            f"bogomips\t: {identity.cpu_mhz * 2:.2f}\n"
            "clflush size\t: 64\ncache_alignment\t: 64\n"
            f"address sizes\t: {cpu.address_sizes}\n"
            "power management:\n"
        )
    return "\n".join(blocks) + "\n"


def lscpu(identity: HostIdentity) -> str:
    cpu = cpu_facts(identity)
    return (
        "Architecture:                    x86_64\n"
        "CPU op-mode(s):                  32-bit, 64-bit\n"
        "Byte Order:                      Little Endian\n"
        f"Address sizes:                   {cpu.address_sizes}\n"
        f"CPU(s):                          {identity.cpu_cores}\n"
        f"On-line CPU(s) list:             0-{identity.cpu_cores - 1}\n"
        "Thread(s) per core:              1\n"
        f"Core(s) per socket:              {identity.cpu_cores}\n"
        "Socket(s):                       1\n"
        "NUMA node(s):                    1\n"
        f"Vendor ID:                       {cpu.vendor}\n"
        f"CPU family:                      {cpu.family}\n"
        f"Model:                           {cpu.model}\n"
        f"Model name:                      {identity.cpu_model}\n"
        f"Stepping:                        {cpu.stepping}\n"
        f"CPU MHz:                         {identity.cpu_mhz:.3f}\n"
        f"BogoMIPS:                        {identity.cpu_mhz * 2:.2f}\n"
        f"Hypervisor vendor:               {platform_facts(identity)[2]}\n"
        "Virtualization type:             full\n"
    )


@dataclass(frozen=True)
class Memory:
    total: int
    used: int
    free: int
    shared: int
    buffers: int
    cached: int
    available: int
    swap_total: int
    swap_used: int

    @property
    def buff_cache(self) -> int:
        return self.buffers + self.cached


def memory(identity: HostIdentity, now: Optional[float] = None) -> Memory:
    """Memory use, in kB: one set of numbers for ``free`` and ``/proc/meminfo``.

    The split is the deployment's own, and drifts by a few megabytes from
    minute to minute as a running machine's does — but two commands in the
    same minute agree, where separate ``random`` calls never did.
    """
    rng = seeded(identity, "memory")
    total = identity.mem_kb
    used_share = rng.uniform(0.21, 0.44)
    free_share = rng.uniform(0.08, 0.24)
    minute = int((now if now is not None else time.time()) // 60)
    drift = random.Random(f"{identity.seed}:memory:{minute}").randint(-6000, 6000)
    used = int(total * used_share) + drift
    free = int(total * free_share) - drift
    buff_cache = total - used - free
    buffers = int(buff_cache * 0.12)
    shared = int(total * 0.004)
    swap_used = int(identity.swap_kb * rng.uniform(0.0, 0.06)) if identity.swap_kb else 0
    return Memory(
        total=total,
        used=used,
        free=free,
        shared=shared,
        buffers=buffers,
        cached=buff_cache - buffers,
        available=free + int(buff_cache * 0.82),
        swap_total=identity.swap_kb,
        swap_used=swap_used,
    )


def meminfo(identity: HostIdentity) -> str:
    m = memory(identity)
    rows = [
        ("MemTotal", m.total), ("MemFree", m.free), ("MemAvailable", m.available),
        ("Buffers", m.buffers), ("Cached", m.cached), ("SwapCached", 0),
        ("Active", int(m.used * 0.7 + m.cached * 0.4)),
        ("Inactive", int(m.used * 0.2 + m.cached * 0.55)),
        ("SwapTotal", m.swap_total), ("SwapFree", m.swap_total - m.swap_used),
        ("Dirty", 148), ("Writeback", 0),
        ("Shmem", m.shared), ("Slab", int(m.total * 0.03)),
    ]
    return "".join(f"{name + ':':<16}{value:>8} kB\n" for name, value in rows)


def load_average(identity: HostIdentity, now: Optional[float] = None) -> tuple[float, float, float]:
    """Load figures that hold still for a minute, like the kernel's own."""
    minute = int((now if now is not None else time.time()) // 60)
    rng = random.Random(f"{identity.seed}:load:{minute}")
    base = seeded(identity, "load").uniform(0.02, 0.18)
    one = max(0.0, base + rng.uniform(-0.03, 0.12))
    return round(one, 2), round(base + 0.02, 2), round(base, 2)


def platform_facts(identity: HostIdentity) -> tuple[str, str, str]:
    """(product name, system vendor, hypervisor) to go with the NIC's vendor.

    The MAC prefix already says which hypervisor the machine claims to run
    on; the DMI strings and ``lscpu`` must not say another.
    """
    oui = identity.mac[:8].lower()
    if oui in ("00:50:56", "00:0c:29"):
        return "VMware Virtual Platform", "VMware, Inc.", "VMware"
    if oui == "00:16:3e":
        return "HVM domU", "Xen", "Xen"
    if oui == "06:7a:1c":
        return "t3.medium", "Amazon EC2", "KVM"
    if oui == "42:01:0a":
        return "Google Compute Engine", "Google", "KVM"
    return "Standard PC (i440FX + PIIX, 1996)", "QEMU", "KVM"


def interface_counters(identity: HostIdentity) -> tuple[int, int, int, int]:
    """(rx bytes, rx packets, tx bytes, tx packets) for eth0.

    They grow with uptime instead of being re-rolled on each call, so
    ``ifconfig`` twice shows a counter that moved forwards.
    """
    rng = seeded(identity, "interface")
    rx_rate = rng.uniform(1.5, 14.0)
    tx_rate = rng.uniform(1.0, 9.0)
    rx_packets = int(identity.uptime_seconds * rx_rate) + 4000
    tx_packets = int(identity.uptime_seconds * tx_rate) + 3000
    return rx_packets * rng.randint(70, 240), rx_packets, tx_packets * rng.randint(60, 180), tx_packets


# --------------------------------------------------------------------------
# Accounts
# --------------------------------------------------------------------------

_SYSTEM_ACCOUNTS = [
    ("root", 0, 0, "root", "/root", "/bin/bash"),
    ("daemon", 1, 1, "daemon", "/usr/sbin", "/usr/sbin/nologin"),
    ("bin", 2, 2, "bin", "/bin", "/usr/sbin/nologin"),
    ("sys", 3, 3, "sys", "/dev", "/usr/sbin/nologin"),
    ("sync", 4, 65534, "sync", "/bin", "/bin/sync"),
    ("games", 5, 60, "games", "/usr/games", "/usr/sbin/nologin"),
    ("man", 6, 12, "man", "/var/cache/man", "/usr/sbin/nologin"),
    ("lp", 7, 7, "lp", "/var/spool/lpd", "/usr/sbin/nologin"),
    ("mail", 8, 8, "mail", "/var/mail", "/usr/sbin/nologin"),
    ("news", 9, 9, "news", "/var/spool/news", "/usr/sbin/nologin"),
    ("uucp", 10, 10, "uucp", "/var/spool/uucp", "/usr/sbin/nologin"),
    ("proxy", 13, 13, "proxy", "/bin", "/usr/sbin/nologin"),
    ("www-data", 33, 33, "www-data", "/var/www", "/usr/sbin/nologin"),
    ("backup", 34, 34, "backup", "/var/backups", "/usr/sbin/nologin"),
    ("list", 38, 38, "Mailing List Manager", "/var/list", "/usr/sbin/nologin"),
    ("irc", 39, 39, "ircd", "/var/run/ircd", "/usr/sbin/nologin"),
    ("gnats", 41, 41, "Gnats Bug-Reporting System (admin)", "/var/lib/gnats", "/usr/sbin/nologin"),
    ("nobody", 65534, 65534, "nobody", "/nonexistent", "/usr/sbin/nologin"),
    ("systemd-network", 100, 102, "systemd Network Management,,,", "/run/systemd", "/usr/sbin/nologin"),
    ("systemd-resolve", 101, 103, "systemd Resolver,,,", "/run/systemd", "/usr/sbin/nologin"),
    ("systemd-timesync", 102, 104, "systemd Time Synchronization,,,", "/run/systemd", "/usr/sbin/nologin"),
    ("messagebus", 103, 106, "", "/nonexistent", "/usr/sbin/nologin"),
    ("syslog", 104, 110, "", "/home/syslog", "/usr/sbin/nologin"),
    ("_apt", 105, 65534, "", "/nonexistent", "/usr/sbin/nologin"),
    ("sshd", 110, 65534, "", "/run/sshd", "/usr/sbin/nologin"),
    ("mysql", 112, 117, "MySQL Server,,,", "/nonexistent", "/bin/false"),
]


def extra_login_user() -> tuple[str, int, str, str]:
    """The planted account (see core/honeytokens.py), as a passwd row."""
    from honeypot.core.honeytokens import get_honeytokens

    name = get_honeytokens().username
    return name, 1100, f"/home/{name}", "/bin/bash"


def login_accounts(identity: HostIdentity) -> list[tuple[str, int, str, str]]:
    """Every account with a shell: (name, uid, home, shell)."""
    accounts = [(name, uid, home, shell) for name, uid, home, shell in identity.users]
    accounts.append(extra_login_user())
    return accounts


def passwd(identity: HostIdentity) -> str:
    lines = [f"{n}:x:{u}:{g}:{gecos}:{h}:{s}" for n, u, g, gecos, h, s in _SYSTEM_ACCOUNTS]
    if identity.ftp_family == "proftpd":
        lines.append("proftpd:x:113:65534::/run/proftpd:/usr/sbin/nologin")
        lines.append("ftp:x:114:65534::/srv/ftp:/usr/sbin/nologin")
    else:
        lines.append("ftp:x:113:118:ftp daemon,,,:/srv/ftp:/usr/sbin/nologin")
    for name, uid, home, shell in login_accounts(identity):
        lines.append(f"{name}:x:{uid}:{uid}:{name.title()},,,:{home}:{shell}")
    return "\n".join(lines) + "\n"


def group(identity: HostIdentity) -> str:
    first_user = identity.users[0][0] if identity.users else "admin"
    fixed = [
        ("root", 0, ""), ("daemon", 1, ""), ("bin", 2, ""), ("sys", 3, ""),
        ("adm", 4, f"syslog,{first_user}"), ("tty", 5, ""), ("disk", 6, ""),
        ("lp", 7, ""), ("mail", 8, ""), ("news", 9, ""), ("uucp", 10, ""),
        ("man", 12, ""), ("proxy", 13, ""), ("kmem", 15, ""),
        ("dialout", 20, ""), ("fax", 21, ""), ("voice", 22, ""),
        ("cdrom", 24, first_user), ("floppy", 25, ""), ("tape", 26, ""),
        ("sudo", 27, first_user), ("audio", 29, ""), ("dip", 30, first_user),
        ("www-data", 33, ""), ("backup", 34, ""), ("operator", 37, ""),
        ("list", 38, ""), ("irc", 39, ""), ("src", 40, ""), ("gnats", 41, ""),
        ("shadow", 42, ""), ("utmp", 43, ""), ("video", 44, ""),
        ("sasl", 45, ""), ("plugdev", 46, first_user), ("staff", 50, ""),
        ("games", 60, ""), ("users", 100, ""), ("nogroup", 65534, ""),
        ("systemd-journal", 101, ""), ("systemd-network", 102, ""),
        ("systemd-resolve", 103, ""), ("systemd-timesync", 104, ""),
        ("crontab", 105, ""), ("messagebus", 106, ""), ("syslog", 110, ""),
        ("ssh", 115, ""), ("mysql", 117, ""),
    ]
    lines = [f"{name}:x:{gid}:{members}" for name, gid, members in fixed]
    for name, uid, _home, _shell in login_accounts(identity):
        lines.append(f"{name}:x:{uid}:")
    return "\n".join(lines) + "\n"


_CRYPT_ALPHABET = "./0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz"


def shadow(identity: HostIdentity) -> str:
    """``/etc/shadow``: the same file on every read.

    It used to be regenerated with fresh random characters each time it was
    read, so ``cat /etc/shadow`` twice printed two different hashes. The
    strings here are shaped like sha512-crypt entries but are not the hash
    of any password.
    """
    rng = seeded(identity, "shadow")
    changed = 19000 + rng.randint(40, 500)

    def entry() -> str:
        salt = "".join(rng.choice(_CRYPT_ALPHABET) for _ in range(16))
        digest = "".join(rng.choice(_CRYPT_ALPHABET) for _ in range(86))
        return f"$6${salt}${digest}"

    lines = [f"root:{entry()}:{changed}:0:99999:7:::"]
    for name, *_ in _SYSTEM_ACCOUNTS[1:]:
        lines.append(f"{name}:*:{changed - rng.randint(0, 30)}:0:99999:7:::")
    lines.append("ftp:*:%d:0:99999:7:::" % changed)
    for name, _uid, _home, _shell in login_accounts(identity):
        lines.append(f"{name}:{entry()}:{changed + rng.randint(0, 200)}:0:99999:7:::")
    return "\n".join(lines) + "\n"


# --------------------------------------------------------------------------
# Processes and sockets
# --------------------------------------------------------------------------


@dataclass(frozen=True)
class Process:
    pid: int
    ppid: int
    user: str
    command: str
    #: Short name, as ``top`` and ``ss`` show it.
    name: str
    vsz: int = 0
    rss: int = 0
    tty: str = "?"
    stat: str = "S"
    kernel: bool = False


@dataclass(frozen=True)
class Listener:
    proto: str          # tcp | udp
    address: str        # 0.0.0.0, 127.0.0.1, 127.0.0.53, ::
    port: int
    pid: int
    program: str
    backlog: int = 128


def _enabled_protocols() -> set[str]:
    from honeypot.core.config import config

    return {getattr(p, "value", str(p)) for p in config.enabled_protocols}


def processes(identity: HostIdentity) -> list[Process]:
    """The daemons this host runs, in pid order.

    Which daemons follows from the identity (nginx or Apache, vsftpd or
    ProFTPD) and from the decoys that are actually listening; the process
    ids come from the seed.
    """
    rng = seeded(identity, "processes")
    enabled = _enabled_protocols()
    table: list[Process] = [
        Process(1, 0, "root", "/sbin/init", "systemd", 169404 + rng.randint(-900, 900), 11192 + rng.randint(-400, 400), stat="Ss"),
        Process(2, 0, "root", "[kthreadd]", "kthreadd", kernel=True),
        Process(3, 2, "root", "[rcu_gp]", "rcu_gp", stat="I<", kernel=True),
        Process(4, 2, "root", "[rcu_par_gp]", "rcu_par_gp", stat="I<", kernel=True),
        Process(6, 2, "root", "[kworker/0:0H-kblockd]", "kworker/0:0H-kblockd", stat="I<", kernel=True),
        Process(9, 2, "root", "[mm_percpu_wq]", "mm_percpu_wq", stat="I<", kernel=True),
        Process(10, 2, "root", "[ksoftirqd/0]", "ksoftirqd/0", kernel=True),
        Process(11, 2, "root", "[rcu_sched]", "rcu_sched", stat="I", kernel=True),
        Process(12, 2, "root", "[migration/0]", "migration/0", kernel=True),
    ]
    pid = 12
    for name in ("kdevtmpfs", "kauditd", "khungtaskd", "oom_reaper", "kcompactd0", "kswapd0", "jbd2/vda1-8"):
        pid += rng.randint(1, 14)
        table.append(Process(pid, 2, "root", f"[{name}]", name, kernel=True))

    pid = max(pid + 40, rng.randint(280, 420))

    def daemon(user: str, command: str, name: str, vsz: int, rss: int, stat: str = "Ss", ppid: int = 1, tty: str = "?") -> int:
        nonlocal pid
        pid += rng.randint(3, 46)
        table.append(Process(
            pid, ppid, user, command, name,
            vsz + rng.randint(-vsz // 50, vsz // 50), rss + rng.randint(-rss // 20, rss // 20),
            tty=tty, stat=stat,
        ))
        return pid

    daemon("root", "/lib/systemd/systemd-journald", "systemd-journal", 102232, 19684)
    daemon("root", "/lib/systemd/systemd-udevd", "systemd-udevd", 21844, 5312)
    daemon("systemd-network", "/lib/systemd/systemd-networkd", "systemd-network", 26604, 7620)
    daemon("systemd-resolve", "/lib/systemd/systemd-resolved", "systemd-resolve", 23896, 12108)
    daemon("systemd-timesync", "/lib/systemd/systemd-timesyncd", "systemd-timesyn", 90228, 6164, "Ssl")
    daemon("root", "/usr/sbin/cron -f", "cron", 8536, 2912)
    daemon("messagebus", "/usr/bin/dbus-daemon --system --address=systemd: --nofork --nopidfile --systemd-activation --syslog-only", "dbus-daemon", 7552, 4532)
    daemon("root", "/usr/bin/python3 /usr/bin/networkd-dispatcher --run-startup-triggers", "networkd-dispat", 29660, 18244, "Ssl")
    daemon("syslog", "/usr/sbin/rsyslogd -n -iNONE", "rsyslogd", 224344, 5012, "Ssl")
    daemon("root", "/lib/systemd/systemd-logind", "systemd-logind", 16972, 7584)
    daemon("root", "/sbin/agetty -o -p -- \\u --keep-baud 115200,38400,9600 ttyS0 vt220", "agetty", 7352, 2244, "Ss+", tty="ttyS0")
    daemon("root", "/sbin/agetty -o -p -- \\u --noclear tty1 linux", "agetty", 5828, 1836, "Ss+", tty="tty1")
    daemon("root", "sshd: /usr/sbin/sshd -D [listener] 0 of 10-100 startups", "sshd", 12176, 7264)
    daemon("mysql", "/usr/sbin/mysqld", "mysqld", 1790012, 388140, "Ssl")
    if "ftp" in enabled:
        if identity.ftp_family == "proftpd":
            daemon("proftpd", "proftpd: (accepting connections)", "proftpd", 23632, 4016)
        else:
            daemon("root", "/usr/sbin/vsftpd /etc/vsftpd.conf", "vsftpd", 6816, 3108)
    if "telnet" in enabled:
        daemon("root", "/usr/sbin/inetd", "inetd", 2780, 1524)
    if enabled & {"http", "https"}:
        if identity.http_family == "nginx":
            master = daemon("root", "nginx: master process /usr/sbin/nginx -g daemon on; master_process on;", "nginx", 55280, 1560)
            for _ in range(identity.cpu_cores):
                daemon("www-data", "nginx: worker process", "nginx", 55848, 5412, "S", ppid=master)
        else:
            master = daemon("root", "/usr/sbin/apache2 -k start", "apache2", 238512, 25460)
            for _ in range(3):
                daemon("www-data", "/usr/sbin/apache2 -k start", "apache2", 240100, 17840, "S", ppid=master)
        if identity.php_version and identity.http_family == "nginx":
            fpm = daemon("root", "php-fpm: master process (/etc/php/7.4/fpm/php-fpm.conf)", "php-fpm7.4", 194420, 9456)
            for _ in range(2):
                daemon("www-data", "php-fpm: pool www", "php-fpm7.4", 194884, 11208, "S", ppid=fpm)
    return table


def process_named(identity: HostIdentity, name: str) -> Optional[Process]:
    for proc in processes(identity):
        if proc.name.startswith(name) and proc.ppid in (0, 1):
            return proc
    return None


def listeners(identity: HostIdentity) -> list[Listener]:
    """Listening sockets, owned by the processes ``ps`` shows."""
    enabled = _enabled_protocols()

    def owner(name: str) -> tuple[int, str]:
        proc = process_named(identity, name)
        return (proc.pid, proc.name) if proc else (0, name)

    out: list[Listener] = []
    pid, program = owner("systemd-resolve")
    out.append(Listener("tcp", "127.0.0.53", 53, pid, program, 4096))
    out.append(Listener("udp", "127.0.0.53", 53, pid, program, 0))
    pid, program = owner("sshd")
    out.append(Listener("tcp", "0.0.0.0", 22, pid, program))
    out.append(Listener("tcp", "::", 22, pid, program))
    pid, program = owner("mysqld")
    out.append(Listener("tcp", "127.0.0.1", 3306, pid, program, 151))
    if "ftp" in enabled:
        pid, program = owner("proftpd" if identity.ftp_family == "proftpd" else "vsftpd")
        out.append(Listener("tcp", "0.0.0.0", 21, pid, program, 32))
    if "telnet" in enabled:
        pid, program = owner("inetd")
        out.append(Listener("tcp", "0.0.0.0", 23, pid, program))
    web = owner("nginx" if identity.http_family == "nginx" else "apache2")
    if "http" in enabled:
        out.append(Listener("tcp", "0.0.0.0", 80, web[0], web[1], 511))
    if "https" in enabled:
        out.append(Listener("tcp", "0.0.0.0", 443, web[0], web[1], 511))
    pid, program = owner("systemd-network")
    out.append(Listener("udp", identity.ip, 68, pid, program, 0))
    return out


# --------------------------------------------------------------------------
# Small files
# --------------------------------------------------------------------------


def os_release(identity: HostIdentity) -> str:
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
        'PRIVACY_POLICY_URL="https://www.ubuntu.com/legal/terms-and-policies/privacy-policy"\n'
        'VERSION_CODENAME=focal\nUBUNTU_CODENAME=focal\n'
    )


def hosts(identity: HostIdentity) -> str:
    return (
        f"127.0.0.1\tlocalhost\n127.0.1.1\t{identity.hostname}\n\n"
        "# The following lines are desirable for IPv6 capable hosts\n"
        "::1     ip6-localhost ip6-loopback\nfe00::0 ip6-localnet\n"
        "ff00::0 ip6-mcastprefix\nff02::1 ip6-allnodes\nff02::2 ip6-allrouters\n"
    )


def seeded_uuid(identity: HostIdentity, label: str) -> str:
    rng = seeded(identity, label)
    raw = "".join(rng.choice("0123456789abcdef") for _ in range(32))
    return f"{raw[:8]}-{raw[8:12]}-{raw[12:16]}-{raw[16:20]}-{raw[20:]}"


def root_uuid(identity: HostIdentity) -> str:
    return seeded_uuid(identity, "root-uuid")


def fstab(identity: HostIdentity) -> str:
    lines = [
        "# /etc/fstab: static file system information.",
        "#",
        "# <file system> <mount point>   <type>  <options>       <dump>  <pass>",
        f"UUID={root_uuid(identity)} /               ext4    errors=remount-ro 0       1",
    ]
    if identity.swap_kb:
        lines.append("/swap.img\tnone\tswap\tsw\t0\t0")
    return "\n".join(lines) + "\n"


def mounts(identity: HostIdentity) -> str:
    return (
        "sysfs /sys sysfs rw,nosuid,nodev,noexec,relatime 0 0\n"
        "proc /proc proc rw,nosuid,nodev,noexec,relatime 0 0\n"
        f"udev /dev devtmpfs rw,nosuid,noexec,relatime,size={identity.mem_kb // 2}k,nr_inodes={identity.mem_kb // 8},mode=755 0 0\n"
        "devpts /dev/pts devpts rw,nosuid,noexec,relatime,gid=5,mode=620,ptmxmode=000 0 0\n"
        f"tmpfs /run tmpfs rw,nosuid,nodev,noexec,relatime,size={identity.mem_kb // 10}k,mode=755 0 0\n"
        "/dev/vda1 / ext4 rw,relatime,errors=remount-ro 0 0\n"
        "securityfs /sys/kernel/security securityfs rw,nosuid,nodev,noexec,relatime 0 0\n"
        "tmpfs /dev/shm tmpfs rw,nosuid,nodev 0 0\n"
        "tmpfs /run/lock tmpfs rw,nosuid,nodev,noexec,relatime,size=5120k 0 0\n"
        "tmpfs /sys/fs/cgroup tmpfs ro,nosuid,nodev,noexec,mode=755 0 0\n"
        "cgroup /sys/fs/cgroup/systemd cgroup rw,nosuid,nodev,noexec,relatime,xattr,name=systemd 0 0\n"
    )


def cgroup() -> str:
    """``/proc/<pid>/cgroup`` for a process on the host itself.

    Loaders read this to ask "am I in a container?"; these are the lines a
    systemd host outside one shows.
    """
    controllers = [
        "12:freezer", "11:memory", "10:devices", "9:blkio", "8:pids",
        "7:cpu,cpuacct", "6:hugetlb", "5:net_cls,net_prio", "4:cpuset",
        "3:rdma", "2:perf_event", "1:name=systemd", "0:",
    ]
    return "".join(f"{c}:/\n" for c in controllers)
