"""One machine, consistently.

Every service the engine emulates used to invent its own view of the host:
the SSH banner said OpenSSH 8.2p1 on Ubuntu 20.04, the login banner said
Ubuntu 22.04 with a 5.15 kernel, ``uname -a`` picked a kernel from a pool
that rotated hourly (a CentOS 3.10 kernel tagged ``#101-Ubuntu`` was one of
the possible answers), the prompt's hostname was chosen at boot, and
``hostname`` chose a different one on every call. The TLS certificate carried
yet another. Two commands in a row disagreeing about what machine they are
running on is the cheapest fingerprint there is, and a returning attacker
seeing a different box behind the same address is the second cheapest.

This module decides the facts once and persists them beside the SSH host
keys, so the same decoy answers the same way across restarts: hostname,
distribution, kernel, CPU, memory, disks, addresses, users, boot time and the
server software the FTP and HTTP decoys claim to be. Everything that prints a
fact about the machine reads it from here.

Values are drawn from a seeded generator so a fresh deployment gets its own
plausible box rather than one shared by every install of this project, and
the seed is what is persisted, so the identity can be regenerated exactly.
"""

from __future__ import annotations

import json
import logging
import os
import random
import threading
import time
from dataclasses import asdict, dataclass, field
from typing import Optional

logger = logging.getLogger(__name__)

IDENTITY_FILE = "host-identity.json"
IDENTITY_VERSION = 1

#: Ubuntu 20.04 kernels, with the build strings their packages carry.
#: 20.04 because the SSH transport profile pins OpenSSH 8.2p1, which is
#: 20.04's release; a 5.15 kernel beside an 8.2 sshd is a contradiction.
_KERNELS = [
    ("5.4.0-150-generic", "#167-Ubuntu SMP Mon May 15 17:35:05 UTC 2023"),
    ("5.4.0-156-generic", "#173-Ubuntu SMP Tue Jul 11 07:25:22 UTC 2023"),
    ("5.4.0-164-generic", "#181-Ubuntu SMP Fri Sep 1 13:41:22 UTC 2023"),
    ("5.4.0-170-generic", "#188-Ubuntu SMP Wed Jan 10 09:51:01 UTC 2024"),
    ("5.4.0-174-generic", "#193-Ubuntu SMP Thu Mar 7 14:29:28 UTC 2024"),
    ("5.4.0-182-generic", "#202-Ubuntu SMP Fri Apr 26 12:29:36 UTC 2024"),
]

_POINT_RELEASES = ["20.04.5", "20.04.6"]

_CPUS = [
    ("Intel(R) Xeon(R) CPU E5-2680 v4 @ 2.40GHz", 2400.000, 4),
    ("Intel(R) Xeon(R) Gold 6248 CPU @ 2.50GHz", 2500.000, 4),
    ("Intel(R) Xeon(R) Platinum 8259CL CPU @ 2.50GHz", 2499.998, 2),
    ("Intel(R) Xeon(R) CPU E5-2650 v2 @ 2.60GHz", 2593.906, 2),
    ("AMD EPYC 7571", 2199.900, 4),
    ("AMD EPYC 7R32", 2799.998, 2),
    ("Intel(R) Xeon(R) E-2236 CPU @ 3.40GHz", 3400.000, 6),
]

_MEMORY_KB = [2_035_476, 4_030_488, 8_148_228, 16_392_060]

_HOSTNAME_PREFIXES = [
    "web", "app", "api", "db", "srv", "node", "prod", "staging", "mail",
    "backup", "vpn", "git", "jenkins", "nginx", "store", "shop", "erp",
    "crm", "edge", "worker",
]
_DOMAINS = [
    "internal", "corp", "lan", "local", "prod.internal", "cloud.internal",
]

#: Vendor OUIs that real NICs and hypervisors use. Docker's 02:42 is not
#: among them: that prefix in ``ifconfig`` says "container" on its own.
_MAC_OUIS = [
    "00:50:56",  # VMware
    "00:0c:29",  # VMware
    "52:54:00",  # QEMU/KVM
    "00:16:3e",  # Xen
    "06:7a:1c",  # AWS
    "42:01:0a",  # GCE
    "00:1a:4a",  # Qumranet/KVM
]

_HTTP_SERVERS = [
    ("apache", "Apache/2.4.41 (Ubuntu)", "PHP/7.4.3"),
    ("apache", "Apache/2.4.41 (Ubuntu)", "PHP/7.4.33"),
    ("nginx", "nginx/1.18.0 (Ubuntu)", "PHP/7.4.3"),
    ("nginx", "nginx/1.18.0 (Ubuntu)", None),
]

_FTP_SERVERS = [
    ("vsftpd", "220 (vsFTPd 3.0.3)"),
    ("vsftpd", "220 (vsFTPd 3.0.3)"),
    ("proftpd", "220 ProFTPD 1.3.6c Server (Debian) [::ffff:{ip}]"),
]

_TIMEZONES = ["Etc/UTC", "Etc/UTC", "Europe/London", "America/New_York", "Asia/Dubai"]

#: Accounts beyond root the SSH decoy lets in; they must exist in the
#: password file the shell shows, or ``cat /etc/passwd`` contradicts the login
#: that just succeeded.
_LOGIN_USERS = ["admin", "user", "test", "ubuntu", "pi", "oracle", "postgres"]


@dataclass
class HostIdentity:
    version: int
    seed: int
    hostname: str
    domain: str
    os_name: str
    os_version: str
    os_codename: str
    kernel: str
    kernel_build: str
    arch: str
    cpu_model: str
    cpu_mhz: float
    cpu_cores: int
    mem_kb: int
    swap_kb: int
    mac: str
    ip: str
    netmask: str
    gateway: str
    nameserver: str
    timezone: str
    boot_time: float
    disk_total_kb: int
    disk_used_kb: int
    machine_id: str
    http_family: str
    http_server: str
    php_version: Optional[str]
    ftp_family: str
    ftp_banner: str
    last_login_ip: str
    last_login_time: float
    users: list[list] = field(default_factory=list)

    # ---- derived facts -------------------------------------------------

    @property
    def fqdn(self) -> str:
        return f"{self.hostname}.{self.domain}"

    @property
    def uname_a(self) -> str:
        return (
            f"Linux {self.hostname} {self.kernel} {self.kernel_build} "
            f"{self.arch} {self.arch} {self.arch} GNU/Linux"
        )

    @property
    def uptime_seconds(self) -> float:
        return max(0.0, time.time() - self.boot_time)

    @property
    def disk_free_kb(self) -> int:
        return self.disk_total_kb - self.disk_used_kb

    def home_for(self, username: str) -> str:
        if username == "root":
            return "/root"
        for name, _uid, home, _shell in self.users:
            if name == username:
                return home
        return f"/home/{username}"

    def uid_for(self, username: str) -> int:
        if username == "root":
            return 0
        for name, uid, _home, _shell in self.users:
            if name == username:
                return uid
        return 1000

    def ftp_banner_text(self) -> str:
        return self.ftp_banner.format(ip=self.ip)

    def note_login(self, source_ip: str) -> None:
        """Advance the "Last login" line the way sshd does."""
        self.last_login_ip = source_ip
        self.last_login_time = time.time()

    def to_json(self) -> dict:
        return asdict(self)


def _derive(seed: int) -> HostIdentity:
    rng = random.Random(seed)
    kernel, build = rng.choice(_KERNELS)
    cpu_model, mhz, cores = rng.choice(_CPUS)
    mem = rng.choice(_MEMORY_KB)
    prefix = rng.choice(_HOSTNAME_PREFIXES)
    hostname = f"{prefix}-{rng.randint(1, 9):02d}" if rng.random() < 0.7 else f"{prefix}{rng.randint(1, 30)}"
    http_family, http_server, php = rng.choice(_HTTP_SERVERS)
    ftp_family, ftp_banner = rng.choice(_FTP_SERVERS)
    subnet = rng.choice(["10.0.0", "10.0.1", "10.10.20", "172.16.4", "192.168.1", "192.168.10"])
    host_octet = rng.randint(10, 200)
    now = time.time()
    # Booted somewhere between four days and five months ago; the clock
    # keeps running from there across engine restarts.
    boot_time = now - rng.randint(4 * 86400, 150 * 86400)
    disk_total = rng.choice([40, 80, 100, 160, 250]) * 1024 * 1024
    disk_used = int(disk_total * rng.uniform(0.18, 0.62))
    uid = 1000
    users = []
    for name in _LOGIN_USERS:
        users.append([name, uid, f"/home/{name}", "/bin/bash"])
        uid += 1
    # Who logged in before the attacker: an operator from inside the network
    # some days ago, or from a plausible remote office address. Never the
    # attacker's own address at the current time — that is what the old
    # banner printed, and sshd never would on a first login.
    if rng.random() < 0.6:
        last_ip = f"{subnet}.{rng.randint(2, 9)}"
    else:
        last_ip = rng.choice(["81.2.69.142", "193.19.204.66", "212.58.244.20", "94.100.180.200"])
    last_login = now - rng.randint(1 * 86400, 12 * 86400)
    point = rng.choice(_POINT_RELEASES)
    return HostIdentity(
        version=IDENTITY_VERSION,
        seed=seed,
        hostname=hostname,
        domain=rng.choice(_DOMAINS),
        os_name="Ubuntu",
        os_version=point,
        os_codename="focal",
        kernel=kernel,
        kernel_build=build,
        arch="x86_64",
        cpu_model=cpu_model,
        cpu_mhz=mhz,
        cpu_cores=cores,
        mem_kb=mem,
        swap_kb=rng.choice([0, 0, 2_097_148, 4_194_300]),
        mac=rng.choice(_MAC_OUIS) + ":" + ":".join(f"{rng.randint(0, 255):02x}" for _ in range(3)),
        ip=f"{subnet}.{host_octet}",
        netmask="255.255.255.0",
        gateway=f"{subnet}.1",
        nameserver=rng.choice([f"{subnet}.1", "8.8.8.8", "1.1.1.1", "10.0.0.2"]),
        timezone=rng.choice(_TIMEZONES),
        boot_time=boot_time,
        disk_total_kb=disk_total,
        disk_used_kb=disk_used,
        machine_id="".join(rng.choice("0123456789abcdef") for _ in range(32)),
        http_family=http_family,
        http_server=http_server,
        php_version=php,
        ftp_family=ftp_family,
        ftp_banner=ftp_banner,
        last_login_ip=last_ip,
        last_login_time=last_login,
        users=users,
    )


class _IdentityStore:
    """Lazy, cached, persisted. Keyed by the directory it lives in, so tests
    that point the engine at a temporary capture directory get their own."""

    def __init__(self) -> None:
        self._lock = threading.Lock()
        self._cached: Optional[HostIdentity] = None
        self._cached_dir: Optional[str] = None

    def _directory(self) -> str:
        from honeypot.core.config import config

        return config.session_capture_dir

    def get(self) -> HostIdentity:
        directory = self._directory()
        with self._lock:
            if self._cached is not None and self._cached_dir == directory:
                return self._cached
            identity = self._load(directory) or self._create(directory)
            self._cached, self._cached_dir = identity, directory
            return identity

    def reset(self) -> None:
        with self._lock:
            self._cached = None
            self._cached_dir = None

    def _load(self, directory: str) -> Optional[HostIdentity]:
        path = os.path.join(directory, IDENTITY_FILE)
        try:
            with open(path, "r", encoding="utf-8") as handle:
                data = json.load(handle)
        except (OSError, ValueError):
            return None
        if data.get("version") != IDENTITY_VERSION or "seed" not in data:
            return None
        identity = _derive(int(data["seed"]))
        # The seed reproduces the static facts; the moving ones are restored
        # from what was stored so a restart does not rewind them.
        for key in ("boot_time", "last_login_ip", "last_login_time"):
            if key in data:
                setattr(identity, key, data[key])
        return identity

    def _create(self, directory: str) -> HostIdentity:
        env_seed = os.environ.get("HONEYPOT_IDENTITY_SEED")
        try:
            seed = int(env_seed) if env_seed else random.SystemRandom().randrange(1, 2**31)
        except ValueError:
            seed = random.SystemRandom().randrange(1, 2**31)
        identity = _derive(seed)
        self._persist(directory, identity)
        logger.info(
            "Host identity: %s (%s %s, %s, seed %d)",
            identity.hostname, identity.os_name, identity.os_version, identity.kernel, seed,
        )
        return identity

    @staticmethod
    def _persist(directory: str, identity: HostIdentity) -> None:
        try:
            os.makedirs(directory, exist_ok=True)
            path = os.path.join(directory, IDENTITY_FILE)
            tmp = path + ".tmp"
            with open(tmp, "w", encoding="utf-8") as handle:
                json.dump(identity.to_json(), handle, indent=2)
            os.replace(tmp, path)
        except OSError as exc:
            # A read-only filesystem is expected in some deployments; the
            # identity then lives for the life of the process.
            logger.warning("Could not persist host identity: %s", exc)


_store = _IdentityStore()


def get_identity() -> HostIdentity:
    return _store.get()


def reset_identity() -> None:
    """Forget the cached identity (tests, or after the capture dir moved)."""
    _store.reset()
