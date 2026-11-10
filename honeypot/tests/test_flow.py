"""Socket-level flow statistics, the stage-1 classifier's input.

The unit tests pin the arithmetic against CICFlowMeter's definitions; the
connection tests prove each emulator actually feeds the meter, which is the
part that silently did not happen before (the classifier received zeros).
"""

import asyncio

import asyncssh
import pytest

from honeypot.capture.flow import FlowMeter
from honeypot.core.config import config
from honeypot.core.session import session_manager
from honeypot.emulators.http import HTTPHoneypot
from honeypot.emulators.ssh import SSHHoneypot


def test_aggregates_follow_cicflowmeter_definitions():
    meter = FlowMeter(now=100.0)
    meter.outbound(40, now=100.1)      # banner
    meter.inbound(30, now=100.5)       # first client data
    meter.inbound(10, now=101.5)       # fwd IAT 1.0
    meter.outbound(500, now=101.6)
    meter.inbound(20, now=104.5)       # fwd IAT 3.0, longest silence 2.9
    meter.close(now=105.0)

    s = meter.summary()
    assert s["duration"] == pytest.approx(5.0)
    assert (s["fwd_packets"], s["fwd_bytes"], s["fwd_max"]) == (3, 60, 30)
    assert (s["bwd_packets"], s["bwd_bytes"], s["bwd_max"]) == (2, 540, 500)
    assert s["fwd_iat_mean"] == pytest.approx(2.0)
    assert s["fwd_iat_max"] == pytest.approx(3.0)
    assert s["flow_iat_max"] == pytest.approx(2.9)


def test_empty_chunks_and_traffic_after_close_are_ignored():
    meter = FlowMeter(now=0.0)
    meter.inbound(0, now=1.0)
    meter.close(now=2.0)
    meter.inbound(100, now=3.0)
    s = meter.summary()
    assert s["fwd_packets"] == 0 and s["fwd_bytes"] == 0
    assert s["duration"] == pytest.approx(2.0)


@pytest.fixture
def capture(tmp_path, monkeypatch):
    monkeypatch.setattr(config, "bind_address", "127.0.0.1")
    monkeypatch.setattr(config, "session_capture_dir", str(tmp_path / "sessions"))
    monkeypatch.setattr(config, "file_capture_dir", str(tmp_path / "uploads"))
    ingested: asyncio.Queue = asyncio.Queue()

    async def capture_ingest(session):
        await ingested.put(session.to_backend_payload())

    monkeypatch.setattr(session_manager, "_send_to_backend", capture_ingest)
    return ingested


async def test_ssh_flow_counts_the_encrypted_transport(capture, monkeypatch):
    monkeypatch.setattr(
        SSHHoneypot, "_host_keys", lambda self: [asyncssh.generate_private_key("ssh-ed25519")]
    )
    honeypot = SSHHoneypot()
    honeypot.port = 24330
    await honeypot.start()
    try:
        async with asyncssh.connect(
            "127.0.0.1", honeypot.port, username="root", password="root",
            known_hosts=None, client_keys=None, agent_path=None,
        ) as conn:
            await conn.run("uname -a")
        payload = await asyncio.wait_for(capture.get(), timeout=10)
    finally:
        await honeypot.stop()

    flow = payload["flow"]
    assert flow["measured_at"] == "ssh_transport"
    # Version strings and key exchange alone are well over a kilobyte each
    # way; channel data would be a few dozen bytes. This is the wire.
    assert flow["fwd_bytes"] > 1000 and flow["bwd_bytes"] > 1000
    assert flow["fwd_packets"] >= 3 and flow["bwd_packets"] >= 3
    assert flow["duration"] > 0


async def test_http_flow_counts_request_and_response(capture):
    honeypot = HTTPHoneypot()
    honeypot.port = 24331
    await honeypot.start()
    try:
        reader, writer = await asyncio.open_connection("127.0.0.1", honeypot.port)
        request = b"GET /robots.txt HTTP/1.1\r\nHost: x\r\nConnection: close\r\n\r\n"
        writer.write(request)
        await writer.drain()
        response = await reader.read()
        writer.close()
        payload = await asyncio.wait_for(capture.get(), timeout=10)
    finally:
        await honeypot.stop()

    flow = payload["flow"]
    assert flow["measured_at"] == "socket"
    assert flow["fwd_bytes"] == len(request)
    assert flow["bwd_bytes"] == len(response)
    assert flow["fwd_max"] == len(request)


def test_a_connection_joining_a_session_hands_over_what_it_counted():
    first = FlowMeter(now=10.0)
    first.inbound(100, now=10.2)
    session = FlowMeter(now=first.start)
    first.join(session)
    first.outbound(400, now=10.3)        # counted on the session from here on
    session.close(now=10.4)              # the first connection closed

    # The client comes back two seconds later on a new connection.
    second = FlowMeter(now=12.4)
    second.inbound(50, now=12.5)
    session.reopen()
    second.join(session)
    second.inbound(30, now=12.7)
    second.outbound(900, now=12.8)
    session.close(now=13.0)
    # The session is delivered half a minute later; closing again then must
    # not move the end or count the wait as a silence.
    session.close(now=43.0)

    s = session.summary()
    assert (s["fwd_packets"], s["fwd_bytes"], s["fwd_max"]) == (3, 180, 100)
    assert (s["bwd_packets"], s["bwd_bytes"], s["bwd_max"]) == (2, 1300, 900)
    assert s["duration"] == pytest.approx(3.0)
    # Forward gaps: 10.2 -> 12.5 across the two connections, then 12.5 -> 12.7.
    assert s["fwd_iat_max"] == pytest.approx(2.3)
    assert s["fwd_iat_mean"] == pytest.approx(1.25)
    # Longest silence: from the first connection closing to the second's
    # first data.
    assert s["flow_iat_max"] == pytest.approx(2.1)


def test_a_joined_meter_cannot_close_the_session_under_other_connections():
    session = FlowMeter(now=0.0)
    one, two = FlowMeter(now=0.0), FlowMeter(now=0.1)
    one.join(session)
    two.join(session)
    one.close(now=1.0)
    two.inbound(10, now=2.0)
    assert session.summary()["fwd_bytes"] == 10
