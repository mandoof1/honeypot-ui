"""The plain command summary must not carry what attackers typed into forms.

Web sessions' commands are requests with their bodies attached, and the
summary used to be those commands verbatim, so every password typed into a
decoy login form sat in a plain column next to the encrypted credentials.
"""

import json
import os

from app.core.encryption import encrypt_data
from app.models import HoneypotSession, UserRole
from app.services.analysis import summarise_commands
from app.tools.reanalyze import rebuild_summary

INGEST_HEADERS = {"X-Honeypot-Token": os.environ["HONEYPOT_INGEST_TOKEN"]}

LOGIN = (
    "POST /api/auth/login  [ua: Mozilla/5.0]\n"
    '{"email":"sam@example.com","password":"hunter2-secret"}'
)


def test_web_summary_keeps_the_request_line_and_drops_the_body():
    summary = summarise_commands(["GET /  [ua: curl/8]", LOGIN], "https")
    assert "POST /api/auth/login" in summary
    assert "curl/8" in summary
    assert "hunter2-secret" not in summary
    assert "sam@example.com" not in summary


def test_secret_query_values_are_masked():
    summary = summarise_commands(["GET /login?user=admin&password=letmein&x=1"], "http")
    assert "letmein" not in summary
    assert "password=[redacted]" in summary
    assert "user=admin" in summary and "x=1" in summary


def test_shell_summaries_are_unchanged():
    commands = ["uname -a", "echo 'root:toor' | chpasswd"]
    assert summarise_commands(commands, "ssh") == "uname -a echo 'root:toor' | chpasswd"


def test_rebuild_summary_cleans_a_stored_row():
    session = HoneypotSession(
        protocol="http",
        command_summary="POST /api/auth/login  [ua: Mozilla/5.0]\n" + LOGIN.split("\n", 1)[1],
        transcript_encrypted=encrypt_data(json.dumps([{"command": LOGIN}])),
        raw_commands_encrypted=encrypt_data(LOGIN),
    )
    assert rebuild_summary(session) is True
    assert "hunter2-secret" not in session.command_summary
    assert session.command_summary.startswith("POST /api/auth/login")
    assert rebuild_summary(session) is False


def test_rebuild_summary_without_a_transcript_keeps_only_request_lines():
    session = HoneypotSession(
        protocol="https",
        command_summary=None,
        transcript_encrypted=None,
        raw_commands_encrypted=encrypt_data(LOGIN),
    )
    rebuild_summary(session)
    assert "hunter2-secret" not in session.command_summary


async def test_ingested_web_session_summary_has_no_password(client, auth_headers):
    headers = await auth_headers(UserRole.ADMIN)
    node = await client.post(
        "/api/v1/nodes/",
        headers=headers,
        json={"name": "edge-web", "protocol": "http", "ip_address": "10.0.0.8", "port": 8080},
    )
    assert node.status_code == 201, node.text
    response = await client.post(
        f"/api/v1/sessions/ingest-internal?node_id={node.json()['id']}",
        json={
            "protocol": "https",
            "attacker_ip": "203.0.113.50",
            "attacker_port": 50000,
            "started_at": "2026-10-11T10:00:00Z",
            "status": "completed",
            "duration_seconds": 3.0,
            "commands": [LOGIN],
            "transcript": [{"command": LOGIN}],
        },
        headers=INGEST_HEADERS,
    )
    assert response.status_code == 200, response.text
    listed = await client.get("/api/v1/sessions/", headers=headers)
    rows = [r for r in listed.json()["sessions"] if r["attacker_ip"] == "203.0.113.50"]
    assert rows and "hunter2-secret" not in (rows[0].get("command_summary") or "")
    assert "POST /api/auth/login" in rows[0]["command_summary"]
