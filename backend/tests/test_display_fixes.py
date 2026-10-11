"""Small correctness fixes found while photographing the deployed console."""

import os

from app.ai.mitre_mapper import merge_duplicate_techniques
from app.models import UserRole
from app.services.alerts import alert_title

INGEST_HEADERS = {"X-Honeypot-Token": os.environ["HONEYPOT_INGEST_TOKEN"]}


def test_a_technique_reached_by_tool_and_intent_is_listed_once():
    merged = merge_duplicate_techniques([
        {"id": "T1082", "name": "System Information Discovery", "source": "tool:enum_linux", "confidence": 0.85},
        {"id": "T1053", "name": "Scheduled Task/Job", "source": "tool:persistence", "confidence": 0.85},
        {"id": "T1053", "name": "Scheduled Task/Job", "source": "intent:persistence", "confidence": 0.7},
    ])
    assert [t["id"] for t in merged] == ["T1082", "T1053"]
    cron = merged[1]
    assert cron["confidence"] == 0.85
    assert cron["source"] == "tool:persistence, intent:persistence"


def test_alert_titles_do_not_call_a_benign_session_an_attack():
    assert alert_title("benign", "203.0.113.5") == "Suspicious activity from 203.0.113.5"
    assert alert_title("exploitation", "203.0.113.5") == "Exploitation attempt from 203.0.113.5"
    assert alert_title("reconnaissance", "203.0.113.5") == "Reconnaissance from 203.0.113.5"
    assert alert_title("", "203.0.113.5") == "Suspicious activity from 203.0.113.5"


async def test_nodes_report_the_sessions_stored_for_them(client, auth_headers):
    headers = await auth_headers(UserRole.ADMIN)
    node = await client.post(
        "/api/v1/nodes/",
        headers=headers,
        json={"name": "edge-count", "protocol": "ssh", "ip_address": "10.0.0.7", "port": 2222},
    )
    node_id = node.json()["id"]
    for port in (40001, 40002):
        response = await client.post(
            f"/api/v1/sessions/ingest-internal?node_id={node_id}",
            json={"protocol": "ssh", "attacker_ip": "203.0.113.61", "attacker_port": port,
                  "status": "completed", "duration_seconds": 1.0, "commands": ["id"]},
            headers=INGEST_HEADERS,
        )
        assert response.status_code == 200, response.text
    listed = await client.get("/api/v1/nodes/", headers=headers)
    row = next(n for n in listed.json() if n["id"] == node_id)
    assert row["stored_sessions"] == 2
    one = await client.get(f"/api/v1/nodes/{node_id}", headers=headers)
    assert one.json()["stored_sessions"] == 2
