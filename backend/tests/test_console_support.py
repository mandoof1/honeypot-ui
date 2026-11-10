"""List filters and response fields the console's pivots depend on."""

from datetime import datetime, timezone

from app.models import (
    AttackCategory,
    HoneypotNode,
    HoneypotSession,
    IndicatorOfCompromise,
    UserRole,
)
from app.schemas import SessionEnrichment


async def _node(db_session) -> HoneypotNode:
    node = HoneypotNode(name="console-support-node", protocol="ssh", ip_address="10.0.0.9", port=2222)
    db_session.add(node)
    await db_session.commit()
    await db_session.refresh(node)
    return node


def _session(node, ip, **fields) -> HoneypotSession:
    return HoneypotSession(
        node_id=node.id,
        attacker_ip=ip,
        attacker_port=fields.pop("attacker_port", 40000),
        protocol=fields.pop("protocol", "ssh"),
        started_at=datetime.now(timezone.utc),
        attack_category=AttackCategory.RECONNAISSANCE,
        **fields,
    )


async def _listed_ips(client, headers, query: str) -> set[str]:
    response = await client.get(f"/api/v1/sessions/?{query}", headers=headers)
    assert response.status_code == 200, response.text
    body = response.json()
    rows = body["sessions"] if isinstance(body, dict) and "sessions" in body else body.get("items", body)
    return {row["attacker_ip"] for row in rows}


async def test_sessions_filter_by_technique_is_exact(client, auth_headers, db_session):
    headers = await auth_headers(UserRole.ANALYST)
    node = await _node(db_session)
    db_session.add_all([
        _session(node, "45.83.64.1", mitre_techniques=[{"id": "T1059", "name": "Command and Scripting Interpreter"}]),
        _session(node, "45.83.64.2", mitre_techniques=[{"id": "T1059.004", "name": "Unix Shell"}]),
        _session(node, "45.83.64.3", mitre_techniques=[]),
    ])
    await db_session.commit()

    assert await _listed_ips(client, headers, "technique=T1059") == {"45.83.64.1"}
    assert await _listed_ips(client, headers, "technique=t1059.004") == {"45.83.64.2"}
    bad = await client.get("/api/v1/sessions/?technique=T1059%22%20OR", headers=headers)
    assert bad.status_code in (400, 422)


async def test_sessions_filter_by_fingerprint_cluster_and_refusal(client, auth_headers, db_session):
    headers = await auth_headers(UserRole.ANALYST)
    node = await _node(db_session)
    hassh = "ec7378c1a92f5a8dde7e8b7a1ddf33d1"
    db_session.add_all([
        _session(node, "45.83.64.11", fingerprints={"hassh": hassh, "ssh_client_version": "SSH-2.0-Go"}),
        _session(node, "45.83.64.12", fingerprints={"hassh": "0" * 32}, cluster_id=3),
        _session(node, "45.83.64.13", attacker_port=0, signals={"refusal": True}),
    ])
    await db_session.commit()

    assert await _listed_ips(client, headers, f"fingerprint={hassh}") == {"45.83.64.11"}
    assert await _listed_ips(client, headers, "fingerprint=SSH-2.0-Go") == {"45.83.64.11"}
    assert await _listed_ips(client, headers, "cluster_id=3") == {"45.83.64.12"}
    assert await _listed_ips(client, headers, "refused=true") == {"45.83.64.13"}
    assert await _listed_ips(client, headers, "refused=false") == {"45.83.64.11", "45.83.64.12"}
    # A value that could close the JSON string it is matched inside is refused.
    bad = await client.get('/api/v1/sessions/?fingerprint=abc%22def', headers=headers)
    assert bad.status_code == 400


async def test_indicator_list_carries_the_union_of_tags(client, auth_headers, db_session):
    headers = await auth_headers(UserRole.VIEWER)
    node = await _node(db_session)
    first, second = _session(node, "45.83.64.21"), _session(node, "45.83.64.22")
    db_session.add_all([first, second])
    await db_session.commit()
    db_session.add_all([
        IndicatorOfCompromise(session_id=first.id, ioc_type="ip", value="45.83.64.21", tags=["attacker_ip"]),
        IndicatorOfCompromise(session_id=first.id, ioc_type="ip", value="198.51.100.9", tags=["c2_host", "dropper"]),
        IndicatorOfCompromise(session_id=second.id, ioc_type="ip", value="198.51.100.9", tags=["c2_host"]),
    ])
    await db_session.commit()

    body = (await client.get("/api/v1/iocs/", headers=headers)).json()
    tags = {row["value"]: row["tags"] for row in body["indicators"]}
    assert tags["45.83.64.21"] == ["attacker_ip"]
    assert tags["198.51.100.9"] == ["c2_host", "dropper"]


def test_enrichment_response_keeps_unverified_techniques():
    shown = SessionEnrichment(
        intent="x",
        unverified_techniques=[{"id": "T1190.001", "name": "SQL Injection"}, {"name": "no id at all"}],
    )
    assert [t.get("name") for t in shown.unverified_techniques] == ["SQL Injection", "no id at all"]
