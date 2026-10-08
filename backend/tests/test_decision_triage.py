"""Decision-model triage ahead of the language model, and technique checks.

The decision model itself is replaced by canned /v1/systemone answers: these
tests cover what the pipeline does with an answer (routing, storage, the
fallback when the model is down), not the model's judgement, which is
measured separately by app.tools.eval_decider.
"""

from datetime import datetime, timedelta, timezone

import pytest
from sqlalchemy import select

from app.ai import decider as decider_module
from app.ai import llm
from app.ai.decider import DeciderUnavailable, decider, technique_question
from app.core.config import get_settings
from app.models import HoneypotSession
from app.services import enrichment
from test_operations_round import ATTACK, BROWSING, _ingest, _node

RECON = {
    **ATTACK,
    "attacker_ip": "203.0.113.50",
    "commands": ["uname -a", "whoami", "cat /proc/cpuinfo"],
    "failed_logins": 0,
}


@pytest.fixture(autouse=True)
def models_up():
    enrichment._decider_down_until = 0.0
    enrichment._chimera_down_until = 0.0
    yield
    enrichment._decider_down_until = 0.0
    enrichment._chimera_down_until = 0.0


def _enable(monkeypatch, chimera=True, decision=True):
    settings = get_settings()
    if chimera:
        monkeypatch.setattr(settings, "CHIMERA_URL", "http://model.test/v1")
        monkeypatch.setattr(settings, "CHIMERA_MODEL", "wolfram")
    if decision:
        monkeypatch.setattr(settings, "DECIDER_URL", "http://decider.test")
        monkeypatch.setattr(settings, "DECIDER_MODEL", "kev-4b")


def _reply(category, severity, operator=(0.8, 0.2)):
    """A /v1/systemone answer in the server's shape."""
    names = list(decider_module.CATEGORY_CRITERIA)
    return {
        "answers": {
            "category": {"type": "choice", "probabilities": dict(zip(names, category))},
            "severity": {"type": "score", "probabilities": {str(i): p for i, p in enumerate(severity)}},
            "operator": {"type": "choice", "probabilities": {"automated": operator[0], "human": operator[1]}},
        },
        "input_tokens": 300,
    }


def _fake_triage(monkeypatch, reply, calls=None):
    async def triage(commands, protocol="ssh", duration_seconds=None, keystrokes=None):
        if calls is not None:
            calls.append(commands)
        return decider.parse_triage(reply, elapsed_ms=1200.0)

    monkeypatch.setattr(decider, "triage", triage)


COMPROMISE = _reply(category=(0.02, 0.08, 0.85, 0.05), severity=(0.01, 0.07, 0.62, 0.30))
GATHERING = _reply(category=(0.05, 0.9, 0.04, 0.01), severity=(0.15, 0.80, 0.04, 0.01))


async def _row(db_session, session_id):
    db_session.expire_all()
    return (
        await db_session.execute(select(HoneypotSession).where(HoneypotSession.id == session_id))
    ).scalar_one()


class TestRouting:
    def test_confident_gathering_with_agreeing_rules_is_skipped(self):
        status, reason = enrichment.route_after_triage("pending", "reconnaissance", {"p_low": 0.9})
        assert status == "skipped"
        assert "information gathering" in reason

    def test_rules_evidence_of_exploitation_is_never_skipped(self):
        status, _ = enrichment.route_after_triage("pending", "exploitation", {"p_low": 0.99})
        assert status == "pending"

    def test_uncertain_triage_sends_the_session_on(self):
        status, _ = enrichment.route_after_triage("pending", "reconnaissance", {"p_low": 0.6})
        assert status == "pending"

    def test_triage_can_escalate_what_the_rules_skipped(self):
        status, reason = enrichment.route_after_triage("skipped", "benign", {"p_compromise": 0.7})
        assert status == "pending"
        assert "did not flag" in reason

    def test_agreeing_skip_stays_skipped(self):
        status, _ = enrichment.route_after_triage("skipped", "benign", {"p_compromise": 0.2})
        assert status == "skipped"


class TestIngest:
    async def test_sessions_wait_on_triage_before_the_language_model(self, client, auth_headers, monkeypatch):
        _enable(monkeypatch)
        node_id, _ = await _node(client, auth_headers)
        attack = await _ingest(client, node_id, ATTACK)
        browsing = await _ingest(client, node_id, BROWSING)
        assert attack["enrichment_status"] == "triage"
        assert attack["triage_status"] == "pending"
        # Plain browsing is left to the rules unless asked for.
        assert browsing["enrichment_status"] == "skipped"
        assert browsing["triage_status"] == "none"

    async def test_rule_skipped_sessions_are_triaged_when_enabled(self, client, auth_headers, monkeypatch):
        _enable(monkeypatch)
        monkeypatch.setattr(get_settings(), "DECIDER_TRIAGE_RULE_SKIPPED", True)
        node_id, _ = await _node(client, auth_headers)
        browsing = await _ingest(client, node_id, BROWSING)
        # Waiting on triage, which can still send it on.
        assert browsing["enrichment_status"] == "triage"
        assert browsing["triage_status"] == "pending"

    async def test_triage_runs_without_a_language_model(self, client, auth_headers, monkeypatch):
        _enable(monkeypatch, chimera=False)
        node_id, headers = await _node(client, auth_headers)
        result = await _ingest(client, node_id, ATTACK)
        assert result["triage_status"] == "pending"
        detail = (await client.get(f"/api/v1/sessions/{result['session_id']}", headers=headers)).json()
        assert detail["enrichment_status"] == "not_configured"

    async def test_sessions_without_commands_are_not_triaged(self, client, auth_headers, monkeypatch):
        _enable(monkeypatch)
        node_id, _ = await _node(client, auth_headers)
        result = await _ingest(client, node_id, {**ATTACK, "commands": []})
        assert result["triage_status"] == "none"
        assert result["enrichment_status"] == "skipped"


class TestWorker:
    async def test_triage_then_analysis_then_technique_check(self, client, auth_headers, db_session, monkeypatch):
        _enable(monkeypatch)
        node_id, headers = await _node(client, auth_headers)
        result = await _ingest(client, node_id, ATTACK)
        _fake_triage(monkeypatch, COMPROMISE)

        async def fake_analyse(commands, protocol="ssh"):
            return {
                "intent": "Install a cryptominer", "objectives": [], "confidence": 0.8,
                # Neither is matched by the rule map for these commands, so
                # both arrive as the language model's own techniques.
                "mitre_techniques": [{"id": "T1036", "name": "Masquerading"},
                                     {"id": "T1486", "name": "Data Encrypted for Impact"}],
                "iocs": {"hosts": [], "urls": [], "files": []},
                "sophistication": "automated", "model": "wolfram",
            }

        async def fake_check(commands, protocol, techniques):
            return {"T1036": 0.94, "T1486": 0.04}

        monkeypatch.setattr(llm.chimera, "analyse", fake_analyse)
        monkeypatch.setattr(decider, "check_techniques", fake_check)

        assert await enrichment.run_once(db_session) is True  # triage
        row = await _row(db_session, result["session_id"])
        assert row.triage_status == "complete"
        assert row.enrichment_status == "pending"
        assert row.triage["category"] == "exploitation"
        assert row.triage["p_compromise"] == pytest.approx(0.92, abs=1e-3)

        assert await enrichment.run_once(db_session) is True  # language model
        assert await enrichment.run_once(db_session) is False

        detail = (await client.get(f"/api/v1/sessions/{result['session_id']}", headers=headers)).json()
        assert detail["triage_status"] == "complete"
        assert detail["triage"]["operator"] == "automated"
        assert detail["triage"]["route"] == "pending"
        assert detail["enrichment"]["checked_by"] == "kev-4b"
        techniques = {t["id"]: t for t in detail["mitre_techniques"]}
        assert techniques["T1036"]["source"] == "chimera"
        assert techniques["T1036"]["support"] == pytest.approx(0.94)
        assert techniques["T1036"]["unconfirmed"] is False
        assert techniques["T1486"]["unconfirmed"] is True
        # The unconfirmed technique is listed but does not claim Impact.
        assert "TA0040" not in detail["mitre_tactics"]

    async def test_drop_unconfirmed_removes_the_technique(self, client, auth_headers, db_session, monkeypatch):
        _enable(monkeypatch)
        monkeypatch.setattr(get_settings(), "DECIDER_DROP_UNCONFIRMED", True)
        node_id, headers = await _node(client, auth_headers)
        result = await _ingest(client, node_id, ATTACK)
        _fake_triage(monkeypatch, COMPROMISE)

        async def fake_analyse(commands, protocol="ssh"):
            return {"intent": "x", "objectives": [], "confidence": 0.8, "sophistication": "automated",
                    "mitre_techniques": [{"id": "T1486", "name": "Data Encrypted for Impact"}],
                    "iocs": {"hosts": [], "urls": [], "files": []}, "model": "wolfram"}

        async def fake_check(commands, protocol, techniques):
            return {"T1486": 0.02}

        monkeypatch.setattr(llm.chimera, "analyse", fake_analyse)
        monkeypatch.setattr(decider, "check_techniques", fake_check)
        await enrichment.run_once(db_session)
        await enrichment.run_once(db_session)
        detail = (await client.get(f"/api/v1/sessions/{result['session_id']}", headers=headers)).json()
        assert "T1486" not in {t["id"] for t in detail["mitre_techniques"]}
        assert [t["id"] for t in detail["enrichment"]["dropped_techniques"]] == ["T1486"]

    async def test_confident_gathering_skips_the_language_model(self, client, auth_headers, db_session, monkeypatch):
        _enable(monkeypatch)
        node_id, headers = await _node(client, auth_headers)
        result = await _ingest(client, node_id, RECON)
        _fake_triage(monkeypatch, GATHERING)

        async def must_not_run(commands, protocol="ssh"):
            raise AssertionError("the language model was called for a skipped session")

        monkeypatch.setattr(llm.chimera, "analyse", must_not_run)
        await enrichment.run_once(db_session)
        assert await enrichment.run_once(db_session) is False
        detail = (await client.get(f"/api/v1/sessions/{result['session_id']}", headers=headers)).json()
        assert detail["enrichment_status"] == "skipped"
        assert detail["triage"]["route"] == "skipped"
        assert "information gathering" in detail["triage"]["route_reason"]

    async def test_identical_transcript_is_triaged_once(self, client, auth_headers, db_session, monkeypatch):
        _enable(monkeypatch, chimera=False)
        node_id, headers = await _node(client, auth_headers)
        first = await _ingest(client, node_id, ATTACK)
        second = await _ingest(client, node_id, {**ATTACK, "attacker_ip": "203.0.113.99"})
        calls = []
        _fake_triage(monkeypatch, COMPROMISE, calls)
        await enrichment.run_once(db_session)
        await enrichment.run_once(db_session)
        assert len(calls) == 1
        detail = (await client.get(f"/api/v1/sessions/{second['session_id']}", headers=headers)).json()
        assert detail["triage"]["reused_from_session"] == first["session_id"]

    async def test_analyst_request_during_triage_is_not_overridden(self, client, auth_headers, db_session, monkeypatch):
        _enable(monkeypatch)
        node_id, headers = await _node(client, auth_headers)
        result = await _ingest(client, node_id, RECON)
        queued = await client.post(f"/api/v1/sessions/{result['session_id']}/enrich", headers=headers)
        assert queued.status_code == 202
        _fake_triage(monkeypatch, GATHERING)
        await enrichment.run_once(db_session)
        row = await _row(db_session, result["session_id"])
        assert "route" not in row.triage
        assert row.triage["suggested_route"] == "skipped"
        assert row.enrichment_status == "pending"  # the analyst asked

    async def test_unreachable_decider_falls_back_to_the_rules(self, client, auth_headers, db_session, monkeypatch):
        _enable(monkeypatch)
        node_id, _ = await _node(client, auth_headers)
        result = await _ingest(client, node_id, ATTACK)

        async def down(*args, **kwargs):
            raise DeciderUnavailable("connection refused")

        monkeypatch.setattr(decider, "triage", down)
        assert await enrichment.run_once(db_session) is True
        row = await _row(db_session, result["session_id"])
        assert row.triage_status == "pending"
        assert row.enrichment_status == "triage"

        # Past the fallback window the rules' verdict decides on its own.
        row.created_at = datetime.now(timezone.utc) - timedelta(
            seconds=get_settings().DECIDER_FALLBACK_SECONDS + 60
        )
        await db_session.commit()

        async def analyse(commands, protocol="ssh"):
            return None

        monkeypatch.setattr(llm.chimera, "analyse", analyse)
        await enrichment.run_once(db_session)
        row = await _row(db_session, result["session_id"])
        assert row.triage_status == "failed"
        assert row.triage["route"] == "pending"
        assert "unreachable" in row.triage["error"]
        # And the language model's worker took it in the same turn.
        assert row.enrichment_status == "failed"

    async def test_health_and_settings_report_the_decision_model(self, client, auth_headers, monkeypatch):
        _enable(monkeypatch)
        body = (await client.get("/health")).json()
        assert body["triage"]["configured"] is True
        assert body["triage"]["model"] == "kev-4b"
        _, headers = await _node(client, auth_headers)
        system = (await client.get("/api/v1/settings/system", headers=headers)).json()
        assert system["triage"]["configured"] is True
        assert system["triage"]["skip_threshold"] == get_settings().DECIDER_SKIP_THRESHOLD


class TestClient:
    def test_parse_triage_reads_the_distributions(self):
        triage = decider.parse_triage(COMPROMISE)
        assert triage["category"] == "exploitation"
        assert triage["severity"] == pytest.approx(0 * 0.01 + 1 * 0.07 + 2 * 0.62 + 3 * 0.30)
        assert triage["p_low"] == pytest.approx(0.08)
        assert triage["operator"] == "automated"

    def test_parse_triage_rejects_a_missing_question(self):
        reply = _reply((0.1, 0.2, 0.6, 0.1), (0.1, 0.2, 0.6, 0.1))
        del reply["answers"]["severity"]
        assert decider.parse_triage(reply) is None

    def test_parse_triage_ignores_options_it_did_not_offer(self):
        reply = _reply((0.1, 0.2, 0.6, 0.1), (0.1, 0.2, 0.6, 0.1))
        reply["answers"]["category"]["probabilities"]["root_the_box"] = 0.99
        assert decider.parse_triage(reply)["category"] == "exploitation"

    async def test_check_techniques_keeps_only_asked_ids(self, monkeypatch):
        _enable(monkeypatch)

        async def ask(state, questions):
            assert set(questions) == {"T1105"}
            return {"answers": {"T1105": {"type": "noul", "noul": 0.9}, "T9999": {"noul": 1.0}}}

        monkeypatch.setattr(decider, "ask", ask)
        support = await decider.check_techniques(["wget http://x/y"], "ssh", [{"id": "T1105"}])
        assert support == {"T1105": 0.9}

    def test_technique_question_uses_the_description(self):
        described = technique_question("T1105", "Ingress Tool Transfer")
        assert "copies a tool or file onto the host" in described["instructions"]
        assert set(described["criteria"]) == {"true", "false"}
        # A sub-technique without its own entry falls back to its parent's.
        assert "scheduled task" in technique_question("T1053.005", "Scheduled Task")["instructions"]
        plain = technique_question("T1600", "Weaken Encryption")
        assert plain["instructions"].endswith("T1600 (Weaken Encryption)?")

    def test_long_transcripts_keep_both_ends(self, monkeypatch):
        monkeypatch.setattr(get_settings(), "DECIDER_MAX_TRANSCRIPT_CHARS", 300)
        commands = ["first command"] + [f"filler {i}" for i in range(200)] + ["last command"]
        state = decider.build_state(commands, "ssh")
        assert "first command" in state and "last command" in state
        assert "characters omitted" in state
