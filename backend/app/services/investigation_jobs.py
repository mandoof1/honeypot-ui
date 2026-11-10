"""Bounded, owner-scoped report jobs for the single dashboard API process.

A job is the model writing one investigation from a fixed snapshot of
evidence. Jobs live in this process's memory and nowhere else:

* They belong to the user who asked. Another user, whatever their role,
  gets "not found" for the id, and a job is only ever reused for the same
  user asking for the same evidence with the same sensitivity. A report that
  includes original credentials is therefore never handed to someone who
  asked for the redacted one.
* They do not survive a restart, and with more than one API process a
  request can land where the job is not. Both look the same from outside:
  the id is unknown, the status and download routes answer 404 "generate it
  again", and nothing is half-delivered. On a clean shutdown the jobs still
  being written are cancelled first, so none is left reporting progress
  that will never complete.
* They wait their turn for the language model through ``model_slot``, which
  the background enrichment worker shares, and give up with a plain "busy,
  try again" after REPORT_MODEL_WAIT_SECONDS rather than queueing without
  limit.
"""

from __future__ import annotations

import asyncio
import hashlib
import json
import time
from uuid import uuid4

from starlette.concurrency import run_in_threadpool

from app.core.config import get_settings
from app.core.model_slot import ModelBusy, model_slot
from app.services.investigation_narrative import (
    generate_narrative,
    NarrativeUnavailable,
)
from app.services.pdf_report import generate_pdf_report


class JobsFull(Exception):
    pass


class ReportJobs:
    TTL = 1800
    MAX_JOBS = 6
    #: Jobs being written at once, across all users and per user. One user
    #: holding both global places would lock every other analyst out.
    MAX_ACTIVE = 2
    MAX_ACTIVE_PER_OWNER = 1

    def __init__(self):
        self.jobs = {}
        self.render_slot = asyncio.Semaphore(2)

    def prune(self):
        now = time.monotonic()
        for key, job in list(self.jobs.items()):
            if job["task"].done() and now - job["touched"] > self.TTL:
                self.jobs.pop(key, None)

    def submit(self, owner, records, sensitive=False):
        self.prune()
        sensitive = bool(sensitive)
        signature = hashlib.sha256(
            json.dumps(
                [records, sensitive],
                sort_keys=True,
                ensure_ascii=False,
                default=str,
            ).encode()
        ).hexdigest()
        for job in self.jobs.values():
            # Same user, same evidence, same sensitivity. The signature
            # already covers the last, but it is the property that keeps
            # credentials out of a redacted report, so it is checked by name.
            if (
                job["owner"] == owner
                and job["sensitive"] == sensitive
                and job["signature"] == signature
                and job["status"] != "failed"
            ):
                job["touched"] = time.monotonic()
                return job

        active = [j for j in self.jobs.values() if not j["task"].done()]
        if sum(j["owner"] == owner for j in active) >= self.MAX_ACTIVE_PER_OWNER:
            raise JobsFull(
                "You already have a report being prepared. Please wait for it to finish."
            )
        if len(active) >= self.MAX_ACTIVE:
            raise JobsFull(
                "Two reports are already being prepared. Please wait for one to finish."
            )
        if len(self.jobs) >= self.MAX_JOBS:
            completed = [j for j in self.jobs.values() if j["task"].done()]
            if not completed:
                raise JobsFull("Report generation is busy. Please retry shortly.")
            self.jobs.pop(min(completed, key=lambda j: j["touched"])["id"])
        job = {
            "id": str(uuid4()),
            "owner": owner,
            "signature": signature,
            "records": records,
            "sensitive": sensitive,
            "status": "queued",
            "message": "Waiting for the local analysis model.",
            "error": None,
            "narrative": None,
            "files": {},
            "touched": time.monotonic(),
        }
        self.jobs[job["id"]] = job
        job["task"] = asyncio.create_task(
            self._write(job), name="investigation-" + job["id"]
        )
        return job

    async def _write(self, job):
        wait = get_settings().REPORT_MODEL_WAIT_SECONDS
        try:
            if model_slot.holder is not None:
                job["message"] = (
                    "Waiting for the local analysis model to finish the "
                    "session it is analysing."
                )
            async with model_slot.hold("report", wait=wait):
                job.update(
                    status="analysing",
                    message="Our local model is writing findings from the selected evidence. This can take several minutes.",
                )
                job["narrative"] = await generate_narrative(job["records"])
                job.update(
                    status="complete", message="The investigation is ready to download."
                )
        except asyncio.CancelledError:
            job.update(
                status="failed",
                error="Report generation was interrupted. Please generate it again.",
            )
            raise
        except ModelBusy:
            job.update(
                status="failed",
                error=(
                    "The local analysis model stayed busy with background "
                    "analysis. Please generate the report again in a few minutes."
                ),
            )
        except NarrativeUnavailable as exc:
            job.update(status="failed", error=str(exc))
        except Exception:
            job.update(
                status="failed",
                error="The investigation could not be prepared. Please retry; no generic report was substituted.",
            )
        finally:
            job["touched"] = time.monotonic()

    def owned(self, identity, owner):
        self.prune()
        job = self.jobs.get(identity)
        if not job or job["owner"] != owner:
            raise KeyError(identity)
        job["touched"] = time.monotonic()
        return job

    @staticmethod
    def status(job):
        return {
            "id": job["id"],
            "status": job["status"],
            "message": job["error"] if job["status"] == "failed" else job["message"],
            "session_count": len(job["records"]),
            "include_sensitive": job["sensitive"],
            "model": (job.get("narrative") or {}).get("model"),
        }

    async def render(self, job, format):
        if job["status"] != "complete":
            raise NarrativeUnavailable(
                job["error"] or "The local model is still preparing this report."
            )
        if format not in job["files"]:
            async with self.render_slot:
                if format not in job["files"]:
                    job["files"][format] = await run_in_threadpool(
                        generate_pdf_report,
                        job["records"],
                        format,
                        job["narrative"],
                        job["sensitive"],
                    )
        return job["files"][format]

    async def shutdown(self):
        """Cancel what is still being written and forget every job.

        Called when the API stops. A job left running would be cut off
        mid-request by the interpreter exiting; cancelling it here lets it
        record that it was interrupted and release the model.
        """
        tasks = [job["task"] for job in self.jobs.values() if not job["task"].done()]
        for task in tasks:
            task.cancel()
        if tasks:
            await asyncio.gather(*tasks, return_exceptions=True)
        self.jobs.clear()


report_jobs = ReportJobs()
