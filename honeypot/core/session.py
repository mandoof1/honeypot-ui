import asyncio
import base64
import hashlib
import json
import logging
import os
import time
import uuid
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Optional

import httpx

from honeypot.capture.flow import FlowMeter
from honeypot.core.config import config
from honeypot.core.retention import prune_captures
from honeypot.core.spool import Spool

logger = logging.getLogger(__name__)


@dataclass
class SessionRecord:
    session_id: str
    protocol: str
    source_ip: str
    source_port: int
    start_time: float
    end_time: Optional[float] = None
    commands: list[dict] = field(default_factory=list)
    files_uploaded: list[dict] = field(default_factory=list)
    files_downloaded: list[dict] = field(default_factory=list)
    network_events: list[dict] = field(default_factory=list)
    keystrokes: list[dict] = field(default_factory=list)
    authentication_attempts: list[dict] = field(default_factory=list)
    metadata: dict = field(default_factory=dict)
    keystroke_total: int = 0
    threat_profile: Optional[str] = None
    anomaly_score: float = 0.0
    #: Socket-level traffic statistics; the classifier's input.
    flow: Optional[FlowMeter] = None
    #: Items dropped at the in-memory caps, by kind, so the record says it is
    #: partial rather than looking complete.
    truncated: dict[str, int] = field(default_factory=dict)

    @property
    def duration(self) -> float:
        if self.end_time:
            return self.end_time - self.start_time
        return time.time() - self.start_time

    @property
    def start_datetime(self) -> str:
        return datetime.fromtimestamp(self.start_time, tz=timezone.utc).isoformat()

    @property
    def end_datetime(self) -> Optional[str]:
        if self.end_time:
            return datetime.fromtimestamp(self.end_time, tz=timezone.utc).isoformat()
        return None

    #: Bounds on what one session may push. A session that runs thousands of
    #: commands is either a fuzzer or an attempt to make the ingest endpoint
    #: the expensive part of the system; either way the first few hundred
    #: carry the behaviour and the rest are noise.
    MAX_TRANSCRIPT_ENTRIES = 500
    MAX_OUTPUT_CHARS = 4096
    MAX_CREDENTIALS = 200
    MAX_EVENTS = 200
    MAX_PACKETS = 2000

    #: In-memory caps, applied as items arrive. The payload caps above only
    #: bounded what was *sent*; the lists behind them grew without limit for
    #: as long as a connection stayed open.
    MAX_COMMANDS = 2000
    MAX_NETWORK_EVENTS = 500
    MAX_AUTH_ATTEMPTS = 200

    def to_backend_payload(self, node_id: int = 1) -> dict[str, Any]:
        command_strings = [c["command"] for c in self.commands]
        return {
            # The engine's own id, so a delivery retried after a lost
            # response is recognised rather than stored twice.
            "session_id": self.session_id,
            "protocol": self.protocol,
            "attacker_ip": self.source_ip,
            "attacker_port": self.source_port,
            "started_at": self.start_datetime,
            "status": "completed",
            "duration_seconds": round(self.duration, 2),
            "commands": command_strings,
            "payload": self.metadata.get("payload", ""),
            "uploads": self._uploads_payload(),
            "failed_logins": sum(
                1 for a in self.authentication_attempts if not a["success"]
            ),
            # Command/output pairs, not just the commands. What the machine
            # appeared to say is half of what makes a transcript readable, and
            # it is the only way to tell a command that worked from one that
            # was refused.
            "transcript": [
                {
                    "command": c["command"],
                    "output": (c.get("output") or "")[: self.MAX_OUTPUT_CHARS],
                    "exit_code": c.get("exit_code", 0),
                    "timestamp": c["timestamp"],
                }
                for c in self.commands[: self.MAX_TRANSCRIPT_ENTRIES]
            ],
            # The credentials themselves, not a count of failures. A honeypot
            # that discards these throws away its most directly actionable
            # output: the password lists actually in circulation, which is
            # what makes the capture worth defending against reuse.
            "credentials": [
                {
                    "username": a["username"][:128],
                    "password": a["password"][:128],
                    "success": a["success"],
                    "timestamp": a["timestamp"],
                }
                for a in self.authentication_attempts[: self.MAX_CREDENTIALS]
            ],
            "keystroke_count": max(self.keystroke_total, len(self.keystrokes)),
            "flow": self.flow.summary() if self.flow else None,
            # Retrieval and execution events — where a dropper's C2 URL is —
            # and the moment a web client was handed to the decoy application.
            # Filtered before the cap: a web session logs an event per
            # request, which would otherwise push these past it.
            "events": [
                {k: v for k, v in e.items() if k != "timestamp"} | {"at": e["timestamp"]}
                for e in [
                    e for e in self.network_events
                    if e.get("event_type") in ("file_download", "payload_execution", "http_diversion")
                ][: self.MAX_EVENTS]
            ],
            "packets": [
                {
                    "type": e.get("event_type", "unknown"),
                    "size": len(json.dumps(e, default=str)),
                }
                for e in self.network_events[: self.MAX_PACKETS]
            ],
            "truncated": dict(self.truncated),
        }

    def _count_drop(self, kind: str) -> None:
        self.truncated[kind] = self.truncated.get(kind, 0) + 1

    def _uploads_payload(self) -> list[dict[str, Any]]:
        """Captured files, with their bytes where the budget allows.

        The hashes alone were all the backend ever received, so nothing
        downstream could say what a file *was*. Content is read back from the
        capture directory rather than held in memory for the session's life,
        and bounded per file and per session so one session cannot turn the
        ingest request into the expensive part of the system. A file over the
        budget still arrives as metadata, so its hash is never lost.
        """
        budget = config.upload_forward_session_bytes
        forwarded: set[str] = set()
        uploads = []
        for f in self.files_uploaded:
            entry = {
                "filename": f["filename"],
                "sha256": f["sha256"],
                "size": f["size"],
                "source": f.get("source", "unknown"),
                "remote_path": f.get("remote_path", f["filename"]),
                "captured_at": datetime.fromtimestamp(
                    f["timestamp"], tz=timezone.utc
                ).isoformat(),
                "methods": f.get("methods", []),
            }
            sha = f["sha256"]
            if (
                sha not in forwarded
                and f["size"] <= config.upload_forward_max_bytes
                and f["size"] <= budget
            ):
                content = _read_capture(f.get("stored_path"), sha)
                if content is not None:
                    entry["content_b64"] = base64.b64encode(content).decode("ascii")
                    budget -= len(content)
                    forwarded.add(sha)
            uploads.append(entry)
        return uploads

    def to_dict(self) -> dict[str, Any]:
        return {
            "session_id": self.session_id,
            "protocol": self.protocol,
            "source_ip": self.source_ip,
            "source_port": self.source_port,
            "start_time": self.start_datetime,
            "end_time": self.end_datetime,
            "duration_seconds": round(self.duration, 2),
            "commands": self.commands,
            "files_uploaded": self.files_uploaded,
            "files_downloaded": self.files_downloaded,
            "network_events": self.network_events,
            "flow": self.flow.summary() if self.flow else None,
            "keystrokes": self.keystrokes,
            "authentication_attempts": self.authentication_attempts,
            "metadata": self.metadata,
            "threat_profile": self.threat_profile,
            "anomaly_score": self.anomaly_score,
        }


def _store_upload(content: bytes) -> tuple[str, str]:
    """Write an upload under its own digest; returns (sha256, path).

    Naming the file after its digest means an attacker-supplied filename can
    never influence where it lands on disk.
    """
    file_hash = hashlib.sha256(content).hexdigest()
    os.makedirs(config.file_capture_dir, exist_ok=True)
    file_path = os.path.join(config.file_capture_dir, file_hash)
    if not os.path.exists(file_path):
        with open(file_path, "wb") as handle:
            handle.write(content)
    return file_hash, file_path


def _read_capture(path: Optional[str], sha256: str) -> Optional[bytes]:
    """Read a stored capture back, refusing anything that no longer matches."""
    if not path:
        return None
    try:
        with open(path, "rb") as handle:
            content = handle.read(config.upload_forward_max_bytes + 1)
    except OSError:
        return None
    if hashlib.sha256(content).hexdigest() != sha256:
        return None
    return content


class SessionManager:
    #: Uploads are attacker-controlled; cap what a single session can persist.
    MAX_UPLOAD_BYTES = 16 * 1024 * 1024
    #: Files one session may deposit. Droppers write a handful.
    MAX_UPLOADS_PER_SESSION = 64
    #: Finished sessions are retained only for the status endpoint.
    MAX_RETAINED_SESSIONS = 1000

    #: One delivery attempt's budget. Beyond it the payload is spooled.
    INGEST_TIMEOUT = 15
    #: Deliveries in flight at once. A burst of sessions used to open one
    #: client each and hit the backend all together.
    INGEST_CONCURRENCY = 8
    SPOOL_RETRY_INTERVAL = 30
    SPOOL_RETRY_MAX_INTERVAL = 300
    SPOOL_BATCH = 20

    def __init__(self):
        self._sessions: dict[str, SessionRecord] = {}
        self._lock = asyncio.Lock()
        self._node_id: int = 1
        self._registered = False
        self._total_sessions: int = 0
        self._started_at = time.time()
        # asyncio only holds a weak reference to tasks, so a fire-and-forget
        # ingest could be garbage collected mid-flight.
        self._background: set[asyncio.Task] = set()
        self._service_tasks: list[asyncio.Task] = []
        self._client: Optional[httpx.AsyncClient] = None
        self._ingest_sem: Optional[asyncio.Semaphore] = None
        self._spool: Optional[Spool] = None
        #: Consecutive heartbeat and registration failures, so a long outage
        #: logs once rather than every tick.
        self._heartbeat_failures = 0
        self._register_failures = 0
        self.ingest_stats = {"sent": 0, "spooled": 0, "replayed": 0, "rejected": 0}
        Path(config.session_capture_dir).mkdir(parents=True, exist_ok=True)
        Path(config.file_capture_dir).mkdir(parents=True, exist_ok=True)

    # -- plumbing ----------------------------------------------------------

    @property
    def spool(self) -> Spool:
        # Built lazily so tests that point the capture directory elsewhere
        # get a spool there too.
        if self._spool is None or not self._spool._dir.startswith(config.session_capture_dir):
            self._spool = Spool(
                config.session_capture_dir, config.spool_max_files, config.spool_max_bytes
            )
        return self._spool

    def _http(self) -> httpx.AsyncClient:
        if self._client is None or self._client.is_closed:
            self._client = httpx.AsyncClient(
                limits=httpx.Limits(max_connections=self.INGEST_CONCURRENCY, max_keepalive_connections=4),
                headers={"X-Honeypot-Token": config.ingest_token},
            )
        return self._client

    def _semaphore(self) -> asyncio.Semaphore:
        if self._ingest_sem is None:
            self._ingest_sem = asyncio.Semaphore(self.INGEST_CONCURRENCY)
        return self._ingest_sem

    @property
    def uptime_seconds(self) -> float:
        return time.time() - self._started_at

    @property
    def registered(self) -> bool:
        return self._registered

    @property
    def node_id(self) -> int:
        return self._node_id

    async def set_node_id(self, node_id: int):
        self._node_id = node_id

    async def create_session(
        self,
        protocol: str,
        source_ip: str,
        source_port: int,
        metadata: Optional[dict] = None,
        flow: Optional[FlowMeter] = None,
    ) -> str:
        session_id = str(uuid.uuid4())
        session = SessionRecord(
            session_id=session_id,
            protocol=protocol,
            source_ip=source_ip,
            source_port=source_port,
            start_time=time.time(),
            metadata=metadata or {},
            flow=flow,
        )
        async with self._lock:
            self._sessions[session_id] = session
            self._total_sessions += 1
            self._evict_finished_locked()
        logger.info(f"New session {session_id} from {source_ip}:{source_port} ({protocol})")
        return session_id

    async def get_session(self, session_id: str) -> Optional[SessionRecord]:
        async with self._lock:
            return self._sessions.get(session_id)

    async def end_session(self, session_id: str) -> Optional[SessionRecord]:
        async with self._lock:
            session = self._sessions.get(session_id)
            if session is None or session.end_time is not None:
                # Already ended; do not persist or ingest the session twice.
                return session
            session.end_time = time.time()
            if session.flow is not None:
                session.flow.close()

        # The local copy is a convenience; the backend is the record. A full
        # disk or a bad mount must not stop the session being delivered,
        # which is the opposite of what the previous ordering did.
        try:
            await asyncio.to_thread(self._persist_session, session)
        except Exception as exc:
            logger.error("Could not write local copy of session %s: %s", session_id, exc)
        self._spawn(self._send_to_backend(session))
        return session

    def _spawn(self, coro):
        task = asyncio.create_task(coro)
        self._background.add(task)
        task.add_done_callback(self._background.discard)
        return task

    def _evict_finished_locked(self):
        """Drop the oldest finished sessions once the cache is oversized.

        Without this the process retained every session it ever handled, which
        is an unbounded memory leak on a service exposed to the internet.
        """
        if len(self._sessions) <= self.MAX_RETAINED_SESSIONS:
            return
        finished = sorted(
            (s for s in self._sessions.values() if s.end_time is not None),
            key=lambda s: s.end_time or 0,
        )
        overflow = len(self._sessions) - self.MAX_RETAINED_SESSIONS
        for session in finished[:overflow]:
            self._sessions.pop(session.session_id, None)

    async def record_command(
        self, session_id: str, command: str, output: str = "", exit_code: int = 0
    ):
        session = await self.get_session(session_id)
        if session:
            if len(session.commands) >= session.MAX_COMMANDS:
                session._count_drop("commands")
                return
            session.commands.append(
                {
                    "timestamp": time.time(),
                    "command": command,
                    "output": output,
                    "exit_code": exit_code,
                }
            )

    async def record_file_upload(
        self,
        session_id: str,
        filename: str,
        content: bytes,
        remote_path: str = "",
        source: str = "unknown",
        methods: Optional[list[str]] = None,
    ) -> Optional[str]:
        """Store an attacker-supplied file and note it against the session.

        ``source`` says which channel carried it — ``ftp_stor``,
        ``http_multipart``, ``ssh_shell``, ``sftp`` — because the same bytes
        mean different things arriving through a webshell upload and through
        an echoloader. Returns the SHA-256, or None if the file was refused.

        Nothing here opens, parses or executes the content. It is written
        under its own digest and analysed later, by the backend, in a
        resource-limited process away from the internet-facing engine.
        """
        session = await self.get_session(session_id)
        if not session or not content:
            return None
        if len(content) > self.MAX_UPLOAD_BYTES:
            logger.warning(
                f"Discarding {len(content)} byte upload from session "
                f"{session_id}: exceeds {self.MAX_UPLOAD_BYTES} byte cap"
            )
            return None
        if len(session.files_uploaded) >= self.MAX_UPLOADS_PER_SESSION:
            logger.warning(f"Session {session_id} exceeded its upload count cap")
            return None

        # Hashing and writing up to 16 MiB blocks every other connection if
        # it runs on the loop; it goes to a worker thread.
        file_hash, file_path = await asyncio.to_thread(_store_upload, content)
        session.files_uploaded.append(
            {
                "timestamp": time.time(),
                # Attacker-controlled strings; bounded before they go anywhere.
                "filename": (filename or file_hash)[:255],
                "remote_path": (remote_path or filename or "")[:500],
                "size": len(content),
                "sha256": file_hash,
                "stored_path": file_path,
                "source": source,
                "methods": list(methods or [])[:8],
            }
        )
        return file_hash

    async def record_file_download(
        self, session_id: str, filename: str, content: bytes, remote_path: str = ""
    ):
        session = await self.get_session(session_id)
        if session:
            file_hash = hashlib.sha256(content).hexdigest()
            session.files_downloaded.append(
                {
                    "timestamp": time.time(),
                    "filename": filename,
                    "remote_path": remote_path or filename,
                    "size": len(content),
                    "sha256": file_hash,
                }
            )

    async def record_network_event(
        self, session_id: str, event_type: str, details: dict
    ):
        session = await self.get_session(session_id)
        if session:
            if len(session.network_events) >= session.MAX_NETWORK_EVENTS:
                session._count_drop("events")
                return
            session.network_events.append(
                {"timestamp": time.time(), "event_type": event_type, **details}
            )

    #: Keystrokes retained per session. They were recorded without limit, so a
    #: large paste grew one list by a dict per character on the component that
    #: faces the internet. Past the cap they are counted, not stored.
    MAX_KEYSTROKES = 20_000

    async def record_keystroke(self, session_id: str, keystroke: str):
        session = await self.get_session(session_id)
        if session:
            session.keystroke_total += 1
            if len(session.keystrokes) < self.MAX_KEYSTROKES:
                session.keystrokes.append(
                    {"timestamp": time.time(), "key": keystroke}
                )

    async def record_auth_attempt(
        self, session_id: str, username: str, password: str, success: bool
    ):
        session = await self.get_session(session_id)
        if session:
            if len(session.authentication_attempts) >= session.MAX_AUTH_ATTEMPTS:
                session._count_drop("credentials")
                return
            session.authentication_attempts.append(
                {
                    "timestamp": time.time(),
                    "username": username,
                    "password": password,
                    "success": success,
                }
            )

    async def set_threat_profile(self, session_id: str, profile: str):
        session = await self.get_session(session_id)
        if session:
            session.threat_profile = profile

    async def set_anomaly_score(self, session_id: str, score: float):
        session = await self.get_session(session_id)
        if session:
            session.anomaly_score = score

    def _persist_session(self, session: SessionRecord):
        # A capture directory removed after startup must not stop the session
        # reaching the backend: this runs before the ingest is spawned.
        os.makedirs(config.session_capture_dir, exist_ok=True)
        capture_file = os.path.join(
            config.session_capture_dir, f"{session.session_id}.json"
        )
        with open(capture_file, "w") as f:
            json.dump(session.to_dict(), f, indent=2)
        logger.info(f"Session persisted: {capture_file}")

    async def _send_to_backend(self, session: SessionRecord):
        """Deliver one session, or queue it for the retry loop.

        Delivery used to be a single attempt: anything but an immediate 200
        dropped the capture. Now a retryable failure (backend down, timing
        out, 5xx, 429) spools the payload to disk and the retry loop takes it
        from there; only a definite rejection (another 4xx) gives up, and
        even that keeps a copy under failed/ for inspection.
        """
        try:
            # Reading uploads back and base64-encoding up to 24 MiB is CPU
            # work; it runs off the loop.
            payload = await asyncio.to_thread(session.to_backend_payload, self._node_id)
        except Exception as exc:
            logger.error("Could not build payload for session %s: %s", session.session_id, exc)
            return
        async with self._semaphore():
            outcome, detail = await self._post_session(payload)
        if outcome == "ok":
            self.ingest_stats["sent"] += 1
            logger.info(
                f"Session {session.session_id} ingested to backend. Classification: {detail}"
            )
        elif outcome == "retry":
            self.ingest_stats["spooled"] += 1
            logger.warning(
                "Backend unavailable (%s); session %s spooled for retry",
                detail, session.session_id,
            )
            await asyncio.to_thread(self.spool.put, session.session_id, payload)
        else:
            self.ingest_stats["rejected"] += 1
            logger.error("Backend rejected session %s: %s", session.session_id, detail)
            await asyncio.to_thread(self.spool.put_failed, session.session_id, payload, detail)

    async def _post_session(self, payload: dict) -> tuple[str, str]:
        """One POST. Returns ("ok"|"retry"|"drop", detail)."""
        try:
            response = await self._http().post(
                f"{config.backend_api_url}/sessions/ingest-internal",
                json=payload,
                params={"node_id": self._node_id},
                timeout=self.INGEST_TIMEOUT,
            )
        except (httpx.TransportError, httpx.TimeoutException) as exc:
            return "retry", f"{type(exc).__name__}: {exc}" if str(exc) else type(exc).__name__
        except Exception as exc:
            return "retry", f"{type(exc).__name__}: {exc}"

        if response.status_code == 200:
            try:
                body = response.json()
            except ValueError:
                body = {}
            if body.get("duplicate"):
                return "ok", "duplicate (already stored)"
            return "ok", body.get("ai_classification", {}).get("category", "unknown")
        if response.status_code == 429 or response.status_code >= 500:
            return "retry", f"HTTP {response.status_code}"
        return "drop", f"HTTP {response.status_code} - {response.text[:200]}"

    async def replay_spool(self, limit: Optional[int] = None) -> int:
        """Resend queued sessions, oldest first; the number delivered.

        Stops at the first retryable failure: if the backend is still down,
        every later entry would fail the same way.
        """
        delivered = 0
        for path in self.spool.oldest(limit or self.SPOOL_BATCH):
            payload = self.spool.load(path)
            if payload is None:
                continue
            session_id = payload.get("session_id") or Spool.session_id_of(path)
            outcome, detail = await self._post_session(payload)
            if outcome == "retry":
                logger.warning("Spool replay paused: backend unavailable (%s)", detail)
                break
            self.spool.remove(path)
            if outcome == "ok":
                delivered += 1
                self.ingest_stats["replayed"] += 1
            else:
                self.ingest_stats["rejected"] += 1
                logger.error("Backend rejected spooled session %s: %s", session_id, detail)
                self.spool.put_failed(session_id, payload, detail)
        if delivered:
            logger.info("Replayed %d spooled session(s); %d still queued", delivered, self.spool.pending)
        return delivered

    async def _spool_loop(self) -> None:
        interval = self.SPOOL_RETRY_INTERVAL
        while True:
            try:
                if self.spool.pending:
                    before = self.spool.pending
                    await self.replay_spool()
                    # Anything still queued after a pass means the backend
                    # refused or vanished; back off, and reset once it drains.
                    if self.spool.pending and self.spool.pending >= before:
                        interval = min(interval * 2, self.SPOOL_RETRY_MAX_INTERVAL)
                    else:
                        interval = self.SPOOL_RETRY_INTERVAL
                else:
                    interval = self.SPOOL_RETRY_INTERVAL
            except asyncio.CancelledError:
                raise
            except Exception as exc:
                logger.error("Spool replay failed: %s", exc)
            await asyncio.sleep(interval)

    async def _retention_loop(self) -> None:
        while True:
            try:
                await asyncio.to_thread(
                    prune_captures,
                    config.session_capture_dir,
                    config.file_capture_dir,
                    config.capture_retention_days,
                    config.upload_retention_days,
                )
            except asyncio.CancelledError:
                raise
            except Exception as exc:
                logger.error("Retention pass failed: %s", exc)
            await asyncio.sleep(3600)

    def start_background(self) -> None:
        """Start the spool replay and retention loops."""
        if self._service_tasks:
            return
        self._service_tasks = [
            asyncio.create_task(self._spool_loop(), name="spool-replay"),
            asyncio.create_task(self._retention_loop(), name="capture-retention"),
        ]

    async def stop_background(self) -> None:
        for task in self._service_tasks:
            task.cancel()
        for task in self._service_tasks:
            try:
                await task
            except (asyncio.CancelledError, Exception):
                pass
        self._service_tasks = []
        if self._client is not None and not self._client.is_closed:
            await self._client.aclose()

    # -- node registration and heartbeat ------------------------------------

    def node_payload(self) -> dict:
        return {
            "name": config.node_name,
            "protocol": "multi",
            "ip_address": config.bind_address,
            "port": config.ssh_port,
            "mode": config.operational_mode.value,
        }

    async def heartbeat(self, status: dict) -> bool:
        """Tell the backend the node is alive, and what state it is in.

        The node row's ``last_heartbeat`` was only ever written at
        registration, so the dashboard could not tell a running engine from
        one that died an hour ago. Returns True when the backend answered.
        """
        if not self._registered:
            await self.register_node()
        body = {"node_id": self._node_id, "name": config.node_name, "status": status}
        try:
            response = await self._http().post(
                f"{config.backend_api_url}/nodes/heartbeat-internal",
                json=body,
                timeout=10,
            )
        except Exception as exc:
            self._heartbeat_failures += 1
            if self._heartbeat_failures == 1:
                logger.warning("Heartbeat failed: %s (will keep trying quietly)", exc)
            return False

        if response.status_code == 404:
            # The backend lost or never had this node: claim an id again.
            logger.warning("Backend does not know node %s; re-registering", self._node_id)
            self._registered = False
            await self.register_node()
            return False
        if response.status_code != 200:
            self._heartbeat_failures += 1
            if self._heartbeat_failures == 1:
                logger.warning("Heartbeat rejected: HTTP %s %s", response.status_code, response.text[:200])
            return False

        if self._heartbeat_failures:
            logger.info("Heartbeat restored after %d failure(s)", self._heartbeat_failures)
            self._heartbeat_failures = 0
        try:
            data = response.json()
        except ValueError:
            data = {}
        if isinstance(data, dict):
            if isinstance(data.get("id"), int):
                self._node_id = data["id"]
            self._adopt_stored_mode(data.get("mode"))
        return True

    async def register_node(self) -> int:
        """Claim a node id from the backend using the shared ingest token.

        The previous implementation POSTed to the admin-only ``/nodes/``
        endpoint with no credentials, so it always failed and silently fell
        back to node id 1. A failure here is now retried by the heartbeat
        loop rather than being final.
        """
        try:
            response = await self._http().post(
                f"{config.backend_api_url}/nodes/register-internal",
                json=self.node_payload(),
                timeout=10,
            )
            if response.status_code in (200, 201):
                node = response.json()
                self._node_id = node["id"]
                self._registered = True
                if self._register_failures:
                    logger.info("Node registration succeeded after %d failure(s)", self._register_failures)
                self._register_failures = 0
                logger.info(f"Registered as honeypot node {self._node_id}")
                self._adopt_stored_mode(node.get("mode"))
                return self._node_id
            self._note_register_failure(
                f"Node registration rejected: HTTP {response.status_code} - {response.text[:200]}"
            )
        except Exception as e:
            self._note_register_failure(f"Could not register honeypot node: {e}")
        if not self._registered:
            self._node_id = 1
        return self._node_id

    def _note_register_failure(self, message: str) -> None:
        self._register_failures += 1
        # The heartbeat loop retries registration every tick; one warning
        # per outage, the rest at debug.
        logger.log(logging.WARNING if self._register_failures == 1 else logging.DEBUG, message)

    @staticmethod
    def _adopt_stored_mode(stored: Optional[str]) -> None:
        """Run in the mode the operator last chose, not the env default.

        An existing node keeps its stored mode across re-registration, but the
        engine always booted in HONEYPOT_OPERATIONAL_MODE, so a restart quietly
        undid "passive" while the dashboard still showed it.
        """
        from honeypot.core.config import OperationalMode
        from honeypot.core.modes import mode_handler

        try:
            mode = OperationalMode(stored)
        except ValueError:
            return
        if mode != mode_handler.mode:
            logger.info("Adopting stored operational mode: %s", mode.value)
            mode_handler.mode = mode

    async def get_active_sessions(self) -> list[SessionRecord]:
        async with self._lock:
            return [
                s for s in self._sessions.values() if s.end_time is None
            ]

    async def get_session_count(self) -> int:
        async with self._lock:
            return self._total_sessions

    async def drain(self, timeout: float = 8.0):
        """Wait for in-flight backend ingests before shutting down.

        Bounded: Docker's stop grace period is finite, and a backend that is
        down should not hold the engine's exit hostage. Anything still in
        flight when time runs out has either been spooled or will be lost,
        which the log says.
        """
        pending = list(self._background)
        if not pending:
            return
        done, still = await asyncio.wait(pending, timeout=timeout)
        if still:
            logger.warning("%d ingest(s) still in flight at shutdown", len(still))
            for task in still:
                task.cancel()


session_manager = SessionManager()
