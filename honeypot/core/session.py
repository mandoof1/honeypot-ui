import asyncio
import hashlib
import json
import logging
import os
import time
import tempfile
from itertools import islice
import uuid
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Optional

import httpx

from honeypot.core.config import config
from honeypot.core.outbox import DeliveryOutbox

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
    threat_profile: Optional[str] = None
    anomaly_score: float = 0.0
    capture_dropped: dict[str, int] = field(default_factory=dict)
    keystrokes_observed: int = 0

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
    MAX_COMMAND_CHARS = 4096
    MAX_KEYSTROKES = 1024
    MAX_FILES = 50

    def dropped(self, kind: str, count: int = 1):
        self.capture_dropped[kind] = self.capture_dropped.get(kind, 0) + count

    def to_backend_payload(self, node_id: int = 1) -> dict[str, Any]:
        command_strings = [c["command"] for c in self.commands]
        return {
            "capture_id": self.session_id,
            "protocol": self.protocol,
            "attacker_ip": self.source_ip,
            "attacker_port": self.source_port,
            "started_at": self.start_datetime,
            "ended_at": self.end_datetime,
            "status": "completed",
            "duration_seconds": round(self.duration, 2),
            "commands": command_strings,
            "payload": self.metadata.get("payload", ""),
            "uploads": [
                {
                    "filename": f["filename"],
                    "sha256": f["sha256"],
                    "size": f["size"],
                }
                for f in self.files_uploaded
            ],
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
            "keystroke_count": max(self.keystrokes_observed, len(self.keystrokes)),
            "capture_dropped": dict(self.capture_dropped),
            # Retrieval and execution events — where a dropper's C2 URL is.
            "events": [
                {k: v for k, v in e.items() if k != "timestamp"} | {"at": e["timestamp"]}
                for e in self.network_events[: self.MAX_EVENTS]
                if e.get("event_type") in ("file_download", "payload_execution")
            ],
            "packets": [
                {
                    "type": e.get("event_type", "unknown"),
                    "size": len(json.dumps(e)),
                }
                for e in self.network_events
            ],
        }

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
            "keystrokes": self.keystrokes,
            "authentication_attempts": self.authentication_attempts,
            "metadata": self.metadata,
            "threat_profile": self.threat_profile,
            "anomaly_score": self.anomaly_score,
            "capture_dropped": self.capture_dropped,
            "keystrokes_observed": self.keystrokes_observed,
        }


class SessionManager:
    #: Uploads are attacker-controlled; cap what a single session can persist.
    MAX_UPLOAD_BYTES = 16 * 1024 * 1024
    def __init__(self):
        self._sessions: dict[str, SessionRecord] = {}
        self._lock = asyncio.Lock()
        self._node_id: Optional[int] = None
        self._next_registration = 0.0
        self._total_sessions: int = 0
        self.outbox = DeliveryOutbox(
            Path(config.session_capture_dir) / "delivery.sqlite3",
            config.backend_api_url, config.ingest_token,
        )
        self.capture_errors = 0
        self._finishing: dict[str, asyncio.Task] = {}
        self._background: set[asyncio.Task] = set()
        Path(config.session_capture_dir).mkdir(parents=True, exist_ok=True)
        Path(config.file_capture_dir).mkdir(parents=True, exist_ok=True)
        Path(config.log_dir).mkdir(parents=True, exist_ok=True)

    @property
    def node_id(self) -> Optional[int]:
        return self._node_id

    async def set_node_id(self, node_id: int):
        self._node_id = node_id

    async def create_session(
        self,
        protocol: str,
        source_ip: str,
        source_port: int,
        metadata: Optional[dict] = None,
    ) -> str:
        session_id = str(uuid.uuid4())
        session = SessionRecord(
            session_id=session_id,
            protocol=protocol,
            source_ip=source_ip,
            source_port=source_port,
            start_time=time.time(),
            metadata=metadata or {},
        )
        async with self._lock:
            self._sessions[session_id] = session
            self._total_sessions += 1
        logger.info(f"New session {session_id} from {source_ip}:{source_port} ({protocol})")
        return session_id

    async def get_session(self, session_id: str) -> Optional[SessionRecord]:
        async with self._lock:
            return self._sessions.get(session_id)

    async def end_session(self, session_id: str) -> Optional[SessionRecord]:
        async with self._lock:
            if session_id in self._finishing:
                task = self._finishing[session_id]
            else:
                session = self._sessions.get(session_id)
                if session is None:
                    return None
                session.end_time = time.time()
                task = asyncio.create_task(self._finish_session(session))
                self._finishing[session_id] = task
                task.add_done_callback(lambda done: self._finishing.pop(session_id, None))
        # A disconnect or cancelled protocol handler must not interrupt the
        # disk transaction. Shutdown explicitly joins these retained tasks.
        return await asyncio.shield(task)

    def end_session_soon(self, session_id: str):
        task = asyncio.create_task(self.end_session(session_id))
        self._background.add(task)
        task.add_done_callback(self._background.discard)

    async def _finish_session(self, session: SessionRecord):
        session_id = session.session_id

        try:
            # Persist the immutable delivery before any network attempt.
            await self.outbox.enqueue(session.to_backend_payload(), self._node_id)
        except Exception:
            self.capture_errors += 1
            logger.exception("Could not queue capture %s; check capture volume", session_id)
            # Retain the raw archive even when queue storage fails.
        try:
            await self._persist_session(session)
        except OSError:
            self.capture_errors += 1
            logger.exception("Could not archive capture %s; check capture volume", session_id)
        async with self._lock:
            # Counts have their own counter; status only needs active records.
            # Keeping 1,000 full completed transcripts could retain gigabytes.
            self._sessions.pop(session_id, None)
        return session

    async def record_command(
        self, session_id: str, command: str, output: str = "", exit_code: int = 0
    ):
        session = await self.get_session(session_id)
        if session and session.end_time is None:
            if len(session.commands) >= session.MAX_TRANSCRIPT_ENTRIES:
                session.dropped("commands")
                return
            if len(command) > session.MAX_COMMAND_CHARS:
                session.dropped("command_characters", len(command) - session.MAX_COMMAND_CHARS)
            if len(output) > session.MAX_OUTPUT_CHARS:
                session.dropped("output_characters", len(output) - session.MAX_OUTPUT_CHARS)
            session.commands.append(
                {
                    "timestamp": time.time(),
                    "command": command[:session.MAX_COMMAND_CHARS],
                    "output": output[:session.MAX_OUTPUT_CHARS],
                    "exit_code": exit_code,
                }
            )

    async def record_file_upload(
        self, session_id: str, filename: str, content: bytes, remote_path: str = ""
    ):
        session = await self.get_session(session_id)
        if session and session.end_time is None:
            if (len(session.files_uploaded) >= session.MAX_FILES
                    or sum(f["size"] for f in session.files_uploaded) + len(content) > self.MAX_UPLOAD_BYTES):
                session.dropped("uploads")
                logger.warning(
                    f"Discarding {len(content)} byte upload from session "
                    f"{session_id}: exceeds {self.MAX_UPLOAD_BYTES} byte cap"
                )
                return
            file_hash = hashlib.sha256(content).hexdigest()
            # Name the file after its own digest so an attacker-supplied
            # filename can never influence where it lands on disk.
            file_path = os.path.join(config.file_capture_dir, file_hash)
            fd = os.open(file_path, os.O_CREAT | os.O_WRONLY | os.O_TRUNC, 0o600)
            with os.fdopen(fd, "wb") as f:
                f.write(content)
            session.files_uploaded.append(
                {
                    "timestamp": time.time(),
                    "filename": filename[:512],
                    "remote_path": (remote_path or filename)[:1024],
                    "size": len(content),
                    "sha256": file_hash,
                    "stored_path": file_path,
                }
            )

    async def record_file_download(
        self, session_id: str, filename: str, content: bytes, remote_path: str = ""
    ):
        session = await self.get_session(session_id)
        if session and session.end_time is None:
            if len(session.files_downloaded) >= session.MAX_FILES:
                session.dropped("downloads")
                return
            file_hash = hashlib.sha256(content).hexdigest()
            session.files_downloaded.append(
                {
                    "timestamp": time.time(),
                    "filename": filename[:512],
                    "remote_path": (remote_path or filename)[:1024],
                    "size": len(content),
                    "sha256": file_hash,
                }
            )

    async def record_network_event(
        self, session_id: str, event_type: str, details: dict
    ):
        session = await self.get_session(session_id)
        if session and session.end_time is None:
            if len(session.network_events) >= session.MAX_EVENTS:
                session.dropped("events")
                return
            # Preserve nested HTTP headers, with a shared character/node
            # budget so nested dictionaries cannot multiply the memory cap.
            budget = [8192, 64]

            def bounded_value(value, depth=0):
                if budget[0] <= 0 or budget[1] <= 0 or depth > 2:
                    session.dropped("event_fields")
                    return None
                budget[1] -= 1
                if isinstance(value, str):
                    kept = value[:min(4096, budget[0])]
                    budget[0] -= len(kept)
                    if len(kept) < len(value):
                        session.dropped("event_characters", len(value) - len(kept))
                    return kept
                if isinstance(value, dict):
                    if len(value) > 32:
                        session.dropped("event_fields", len(value) - 32)
                    return {str(k)[:64]: bounded_value(v, depth + 1) for k, v in islice(value.items(), 32)}
                if isinstance(value, (int, float, bool)) or value is None:
                    return value
                session.dropped("event_fields")
                return None

            bounded = bounded_value(details)
            session.network_events.append(
                {**bounded, "timestamp": time.time(), "event_type": event_type[:64]}
            )

    async def record_keystroke(self, session_id: str, keystroke: str):
        session = await self.get_session(session_id)
        if session and session.end_time is None:
            session.keystrokes_observed += 1
            if len(session.keystrokes) >= session.MAX_KEYSTROKES:
                session.dropped("keystrokes")
                return
            session.keystrokes.append(
                {"timestamp": time.time(), "key": keystroke[:16]}
            )

    async def record_auth_attempt(
        self, session_id: str, username: str, password: str, success: bool
    ):
        session = await self.get_session(session_id)
        if session and session.end_time is None:
            if len(session.authentication_attempts) >= session.MAX_CREDENTIALS:
                session.dropped("credentials")
                return
            if len(username) > 128 or len(password) > 128:
                session.dropped("credential_characters", max(0, len(username) - 128) + max(0, len(password) - 128))
            session.authentication_attempts.append(
                {
                    "timestamp": time.time(),
                    "username": username[:128],
                    "password": password[:128],
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

    async def _persist_session(self, session: SessionRecord):
        def write():
            capture_dir = Path(config.session_capture_dir)
            fd, temporary = tempfile.mkstemp(dir=capture_dir, suffix=".tmp")
            try:
                with os.fdopen(fd, "w") as f:
                    json.dump(session.to_dict(), f)
                    f.flush()
                    os.fsync(f.fileno())
                os.replace(temporary, capture_dir / f"{session.session_id}.json")
            finally:
                if os.path.exists(temporary):
                    os.unlink(temporary)
        await asyncio.to_thread(write)

    async def register_node(self) -> Optional[int]:
        """Claim a node id from the backend using the shared ingest token.

        The previous implementation POSTed to the admin-only ``/nodes/``
        endpoint with no credentials, so it always failed and silently fell
        back to node id 1.
        """
        if self._node_id is not None or time.monotonic() < self._next_registration:
            return self._node_id
        self._next_registration = time.monotonic() + 30
        try:
            async with httpx.AsyncClient() as client:
                response = await client.post(
                    f"{config.backend_api_url}/nodes/register-internal",
                    json={
                        "name": config.node_name,
                        "protocol": "multi",
                        "ip_address": config.bind_address,
                        "port": config.ssh_port,
                        "mode": config.operational_mode.value,
                    },
                    headers={"X-Honeypot-Token": config.ingest_token},
                    timeout=10,
                )
                if response.status_code in (200, 201):
                    node_id = response.json()["id"]
                    if type(node_id) is not int or node_id < 1:
                        raise ValueError("Invalid node registration receipt")
                    self._node_id = node_id
                    logger.info(f"Registered as honeypot node {self._node_id}")
                    return self._node_id
                logger.warning(
                    f"Node registration rejected: HTTP {response.status_code}"
                )
        except Exception as e:
            logger.warning(f"Could not register honeypot node: {e}")
        return self._node_id

    async def get_active_sessions(self) -> list[SessionRecord]:
        async with self._lock:
            return [
                s for s in self._sessions.values() if s.end_time is None
            ]

    async def get_session_count(self) -> int:
        async with self._lock:
            return self._total_sessions

    async def drain(self):
        """Stop delivery; unacknowledged captures resume on next startup."""
        pending = list(self._background) + list(self._finishing.values())
        if pending:
            await asyncio.gather(*pending, return_exceptions=True)
        await self.outbox.stop()


session_manager = SessionManager()
