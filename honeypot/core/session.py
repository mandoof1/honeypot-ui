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

from honeypot.core.config import config

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

    def to_backend_payload(self, node_id: int = 1) -> dict[str, Any]:
        command_strings = [c["command"] for c in self.commands]
        return {
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
            "keystrokes": self.keystrokes,
            "authentication_attempts": self.authentication_attempts,
            "metadata": self.metadata,
            "threat_profile": self.threat_profile,
            "anomaly_score": self.anomaly_score,
        }


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

    def __init__(self):
        self._sessions: dict[str, SessionRecord] = {}
        self._lock = asyncio.Lock()
        self._node_id: int = 1
        self._total_sessions: int = 0
        # asyncio only holds a weak reference to tasks, so a fire-and-forget
        # ingest could be garbage collected mid-flight.
        self._background: set[asyncio.Task] = set()
        Path(config.session_capture_dir).mkdir(parents=True, exist_ok=True)
        Path(config.file_capture_dir).mkdir(parents=True, exist_ok=True)
        Path(config.log_dir).mkdir(parents=True, exist_ok=True)

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

        await self._persist_session(session)
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

        file_hash = hashlib.sha256(content).hexdigest()
        # Name the file after its own digest so an attacker-supplied
        # filename can never influence where it lands on disk.
        os.makedirs(config.file_capture_dir, exist_ok=True)
        file_path = os.path.join(config.file_capture_dir, file_hash)
        if not os.path.exists(file_path):
            with open(file_path, "wb") as f:
                f.write(content)
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

    async def _persist_session(self, session: SessionRecord):
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
        payload = session.to_backend_payload(self._node_id)
        try:
            async with httpx.AsyncClient() as client:
                response = await client.post(
                    f"{config.backend_api_url}/sessions/ingest-internal",
                    json=payload,
                    params={"node_id": self._node_id},
                    headers={"X-Honeypot-Token": config.ingest_token},
                    timeout=15,
                )
                if response.status_code == 200:
                    result = response.json()
                    logger.info(
                        f"Session {session.session_id} ingested to backend. "
                        f"Classification: {result.get('ai_classification', {}).get('category', 'unknown')}"
                    )
                else:
                    logger.error(
                        f"Failed to ingest session {session.session_id}: "
                        f"HTTP {response.status_code} - {response.text}"
                    )
        except httpx.ConnectError:
            logger.warning(
                f"Backend unavailable, session {session.session_id} saved locally only"
            )
        except Exception as e:
            logger.error(f"Error sending session to backend: {e}")

    async def register_node(self) -> int:
        """Claim a node id from the backend using the shared ingest token.

        The previous implementation POSTed to the admin-only ``/nodes/``
        endpoint with no credentials, so it always failed and silently fell
        back to node id 1.
        """
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
                    self._node_id = response.json()["id"]
                    logger.info(f"Registered as honeypot node {self._node_id}")
                    return self._node_id
                logger.warning(
                    f"Node registration rejected: HTTP {response.status_code} "
                    f"- {response.text[:200]}"
                )
        except Exception as e:
            logger.warning(f"Could not register honeypot node: {e}")
        self._node_id = 1
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
        """Wait for in-flight backend ingests before shutting down."""
        pending = list(self._background)
        if pending:
            await asyncio.gather(*pending, return_exceptions=True)


session_manager = SessionManager()
