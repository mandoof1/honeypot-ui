import asyncio
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

    def to_backend_payload(self, node_id: int = 1) -> dict[str, Any]:
        command_strings = [c["command"] for c in self.commands]
        return {
            "attacker_ip": self.source_ip,
            "attacker_port": self.source_port,
            "started_at": self.start_datetime,
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
        }


class SessionManager:
    def __init__(self):
        self._sessions: dict[str, SessionRecord] = {}
        self._lock = asyncio.Lock()
        self._node_id: int = 1
        Path(config.session_capture_dir).mkdir(parents=True, exist_ok=True)
        Path(config.file_capture_dir).mkdir(parents=True, exist_ok=True)
        Path(config.log_dir).mkdir(parents=True, exist_ok=True)

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
        logger.info(f"New session {session_id} from {source_ip}:{source_port} ({protocol})")
        return session_id

    async def get_session(self, session_id: str) -> Optional[SessionRecord]:
        async with self._lock:
            return self._sessions.get(session_id)

    async def end_session(self, session_id: str) -> Optional[SessionRecord]:
        async with self._lock:
            session = self._sessions.get(session_id)
            if session:
                session.end_time = time.time()
                await self._persist_session(session)
                asyncio.create_task(self._send_to_backend(session))
            return session

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
        self, session_id: str, filename: str, content: bytes, remote_path: str = ""
    ):
        session = await self.get_session(session_id)
        if session:
            file_hash = hashlib.sha256(content).hexdigest()
            file_path = os.path.join(config.file_capture_dir, file_hash)
            with open(file_path, "wb") as f:
                f.write(content)
            session.files_uploaded.append(
                {
                    "timestamp": time.time(),
                    "filename": filename,
                    "remote_path": remote_path or filename,
                    "size": len(content),
                    "sha256": file_hash,
                    "stored_path": file_path,
                }
            )

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

    async def record_keystroke(self, session_id: str, keystroke: str):
        session = await self.get_session(session_id)
        if session:
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
        try:
            async with httpx.AsyncClient() as client:
                response = await client.post(
                    f"{config.backend_api_url}/nodes/",
                    json={
                        "name": "honeypot-engine-main",
                        "protocol": "multi",
                        "ip_address": "0.0.0.0",
                        "port": 0,
                        "mode": config.operational_mode.value,
                    },
                    timeout=10,
                )
                if response.status_code in (200, 201, 409):
                    if response.status_code == 409:
                        list_resp = await client.get(
                            f"{config.backend_api_url}/nodes/",
                            timeout=10,
                        )
                        nodes = list_resp.json()
                        for node in nodes:
                            if node.get("name") == "honeypot-engine-main":
                                self._node_id = node["id"]
                                return self._node_id
                    else:
                        data = response.json()
                        self._node_id = data.get("id", 1)
                        return self._node_id
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
            return len(self._sessions)


session_manager = SessionManager()
