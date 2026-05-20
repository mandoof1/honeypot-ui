from __future__ import annotations
import httpx
import logging
from typing import Dict, List, Optional
from datetime import datetime
from app.core.config import get_settings

settings = get_settings()
logger = logging.getLogger(__name__)


class CowrieAdapter:
    PROTOCOL = "ssh"

    def __init__(self):
        self.base_url = settings.COWRIE_API_URL

    async def get_sessions(self, limit: int = 100) -> List[Dict]:
        try:
            async with httpx.AsyncClient(timeout=10) as client:
                resp = await client.get(f"{self.base_url}/api/sessions", params={"limit": limit})
                resp.raise_for_status()
                return resp.json()
        except Exception as e:
            logger.error(f"Cowrie API error: {e}")
            return []

    async def get_session_details(self, session_id: str) -> Dict:
        try:
            async with httpx.AsyncClient(timeout=10) as client:
                resp = await client.get(f"{self.base_url}/api/sessions/{session_id}")
                resp.raise_for_status()
                return resp.json()
        except Exception as e:
            logger.error(f"Cowrie session details error: {e}")
            return {}

    async def get_session_commands(self, session_id: str) -> List[str]:
        try:
            async with httpx.AsyncClient(timeout=10) as client:
                resp = await client.get(f"{self.base_url}/api/sessions/{session_id}/commands")
                resp.raise_for_status()
                data = resp.json()
                return [cmd.get("command", "") for cmd in data] if isinstance(data, list) else []
        except Exception as e:
            logger.error(f"Cowrie commands error: {e}")
            return []

    async def get_session_downloads(self, session_id: str) -> List[Dict]:
        try:
            async with httpx.AsyncClient(timeout=10) as client:
                resp = await client.get(f"{self.base_url}/api/sessions/{session_id}/downloads")
                resp.raise_for_status()
                return resp.json()
        except Exception as e:
            logger.error(f"Cowrie downloads error: {e}")
            return []

    def parse_session(self, raw: Dict) -> Dict:
        return {
            "session_uuid": raw.get("session", raw.get("id", "")),
            "attacker_ip": raw.get("src_ip", ""),
            "attacker_port": raw.get("src_port"),
            "protocol": self.PROTOCOL,
            "started_at": raw.get("startTime", raw.get("timestamp")),
            "duration_seconds": raw.get("duration", 0),
            "commands": raw.get("commands", []),
            "tty_log": raw.get("ttylog", ""),
            "uploads": raw.get("downloads", []),
        }


class DionaeaAdapter:
    PROTOCOL = "http"

    def __init__(self):
        self.base_url = settings.DIONAEA_API_URL

    async def get_sessions(self, limit: int = 100) -> List[Dict]:
        try:
            async with httpx.AsyncClient(timeout=10) as client:
                resp = await client.get(f"{self.base_url}/api/connections", params={"limit": limit})
                resp.raise_for_status()
                return resp.json()
        except Exception as e:
            logger.error(f"Dionaea API error: {e}")
            return []

    async def get_session_details(self, session_id: str) -> Dict:
        try:
            async with httpx.AsyncClient(timeout=10) as client:
                resp = await client.get(f"{self.base_url}/api/connections/{session_id}")
                resp.raise_for_status()
                return resp.json()
        except Exception as e:
            logger.error(f"Dionaea session details error: {e}")
            return {}

    async def get_offered_files(self, session_id: str) -> List[Dict]:
        try:
            async with httpx.AsyncClient(timeout=10) as client:
                resp = await client.get(f"{self.base_url}/api/connections/{session_id}/offers")
                resp.raise_for_status()
                return resp.json()
        except Exception as e:
            logger.error(f"Dionaea offers error: {e}")
            return []

    def parse_session(self, raw: Dict) -> Dict:
        return {
            "session_uuid": raw.get("connection", raw.get("id", "")),
            "attacker_ip": raw.get("remote_ip", raw.get("src_ip", "")),
            "attacker_port": raw.get("remote_port", raw.get("src_port")),
            "protocol": raw.get("protocol", self.PROTOCOL),
            "started_at": raw.get("timestamp", raw.get("connection_time")),
            "duration_seconds": raw.get("duration", 0),
            "payload": raw.get("payload", ""),
            "url": raw.get("url", ""),
            "method": raw.get("method", "GET"),
            "user_agent": raw.get("user_agent", ""),
            "uploads": raw.get("offers", []),
        }


class HoneypotIngestionService:
    def __init__(self):
        self.cowrie = CowrieAdapter()
        self.dionaea = DionaeaAdapter()
        self.adapters = {
            "ssh": self.cowrie,
            "http": self.dionaea,
            "https": self.dionaea,
            "ftp": self.dionaea,
        }

    async def ingest_all(self) -> List[Dict]:
        all_sessions = []

        cowrie_sessions = await self.cowrie.get_sessions()
        for raw in cowrie_sessions:
            parsed = self.cowrie.parse_session(raw)
            parsed["commands"] = await self.cowrie.get_session_commands(parsed["session_uuid"])
            parsed["uploads"] = await self.cowrie.get_session_downloads(parsed["session_uuid"])
            all_sessions.append(parsed)

        dionaea_sessions = await self.dionaea.get_sessions()
        for raw in dionaea_sessions:
            parsed = self.dionaea.parse_session(raw)
            parsed["uploads"] = await self.dionaea.get_offered_files(parsed["session_uuid"])
            all_sessions.append(parsed)

        return all_sessions

    def get_adapter(self, protocol: str):
        return self.adapters.get(protocol.lower(), self.dionaea)


honeypot_ingestion = HoneypotIngestionService()
