"""Round 2: refresh-token rotation and revocation, sign-out, access-token
invalidation, the feed token, and audit rows for engine controls."""

import os

import pytest
from sqlalchemy import select

from app.models import AuditLog, RefreshToken, UserRole

INGEST_HEADERS = {"X-Honeypot-Token": os.environ["HONEYPOT_INGEST_TOKEN"]}


async def _login(client, email="analyst@example.com", password="correct-horse-battery"):
    response = await client.post("/api/v1/auth/login", json={"email": email, "password": password})
    assert response.status_code == 200, response.text
    return response.json()


class TestRefreshRotation:
    async def test_refresh_rotates_and_old_token_is_spent(self, client, make_user, db_session):
        await make_user()
        first = await _login(client)
        rows = (await db_session.execute(select(RefreshToken))).scalars().all()
        assert len(rows) == 1 and rows[0].revoked_at is None

        second = await client.post("/api/v1/auth/refresh", json={"refresh_token": first["refresh_token"]})
        assert second.status_code == 200
        assert second.json()["refresh_token"] != first["refresh_token"]

        again = await client.post("/api/v1/auth/refresh", json={"refresh_token": first["refresh_token"]})
        assert again.status_code == 401

        # Reuse revoked the family: the successor is dead too.
        successor = await client.post(
            "/api/v1/auth/refresh", json={"refresh_token": second.json()["refresh_token"]}
        )
        assert successor.status_code == 401
        audit = (
            await db_session.execute(select(AuditLog).where(AuditLog.action == "refresh_token_reuse"))
        ).scalars().all()
        assert len(audit) >= 1

    async def test_refresh_token_without_a_row_is_refused(self, client, make_user):
        from app.core.security import create_refresh_token

        user = await make_user()
        forged = create_refresh_token({"sub": str(user.id), "role": "analyst", "ver": 0})
        response = await client.post("/api/v1/auth/refresh", json={"refresh_token": forged})
        assert response.status_code == 401

    async def test_logout_revokes_the_family(self, client, make_user):
        await make_user()
        tokens = await _login(client)
        out = await client.post("/api/v1/auth/logout", json={"refresh_token": tokens["refresh_token"]})
        assert out.status_code == 200
        response = await client.post("/api/v1/auth/refresh", json={"refresh_token": tokens["refresh_token"]})
        assert response.status_code == 401
        # Idempotent, and never leaks whether the token was valid.
        assert (await client.post("/api/v1/auth/logout", json={"refresh_token": "garbage"})).status_code == 200


class TestAccessTokenInvalidation:
    async def test_password_change_signs_out_everywhere(self, client, make_user):
        await make_user()
        tokens = await _login(client)
        headers = {"Authorization": f"Bearer {tokens['access_token']}"}
        assert (await client.get("/api/v1/auth/me", headers=headers)).status_code == 200
        changed = await client.post(
            "/api/v1/auth/change-password", headers=headers,
            json={"current_password": "correct-horse-battery", "new_password": "a-brand-new-password"},
        )
        assert changed.status_code == 200
        assert (await client.get("/api/v1/auth/me", headers=headers)).status_code == 401
        refreshed = await client.post("/api/v1/auth/refresh", json={"refresh_token": tokens["refresh_token"]})
        assert refreshed.status_code == 401

    async def test_logout_all(self, client, make_user):
        await make_user()
        tokens = await _login(client)
        headers = {"Authorization": f"Bearer {tokens['access_token']}"}
        assert (await client.post("/api/v1/auth/logout-all", headers=headers)).status_code == 200
        assert (await client.get("/api/v1/auth/me", headers=headers)).status_code == 401

    async def test_deactivation_takes_effect_immediately(self, client, auth_headers, make_user):
        admin = await auth_headers(UserRole.ADMIN)
        user = await make_user(email="victim@example.com")
        tokens = await _login(client, "victim@example.com")
        headers = {"Authorization": f"Bearer {tokens['access_token']}"}
        assert (await client.get("/api/v1/auth/me", headers=headers)).status_code == 200
        await client.patch(f"/api/v1/auth/users/{user.id}", headers=admin, json={"is_active": False})
        assert (await client.get("/api/v1/auth/me", headers=headers)).status_code == 401

    async def test_demotion_applies_without_a_new_token(self, client, auth_headers, make_user):
        admin = await auth_headers(UserRole.ADMIN)
        user = await make_user(email="demoted@example.com", role=UserRole.ANALYST)
        tokens = await _login(client, "demoted@example.com")
        headers = {"Authorization": f"Bearer {tokens['access_token']}"}
        ok = await client.post("/api/v1/alerts/bulk", headers=headers, json={"ids": [1], "status": "resolved"})
        assert ok.status_code == 200
        await client.patch(f"/api/v1/auth/users/{user.id}/role", headers=admin, json={"role": "viewer"})
        denied = await client.post("/api/v1/alerts/bulk", headers=headers, json={"ids": [1], "status": "resolved"})
        assert denied.status_code == 403


class TestFeedToken:
    async def test_static_token_reads_the_feed(self, client, monkeypatch):
        from app.core.config import get_settings

        monkeypatch.setattr(get_settings(), "IOC_FEED_TOKEN", "feed-secret-token")
        anonymous = await client.get("/api/v1/iocs/feed")
        assert anonymous.status_code == 401
        wrong = await client.get("/api/v1/iocs/feed", headers={"X-Feed-Token": "nope"})
        assert wrong.status_code == 401
        ok = await client.get("/api/v1/iocs/feed", headers={"X-Feed-Token": "feed-secret-token"})
        assert ok.status_code == 200 and ok.text.startswith("# HoneySentinel indicator feed")

    async def test_private_addresses_never_enter_the_ip_feed(self, client, auth_headers):
        headers = await auth_headers(UserRole.ADMIN)
        node = await client.post(
            "/api/v1/nodes/", headers=headers,
            json={"name": "n", "protocol": "multi", "ip_address": "10.0.0.9", "port": 2222},
        )
        node_id = node.json()["id"]
        # Tailnet (carrier-grade NAT), private, documentation and link-local
        # addresses, and one ordinary global address.
        for ip in ("100.87.82.102", "10.10.21.69", "203.0.113.9", "169.254.10.1", "45.83.64.1"):
            for _ in range(2):
                await client.post(
                    f"/api/v1/sessions/ingest-internal?node_id={node_id}", headers=INGEST_HEADERS,
                    json={"protocol": "ssh", "attacker_ip": ip, "commands": ["id"], "started_at": "2026-01-01T00:00:00Z"},
                )
        feed = await client.get("/api/v1/iocs/feed?min_sessions=1", headers=headers)
        lines = [l for l in feed.text.splitlines() if not l.startswith("#")]
        assert lines == ["45.83.64.1"]

    async def _session_with_indicators(self, db_session, rows):
        """One stored session carrying the given (type, value, tags) rows."""
        from app.models import HoneypotNode, HoneypotSession, IndicatorOfCompromise

        node = HoneypotNode(name="feed-node", protocol="ssh", ip_address="10.0.0.9", port=2222)
        db_session.add(node)
        await db_session.flush()
        session = HoneypotSession(node_id=node.id, protocol="ssh", attacker_ip="45.83.64.1")
        db_session.add(session)
        await db_session.flush()
        for ioc_type, value, tags in rows:
            db_session.add(
                IndicatorOfCompromise(session_id=session.id, ioc_type=ioc_type, value=value, tags=tags)
            )
        await db_session.commit()

    async def test_only_addresses_that_connected_are_exported(self, client, auth_headers, db_session):
        """Typing an address into a decoy must not get it blocked.

        The feed selected every ``ip`` row. That included addresses that only
        appeared in a command, and whatever else had been stored as an "ip".
        """
        await self._session_with_indicators(db_session, [
            ("ip", "45.83.64.1", ["attacker_ip"]),
            ("ip", "45.83.64.2", ["referenced_ip"]),          # typed, never connected
            ("ip", "45.83.64.3", ["payload", "c2"]),          # named inside a file
            ("referenced_ip", "45.83.64.4", ["referenced_ip"]),
            ("ip", "0.0.0.0/0", ["attacker_ip"]),             # not an address
            ("ip", "evil.example", ["attacker_ip"]),
            ("ip", "224.0.0.251", ["attacker_ip"]),           # multicast
            ("ip", "45.83.64.9\n10.0.0.0/8", ["attacker_ip"]),
        ])
        headers = await auth_headers(UserRole.ADMIN)
        feed = await client.get("/api/v1/iocs/feed?min_sessions=1", headers=headers)
        assert feed.status_code == 200
        lines = [l for l in feed.text.splitlines() if not l.startswith("#")]
        assert lines == ["45.83.64.1"]

        refused = await client.get("/api/v1/iocs/feed?ioc_type=referenced_ip", headers=headers)
        assert refused.status_code == 400

    async def test_allowlisted_addresses_are_left_out(self, client, auth_headers, db_session, monkeypatch):
        from app.core.config import get_settings

        await self._session_with_indicators(db_session, [
            ("ip", "45.83.64.1", ["attacker_ip"]),
            ("ip", "45.83.65.7", ["attacker_ip"]),
            ("ip", "45.83.66.8", ["attacker_ip"]),
        ])
        monkeypatch.setattr(get_settings(), "IOC_FEED_ALLOWLIST", "45.83.64.1, 45.83.65.0/24, nonsense")
        headers = await auth_headers(UserRole.ADMIN)
        feed = await client.get("/api/v1/iocs/feed?min_sessions=1", headers=headers)
        lines = [l for l in feed.text.splitlines() if not l.startswith("#")]
        assert lines == ["45.83.66.8"]

    async def test_bearer_token_reads_the_feed_with_nothing_cached(self, client, auth_headers):
        """A scheduled pull is the first request its user makes.

        ``feed_auth`` called the user lookup without a database session. It
        only worked when an earlier request had cached that user's state,
        which every other test's sign-in happened to do.
        """
        from app.core import security

        headers = await auth_headers(UserRole.VIEWER)
        security._user_state_cache.clear()
        feed = await client.get("/api/v1/iocs/feed", headers=headers)
        assert feed.status_code == 200, feed.text
        assert feed.text.startswith("# HoneySentinel indicator feed")

    async def test_other_feed_types_cannot_carry_a_second_line(self, client, auth_headers, db_session):
        await self._session_with_indicators(db_session, [
            ("domain", "c2.example.net", ["c2_host"]),
            ("domain", "x.example.net\n0.0.0.0/0", ["c2_host"]),
            ("domain", "# not a comment", ["c2_host"]),
        ])
        headers = await auth_headers(UserRole.ADMIN)
        feed = await client.get("/api/v1/iocs/feed?ioc_type=domain&min_sessions=1", headers=headers)
        lines = [l for l in feed.text.splitlines() if not l.startswith("#")]
        assert lines == ["c2.example.net"]


class TestEngineControlAudit:
    async def test_block_ip_is_audited(self, client, auth_headers, db_session, monkeypatch):
        from app.api import honeypot as engine_api

        async def fake_request(method, path, body=None, base_url=None):
            return {"status": "blocked"}

        monkeypatch.setattr(engine_api, "_engine_request", fake_request)
        headers = await auth_headers(UserRole.ANALYST)
        response = await client.post("/api/v1/honeypot/block-ip", headers=headers, json={"ip": "203.0.113.5"})
        assert response.status_code == 200
        rows = (await db_session.execute(select(AuditLog).where(AuditLog.action == "ip_blocked"))).scalars().all()
        assert len(rows) == 1 and rows[0].details == {"ip": "203.0.113.5"}

    async def test_block_and_mode_reach_every_engine(self, client, auth_headers, monkeypatch):
        # The website decoys run as a second engine; a block or mode change
        # that reached only the first would leave the website answering.
        from app.api import honeypot as engine_api
        from app.core.config import get_settings

        monkeypatch.setattr(get_settings(), "HONEYPOT_CONTROL_URL", "http://honeypot:8000")
        monkeypatch.setattr(get_settings(), "HONEYPOT_CONTROL_EXTRA_URLS", "http://honeypot-web:8000, ")
        calls = []

        async def fake_request(method, path, body=None, base_url=None):
            calls.append((base_url, path))
            return {"ok": True}

        monkeypatch.setattr(engine_api, "_engine_request", fake_request)
        headers = await auth_headers(UserRole.ADMIN)
        assert (await client.post("/api/v1/honeypot/block-ip", headers=headers, json={"ip": "203.0.113.6"})).status_code == 200
        assert (await client.patch("/api/v1/honeypot/mode", headers=headers, json={"mode": "passive"})).status_code == 200
        assert calls == [
            ("http://honeypot:8000", "/block-ip"), ("http://honeypot-web:8000", "/block-ip"),
            ("http://honeypot:8000", "/mode"), ("http://honeypot-web:8000", "/mode"),
        ]

    async def test_a_failing_engine_does_not_stop_the_others(self, client, auth_headers, monkeypatch):
        from fastapi import HTTPException

        from app.api import honeypot as engine_api
        from app.core.config import get_settings

        monkeypatch.setattr(get_settings(), "HONEYPOT_CONTROL_URL", "http://honeypot:8000")
        monkeypatch.setattr(get_settings(), "HONEYPOT_CONTROL_EXTRA_URLS", "http://honeypot-web:8000")
        reached = []

        async def fake_request(method, path, body=None, base_url=None):
            reached.append(base_url)
            if base_url == "http://honeypot:8000":
                raise HTTPException(status_code=503, detail="Honeypot engine is unreachable")
            return {"ok": True}

        monkeypatch.setattr(engine_api, "_engine_request", fake_request)
        headers = await auth_headers(UserRole.ANALYST)
        response = await client.post("/api/v1/honeypot/block-ip", headers=headers, json={"ip": "203.0.113.7"})
        assert response.status_code == 503
        assert reached == ["http://honeypot:8000", "http://honeypot-web:8000"]


class TestManualIngestIsAdminOnly:
    async def test_analyst_cannot_fabricate_sessions(self, client, auth_headers):
        headers = await auth_headers(UserRole.ANALYST)
        response = await client.post("/api/v1/sessions/ingest?node_id=1", headers=headers, json={"attacker_ip": "1.2.3.4"})
        assert response.status_code == 403
