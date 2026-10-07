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
        for ip in ("100.87.82.102", "10.10.21.69", "203.0.113.9"):
            for _ in range(2):
                await client.post(
                    f"/api/v1/sessions/ingest-internal?node_id={node_id}", headers=INGEST_HEADERS,
                    json={"protocol": "ssh", "attacker_ip": ip, "commands": ["id"], "started_at": "2026-01-01T00:00:00Z"},
                )
        feed = await client.get("/api/v1/iocs/feed?min_sessions=1", headers=headers)
        lines = [l for l in feed.text.splitlines() if not l.startswith("#")]
        assert lines == ["203.0.113.9"]


class TestEngineControlAudit:
    async def test_block_ip_is_audited(self, client, auth_headers, db_session, monkeypatch):
        from app.api import honeypot as engine_api

        async def fake_request(method, path, body=None):
            return {"status": "blocked"}

        monkeypatch.setattr(engine_api, "_engine_request", fake_request)
        headers = await auth_headers(UserRole.ANALYST)
        response = await client.post("/api/v1/honeypot/block-ip", headers=headers, json={"ip": "203.0.113.5"})
        assert response.status_code == 200
        rows = (await db_session.execute(select(AuditLog).where(AuditLog.action == "ip_blocked"))).scalars().all()
        assert len(rows) == 1 and rows[0].details == {"ip": "203.0.113.5"}


class TestManualIngestIsAdminOnly:
    async def test_analyst_cannot_fabricate_sessions(self, client, auth_headers):
        headers = await auth_headers(UserRole.ANALYST)
        response = await client.post("/api/v1/sessions/ingest?node_id=1", headers=headers, json={"attacker_ip": "1.2.3.4"})
        assert response.status_code == 403
