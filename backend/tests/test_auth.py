"""Authentication and authorisation regression tests."""

import pytest

from app.core.security import (
    ACCESS_TOKEN_TYPE,
    create_access_token,
    create_refresh_token,
    decode_token,
    get_password_hash,
    verify_password,
)
from app.models import UserRole


class TestPasswordHashing:
    def test_round_trip(self):
        stored = get_password_hash("correct-horse-battery")
        assert verify_password("correct-horse-battery", stored)
        assert not verify_password("wrong", stored)

    def test_salted_per_call(self):
        assert get_password_hash("same") != get_password_hash("same")

    def test_malformed_hash_returns_false(self):
        # Previously raised ValueError, turning a corrupt row into a 500.
        for junk in ("", "no-delimiter", "pbkdf2_sha256$broken"):
            assert verify_password("anything", junk) is False

    def test_legacy_format_still_verifies(self):
        import hashlib

        salt = "abc123"
        digest = hashlib.pbkdf2_hmac(
            "sha256", b"legacy-pass", salt.encode(), 100_000
        ).hex()
        assert verify_password("legacy-pass", f"{salt}:{digest}")


class TestTokenTypes:
    def test_refresh_token_rejected_as_access_token(self):
        token = create_refresh_token({"sub": "1", "role": "admin"})
        with pytest.raises(Exception) as exc:
            decode_token(token, ACCESS_TOKEN_TYPE)
        assert exc.value.status_code == 401

    def test_access_token_rejected_as_refresh_token(self):
        token = create_access_token({"sub": "1", "role": "admin"})
        with pytest.raises(Exception) as exc:
            decode_token(token, "refresh")
        assert exc.value.status_code == 401


class TestRegistration:
    async def test_cannot_self_assign_admin_role(self, client, db_session, mail_outbox):
        """Registration must never honour a client-supplied role."""
        response = await client.post(
            "/api/v1/auth/register",
            json={
                "email": "attacker@example.com",
                "password": "a-very-long-password",
                "name": "Attacker",
                "role": "admin",
            },
        )
        assert response.status_code == 201

        from sqlalchemy import select

        from app.models import User

        user = (
            await db_session.execute(
                select(User).where(User.email == "attacker@example.com")
            )
        ).scalar_one()
        assert user.role == UserRole.VIEWER

    async def test_short_password_rejected(self, client):
        response = await client.post(
            "/api/v1/auth/register",
            json={"email": "a@example.com", "password": "short"},
        )
        assert response.status_code == 422

    async def test_duplicate_email_does_not_leak(self, client, make_user, mail_outbox):
        await make_user(email="taken@example.com")
        response = await client.post(
            "/api/v1/auth/register",
            json={"email": "taken@example.com", "password": "a-very-long-password"},
        )
        # Same response as a fresh registration: no account-existence oracle.
        assert response.status_code == 201


class TestLogin:
    async def test_success(self, client, make_user):
        await make_user(email="ok@example.com")
        response = await client.post(
            "/api/v1/auth/login",
            json={"email": "ok@example.com", "password": "correct-horse-battery"},
        )
        assert response.status_code == 200
        assert set(response.json()) >= {"access_token", "refresh_token"}

    async def test_unknown_and_wrong_password_are_indistinguishable(
        self, client, make_user
    ):
        await make_user(email="real@example.com")
        a = await client.post(
            "/api/v1/auth/login",
            json={"email": "real@example.com", "password": "nope"},
        )
        b = await client.post(
            "/api/v1/auth/login",
            json={"email": "ghost@example.com", "password": "nope"},
        )
        assert a.status_code == b.status_code == 401
        assert a.json()["detail"] == b.json()["detail"]

    async def test_unverified_account_blocked(self, client, make_user):
        await make_user(email="unverified@example.com", is_verified=False)
        response = await client.post(
            "/api/v1/auth/login",
            json={
                "email": "unverified@example.com",
                "password": "correct-horse-battery",
            },
        )
        assert response.status_code == 403


class TestRefresh:
    async def test_access_token_cannot_be_used_to_refresh(
        self, client, make_user
    ):
        user = await make_user(email="refresh@example.com")
        access = create_access_token(
            {"sub": str(user.id), "email": user.email, "role": "analyst"}
        )
        response = await client.post(
            "/api/v1/auth/refresh", json={"refresh_token": access}
        )
        assert response.status_code == 401


class TestRoleEnforcement:
    async def test_viewer_cannot_create_node(self, client, auth_headers):
        headers = await auth_headers(UserRole.VIEWER)
        response = await client.post(
            "/api/v1/nodes/",
            headers=headers,
            json={
                "name": "n",
                "protocol": "ssh",
                "ip_address": "10.0.0.1",
                "port": 22,
            },
        )
        assert response.status_code == 403

    async def test_viewer_cannot_export(self, client, auth_headers):
        headers = await auth_headers(UserRole.VIEWER)
        response = await client.post(
            "/api/v1/export/?format=json", headers=headers
        )
        assert response.status_code == 403

    async def test_admin_can_create_node(self, client, auth_headers):
        headers = await auth_headers(UserRole.ADMIN)
        response = await client.post(
            "/api/v1/nodes/",
            headers=headers,
            json={
                "name": "edge-1",
                "protocol": "ssh",
                "ip_address": "10.0.0.1",
                "port": 22,
            },
        )
        assert response.status_code == 201

    async def test_unauthenticated_is_rejected(self, client):
        # 401 (not 403) is the correct status for absent credentials.
        assert (await client.get("/api/v1/sessions/")).status_code == 401
