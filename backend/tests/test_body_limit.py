"""Oversized request bodies are refused before they are parsed.

The penetration test found the API reading and parsing a 12 MB body sent to
/auth/login without authentication.
"""

import os

from app.core.config import get_settings

LIMIT = get_settings().MAX_REQUEST_BODY_BYTES
INGEST_HEADERS = {"X-Honeypot-Token": os.environ["HONEYPOT_INGEST_TOKEN"]}


async def test_oversized_login_body_is_refused_with_413(client):
    response = await client.post(
        "/api/v1/auth/login",
        content=b"a" * (LIMIT + 1),
        headers={"Content-Type": "application/json"},
    )
    assert response.status_code == 413


async def test_oversized_body_without_content_length_is_refused(client):
    async def chunks():
        for _ in range(LIMIT // 65536 + 2):
            yield b"a" * 65536

    response = await client.post(
        "/api/v1/auth/login",
        content=chunks(),
        headers={"Content-Type": "application/json"},
    )
    assert response.status_code == 413


async def test_normal_login_body_still_reaches_the_route(client):
    response = await client.post(
        "/api/v1/auth/login",
        json={"email": "nobody@example.com", "password": "wrong"},
    )
    assert response.status_code == 401


async def test_engine_ingest_is_exempt(client):
    # Larger than the user-facing limit; refused for its content (unknown
    # node), not its size.
    response = await client.post(
        "/api/v1/sessions/ingest-internal?node_id=9999",
        json={"protocol": "ssh", "commands": ["x" * (LIMIT + 10)]},
        headers=INGEST_HEADERS,
    )
    assert response.status_code != 413
