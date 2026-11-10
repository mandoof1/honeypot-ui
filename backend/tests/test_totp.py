"""Authenticator codes, the second factor at sign-in, and one-time email codes.

There were no tests for any of this. The RFC 6238 vectors pin the algorithm;
the rest pins the behaviour around it: a code works once, wrong codes count,
and none of the answers says whether an account exists.
"""

import time

import pytest
from sqlalchemy import select

from app.core import totp
from app.core.config import get_settings
from app.core.encryption import encrypt_data, totp_context
from app.core.security import get_password_hash
from app.models import AuditLog, OTPVerification, User, UserRole

PASSWORD = "correct-horse-battery"
LOGIN = "/api/v1/auth/login"

#: RFC 6238 appendix B: the ASCII secret "12345678901234567890", SHA-1.
RFC_SECRET = "GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ"
#: (Unix time, the RFC's eight-digit code). This implementation issues six
#: digits, which are the last six of the same truncated value.
RFC_VECTORS = [
    (59, "94287082"),
    (1111111109, "07081804"),
    (1111111111, "14050471"),
    (1234567890, "89005924"),
    (2000000000, "69279037"),
    (20000000000, "65353130"),
]


# --- the algorithm -------------------------------------------------------------

@pytest.mark.parametrize("at, eight_digits", RFC_VECTORS)
def test_rfc6238_vectors(at, eight_digits):
    assert totp.current_code(RFC_SECRET, at=at) == eight_digits[-6:]
    assert totp.verify(RFC_SECRET, eight_digits[-6:], at=at)
    assert totp.matching_step(RFC_SECRET, eight_digits[-6:], at=at) == at // 30


def test_one_step_of_clock_drift_is_accepted_and_two_are_not():
    at = 1234567890
    code = totp.current_code(RFC_SECRET, at=at)
    assert totp.matching_step(RFC_SECRET, code, at=at + 30) == at // 30
    assert totp.matching_step(RFC_SECRET, code, at=at - 30) == at // 30
    assert totp.matching_step(RFC_SECRET, code, at=at + 61) is None
    assert totp.matching_step(RFC_SECRET, code, at=at - 61) is None


@pytest.mark.parametrize("bad", ["", "12345", "1234567", "12345a", "abcdef", None])
def test_malformed_codes_are_refused(bad):
    assert totp.verify(RFC_SECRET, bad, at=59) is False


def test_malformed_secret_is_refused_not_raised():
    assert totp.verify("not base32 !!", "123456", at=59) is False
    assert totp.verify("", "123456", at=59) is False


def test_spaces_in_a_typed_code_are_ignored():
    code = totp.current_code(RFC_SECRET, at=59)
    assert totp.verify(RFC_SECRET, f"{code[:3]} {code[3:]}", at=59)


def test_generated_secret_and_recovery_codes_have_the_expected_shape():
    secret = totp.generate_secret()
    assert len(secret) == 32 and totp.verify(secret, totp.current_code(secret))
    codes = totp.generate_recovery_codes()
    assert len(set(codes)) == 8
    assert all(len(c) == 14 and c.count("-") == 2 for c in codes)


# --- helpers ---------------------------------------------------------------------

@pytest.fixture
def wide_source_limit(monkeypatch):
    """Take the per-source throttle out of the way of account-level tests."""
    monkeypatch.setattr(get_settings(), "LOGIN_SOURCE_FAILURE_LIMIT", 10_000)


async def _enrolled_user(db_session, make_user, email="mfa@example.com", recovery=()):
    user = await make_user(email=email, role=UserRole.ADMIN)
    secret = totp.generate_secret()
    user.totp_secret_encrypted = encrypt_data(secret, totp_context(user.id))
    user.totp_enabled = True
    user.totp_recovery_hashes = [get_password_hash(code) for code in recovery]
    await db_session.commit()
    return user, secret


def _code(secret, steps_ahead=0):
    return totp.current_code(secret, at=time.time() + 30 * steps_ahead)


def _wrong(secret):
    valid = {_code(secret, s) for s in (-1, 0, 1)}
    return next(c for c in ("000000", "111111", "222222", "333333") if c not in valid)


async def _login(client, email, password=PASSWORD, code=None, headers=None):
    body = {"email": email, "password": password}
    if code is not None:
        body["totp_code"] = code
    return await client.post(LOGIN, json=body, headers=headers or {})


# --- second factor at sign-in -------------------------------------------------------

async def test_enrol_confirm_and_sign_in(client, auth_headers, db_session):
    headers = await auth_headers(UserRole.ANALYST, email="enrol@example.com")
    secret = (await client.post("/api/v1/auth/mfa/enroll", headers=headers)).json()["secret"]
    code = _code(secret)
    confirm = await client.post(
        "/api/v1/auth/mfa/confirm", headers=headers, json={"code": code}
    )
    assert confirm.status_code == 200 and len(confirm.json()["recovery_codes"]) == 8

    prompted = await _login(client, "enrol@example.com")
    assert prompted.status_code == 401 and prompted.headers["x-mfa-required"] == "totp"

    # The code that confirmed enrolment has been used; the next one works.
    assert (await _login(client, "enrol@example.com", code=code)).status_code == 401
    assert (await _login(client, "enrol@example.com", code=_code(secret, 1))).status_code == 200


async def test_a_code_cannot_be_used_twice(client, db_session, make_user, wide_source_limit):
    """A code is valid for about ninety seconds and nothing recorded its use,
    so one seen in transit could be replayed inside that window."""
    user, secret = await _enrolled_user(db_session, make_user)
    code = _code(secret)
    assert (await _login(client, user.email, code=code)).status_code == 200
    replay = await _login(client, user.email, code=code)
    assert replay.status_code == 401
    # An older step is refused as well once a newer one has been accepted.
    assert (await _login(client, user.email, code=_code(secret, 1))).status_code == 200
    assert (await _login(client, user.email, code=_code(secret, 0))).status_code == 401


async def test_wrong_codes_count_and_the_counter_survives_a_right_password(
    client, db_session, make_user, wide_source_limit
):
    """Wrong authenticator codes never counted, and the counter was cleared
    as soon as the password matched, before the code was looked at."""
    user, secret = await _enrolled_user(db_session, make_user)
    for expected in (1, 2, 3):
        response = await _login(client, user.email, code=_wrong(secret))
        assert response.status_code == 401
        await db_session.refresh(user)
        assert user.failed_login_count == expected

    failures = (
        await db_session.execute(select(AuditLog).where(AuditLog.action == "mfa_failed"))
    ).scalars().all()
    assert len(failures) == 3

    assert (await _login(client, user.email, code=_code(secret))).status_code == 200
    await db_session.refresh(user)
    assert user.failed_login_count == 0


async def test_wrong_codes_lock_the_account_and_exhaust_the_second_factor(
    client, db_session, make_user, monkeypatch, wide_source_limit
):
    monkeypatch.setattr(get_settings(), "LOGIN_LOCKOUT_THRESHOLD", 3)
    user, secret = await _enrolled_user(db_session, make_user)
    for _ in range(3):
        await _login(client, user.email, code=_wrong(secret))
    await db_session.refresh(user)
    assert user.locked_until is not None

    # Three wrong codes means someone has the password. The second factor is
    # refused for the window even when the code is right, so it cannot be
    # guessed at leisure; and the answer is the ordinary one.
    refused = await _login(client, user.email, code=_code(secret))
    assert refused.status_code == 401
    assert refused.json()["detail"] == "Invalid authenticator code"


async def test_password_lock_cannot_keep_out_an_account_with_an_authenticator(
    client, db_session, make_user, monkeypatch, wide_source_limit
):
    """Anyone could lock an administrator out by failing ten times."""
    monkeypatch.setattr(get_settings(), "LOGIN_LOCKOUT_THRESHOLD", 3)
    user, secret = await _enrolled_user(db_session, make_user)
    for _ in range(3):
        assert (await _login(client, user.email, password="wrong-password-123")).status_code == 401
    await db_session.refresh(user)
    assert user.locked_until is not None

    ok = await _login(client, user.email, code=_code(secret))
    assert ok.status_code == 200
    await db_session.refresh(user)
    assert user.locked_until is None and user.failed_login_count == 0


async def test_locked_account_answers_like_an_unknown_one(
    client, db_session, make_user, monkeypatch, wide_source_limit
):
    """423 "account locked" told a stranger the address was registered."""
    monkeypatch.setattr(get_settings(), "LOGIN_LOCKOUT_THRESHOLD", 2)
    await make_user(email="plain@example.com")
    for _ in range(2):
        await _login(client, "plain@example.com", password="wrong-password-123")

    locked_right = await _login(client, "plain@example.com")
    locked_wrong = await _login(client, "plain@example.com", password="wrong-password-123")
    unknown = await _login(client, "nobody@example.com", password="wrong-password-123")
    answers = {(r.status_code, r.text) for r in (locked_right, locked_wrong, unknown)}
    assert answers == {(401, '{"detail":"Invalid email or password"}')}


async def test_one_source_runs_out_of_attempts_whether_or_not_the_account_exists(
    client, make_user, monkeypatch
):
    settings = get_settings()
    monkeypatch.setattr(settings, "LOGIN_SOURCE_FAILURE_LIMIT", 3)
    monkeypatch.setattr(settings, "TRUST_PROXY_HEADERS", True)
    await make_user(email="real@example.com")
    here = {"X-Forwarded-For": "45.83.64.10"}
    elsewhere = {"X-Forwarded-For": "45.83.64.11"}

    for email in ("real@example.com", "ghost@example.com"):
        statuses = [
            (await _login(client, email, password="wrong-password-123", headers=here)).status_code
            for _ in range(4)
        ]
        assert statuses == [401, 401, 401, 429], email

    # Refused before the password is looked at, right or wrong...
    assert (await _login(client, "real@example.com", headers=here)).status_code == 429
    # ...but only for that source. The account itself is not locked.
    assert (await _login(client, "real@example.com", headers=elsewhere)).status_code == 200


async def test_recovery_code_works_once(client, db_session, make_user, wide_source_limit):
    user, _ = await _enrolled_user(db_session, make_user, recovery=["a1b2-c3d4-e5f6", "0000-1111-2222"])
    assert (await _login(client, user.email, code="A1B2-C3D4-E5F6")).status_code == 200
    assert (await _login(client, user.email, code="a1b2-c3d4-e5f6")).status_code == 401
    await db_session.refresh(user)
    assert len(user.totp_recovery_hashes) == 1


async def test_wrong_digits_are_not_compared_with_the_recovery_hashes(
    client, db_session, make_user, monkeypatch, wide_source_limit
):
    """Every wrong six-digit code ran eight 600,000-round derivations, on the
    event loop. Only input shaped like a recovery code is compared now."""
    from app.api import auth

    user, secret = await _enrolled_user(db_session, make_user, recovery=["a1b2-c3d4-e5f6"])
    compared = []
    real = auth._matching_recovery_hash
    monkeypatch.setattr(
        auth, "_matching_recovery_hash", lambda code, hashes: compared.append(code) or real(code, hashes)
    )

    for junk in (_wrong(secret), "not-a-recovery-code", "zzzz-zzzz-zzzz", "a1b2c3d4e5f6"):
        assert (await _login(client, user.email, code=junk)).status_code == 401
    assert compared == []

    assert (await _login(client, user.email, code="a1b2-c3d4-e5f6")).status_code == 200
    assert compared == ["a1b2-c3d4-e5f6"]


async def test_change_password_stops_answering_after_repeated_wrong_guesses(
    client, auth_headers, monkeypatch
):
    monkeypatch.setattr(get_settings(), "LOGIN_SOURCE_FAILURE_LIMIT", 3)
    headers = await auth_headers(UserRole.VIEWER)
    body = {"current_password": "not-the-password", "new_password": "a-brand-new-password"}
    statuses = [
        (await client.post("/api/v1/auth/change-password", headers=headers, json=body)).status_code
        for _ in range(4)
    ]
    assert statuses == [401, 401, 401, 429]
    right = {"current_password": PASSWORD, "new_password": "a-brand-new-password"}
    assert (await client.post("/api/v1/auth/change-password", headers=headers, json=right)).status_code == 429


# --- emailed one-time codes -------------------------------------------------------

async def test_without_a_mail_provider_the_emailed_code_flows_refuse(client, make_user, db_session):
    await make_user(email="someone@example.com")
    capabilities = (await client.get("/api/v1/auth/capabilities")).json()
    assert capabilities == {
        "email_delivery": False, "self_registration": False, "password_reset": False, "mfa": True,
    }

    requests = [
        ("/api/v1/auth/register", {"email": "new@example.com", "password": "a-very-long-password"}),
        ("/api/v1/auth/resend-otp", {"email": "someone@example.com"}),
        ("/api/v1/auth/verify-otp", {"email": "someone@example.com", "otp_code": "123456"}),
        ("/api/v1/auth/request-password-reset", {"email": "someone@example.com"}),
        ("/api/v1/auth/reset-password",
         {"email": "someone@example.com", "otp_code": "123456", "new_password": "a-very-long-password"}),
    ]
    for path, body in requests:
        response = await client.post(path, json=body)
        assert response.status_code == 503, path

    # Nothing was created along the way: no stranded account, no live code.
    assert (await db_session.execute(select(User).where(User.email == "new@example.com"))).first() is None
    assert (await db_session.execute(select(OTPVerification))).first() is None


async def test_capabilities_follow_the_mail_provider(client, mail_outbox):
    capabilities = (await client.get("/api/v1/auth/capabilities")).json()
    assert capabilities["email_delivery"] and capabilities["self_registration"] and capabilities["password_reset"]


async def test_register_verify_and_reset_with_mail(client, mail_outbox):
    email = "newcomer@example.com"
    created = await client.post(
        "/api/v1/auth/register", json={"email": email, "password": "a-very-long-password"}
    )
    assert created.status_code == 201
    kind, to, code = mail_outbox[-1]
    assert (kind, to) == ("verification", email)

    assert (await client.post("/api/v1/auth/verify-otp", json={"email": email, "otp_code": code})).status_code == 200
    assert (await _login(client, email, password="a-very-long-password")).status_code == 200

    await client.post("/api/v1/auth/request-password-reset", json={"email": email})
    kind, to, reset_code = mail_outbox[-1]
    assert kind == "reset"
    reset = await client.post(
        "/api/v1/auth/reset-password",
        json={"email": email, "otp_code": reset_code, "new_password": "another-long-password"},
    )
    assert reset.status_code == 200
    assert (await _login(client, email, password="another-long-password")).status_code == 200


async def test_code_requests_are_capped_per_account_and_each_retires_the_last(
    client, make_user, mail_outbox, monkeypatch, db_session
):
    """Five guesses per code and unlimited fresh codes was unlimited guesses."""
    monkeypatch.setattr(get_settings(), "OTP_MAX_CODES_PER_HOUR", 3)
    user = await make_user(email="capped@example.com")
    for _ in range(6):
        response = await client.post("/api/v1/auth/request-password-reset", json={"email": user.email})
        # The answer never changes, capped or not.
        assert response.status_code == 200
        assert response.json()["message"].startswith("If an account exists")
    assert len(mail_outbox) == 3

    rows = (await db_session.execute(select(OTPVerification))).scalars().all()
    assert len(rows) == 3
    assert sorted(r.is_used for r in rows) == [False, True, True]

    # An earlier code no longer works; the latest does.
    stale = await client.post(
        "/api/v1/auth/reset-password",
        json={"email": user.email, "otp_code": mail_outbox[0][2], "new_password": "another-long-password"},
    )
    if mail_outbox[0][2] != mail_outbox[-1][2]:
        assert stale.status_code == 400


async def test_a_code_that_could_not_be_delivered_is_not_valid(
    client, make_user, mail_outbox, monkeypatch, db_session
):
    from app.services.email import email_service

    sent = []

    def failing_send(to_email, otp_code, user_name=""):
        sent.append(otp_code)
        return False

    monkeypatch.setattr(email_service, "send_password_reset_email", failing_send)
    user = await make_user(email="undelivered@example.com")
    await client.post("/api/v1/auth/request-password-reset", json={"email": user.email})
    assert len(sent) == 1

    reset = await client.post(
        "/api/v1/auth/reset-password",
        json={"email": user.email, "otp_code": sent[0], "new_password": "another-long-password"},
    )
    assert reset.status_code == 400
    assert (await _login(client, user.email)).status_code == 200  # password unchanged


async def test_code_failures_say_the_same_thing_for_every_address(client, make_user, mail_outbox):
    """"2 attempt(s) remaining" was only ever said about a real account."""
    user = await make_user(email="known@example.com")
    await client.post("/api/v1/auth/request-password-reset", json={"email": user.email})
    wrong = "000000" if mail_outbox[-1][2] != "000000" else "111111"

    answers = set()
    for email in (user.email, "unknown@example.com"):
        for _ in range(2):
            response = await client.post(
                "/api/v1/auth/reset-password",
                json={"email": email, "otp_code": wrong, "new_password": "another-long-password"},
            )
            answers.add((response.status_code, response.text))
    assert len(answers) == 1
