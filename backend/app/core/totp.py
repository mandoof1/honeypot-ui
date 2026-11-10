"""Time-based one-time passwords — RFC 6238.

Audit finding 9. The report lists MFA among the implemented Protect controls
in Tables III, VI and VIII. Login checked an email address and a password and
nothing else. The OTP machinery that existed served email verification at
signup and password reset — one-time account actions, not a second factor at
authentication.

TOTP rather than emailed codes, for a reason specific to this deployment:
SMTP is not configured, so an emailed second factor would lock every account
out the moment it was enforced. An authenticator app needs no delivery channel
at all, which makes this the one form of MFA that can actually be turned on
here.

Implemented against the RFC directly rather than adding a dependency — the
algorithm is HMAC-SHA1 over a counter, and the engine's dependency surface is
already carrying asyncssh for a reason it could not avoid.

The shared secret is stored encrypted at rest with the same AES-256-GCM used
for captured commands. A plaintext TOTP secret in the database is equivalent
to no second factor at all against anyone who reaches the database.
"""

from __future__ import annotations

import base64
import hashlib
import hmac
import secrets
import struct
import time
import urllib.parse

#: RFC 6238 defaults, and what every authenticator app assumes.
DIGITS = 6
PERIOD = 30

#: Steps either side of now that are accepted, to tolerate clock drift between
#: the server and the user's phone. One step each way is the usual compromise:
#: it forgives ~30s of skew while keeping the window a code is valid short.
DRIFT_STEPS = 1


def generate_secret() -> str:
    """A fresh base32 secret. 160 bits, as RFC 4226 recommends."""
    return base64.b32encode(secrets.token_bytes(20)).decode("ascii").rstrip("=")


def _code_at(secret: str, counter: int) -> str:
    key = base64.b32decode(secret + "=" * (-len(secret) % 8), casefold=True)
    digest = hmac.new(key, struct.pack(">Q", counter), hashlib.sha1).digest()
    # Dynamic truncation, RFC 4226 §5.3.
    offset = digest[-1] & 0x0F
    value = struct.unpack(">I", digest[offset:offset + 4])[0] & 0x7FFFFFFF
    return str(value % (10 ** DIGITS)).zfill(DIGITS)


def current_code(secret: str, at: float | None = None) -> str:
    return _code_at(secret, int((at if at is not None else time.time()) // PERIOD))


def matching_step(secret: str, code: str, at: float | None = None) -> int | None:
    """The time step a submitted code is valid for, or None if it is not.

    Clock drift is allowed for: the steps either side of now are tried too.
    Returning the step, rather than only yes or no, is what lets the caller
    refuse a code that has already been used: it records the step it
    accepted and turns away that step and any earlier one afterwards.

    Compared with ``compare_digest``: a plain ``==`` on a six-digit code leaks
    timing information, and six digits is a small enough space that it is
    worth not helping. Every candidate step is compared, match or not, for
    the same reason.
    """
    if not secret or not code:
        return None
    code = code.strip().replace(" ", "")
    if not code.isdigit() or len(code) != DIGITS:
        return None

    counter = int((at if at is not None else time.time()) // PERIOD)
    matched = None
    for step in range(-DRIFT_STEPS, DRIFT_STEPS + 1):
        try:
            expected = _code_at(secret, counter + step)
        except (ValueError, struct.error):
            # A secret that is not valid base32, or a time before the epoch.
            return None
        if hmac.compare_digest(expected, code) and matched is None:
            matched = counter + step
    return matched


def verify(secret: str, code: str, at: float | None = None) -> bool:
    """Whether a submitted code is currently valid. See ``matching_step``."""
    return matching_step(secret, code, at) is not None


def provisioning_uri(secret: str, email: str, issuer: str = "HoneySentinel") -> str:
    """otpauth:// URI for an authenticator app to scan as a QR code."""
    label = urllib.parse.quote(f"{issuer}:{email}")
    params = urllib.parse.urlencode({
        "secret": secret,
        "issuer": issuer,
        "algorithm": "SHA1",
        "digits": DIGITS,
        "period": PERIOD,
    })
    return f"otpauth://totp/{label}?{params}"


def generate_recovery_codes(count: int = 8) -> list[str]:
    """Single-use codes for a lost authenticator.

    Without these, enrolling in MFA is a way to lose an account permanently —
    which matters more here than usual, because password reset depends on
    email and email is not configured.
    """
    return [
        f"{secrets.token_hex(2)}-{secrets.token_hex(2)}-{secrets.token_hex(2)}"
        for _ in range(count)
    ]
