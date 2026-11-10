"""Encryption at rest for captured attacker commands and payloads.

AES-256-GCM. The report specifies AES-256 for data at rest; the previous
implementation used Fernet, which is AES-**128**-CBC with an HMAC tag, so the
documented control and the shipped one disagreed by a factor of two in key
length. GCM also gives authenticated encryption in one primitive rather than
encrypt-then-MAC composed by the library.

Stored form, current: ``v3:<key id>:<context>:<base64(nonce || ciphertext || tag)>``

* ``key id`` names the key the blob was sealed under (eight hex characters
  derived from the key, not secret). It is what makes rotation possible:
  ENCRYPTION_KEY can change while ENCRYPTION_KEY_PREVIOUS still opens older
  rows, each blob says which key it needs, and ``app.core.rotate_key`` can
  tell which rows are left to re-encrypt.
* ``context`` is an optional label for where the blob belongs, such as
  ``session:412:credentials``, URL-safe base64. It is authenticated with the
  ciphertext, so it cannot be edited, and a reader that passes the context it
  expects refuses a blob that was copied in from another row or column.
  Without it, anyone able to write to the database could move a session's
  admin-only credentials blob into its analyst-readable transcript column.

Still readable: ``v2:<base64(...)>`` (one key, no key id, no context) written
by earlier builds, and the Fernet blobs from before that. Both are tried
against the current key and then each previous key.
"""

from __future__ import annotations

import base64
import binascii
import hashlib
import os
from functools import lru_cache
from typing import Optional

from cryptography.exceptions import InvalidTag
from cryptography.fernet import Fernet, InvalidToken
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

from app.core.config import get_settings

#: Current format. Anything else is read through the legacy paths below.
_PREFIX = "v3:"
#: AES-256-GCM with a single key and no key id or context.
_PREFIX_V2 = "v2:"

#: 96 bits is the nonce size GCM is specified and optimised for.
_NONCE_BYTES = 12

_WRONG_KEY = (
    "Could not decrypt stored data; ENCRYPTION_KEY may have changed, or the "
    "record was tampered with"
)


class ContextMismatch(ValueError):
    """A blob was presented for a row or column it was not sealed for."""


def _derive(secret: str) -> bytes:
    """A 256-bit key from a configured secret.

    SHA-256 gives a full-width key from any input length. An earlier version
    space-padded the raw setting to 32 bytes, so a short secret produced a
    mostly-constant key whose padding contributed no entropy at all.
    """
    return hashlib.sha256(secret.encode()).digest()


def _key_id(key: bytes) -> str:
    """A short public name for a key, so a blob can say which one sealed it."""
    return hashlib.sha256(b"honeysentinel:key-id:" + key).hexdigest()[:8]


@lru_cache(maxsize=4)
def _build_keyring(current: str, previous: tuple) -> tuple:
    """((key id, key), ...) with the current key first."""
    ring = []
    seen = set()
    for secret in (current, *previous):
        key = _derive(secret)
        if key in seen:
            continue
        seen.add(key)
        ring.append((_key_id(key), key))
    return tuple(ring)


def _keyring() -> tuple:
    settings = get_settings()
    return _build_keyring(
        settings.ENCRYPTION_KEY, tuple(settings.previous_encryption_keys)
    )


def current_key_id() -> str:
    return _keyring()[0][0]


def _context_field(context: Optional[str]) -> str:
    if not context:
        return ""
    return base64.urlsafe_b64encode(context.encode()).decode().rstrip("=")


def _context_from_field(field: str) -> Optional[str]:
    if not field:
        return None
    try:
        padded = field + "=" * (-len(field) % 4)
        return base64.urlsafe_b64decode(padded.encode()).decode()
    except (binascii.Error, ValueError, UnicodeDecodeError) as exc:
        raise ValueError("Stored data has a malformed context label") from exc


def _associated_data(key_id: str, context_field: str) -> bytes:
    # The header travels outside the ciphertext, so it is authenticated with
    # it: editing the key id or the context label breaks the tag.
    return f"{_PREFIX}{key_id}:{context_field}".encode()


def _seal(data: bytes, context: Optional[str]) -> str:
    key_id, key = _keyring()[0]
    field = _context_field(context)
    # A fresh random nonce per message. Reusing one under the same key is the
    # single catastrophic failure mode of GCM, so it is never derived from the
    # plaintext or a counter held in application state.
    nonce = os.urandom(_NONCE_BYTES)
    sealed = AESGCM(key).encrypt(nonce, data, _associated_data(key_id, field))
    payload = base64.b64encode(nonce + sealed).decode()
    return f"{_PREFIX}{key_id}:{field}:{payload}"


def _split_v3(blob: str) -> tuple:
    try:
        _, key_id, field, payload = blob.split(":", 3)
    except ValueError as exc:
        raise ValueError("Stored data is not in a recognised format") from exc
    return key_id, field, payload


def _decode_payload(payload: str) -> tuple:
    try:
        raw = base64.b64decode(payload, validate=True)
    except (binascii.Error, ValueError) as exc:
        raise ValueError("Stored data is not valid base64") from exc
    if len(raw) <= _NONCE_BYTES:
        raise ValueError("Stored data is too short to be a sealed record")
    return raw[:_NONCE_BYTES], raw[_NONCE_BYTES:]


def _require_context() -> bool:
    """Whether an unbound blob is refused where a binding is expected.

    Off by default, because rows written before binding existed are unbound
    and must stay readable until `python -m app.core.rotate_key` has re-sealed
    them. Until it is on, an unbound blob still opens anywhere; new rows are
    bound at ingest either way.
    """
    return bool(getattr(get_settings(), "ENCRYPTION_REQUIRE_CONTEXT", False))


def _open_v3(blob: str, context: Optional[str]) -> bytes:
    key_id, field, payload = _split_v3(blob)
    stored_context = _context_from_field(field)
    if context is not None and stored_context is not None and stored_context != context:
        raise ContextMismatch(
            "Stored data was sealed for a different record and was not opened"
        )
    if context is not None and stored_context is None and _require_context():
        raise ContextMismatch(
            "Stored data is not bound to a record; run `python -m app.core.rotate_key` "
            "to bind what was written before binding existed"
        )
    nonce, sealed = _decode_payload(payload)
    for candidate_id, key in _keyring():
        if candidate_id != key_id:
            continue
        try:
            return AESGCM(key).decrypt(nonce, sealed, _associated_data(key_id, field))
        except InvalidTag as exc:
            raise ValueError(_WRONG_KEY) from exc
    raise ValueError(
        f"Stored data was encrypted under key {key_id}, which this deployment "
        "no longer has; add it to ENCRYPTION_KEY_PREVIOUS"
    )


def _open_v2(blob: str) -> bytes:
    nonce, sealed = _decode_payload(blob[len(_PREFIX_V2):])
    for _, key in _keyring():
        try:
            return AESGCM(key).decrypt(nonce, sealed, None)
        except InvalidTag:
            continue
    raise ValueError(_WRONG_KEY)


def _open_fernet(blob: str) -> bytes:
    """Reader for blobs written before the move to AES-256-GCM."""
    for _, key in _keyring():
        try:
            return Fernet(base64.urlsafe_b64encode(key)).decrypt(blob.encode())
        except InvalidToken:
            continue
    raise ValueError("Could not decrypt stored data; ENCRYPTION_KEY may have changed")


def _open(blob: str, context: Optional[str], allow_fernet: bool) -> bytes:
    if blob.startswith(_PREFIX):
        return _open_v3(blob, context)
    if context is not None and _require_context():
        # The older formats cannot carry a binding at all.
        raise ContextMismatch(
            "Stored data is not bound to a record; run `python -m app.core.rotate_key` "
            "to bind what was written before binding existed"
        )
    if blob.startswith(_PREFIX_V2):
        return _open_v2(blob)
    if allow_fernet:
        return _open_fernet(blob)
    raise ValueError("Not an AES-256-GCM blob")


def encrypt_data(data: str, context: Optional[str] = None) -> str:
    """Encrypt text. ``context`` binds the result to a row and column."""
    return _seal(data.encode(), context)


def decrypt_data(encrypted_data: str, context: Optional[str] = None) -> str:
    """Decrypt a stored blob.

    Raises ValueError rather than the library's exception types so callers do
    not have to import cryptography to handle a rotated key. When ``context``
    is given and the blob carries one, the two must match (ContextMismatch,
    a ValueError, otherwise). A blob written before contexts existed carries
    none and is opened as before.
    """
    return _open(encrypted_data, context, allow_fernet=True).decode()


def encrypt_bytes(data: bytes, context: Optional[str] = None) -> str:
    """Encrypt binary content, such as a captured payload sample.

    ``encrypt_data`` takes text, so a binary would need base64 before
    encryption and again after — roughly 1.8x its size at rest. This seals the
    bytes directly, in the same format.
    """
    return _seal(data, context)


def decrypt_bytes(encrypted_data: str, context: Optional[str] = None) -> bytes:
    return _open(encrypted_data, context, allow_fernet=False)


def blob_context(encrypted_data: str) -> Optional[str]:
    """The context label a blob was sealed with, if it has one."""
    if not encrypted_data.startswith(_PREFIX):
        return None
    return _context_from_field(_split_v3(encrypted_data)[1])


def needs_rotation(encrypted_data: str, context: Optional[str] = None) -> bool:
    """Whether a blob should be re-encrypted by ``app.core.rotate_key``.

    True for anything not in the current format, not under the current key,
    or (when ``context`` is given) not yet bound to that context.
    """
    if not encrypted_data.startswith(_PREFIX):
        return True
    key_id, field, _ = _split_v3(encrypted_data)
    if key_id != current_key_id():
        return True
    return context is not None and _context_from_field(field) != context


# Context labels, kept in one place so writers, readers and the rotation
# command cannot drift apart.

def session_context(session_id: int, column: str) -> str:
    return f"session:{session_id}:{column}"


def payload_context(sha256: str) -> str:
    return f"payload:{sha256}"


def totp_context(user_id: int) -> str:
    return f"totp:{user_id}"
