"""Encryption at rest for captured attacker commands and payloads.

AES-256-GCM. The report specifies AES-256 for data at rest; the previous
implementation used Fernet, which is AES-**128**-CBC with an HMAC tag, so the
documented control and the shipped one disagreed by a factor of two in key
length. GCM also gives authenticated encryption in one primitive rather than
encrypt-then-MAC composed by the library.

Stored form is ``v2:<base64(nonce || ciphertext || tag)>``. The version prefix
exists so a future key or cipher change is unambiguous rather than guessed at
by probing, and so Fernet blobs written by earlier builds can still be read.
"""

from __future__ import annotations

import base64
import hashlib
import os
from functools import lru_cache

from cryptography.exceptions import InvalidTag
from cryptography.fernet import Fernet, InvalidToken
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

from app.core.config import get_settings

#: Marks a payload written by this module. Anything without it is treated as a
#: legacy Fernet blob.
_PREFIX = "v2:"

#: 96 bits is the nonce size GCM is specified and optimised for.
_NONCE_BYTES = 12


@lru_cache(maxsize=1)
def _key() -> bytes:
    """Derive a 256-bit key from the configured secret.

    SHA-256 gives a full-width key from any input length. An earlier version
    space-padded the raw setting to 32 bytes, so a short secret produced a
    mostly-constant key whose padding contributed no entropy at all.
    """
    return hashlib.sha256(get_settings().ENCRYPTION_KEY.encode()).digest()


@lru_cache(maxsize=1)
def _legacy_fernet() -> Fernet:
    """Reader for blobs written before the move to AES-256-GCM."""
    return Fernet(base64.urlsafe_b64encode(_key()))


def encrypt_data(data: str) -> str:
    # A fresh random nonce per message. Reusing one under the same key is the
    # single catastrophic failure mode of GCM, so it is never derived from the
    # plaintext or a counter held in application state.
    nonce = os.urandom(_NONCE_BYTES)
    sealed = AESGCM(_key()).encrypt(nonce, data.encode(), None)
    return _PREFIX + base64.b64encode(nonce + sealed).decode()


def decrypt_data(encrypted_data: str) -> str:
    """Decrypt a stored blob.

    Raises ValueError rather than the library's exception types so callers do
    not have to import cryptography to handle a rotated key.
    """
    if encrypted_data.startswith(_PREFIX):
        raw = base64.b64decode(encrypted_data[len(_PREFIX):])
        nonce, sealed = raw[:_NONCE_BYTES], raw[_NONCE_BYTES:]
        try:
            return AESGCM(_key()).decrypt(nonce, sealed, None).decode()
        except InvalidTag as exc:
            raise ValueError(
                "Could not decrypt stored data; ENCRYPTION_KEY may have "
                "changed, or the record was tampered with"
            ) from exc

    try:
        return _legacy_fernet().decrypt(encrypted_data.encode()).decode()
    except InvalidToken as exc:
        raise ValueError(
            "Could not decrypt stored data; ENCRYPTION_KEY may have changed"
        ) from exc


def encrypt_bytes(data: bytes) -> str:
    """Encrypt binary content, such as a captured payload sample.

    ``encrypt_data`` takes text, so a binary would need base64 before
    encryption and again after — roughly 1.8x its size at rest. This seals the
    bytes directly, in the same ``v2:`` format.
    """
    nonce = os.urandom(_NONCE_BYTES)
    sealed = AESGCM(_key()).encrypt(nonce, data, None)
    return _PREFIX + base64.b64encode(nonce + sealed).decode()


def decrypt_bytes(encrypted_data: str) -> bytes:
    if not encrypted_data.startswith(_PREFIX):
        raise ValueError("Not an AES-256-GCM blob")
    raw = base64.b64decode(encrypted_data[len(_PREFIX):])
    nonce, sealed = raw[:_NONCE_BYTES], raw[_NONCE_BYTES:]
    try:
        return AESGCM(_key()).decrypt(nonce, sealed, None)
    except InvalidTag as exc:
        raise ValueError(
            "Could not decrypt stored data; ENCRYPTION_KEY may have "
            "changed, or the record was tampered with"
        ) from exc
