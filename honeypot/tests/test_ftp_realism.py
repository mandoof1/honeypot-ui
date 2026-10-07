"""The FTP decoy checks the password and answers consistently.

The password used to be ignored — any password for a known user was accepted
on the first try, which is a fingerprint — and sizes and dates were random on
every call, so two listings of the same file disagreed.
"""

import pytest

from honeypot.core.config import config
from honeypot.core.identity import reset_identity
from honeypot.emulators.ftp import FTPHoneypot, FTPSessionState, _stable_meta


@pytest.fixture(autouse=True)
def _capture_dir(tmp_path, monkeypatch):
    monkeypatch.setattr(config, "session_capture_dir", str(tmp_path / "cap"))
    monkeypatch.setattr(config, "enable_anti_fingerprinting", True)
    reset_identity()
    yield
    reset_identity()


@pytest.fixture
def ftp():
    return FTPHoneypot()


async def test_anonymous_accepts_any_password(ftp):
    state = FTPSessionState()
    ftp._cmd_user("anonymous", state)
    reply = await ftp._cmd_pass("anything@example.com", state, "sess")
    assert reply.startswith("230")
    assert state.authenticated


async def test_a_named_user_with_the_wrong_password_is_refused(ftp):
    state = FTPSessionState()
    ftp._cmd_user("admin", state)
    reply = await ftp._cmd_pass("not-the-password", state, "sess")
    assert reply.startswith("530")
    assert not state.authenticated


async def test_a_named_user_with_the_weak_password_gets_in(ftp):
    state = FTPSessionState()
    ftp._cmd_user("admin", state)
    reply = await ftp._cmd_pass("admin", state, "sess")
    assert reply.startswith("230")


async def test_brute_force_is_soft_accepted_after_several_tries(ftp):
    state = FTPSessionState()
    ftp._cmd_user("admin", state)
    for _ in range(3):
        await ftp._cmd_pass("wrong", state, "sess")
    reply = await ftp._cmd_pass("still-wrong", state, "sess")
    assert reply.startswith("230")


def test_listing_sizes_are_stable(ftp):
    state = FTPSessionState()
    first = ftp._listing("", state, names_only=False)
    second = ftp._listing("", state, names_only=False)
    assert first == second


def test_size_matches_the_listing(ftp):
    state = FTPSessionState()
    # readme.txt is in the root fake tree.
    size, _ = _stable_meta("/readme.txt")
    reply = ftp._cmd_size("readme.txt", state)
    assert reply.strip() == f"213 {size}"


def test_stat_reports_the_identity_address_not_zero(ftp):
    state = FTPSessionState()
    state.username = "anonymous"
    reply = ftp._cmd_stat(state)
    assert "Connected to 0.0.0.0" not in reply
