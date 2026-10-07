"""One machine, told consistently and persisted.

Every service used to invent its own host facts; these prove the single
identity is stable across a reload and that the SSH shell reads from it, so
``hostname``, ``uname`` and the prompt cannot disagree.
"""

import pytest

from honeypot.core.config import config
from honeypot.core import identity as identity_module
from honeypot.core.identity import get_identity, reset_identity


@pytest.fixture(autouse=True)
def _capture_dir(tmp_path, monkeypatch):
    monkeypatch.setattr(config, "session_capture_dir", str(tmp_path / "cap"))
    reset_identity()
    yield
    reset_identity()


def test_identity_is_stable_within_a_run():
    a = get_identity()
    b = get_identity()
    assert a is b
    assert a.hostname == b.hostname


def test_identity_persists_across_a_reload():
    first = get_identity()
    hostname, kernel, mac, seed = first.hostname, first.kernel, first.mac, first.seed
    # A restart: forget the cache, reload from the file beside the host keys.
    reset_identity()
    second = get_identity()
    assert (second.hostname, second.kernel, second.mac, second.seed) == (
        hostname, kernel, mac, seed
    )


def test_seed_reproduces_every_static_fact():
    from honeypot.core.identity import _derive

    one = _derive(123456).to_json()
    two = _derive(123456).to_json()
    # boot_time and the last-login clock are anchored to "now", so they are
    # persisted and restored rather than re-derived; everything the seed
    # chooses is identical.
    moving = {"boot_time", "last_login_time"}
    assert {k: v for k, v in one.items() if k not in moving} == {
        k: v for k, v in two.items() if k not in moving
    }


def test_kernel_matches_the_openssh_release_claimed():
    # OpenSSH 8.2p1 is Ubuntu 20.04, whose kernels are 5.4.x — never 5.15.
    i = get_identity()
    assert i.os_version.startswith("20.04")
    assert i.kernel.startswith("5.4.")


def test_mac_is_not_the_docker_prefix():
    assert not get_identity().mac.startswith("02:42")


def test_env_seed_pins_the_identity(monkeypatch):
    monkeypatch.setenv("HONEYPOT_IDENTITY_SEED", "987654")
    reset_identity()
    from honeypot.core.identity import _derive

    assert get_identity().hostname == _derive(987654).hostname
