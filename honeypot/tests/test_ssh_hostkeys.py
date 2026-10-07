"""The KEXINIT host-key name-list must read like OpenSSH, not asyncssh.

asyncssh derives the advertised server host-key algorithms from the RSA
keypair's signature algorithms, which include ``ssh-rsa-sha256@ssh.com`` and
three more ``@ssh.com`` names that no OpenSSH has ever offered. That list is
sent in the same packet the transport profile exists to make honest, so it is
read off the wire here rather than trusted from configuration.
"""

import asyncio
import struct

import asyncssh
import pytest

from honeypot.adaptive.ssh_profile import (
    apply_extra_kex_algs,
    apply_host_key_algs,
    get_profile,
)

PORT = 24710


def _host_key_list(payload: bytes) -> list[str]:
    assert payload[0] == 20, "expected SSH_MSG_KEXINIT"
    offset = 17
    lists = []
    for _ in range(10):
        (length,) = struct.unpack(">I", payload[offset:offset + 4])
        offset += 4
        lists.append(payload[offset:offset + length].decode())
        offset += length
    return lists[1].split(",")  # second name-list is server host key algs


@pytest.fixture
async def listener():
    profile = get_profile("openssh-8.2p1-ubuntu")
    apply_extra_kex_algs(profile)
    apply_host_key_algs(profile)

    async def handler(process):
        process.exit(0)

    keys = [
        asyncssh.generate_private_key("ssh-ed25519"),
        asyncssh.generate_private_key("ssh-rsa", key_size=3072),
        asyncssh.generate_private_key("ecdsa-sha2-nistp256"),
    ]
    acceptor = await asyncssh.listen(
        "127.0.0.1", PORT,
        server_factory=asyncssh.SSHServer,
        server_host_keys=keys,
        process_factory=handler,
        server_version=profile.version_string,
        kex_algs=profile.kex_algs,
        encryption_algs=profile.encryption_algs,
        mac_algs=profile.mac_algs,
        compression_algs=profile.compression_algs,
        encoding=None,
    )
    try:
        yield PORT, profile
    finally:
        acceptor.close()
        await acceptor.wait_closed()


async def test_no_ssh_dot_com_names_leak(listener):
    port, _ = listener
    reader, writer = await asyncio.open_connection("127.0.0.1", port)
    try:
        await reader.readline()
        writer.write(b"SSH-2.0-OpenSSH_8.2p1 Ubuntu-4ubuntu0.9\r\n")
        await writer.drain()
        (length,) = struct.unpack(">I", await reader.readexactly(4))
        rest = await reader.readexactly(length)
        host_keys = _host_key_list(rest[1:len(rest) - rest[0]])
    finally:
        writer.close()
    assert not any("@ssh.com" in alg for alg in host_keys)


async def test_host_key_list_is_the_openssh_order(listener):
    port, profile = listener
    reader, writer = await asyncio.open_connection("127.0.0.1", port)
    try:
        await reader.readline()
        writer.write(b"SSH-2.0-OpenSSH_8.2p1 Ubuntu-4ubuntu0.9\r\n")
        await writer.drain()
        (length,) = struct.unpack(">I", await reader.readexactly(4))
        rest = await reader.readexactly(length)
        host_keys = _host_key_list(rest[1:len(rest) - rest[0]])
    finally:
        writer.close()
    assert host_keys == list(profile.host_key_algs)
