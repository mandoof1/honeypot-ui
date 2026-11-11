# Fingerprint audit: ssh

- Date (UTC): 2026-11-11T09:13:06Z
- Tool revision: fd2d146 (from GIT_REVISION)
- Decoy: 127.0.0.1:42222 - engine fd2d146 in a throwaway container, identity seed 8, node controlled-test-node
- Reference: 127.0.0.1:42022 - sshd-focal: service: sshd;os: Ubuntu 20.04.6 LTS;apt_archive: snapshot.ubuntu.com 20231115T000000Z (focal, focal-updates, focal-security);package: openssh-server 1:8.2p1-4ubuntu0.9;package: openssh-client 1:8.2p1-4ubuntu0.9;package: libssl1.1 1.1.1f-1ubuntu2.20;package: libpam-modules 1.3.1-5ubuntu4.6;config_sha256: /etc/ssh/sshd_config 180b7aff7eaf3d3223972dfdaef748f1e0c269b5b244628d711f2f981224f3cb;reports: OpenSSH_8.2p1 Ubuntu-4ubuntu0.9, OpenSSL 1.1.1f  31 Mar 2020;host_keys: ssh_host_ecdsa_key.pub ssh_host_ed25519_key.pub ssh_host_rsa_key.pub ;
- Network: both targets were reached at loopback addresses from the process that ran the audit, so both ran on the same machine
- Checks: 38, matching 26, differing 12
- Timing rows (informational): 3, outside tolerance 1


| Check | Comparison | Result | Similarity | Decoy | Reference |
|---|---|---|---|---|---|
| `ssh.ident.line` | exact | match | 1.00 | `SSH-2.0-OpenSSH_8.2p1 Ubuntu-4ubuntu0.9` | `SSH-2.0-OpenSSH_8.2p1 Ubuntu-4ubuntu0.9` |
| `ssh.ident.line_ending` | exact | match | 1.00 | `\r\n` | `\r\n` |
| `ssh.kexinit.kex_algorithms` | ordered | match | 1.00 | `curve25519-sha256, curve25519-sha256@libssh.org, ecdh-sha2-nistp256...` | `curve25519-sha256, curve25519-sha256@libssh.org, ecdh-sha2-nistp256...` |
| `ssh.kexinit.server_host_key_algorithms` | ordered | match | 1.00 | `rsa-sha2-512, rsa-sha2-256, ssh-rsa, ecdsa-sha2-nistp256, ssh-ed25519` | `rsa-sha2-512, rsa-sha2-256, ssh-rsa, ecdsa-sha2-nistp256, ssh-ed25519` |
| `ssh.kexinit.encryption_client_to_server` | ordered | match | 1.00 | `chacha20-poly1305@openssh.com, aes128-ctr, aes192-ctr, aes256-ctr, ...` | `chacha20-poly1305@openssh.com, aes128-ctr, aes192-ctr, aes256-ctr, ...` |
| `ssh.kexinit.encryption_server_to_client` | ordered | match | 1.00 | `chacha20-poly1305@openssh.com, aes128-ctr, aes192-ctr, aes256-ctr, ...` | `chacha20-poly1305@openssh.com, aes128-ctr, aes192-ctr, aes256-ctr, ...` |
| `ssh.kexinit.mac_client_to_server` | ordered | match | 1.00 | `umac-64-etm@openssh.com, umac-128-etm@openssh.com, hmac-sha2-256-et...` | `umac-64-etm@openssh.com, umac-128-etm@openssh.com, hmac-sha2-256-et...` |
| `ssh.kexinit.mac_server_to_client` | ordered | match | 1.00 | `umac-64-etm@openssh.com, umac-128-etm@openssh.com, hmac-sha2-256-et...` | `umac-64-etm@openssh.com, umac-128-etm@openssh.com, hmac-sha2-256-et...` |
| `ssh.kexinit.compression_client_to_server` | ordered | match | 1.00 | `none, zlib@openssh.com` | `none, zlib@openssh.com` |
| `ssh.kexinit.compression_server_to_client` | ordered | match | 1.00 | `none, zlib@openssh.com` | `none, zlib@openssh.com` |
| `ssh.kexinit.languages` | exact | match | 1.00 | `[[], []]` | `[[], []]` |
| `ssh.kexinit.first_kex_packet_follows` | exact | match | 1.00 | `{"first_kex_packet_follows": false, "reserved": 0}` | `{"first_kex_packet_follows": false, "reserved": 0}` |
| `ssh.kexinit.padding` | exact | MISMATCH | 0.67 | `{"packet_is_multiple_of_8": true, "padding_is_minimum": true, "padd...` | `{"packet_is_multiple_of_8": true, "padding_is_minimum": true, "padd...` |
| `ssh.kexinit.hassh_server` | exact | match | 1.00 | `3ccd1778a76049721c71ad7d2bf62bbc` | `3ccd1778a76049721c71ad7d2bf62bbc` |
| `ssh.kexinit.unprompted_packets` | ordered | match | 1.00 | `SSH_MSG_KEXINIT` | `SSH_MSG_KEXINIT` |
| `ssh.ident_reply.no_software_version.response` | bytes | MISMATCH | 0.00 | ` (0 bytes)` | `Invalid SSH identification string.\r\n (36 bytes)` |
| `ssh.ident_reply.no_software_version.closes` | exact | match | 1.00 | `true` | `true` |
| `ssh.ident_reply.protocol_1.response` | bytes | MISMATCH | 0.00 | ` (0 bytes)` | `Protocol major versions differ.\r\n (33 bytes)` |
| `ssh.ident_reply.protocol_1.closes` | exact | match | 1.00 | `true` | `true` |
| `ssh.ident_reply.over_255_bytes.response` | bytes | MISMATCH | 0.00 | ` (0 bytes)` | `\x00\x00\x04\x1c\n\x14\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\...` |
| `ssh.ident_reply.over_255_bytes.closes` | exact | MISMATCH | 0.00 | `true` | `false` |
| `ssh.ident_reply.over_8192_bytes.response` | bytes | MISMATCH | 0.00 | ` (0 bytes)` | `Invalid SSH identification string. (34 bytes)` |
| `ssh.ident_reply.over_8192_bytes.closes` | exact | match | 1.00 | `true` | `true` |
| `ssh.ident_reply.http_request.response` | bytes | MISMATCH | 0.00 | ` (0 bytes)` | `Invalid SSH identification string. (34 bytes)` |
| `ssh.ident_reply.http_request.closes` | exact | match | 1.00 | `true` | `true` |
| `ssh.packet_reply.bad_length.response` | bytes | match | 1.00 | ` (0 bytes)` | ` (0 bytes)` |
| `ssh.packet_reply.bad_length.closes` | exact | MISMATCH | 0.00 | `false` | `true` |
| `ssh.packet_reply.unknown_message.response` | bytes | MISMATCH | 0.91 | `\x00\x00\x00L\t\x01\x00\x00\x00\x02\x00\x00\x000Invalid request bef...` | `\x00\x00\x004\t\x01\x00\x00\x00\x02\x00\x00\x00\x1dInvalid ssh2 pac...` |
| `ssh.packet_reply.unknown_message.closes` | exact | match | 1.00 | `true` | `true` |
| `ssh.silent.response` | bytes | match | 1.00 | `SSH-2.0-OpenSSH_8.2p1 Ubuntu-4ubuntu0.9\r\n (41 bytes)` | `SSH-2.0-OpenSSH_8.2p1 Ubuntu-4ubuntu0.9\r\n (41 bytes)` |
| `ssh.silent.closes_within_cap` | exact | match | 1.00 | `false` | `false` |
| `ssh.silent.banner_delay` | timing | within tolerance | 0.20 | `0.001` | `0.005` |
| `ssh.silent.disconnect_after` | timing | within tolerance | 1.00 | `null` | `null` |
| `ssh.auth.methods.root` | ordered | match | 1.00 | `publickey, password` | `publickey, password` |
| `ssh.auth.methods.unknown_user` | ordered | match | 1.00 | `publickey, password` | `publickey, password` |
| `ssh.auth.banner` | exact | match | 1.00 | `null` | `null` |
| `ssh.transport.negotiated` | exact | match | 1.00 | `{"key_exchange": "curve25519-sha256", "client_to_server_cipher": "c...` | `{"key_exchange": "curve25519-sha256", "client_to_server_cipher": "c...` |
| `ssh.ext_info.server_sig_algs` | ordered | MISMATCH | 0.14 | `rsa-sha2-256, rsa-sha2-512, ssh-rsa-sha224@ssh.com, ssh-rsa-sha256@...` | `ssh-ed25519, sk-ssh-ed25519@openssh.com, ssh-rsa, rsa-sha2-256, rsa...` |
| `ssh.auth.password.root` | exact | MISMATCH | 0.67 | `{"outcome": "accepted", "wrong_passwords_sent": 4, "disconnect": null}` | `{"outcome": "timeout", "wrong_passwords_sent": 4, "disconnect": null}` |
| `ssh.auth.password.unknown_user` | exact | MISMATCH | 0.00 | `{"outcome": "disconnected", "wrong_passwords_sent": 6, "disconnect"...` | `{"outcome": "timeout", "wrong_passwords_sent": 4, "disconnect": null}` |
| `ssh.auth.failed_password_delay` | timing | outside tolerance | 0.00 | `0.001` | `2.175` |
