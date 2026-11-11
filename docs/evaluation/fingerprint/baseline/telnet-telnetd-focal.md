# Fingerprint audit: telnet

- Date (UTC): 2026-11-11T09:21:25Z
- Tool revision: fd2d146 (from GIT_REVISION)
- Decoy: 127.0.0.1:42323 - engine fd2d146 in a throwaway container, identity seed 8, node controlled-test-node
- Reference: 127.0.0.1:42123 - telnetd-focal: service: telnetd;os: Ubuntu 20.04.6 LTS;apt_archive: snapshot.ubuntu.com 20231115T000000Z (focal, focal-updates, focal-security);package: telnetd 0.17-41.2build1;package: openbsd-inetd 0.20160825-4build1;package: netbase 6.1;package: login 1:4.8.1-1ubuntu5.20.04.4;package: base-files 11ubuntu5.7;config_sha256: /etc/inetd.conf 1e73506cfe8176f50b1b347366cc77e915c1ff1cade35e4f43ebb33639c84fb0;config_sha256: /etc/issue.net d7fef0db871cc555bbd009590ef8acc043d14e082329942adc9568294f522ecf;reports: inetd runs telnet stream tcp nowait telnetd /usr/sbin/tcpd /usr/sbin/in.telnetd;
- Network: both targets were reached at loopback addresses from the process that ran the audit, so both ran on the same machine
- Checks: 10, matching 3, differing 7
- Timing rows (informational): 2, outside tolerance 1


| Check | Comparison | Result | Similarity | Decoy | Reference |
|---|---|---|---|---|---|
| `telnet.silent.negotiation` | ordered | MISMATCH | 0.00 | `WILL ECHO, WILL SUPPRESS-GO-AHEAD, DO SUPPRESS-GO-AHEAD` | `DO TERMINAL-TYPE, DO TERMINAL-SPEED, DO X-DISPLAY-LOCATION, DO NEW-...` |
| `telnet.silent.text` | bytes | MISMATCH | 0.00 | `\r\nUbuntu 20.04.6 LTS\r\n<hostname> login:  (40 bytes)` | ` (0 bytes)` |
| `telnet.silent.first_byte_delay` | timing | within tolerance | 0.33 | `0.001` | `0.003` |
| `telnet.refusing.negotiation` | ordered | MISMATCH | 0.13 | `WILL ECHO, WILL SUPPRESS-GO-AHEAD, DO SUPPRESS-GO-AHEAD, DONT SUPPR...` | `DO TERMINAL-TYPE, DO TERMINAL-SPEED, DO X-DISPLAY-LOCATION, DO NEW-...` |
| `telnet.refusing.login_banner` | bytes | MISMATCH | 0.99 | `\r\nUbuntu 20.04.6 LTS\r\n<hostname> login:  (40 bytes)` | `Ubuntu 20.04.6 LTS\r\n<hostname> login:  (38 bytes)` |
| `telnet.option.client_will_unknown` | exact | match | 1.00 | `{"commands": ["DONT OPTION-99"], "text": ""}` | `{"commands": ["DONT OPTION-99"], "text": ""}` |
| `telnet.option.client_do_unknown` | exact | match | 1.00 | `{"commands": ["WONT OPTION-99"], "text": ""}` | `{"commands": ["WONT OPTION-99"], "text": ""}` |
| `telnet.login.after_username` | bytes | MISMATCH | 0.85 | `Password:  (10 bytes)` | `root\r\nPassword:  (16 bytes)` |
| `telnet.login.after_wrong_password` | bytes | match | 1.00 | `\r\n\r\nLogin incorrect\r\n<hostname> login:  (39 bytes)` | `\r\n\r\nLogin incorrect\r\n<hostname> login:  (39 bytes)` |
| `telnet.login.failed_login_delay` | timing | outside tolerance | 0.35 | `1.003` | `2.885` |
| `telnet.login.wrong_passwords.root` | exact | MISMATCH | 0.00 | `{"wrong_passwords_sent": 4, "ended": "logged-in"}` | `{"wrong_passwords_sent": 5, "ended": "closed-by-server"}` |
| `telnet.login.wrong_passwords.unknown_user` | exact | MISMATCH | 0.50 | `{"wrong_passwords_sent": 6, "ended": "closed-by-server"}` | `{"wrong_passwords_sent": 5, "ended": "closed-by-server"}` |
