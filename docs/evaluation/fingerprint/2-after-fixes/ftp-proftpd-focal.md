# Fingerprint audit: ftp

- Date (UTC): 2026-11-11T12:01:39Z
- Tool revision: f250174 (from GIT_REVISION)
- Decoy: 127.0.0.1:42121 - engine f250174 in a throwaway container, identity seed 75, node controlled-test-node
- Reference: 127.0.0.1:42026 - proftpd-focal: service: proftpd;os: Ubuntu 20.04.6 LTS;apt_archive: snapshot.ubuntu.com 20231115T000000Z (focal, focal-updates, focal-security);package: proftpd-basic 1.3.6c-2;config_sha256: /etc/proftpd/proftpd.conf e935a3de07b3521f0cc0e10ca0d4c7be7c0f7ae9dd552f8e7f2197dee28d5b48;reports: ProFTPD Version 1.3.6c;
- Network: both targets were reached at loopback addresses from the process that ran the audit, so both ran on the same machine
- Checks: 29, matching 27, differing 2
- Timing rows (informational): 3, outside tolerance 0


| Check | Comparison | Result | Similarity | Decoy | Reference |
|---|---|---|---|---|---|
| `ftp.greeting` | bytes | match | 1.00 | `220 ProFTPD Server (Debian) [::ffff:<ip>]\r\n (43 bytes)` | `220 ProFTPD Server (Debian) [::ffff:<ip>]\r\n (43 bytes)` |
| `ftp.greeting.delay` | timing | within tolerance | 0.75 | `0.004` | `0.003` |
| `ftp.before_login.syst` | bytes | match | 1.00 | `215 UNIX Type: L8\r\n (19 bytes)` | `215 UNIX Type: L8\r\n (19 bytes)` |
| `ftp.before_login.feat` | bytes | match | 1.00 | `211-Features:\r\n211-CLNT\r\n211-EPRT\r\n211-EPSV\r\n211-HOST\r\n21...` | `211-Features:\r\n211-CLNT\r\n211-EPRT\r\n211-EPSV\r\n211-HOST\r\n21...` |
| `ftp.before_login.help` | bytes | MISMATCH | 1.00 | `214-The following commands are recognized (* =>'s unimplemented):\r...` | `214-The following commands are recognized (* =>'s unimplemented):\r...` |
| `ftp.before_login.stat` | bytes | match | 1.00 | `530 Please login with USER and PASS\r\n (37 bytes)` | `530 Please login with USER and PASS\r\n (37 bytes)` |
| `ftp.before_login.noop` | bytes | match | 1.00 | `200 NOOP command successful\r\n (29 bytes)` | `200 NOOP command successful\r\n (29 bytes)` |
| `ftp.before_login.pasv` | bytes | match | 1.00 | `530 Please login with USER and PASS\r\n (37 bytes)` | `530 Please login with USER and PASS\r\n (37 bytes)` |
| `ftp.before_login.unknown_command` | bytes | match | 1.00 | `500 FPAUDIT not understood\r\n (28 bytes)` | `500 FPAUDIT not understood\r\n (28 bytes)` |
| `ftp.before_login.pass_before_user` | bytes | match | 1.00 | `503 Login with USER first\r\n (27 bytes)` | `503 Login with USER first\r\n (27 bytes)` |
| `ftp.before_login.quit` | bytes | match | 1.00 | `221 Goodbye.\r\n (14 bytes)` | `221 Goodbye.\r\n (14 bytes)` |
| `ftp.before_login.quit.closes` | exact | match | 1.00 | `true` | `true` |
| `ftp.login.unknown_user.user` | bytes | match | 1.00 | `331 Password required for fpaudit-nouser\r\n (42 bytes)` | `331 Password required for fpaudit-nouser\r\n (42 bytes)` |
| `ftp.login.unknown_user.pass` | bytes | match | 1.00 | `530 Login incorrect.\r\n (22 bytes)` | `530 Login incorrect.\r\n (22 bytes)` |
| `ftp.login.failed_pass_delay` | timing | within tolerance | 0.00 | `0.005` | `0.0` |
| `ftp.login.repeated_wrong_password` | exact | match | 1.00 | `{"pass_replies": ["530 Login incorrect.\r\n", "530 Login incorrect....` | `{"pass_replies": ["530 Login incorrect.\r\n", "530 Login incorrect....` |
| `ftp.after_login.user` | bytes | match | 1.00 | `331 Password required for test\r\n (32 bytes)` | `331 Password required for test\r\n (32 bytes)` |
| `ftp.after_login.pass` | bytes | match | 1.00 | `230 User test logged in\r\n (25 bytes)` | `230 User test logged in\r\n (25 bytes)` |
| `ftp.after_login.syst` | bytes | match | 1.00 | `215 UNIX Type: L8\r\n (19 bytes)` | `215 UNIX Type: L8\r\n (19 bytes)` |
| `ftp.after_login.feat` | bytes | match | 1.00 | `211-Features:\r\n211-CLNT\r\n211-EPRT\r\n211-EPSV\r\n211-HOST\r\n21...` | `211-Features:\r\n211-CLNT\r\n211-EPRT\r\n211-EPSV\r\n211-HOST\r\n21...` |
| `ftp.after_login.help` | bytes | MISMATCH | 1.00 | `214-The following commands are recognized (* =>'s unimplemented):\r...` | `214-The following commands are recognized (* =>'s unimplemented):\r...` |
| `ftp.after_login.stat` | bytes | match | 1.00 | `211-Status of 'Debian'\r\n211-Connected from <ip> (<ip>)\r\n211-Log...` | `211-Status of 'Debian'\r\n211-Connected from <ip> (<ip>)\r\n211-Log...` |
| `ftp.after_login.noop` | bytes | match | 1.00 | `200 NOOP command successful\r\n (29 bytes)` | `200 NOOP command successful\r\n (29 bytes)` |
| `ftp.after_login.pasv` | bytes | match | 1.00 | `227 Entering Passive Mode (<h1,h2,h3,h4,p1,p2>).\r\n (50 bytes)` | `227 Entering Passive Mode (<h1,h2,h3,h4,p1,p2>).\r\n (50 bytes)` |
| `ftp.after_login.unknown_command` | bytes | match | 1.00 | `500 FPAUDIT not understood\r\n (28 bytes)` | `500 FPAUDIT not understood\r\n (28 bytes)` |
| `ftp.after_login.quit` | bytes | match | 1.00 | `221 Goodbye.\r\n (14 bytes)` | `221 Goodbye.\r\n (14 bytes)` |
| `ftp.after_login.quit.closes` | exact | match | 1.00 | `true` | `true` |
| `ftp.overlong.user_5000` | bytes | match | 1.00 | ` (0 bytes)` | ` (0 bytes)` |
| `ftp.overlong.user_5000.closes` | exact | match | 1.00 | `false` | `false` |
| `ftp.overlong.line_70000` | bytes | match | 1.00 | ` (0 bytes)` | ` (0 bytes)` |
| `ftp.overlong.line_70000.closes` | exact | match | 1.00 | `true` | `true` |
| `ftp.reply_latency` | timing | within tolerance | 0.00 | `0.005` | `0.0` |
