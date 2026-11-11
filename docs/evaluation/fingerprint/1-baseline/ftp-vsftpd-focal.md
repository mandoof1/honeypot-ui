# Fingerprint audit: ftp

- Date (UTC): 2026-11-11T09:14:47Z
- Tool revision: fd2d146 (from GIT_REVISION)
- Decoy: 127.0.0.1:42121 - engine fd2d146 in a throwaway container, identity seed 8, node controlled-test-node
- Reference: 127.0.0.1:42021 - vsftpd-focal: service: vsftpd;os: Ubuntu 20.04.6 LTS;apt_archive: snapshot.ubuntu.com 20231115T000000Z (focal, focal-updates, focal-security);package: vsftpd 3.0.3-12;package: libpam-modules 1.3.1-5ubuntu4.6;config_sha256: /etc/vsftpd.conf 58b3e08f07c2461eaedbcc51810dc814b0164e67b295bbc5cff6ee8d540b856f;reports: vsftpd: version 3.0.3;
- Network: both targets were reached at loopback addresses from the process that ran the audit, so both ran on the same machine
- Checks: 29, matching 24, differing 5
- Timing rows (informational): 3, outside tolerance 1


| Check | Comparison | Result | Similarity | Decoy | Reference |
|---|---|---|---|---|---|
| `ftp.greeting` | bytes | match | 1.00 | `220 (vsFTPd 3.0.3)\r\n (20 bytes)` | `220 (vsFTPd 3.0.3)\r\n (20 bytes)` |
| `ftp.greeting.delay` | timing | within tolerance | 0.14 | `0.007` | `0.001` |
| `ftp.before_login.syst` | bytes | match | 1.00 | `530 Please login with USER and PASS.\r\n (38 bytes)` | `530 Please login with USER and PASS.\r\n (38 bytes)` |
| `ftp.before_login.feat` | bytes | MISMATCH | 1.00 | `211-Features:\r\n EPRT\r\n EPSV\r\n MDTM\r\n PASV\r\n REST STREAM\r...` | `211-Features:\r\n EPRT\r\n EPSV\r\n MDTM\r\n PASV\r\n REST STREAM\r...` |
| `ftp.before_login.help` | bytes | match | 1.00 | `530 Please login with USER and PASS.\r\n (38 bytes)` | `530 Please login with USER and PASS.\r\n (38 bytes)` |
| `ftp.before_login.stat` | bytes | match | 1.00 | `530 Please login with USER and PASS.\r\n (38 bytes)` | `530 Please login with USER and PASS.\r\n (38 bytes)` |
| `ftp.before_login.noop` | bytes | match | 1.00 | `530 Please login with USER and PASS.\r\n (38 bytes)` | `530 Please login with USER and PASS.\r\n (38 bytes)` |
| `ftp.before_login.pasv` | bytes | match | 1.00 | `530 Please login with USER and PASS.\r\n (38 bytes)` | `530 Please login with USER and PASS.\r\n (38 bytes)` |
| `ftp.before_login.unknown_command` | bytes | match | 1.00 | `530 Please login with USER and PASS.\r\n (38 bytes)` | `530 Please login with USER and PASS.\r\n (38 bytes)` |
| `ftp.before_login.pass_before_user` | bytes | match | 1.00 | `503 Login with USER first.\r\n (28 bytes)` | `503 Login with USER first.\r\n (28 bytes)` |
| `ftp.before_login.quit` | bytes | match | 1.00 | `221 Goodbye.\r\n (14 bytes)` | `221 Goodbye.\r\n (14 bytes)` |
| `ftp.before_login.quit.closes` | exact | match | 1.00 | `true` | `true` |
| `ftp.login.unknown_user.user` | bytes | match | 1.00 | `331 Please specify the password.\r\n (34 bytes)` | `331 Please specify the password.\r\n (34 bytes)` |
| `ftp.login.unknown_user.pass` | bytes | match | 1.00 | `530 Login incorrect.\r\n (22 bytes)` | `530 Login incorrect.\r\n (22 bytes)` |
| `ftp.login.failed_pass_delay` | timing | outside tolerance | 0.00 | `0.008` | `3.031` |
| `ftp.login.repeated_wrong_password` | exact | MISMATCH | 0.00 | `{"pass_replies": ["530 Login incorrect.\r\n", "530 Login incorrect....` | `{"pass_replies": ["530 Login incorrect.\r\n", "530 Login incorrect....` |
| `ftp.after_login.user` | bytes | match | 1.00 | `331 Please specify the password.\r\n (34 bytes)` | `331 Please specify the password.\r\n (34 bytes)` |
| `ftp.after_login.pass` | bytes | match | 1.00 | `230 Login successful.\r\n (23 bytes)` | `230 Login successful.\r\n (23 bytes)` |
| `ftp.after_login.syst` | bytes | match | 1.00 | `215 UNIX Type: L8\r\n (19 bytes)` | `215 UNIX Type: L8\r\n (19 bytes)` |
| `ftp.after_login.feat` | bytes | MISMATCH | 1.00 | `211-Features:\r\n EPRT\r\n EPSV\r\n MDTM\r\n PASV\r\n REST STREAM\r...` | `211-Features:\r\n EPRT\r\n EPSV\r\n MDTM\r\n PASV\r\n REST STREAM\r...` |
| `ftp.after_login.help` | bytes | match | 1.00 | `214-The following commands are recognized.\r\n ABOR ACCT ALLO APPE ...` | `214-The following commands are recognized.\r\n ABOR ACCT ALLO APPE ...` |
| `ftp.after_login.stat` | bytes | match | 1.00 | `211-FTP server status:\r\n     Connected to ::ffff:<ip>\r\n     Log...` | `211-FTP server status:\r\n     Connected to ::ffff:<ip>\r\n     Log...` |
| `ftp.after_login.noop` | bytes | match | 1.00 | `200 NOOP ok.\r\n (14 bytes)` | `200 NOOP ok.\r\n (14 bytes)` |
| `ftp.after_login.pasv` | bytes | match | 1.00 | `227 Entering Passive Mode (<h1,h2,h3,h4,p1,p2>).\r\n (50 bytes)` | `227 Entering Passive Mode (<h1,h2,h3,h4,p1,p2>).\r\n (50 bytes)` |
| `ftp.after_login.unknown_command` | bytes | match | 1.00 | `500 Unknown command.\r\n (22 bytes)` | `500 Unknown command.\r\n (22 bytes)` |
| `ftp.after_login.quit` | bytes | match | 1.00 | `221 Goodbye.\r\n (14 bytes)` | `221 Goodbye.\r\n (14 bytes)` |
| `ftp.after_login.quit.closes` | exact | match | 1.00 | `true` | `true` |
| `ftp.overlong.user_5000` | bytes | MISMATCH | 0.51 | `331 Please specify the password.\r\n (34 bytes)` | `500 Input line too long.\r\n (26 bytes)` |
| `ftp.overlong.user_5000.closes` | exact | MISMATCH | 0.00 | `false` | `true` |
| `ftp.overlong.line_70000` | bytes | match | 1.00 | `500 Input line too long.\r\n (26 bytes)` | `500 Input line too long.\r\n (26 bytes)` |
| `ftp.overlong.line_70000.closes` | exact | match | 1.00 | `true` | `true` |
| `ftp.reply_latency` | timing | within tolerance | 0.00 | `0.004` | `0.0` |
