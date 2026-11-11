# Fingerprint comparison with the real daemons

How the decoys differ, from a client's point of view, from the software they
claim to be. Method: [`tools/fingerprint_audit`](../../../tools/fingerprint_audit/README.md),
after Vetterl and Clayton, "Bitter Harvest" (WOOT '18). The same probes are
sent to a throwaway engine and to the real daemon, both on loopback on the
same machine, and the answers are compared.

The real daemons are the distribution packages in their stock configuration
(`tools/fingerprint_audit/reference`); each result file names the exact
package versions it was measured against. The engine ran in a throwaway
container as node `controlled-test-node`; the production engines and their
ports were not involved.

| Decoy compared with | baseline: checks that match |
|---|---|
| OpenSSH 8.2p1 (Ubuntu 20.04) | 26 of 38 |
| telnetd 0.17 behind inetd | 3 of 10 |
| vsftpd 3.0.3 | 24 of 29 |
| ProFTPD 1.3.6c | 17 of 29 |
| Apache 2.4.41 with PHP 7.4 | 58 of 86 |
| nginx 1.18.0 | 82 of 86 |

A check is one aspect of one probe (a status line, a list of algorithms in
order, whether the connection closes). "Match" means identical for
structured values and byte-for-byte for raw replies. Timing rows are recorded
in the files and are not counted here.

## What still differs (baseline)

- **OpenSSH 8.2p1 (Ubuntu 20.04)**: `ssh.kexinit.padding`, `ssh.ident_reply.no_software_version.response`, `ssh.ident_reply.protocol_1.response`, `ssh.ident_reply.over_255_bytes.response`, `ssh.ident_reply.over_255_bytes.closes`, `ssh.ident_reply.over_8192_bytes.response`, `ssh.ident_reply.http_request.response`, `ssh.packet_reply.bad_length.closes`, `ssh.packet_reply.unknown_message.response`, `ssh.ext_info.server_sig_algs`, `ssh.auth.password.root`, `ssh.auth.password.unknown_user`
- **telnetd 0.17 behind inetd**: `telnet.silent.negotiation`, `telnet.silent.text`, `telnet.refusing.negotiation`, `telnet.refusing.login_banner`, `telnet.login.after_username`, `telnet.login.wrong_passwords.root`, `telnet.login.wrong_passwords.unknown_user`
- **vsftpd 3.0.3**: `ftp.before_login.feat`, `ftp.login.repeated_wrong_password`, `ftp.after_login.feat`, `ftp.overlong.user_5000`, `ftp.overlong.user_5000.closes`
- **ProFTPD 1.3.6c**: `ftp.greeting`, `ftp.before_login.syst`, `ftp.before_login.feat`, `ftp.before_login.help`, `ftp.before_login.noop`, `ftp.before_login.unknown_command`, `ftp.login.repeated_wrong_password`, `ftp.after_login.feat`, `ftp.after_login.help`, `ftp.after_login.stat`, `ftp.overlong.user_5000`, `ftp.overlong.line_70000`
- **Apache 2.4.41 with PHP 7.4**: `http.get_root.header_values`, `http.get_root.body`, `http.head_root.header_values`, `http.options_root.header_values`, `http.post_root.status_line`, `http.post_root.header_names`, `http.post_root.header_values`, `http.post_root.body`, `http.delete_root.header_values`, `http.unknown_method.header_values`, `http.unknown_method.body`, `http.malformed_request_line.header_values`, `http.malformed_request_line.body`, `http.http09_request.status_line`, `http.http09_request.header_names`, `http.http09_request.server`, `http.http09_request.header_values`, `http.http09_request.body`, `http.no_host_http11.header_values`, `http.no_host_http11.body`, `http.uri_9000.header_values`, `http.uri_9000.body`, `http.uri_70000.header_values`, `http.uri_70000.body`, `http.http10_no_headers.header_values`, `http.http10_no_headers.body`, `http.connection_close.header_values`, `http.connection_close.body`
- **nginx 1.18.0**: `http.http09_request.status_line`, `http.http09_request.header_names`, `http.http09_request.server`, `http.http09_request.header_values`

## Reading these numbers

- They say which of these probes tell the decoy from the real daemon. A
  decoy that matched every probe would not be undetectable; it would only be
  indistinguishable by these probes.
- Several differences are deliberate: the decoy lets a client in after a few
  wrong passwords, which no real server does, because a honeypot that never
  admits anyone records nothing after the login prompt.
- The first run is the first time the decoys were compared with anything.
  Before it, the claim that the SSH transport matched OpenSSH rested on the
  algorithm lists alone. Those do match; the replies to a malformed client
  identification, which is what the cited paper used to find honeypots at
  internet scale, did not.

## Files

One directory per run. In each, `<protocol>-<reference>.json` is the tool's
full output (every probe, what each side sent, the comparison) and the `.md`
beside it is the same as a table.
