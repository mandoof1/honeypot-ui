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
ports were not involved. Both runs were made on 2026-11-11 (UTC) on
the deployment server.

Checks that match, of the checks made:

| Decoy compared with | First run (`fd2d146`) | After the fixes (`f250174`) |
|---|---|---|
| OpenSSH 8.2p1 (Ubuntu 20.04) | 26 of 38 | 36 of 38 |
| telnetd 0.17 behind inetd | 3 of 10 | 9 of 10 |
| vsftpd 3.0.3 | 24 of 29 | 29 of 29 |
| ProFTPD 1.3.6c | 17 of 29 | 27 of 29 |
| Apache 2.4.41 with PHP 7.4 | 58 of 86 | 65 of 86 |
| nginx 1.18.0 | 82 of 86 | 86 of 86 |

A check is one aspect of one probe (a status line, a list of algorithms in
order, whether the connection closes). "Match" means identical for
structured values and byte-for-byte for raw replies. Timing rows are recorded
in the files and are not counted here.

## What the first run found

The first run is the first time the decoys were compared with anything.
Before it, the claim that the SSH transport matched OpenSSH rested on the
algorithm lists alone. Those did match. What did not:

- **SSH**: unencrypted packets were padded with random bytes where OpenSSH
  uses zeros; a malformed client identification was met with silence where
  OpenSSH sends `Invalid SSH identification string.` or
  `Protocol major versions differ.`; a bad first packet and an unknown
  message type were handled differently; the advertised signature algorithms
  were the library's, not OpenSSH's; and a wrong password was refused at
  once where OpenSSH takes about two seconds. The first two are the kind of
  probe the cited paper used to find honeypots across the internet.
- **Telnet**: a different opening negotiation, a blank line before the
  banner, no echo of the user name, a shorter pause after a wrong password.
- **FTP**: feature lists, the greeting and several replies for the ProFTPD
  identity, the pause after a failed login, and the handling of over-long
  lines.
- **HTTP**: HTTP/0.9 requests, `POST` to a static page and the 501 page.

## What still differs after the fixes, and why

- **SSH** (2): `ssh.auth.password.root` is deliberate, the decoy lets a client
  in after a few wrong passwords, which no real server does, because a
  honeypot that admits no one records nothing after the prompt.
  `ssh.auth.password.unknown_user`: both sides time out the same way, but in
  the probe's ten seconds the decoy fitted five wrong passwords and OpenSSH
  four; the real server's pause varies and the decoy's is fixed.
- **Telnet** (1): `telnet.login.wrong_passwords.root`, the same deliberate let-in.
- **ProFTPD** (2): the two `help` replies end with a line naming the host; the
  decoy names its own, the reference its container.
- **Apache** (21): all are content or the host's address, not behaviour. The
  decoy serves its own 720-byte page where the reference serves the
  distribution's 10,918-byte default page, which changes `Content-Length`
  and the body on every request for `/`; the error pages differ by one byte
  because they print the server's address; and the order of methods in
  `Allow` differs because Apache's comes from a hash seeded per process.
- **vsftpd** and **nginx**: nothing.

## Reading these numbers

- They say which of these probes tell the decoy from the real daemon. A
  decoy that matched every probe would not be undetectable; it would only be
  indistinguishable by these probes. HTTPS, FTP data transfers and anything
  below the application protocol were not probed.
- The fixes were written against the first run's evidence and then measured
  again on the same probes. The second column shows those differences are
  gone; it does not show how the decoys fare against probes that were not in
  the set.
- The let-in after wrong passwords remains the plainest way to tell any
  honeypot of this kind from a real server, and it is a choice, not a defect.

## Files

One directory per run. In each, `<protocol>-<reference>.json` is the tool's
full output (every probe, what each side sent, the comparison) and the `.md`
beside it is the same as a table.
