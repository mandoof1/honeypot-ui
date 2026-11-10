# Fingerprint self-audit

The engine's decoys claim to be specific daemons: OpenSSH 8.2p1 on Ubuntu
20.04, vsftpd 3.0.3 or ProFTPD 1.3.6c, Apache 2.4.41 or nginx 1.18.0, a
telnetd login. This tool measures how far each decoy is from the daemon it
names. It follows the method of Vetterl and Clayton, "Bitter Harvest"
(USENIX WOOT '18): send the same probes to the suspect and to the real
thing, and compare the answers.

It is for auditing our own decoys. Both targets must be loopback addresses;
anything else is refused before a connection is made.

## Status

- The tool is tested against small fake servers that run inside the test
  process, and it has been run end to end with the engine as both the decoy
  and the reference, which proves the probes run and nothing more.
- **The reference images in `reference/` have never been built or run with
  Docker.** They were written without a Docker daemon available. Expect to
  fix things on the first build.
- **No comparison between a decoy and a real daemon has been run yet.**
  There are no results, and nothing in this directory says how close or far
  the decoys are.

What is known about the references: an earlier revision of
`reference/provision.sh` was run once in a chroot of the
`ubuntu:focal-20231003` image, outside Docker. Its `sources` and `install`
steps completed for the six Ubuntu services with the package versions listed
below, and the sshd started that way sent
`SSH-2.0-OpenSSH_8.2p1 Ubuntu-4ubuntu0.9`. The script has changed since, the
Debian image was never built, and the other five daemons were never started.

## Reference daemons

`reference/compose.yaml` builds one image per daemon from
`reference/Dockerfile`, which runs `reference/provision.sh` to install the
distribution's package with its stock configuration. Ports are published on
127.0.0.1 only.

| Service | Address | Compare with | Packages (as installed in the one trial above) |
|---|---|---|---|
| `sshd-focal` | 127.0.0.1:42022 | SSH profile `openssh-8.2p1-ubuntu` | openssh-server 1:8.2p1-4ubuntu0.9 |
| `sshd-bullseye` | 127.0.0.1:42023 | SSH profile `openssh-8.4p1-debian` | never built; Debian's bullseye package index lists openssh-server 1:8.4p1-5+deb11u3 |
| `apache-focal` | 127.0.0.1:42080 | identity `http_family` apache | apache2 2.4.41-4ubuntu3.14, libapache2-mod-php7.4 7.4.3-4ubuntu2.19 |
| `nginx-focal` | 127.0.0.1:42081 | identity `http_family` nginx | nginx 1.18.0-0ubuntu1.4 |
| `vsftpd-focal` | 127.0.0.1:42021 | identity `ftp_family` vsftpd | vsftpd 3.0.3-12 |
| `proftpd-focal` | 127.0.0.1:42026 | identity `ftp_family` proftpd | proftpd-basic 1.3.6c-2 |
| `telnetd-focal` | 127.0.0.1:42123 | the Telnet decoy | telnetd 0.17-41.2build1, openbsd-inetd 0.20160825-4build1 |

The Ubuntu images install from `snapshot.ubuntu.com` as of 2023-11-15, when
openssh-server was the `4ubuntu0.9` build the decoy's banner names. vsftpd is
pinned to 3.0.3-12 from the release pocket because `focal-updates` had moved
to 3.0.5 by then. The only additions to a stock install are the runtime
directories an init system would create and, on the two FTP images, a local
account `test` / `test` so the replies after login can be compared.

```sh
cd tools/fingerprint_audit/reference
docker compose up -d --build sshd-focal        # one service at a time
docker compose exec sshd-focal cat /etc/reference-versions
docker compose down --rmi local                # when finished
```

Quote the output of `/etc/reference-versions` in `--reference-description`,
so each result names the packages it was measured against.

## Running the decoy

Start the engine from the repository root on loopback, with a backend
address nothing listens on and a data directory to delete afterwards:

```sh
DATA=$(mktemp -d)
HONEYPOT_NODE_NAME=controlled-test-node \
HONEYPOT_INGEST_TOKEN=fingerprint-audit-local \
BACKEND_API_URL=http://127.0.0.1:9/api/v1 \
HONEYPOT_ENABLE_ISOLATION=false \
HONEYPOT_BIND_ADDRESS=127.0.0.1 HONEYPOT_CONTROL_BIND=127.0.0.1 HONEYPOT_CONTROL_PORT=48000 \
HONEYPOT_PROTOCOLS=ssh,ftp,telnet,http \
HONEYPOT_SSH_PORT=42222 HONEYPOT_FTP_PORT=42121 HONEYPOT_TELNET_PORT=42323 HONEYPOT_HTTP_PORT=48080 \
HONEYPOT_FTP_PASV_PORTS=45000-45009 \
HONEYPOT_CAPTURE_DIR=$DATA/sessions HONEYPOT_FILE_CAPTURE_DIR=$DATA/uploads \
HONEYPOT_IDENTITY_SEED=8 \
~/.cache/hs-venvs/engine/bin/python -m honeypot.main
```

- `HONEYPOT_ENABLE_ISOLATION=false` skips the start-up isolation check,
  which otherwise tries to connect to three public addresses.
- Which FTP and HTTP product the decoy claims comes from
  `HONEYPOT_IDENTITY_SEED`, read only when the data directory has no
  `host-identity.json` yet, so use a fresh directory per seed. At the commit
  this was written against, seed 8 gives Apache with PHP/7.4.3 and vsftpd,
  seed 75 nginx without PHP and ProFTPD, seed 9 nginx with PHP/7.4.3 and
  ProFTPD (all three with OS version 20.04.6). Check before relying on them:

  ```sh
  ~/.cache/hs-venvs/engine/bin/python -c "from honeypot.core.identity import _derive as d; i = d(8); print(i.http_server, i.php_version, i.ftp_family, i.os_version)"
  ```
- The SSH claim comes from `HONEYPOT_SSH_PROFILE` (`openssh-8.2p1-ubuntu` by
  default, or `openssh-8.4p1-debian`).
- Restart the engine, with a fresh data directory, before each audit run.
  The decoy counts failed logins per source address across SSH and Telnet,
  and the audit's own wrong passwords would carry over.

## Running the audit

```sh
~/.cache/hs-venvs/engine/bin/python -m tools.fingerprint_audit \
    --decoy 127.0.0.1:42222 --reference 127.0.0.1:42022 --protocol ssh \
    --out ssh.json --markdown ssh.md \
    --decoy-description "engine <commit>, profile openssh-8.2p1-ubuntu, seed 8" \
    --reference-description "openssh-server 1:8.2p1-4ubuntu0.9 on Ubuntu 20.04.6 (sshd-focal)"
```

`--protocol` is `ssh`, `ftp`, `http` or `telnet`. Only SSH needs asyncssh;
the rest is standard library. Useful options: `--idle-cap 130` to hold the
silent SSH connection long enough to see a two-minute login timeout,
`--wait 20` to wait for both listeners, `--raw-dir DIR` to keep every raw
capture, `--ftp-user` / `--ftp-password` for the account both FTP targets
accept. `GIT_REVISION` in the environment overrides the revision recorded
for the tool.

The audit opens one connection at a time and leaves 1.1 s between
connections, which keeps a run under the decoy's default limit of 60
connections a minute from one address. Leave a minute between runs against
the same engine, or the next run starts inside the previous run's window.

### What is probed

- **SSH** - identification string and its line ending; the KEXINIT read off
  the wire (eight algorithm name-lists in order, languages,
  `first_kex_packet_follows`, padding behaviour, hasshServer, packets sent
  unprompted); the reply to five bad client identifications (no software
  version, protocol 1.5, 300 bytes, 9010 bytes, an HTTP request) and to two
  bad first packets; what a silent client receives and whether it is dropped
  within `--idle-cap`. With asyncssh as the client: authentication methods
  offered, the pre-auth banner, `server-sig-algs`, the algorithms negotiated,
  and how repeated wrong passwords end for `root` and for an unknown user.
- **FTP** - greeting; SYST, FEAT, HELP, STAT, NOOP, PASV and an unknown
  command, each before and after login; PASS before USER; USER and PASS for
  an unknown user; repeated wrong passwords; a 5000-byte USER and a
  70000-byte line; QUIT. The PASV reply's format is compared; no data
  connection is opened.
- **HTTP** - for each of GET /, a missing path, HEAD /, OPTIONS /, POST /,
  DELETE /, an unknown method, a one-word request line, a request line with
  no version, HTTP/1.1 without Host, a 9000-byte and a 70000-byte URI,
  HTTP/1.0 without headers, and GET / with `Connection: close`: the status
  line, header names in order, `Server`, the other header values, the body,
  and whether the connection is closed. Then whether a second request on one
  connection is answered.
- **Telnet** - what a client that answers nothing receives; the negotiation
  and login banner seen by a client that refuses every option; the replies to
  `IAC WILL 99` and `IAC DO 99`; what follows a username and a wrong
  password; how repeated wrong passwords end for `root` and an unknown user.

Not covered: HTTPS (a stock Apache or nginx install does not listen on 443,
so there is nothing stock to compare with), FTP data transfers, anything
after a successful login, and TCP-level behaviour. Whether a connection ended
with FIN or RST is stored as evidence but never compared, because Docker's
port publishing sits between the audit and a reference and can change it.

## Reading the result

The JSON file records the date, the tool's git revision, both addresses and
descriptions, the settings, a summary, and one row per check:

- `comparison` - `exact` (equal or not), `ordered` (a list whose order
  matters), `bytes` (a raw response) or `timing`.
- `decoy.value` / `reference.value` - the normalised value that was
  compared. Raw responses are stored as length, SHA-256 and the first 4096
  bytes with non-printable bytes escaped. `evidence` holds what was sent and
  the capture before normalisation.
- `match` - true only when the two normalised values are equal.
- `similarity` - 0 to 1; how far apart two values are when they differ. For
  raw responses and strings it is the cosine similarity of the two
  byte-count vectors, which ignores byte order and so never decides a match.
  For lists it is difflib's ratio.
- `timing` rows are informational: one sample (or a median) per side, on
  loopback, flagged only when the two differ by more than 0.25 s and 25 %.
  They are counted separately in the summary.
- `probe_errors` on a side lists probe groups that could not run at all
  (connection refused, for example); their checks appear as not measured.

Normalisation is limited to what differs between two hosts without being a
tell: IPv4 addresses and the PASV tuple in FTP replies, the hostname in
Telnet text, well-formed dates and entity tags in HTTP header values, and
the random cookie and padding of an SSH KEXINIT. Everything else is compared
as sent.

`--markdown` writes the same rows as a table with long values cut short.

## Tests

```sh
~/.cache/hs-venvs/engine/bin/python -m pytest tools/fingerprint_audit/tests -q
```

`test_pure.py` covers parsing, normalisation and scoring. `test_probes.py`
runs every probe set, and the command line, against fake servers on
loopback (`tests/fakes.py`), including an in-process asyncssh server for
the SSH probes that need a key exchange.
