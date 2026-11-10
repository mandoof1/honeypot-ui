# Security policy

HoneySentinel is a honeypot: one part of it is built to be attacked. This
page is about weaknesses in the parts that are not.

## Supported version

| Version | Supported |
|---|---|
| 1.0.x | Yes: fixes are made on `master` and released as 1.0.x |
| earlier (untagged development builds) | No |

Running containers report the git revision they were built from
(`docker inspect`, label `org.opencontainers.image.revision`); include it in
a report.

## What counts

Report it if you can, without being an authenticated administrator:

- make an engine open an outbound connection, or reach the host, the
  database, the dashboard API or another engine from inside an engine
  container (the containment described in
  [docs/THREAT_MODEL.md](docs/THREAT_MODEL.md));
- read captured evidence, credentials or secrets you should not be able to;
- sign in as someone else, raise your role, or bypass two-factor sign-in;
- write sessions under a node name other than the one a token was issued for;
- execute code in the API, the ingest service or the payload analyser by
  sending a crafted session or file;
- make the installer, backup or restore scripts expose a secret or leave the
  firewall rules unloaded.

Not vulnerabilities: that the decoys accept weak passwords, answer on their
published ports, or can be recognised as a honeypot (the last is a research
limitation, documented in the technical reference; a new fingerprinting
method is welcome as an ordinary issue).

## How to report

Privately, through GitHub: the repository's **Security** tab, **Report a
vulnerability** (private vulnerability reporting must be enabled in the
repository settings; if the button is missing, open an issue that says only
"security report, please open a private channel" and nothing else).

Do not put details, proof-of-concept code or captured data in a public issue.

Include what you did, what happened, what you expected, the revision, and
whether it was the self-hosted deployment (`deploy/server`), a remote sensor
(`deploy/node`) or the development stack.

This is a university capstone project maintained by its authors, not a
staffed product. A report is acknowledged when a maintainer reads it; there
is no guaranteed response time and no bounty.

## Testing

Test against your own installation. The project's own deployment is a
research instrument that records everything sent to it, and traffic aimed at
it is treated as captured attack data, not as a report. Never use data
captured by any deployment, yours included, beyond what is needed to
demonstrate the problem.
