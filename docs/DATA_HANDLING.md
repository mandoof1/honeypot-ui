# Data handling

[Back to the project overview](../README.md)

What a HoneySentinel deployment collects, on what basis, how long it keeps
it, and what has to be decided by the organisation hosting it before it is
exposed. This document describes what the software does. It is not legal
advice, and the approvals it mentions are the hosting organisation's to give.

**To date the deployment has recorded only the team's own controlled test
traffic.** Nothing below describes data already collected from the public.

## What is collected

From every connection to a decoy port:

| Data | Detail | Stored |
|---|---|---|
| Source address and port | As seen by the engine; plus country and city from a local GeoIP database (no lookup leaves the machine) | Plain, in the database |
| Timing and flow statistics | Start, duration, bytes and packet counts each way | Plain |
| Client fingerprints | SSH client version and key-exchange fingerprint (HASSH), HTTP user agent, and TLS client fingerprints (JA3/JA4) in engine builds that record them | Plain |
| **Credentials typed into the decoys** | Every username and password tried over SSH, Telnet and FTP, in web login forms and HTTP Basic auth | Encrypted (AES-256-GCM); readable by administrators only, and each read is audit-logged |
| Commands and requests | The full transcript: shell commands with the decoy's replies, FTP commands, HTTP requests with bodies | Encrypted; a plain summary without request bodies is kept for search |
| Uploaded files | Anything written through the shell, SFTP/SCP, FTP or HTTP | Bytes encrypted in the database (up to `PAYLOAD_MAX_STORE_BYTES`); hash and static analysis plain |
| Derived analysis | Category, severity, ATT&CK techniques, indicators extracted from the session, model outputs | Plain |

Card numbers (Luhn-valid digit runs) and security-code fields are masked in
everything the engine stores.

Each engine also keeps local copies in its data volume, **in plain text**:
delivered sessions for `HONEYPOT_CAPTURE_RETENTION_DAYS` (7), raw uploads for
`HONEYPOT_UPLOAD_RETENTION_DAYS` (30), and undelivered sessions until they
are delivered.

About operators: accounts, sign-in times, and an audit log of privileged
actions with the operator's address.

### When a real website sits behind the web decoys

This needs stating plainly, because it is not what people expect of a
honeypot. With `HONEYPOT_HTTP_UPSTREAM` set (the reference deployment fronts
a demo shop), **every request to that site passes through the decoy and is
recorded, including those of ordinary visitors**, and that includes:

- **the username and password of anyone who logs in to the site**, captured
  as credentials exactly as an attacker's would be;
- form contents, session cookies and the pages they viewed.

Consequences for the hosting organisation:

- The site must be a demonstration with no real customers, or its visitors
  must be told before they use it that the site is monitored for security
  research and that what they enter is recorded. A notice on the login page
  is the minimum.
- Nobody should use a password there that they use anywhere else. Say so on
  the page.
- Legitimate visitors' sessions are in the same tables as attackers' and
  must be excluded from any analysis or released dataset (below).

Without an upstream site, the decoys serve only their own bait pages and
nobody has a legitimate reason to log in.

## Who the data is about, and the basis for collecting it

Source addresses, and credentials when they belong to a real person (reused
passwords, credentials stolen from a third party and tried here), are
personal data under most data-protection regimes. People who connect to a
honeypot have not consented to anything.

The basis usually relied on for honeypot research is the operator's
legitimate interest in network security, balanced against the limited
intrusion: the data comes from unsolicited connections to a system with no
legitimate users, is kept for a bounded time, is access-controlled, and is
not used to identify individuals. Whether that basis is available, and under
which law, depends on where the deployment and its operators are.

**Expected from the hosting organisation, in writing, before exposure:**

- approval from whoever is responsible for the network (the IT security
  office) to run a honeypot on it and to forward the listed ports;
- the university's research-ethics position: a decision, or a written
  statement that review is not required, for collecting attacker data that
  includes addresses and credentials;
- the data-protection position: the basis relied on, the retention period,
  and who the responsible contact is;
- if a site sits behind the decoys: approval of the visitor notice above;
- for a remote sensor: that the VPS provider's acceptable-use policy permits
  a honeypot.

None of these exists in the repository; the
[exposure runbook](EXPOSURE_RUNBOOK.md) will not let the checklist pass
without them.

## Retention

| Data | Default | Set with |
|---|---|---|
| Sessions, with their alerts, indicators and payload links | **kept for ever** (`SESSION_RETENTION_DAYS=0`) | `SESSION_RETENTION_DAYS` |
| Audit log | 365 days | `AUDIT_RETENTION_DAYS` |
| Engine-local session copies / uploads | 7 / 30 days | `HONEYPOT_CAPTURE_RETENTION_DAYS`, `HONEYPOT_UPLOAD_RETENTION_DAYS` |
| Backups | 14 days locally; off-host copies as long as the destination keeps them | `BACKUP_KEEP_DAYS` |

**The session default is a flag, not a recommendation.** "For ever" was
chosen in development, where the captures were the point and all of them
were the team's own. For an exposed deployment an unlimited period is hard
to justify for personal data. Decide a period before exposure and set it in
`deploy/server/.env`, for example:

```
SESSION_RETENTION_DAYS=180
```

then `docker compose up -d backend ingest`. Deletion runs hourly in the
backend. Two things it does not reach: backups already taken (they expire
with `BACKUP_KEEP_DAYS`; off-host copies are yours to expire), and datasets
already exported.

Deleting one source's data on request has no button in the console. An
administrator does it in the database, with the statements
`deploy/server/controlled-test.sh --purge` uses for a node (alerts and
indicators first, then the sessions), selecting by `attacker_ip` instead.
Record the request and the deletion.

## Access

Only over the tailnet, with an account. Viewers read sessions and
transcripts; analysts can also export; only administrators can read captured
credentials and download samples, and both actions are audit-logged. Turn on
two-factor sign-in for every account.

## Releasing data

A dataset leaves the deployment only through the export tool
(`python -m app.tools.export_dataset`), never as a database dump, and only
after:

- **Addresses are pseudonymised**: replaced by a keyed hash, with the key
  kept out of the release and destroyed when linking is no longer needed.
  A plain hash of an IPv4 address is reversible by enumeration and is not
  enough. Coarse location (country) may stay; city should not.
- **Passwords are removed or reduced** to what the research needs (length,
  class, membership of a known list). Usernames that look like a person's
  name or an email address are removed.
- **Free text is checked**: commands and request bodies can contain
  addresses, tokens and personal data typed by the attacker or stolen from
  someone else.
- **Legitimate visitors of a fronted site are excluded** altogether, as is
  the team's own controlled test traffic (the `controlled-test-node` node
  and the listed test addresses).
- **Uploaded files are not included.** Publish hashes.
- The organisation's approval covers publication, not only collection.

The team reviews a sample of the export by hand before each release, and
the release states its period, its exclusions and the git revision that
produced it.

## Malware

Uploaded files are real malware.

- They are analysed statically, in a resource-limited subprocess, and are
  never executed; no address found inside one is ever contacted.
- They are stored encrypted in the database; raw copies sit in the engines'
  volumes for 30 days.
- Downloading a sample is an administrator action, audit-logged, served as
  an opaque attachment. Do it only onto an isolated analysis machine.
  Never open one on a workstation.
- Backups contain them (inside the database, and raw in the engine archives
  when the backup is encrypted). An unencrypted backup leaves the raw copies
  out.
- Share samples only by hash, or through a malware-exchange channel that the
  organisation has approved.

## Abuse contact

A honeypot's address will appear in other people's logs, and someone may
write to ask what it is. Before exposure the hosting organisation names a
contact (normally its IT security office) and that contact is recorded:

- in the organisation's WHOIS/abuse records for the address, which is where
  people look first;
- here: **abuse contact: _not yet assigned; required before exposure_**.

The contact needs to know that the address is a research honeypot, who runs
it, and how to have it taken down.

## Kill switch

Anyone responsible for the network must be able to stop the collection
without the team. In order of preference:

1. **Remove the port forwards** on the organisation's firewall. Nothing
   reaches the decoys; everything collected stays available.
2. **Stop the engines** on the server:
   `cd /opt/honeysentinel/deploy/server && sudo docker compose stop honeypot honeypot-web`
   (a remote sensor: `docker compose down` on the VPS, or destroy the VPS).
3. **Stop everything**: `sudo docker compose down`. Data stays in the
   volumes.
4. **Erase**: `sudo docker compose down -v`, then delete
   `/var/backups/honeysentinel` and any off-host copies. Irreversible.

Passive mode (Settings → Emulation mode) keeps recording connection attempts
but stops answering, which ends credential and command capture without
changing the network.

The full procedure, with who to tell, is in the
[exposure runbook](EXPOSURE_RUNBOOK.md#taking-it-down).
