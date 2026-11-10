# Exposure runbook

[Back to the project overview](../README.md)

How to put a HoneySentinel deployment on the internet for the first time,
what to watch, and how to take it off again.

**State at the time of writing:** the deployment has never been exposed. It
has recorded only the team's own controlled test traffic. This runbook has
therefore not been executed end to end; treat the first run as a test of the
runbook too, and correct it where it is wrong.

## 0. Before anything else

| | Requirement | Evidence to keep |
|---|---|---|
| ☐ | The network owner (IT security office) has approved a honeypot on this network and the forwarding of the listed ports | Their written approval |
| ☐ | The research-ethics and data-protection positions are settled, with a retention period ([DATA_HANDLING.md](DATA_HANDLING.md)) | The decision, or the statement that none is needed |
| ☐ | An abuse contact is assigned and recorded in DATA_HANDLING.md and with the address's owner | The name |
| ☐ | Someone other than the team can stop it (the kill switch, below), and knows how | Who |
| ☐ | If a site sits behind the web decoys: its visitor notice is approved and live | Screenshot |

Do not continue without all five.

## 1. Prepare the server

| | Step | Check |
|---|---|---|
| ☐ | **BIOS: "After Power Loss" → "Power On"** (called AC Recovery or Restore on AC Power Loss on some boards). A manual step at the machine: without it a power cut ends the deployment until someone presses the button, which is how a five-day outage happened. | Pull the power cable, plug it back in, the machine boots |
| ☐ | The host's clock is NTP-synchronised | `timedatectl` shows `System clock synchronized: yes` |
| ☐ | The host has its updates, and nothing listens on it that should not | `ss -tlnp`: sshd, tailscaled, Docker's published ports, nothing else |
| ☐ | The checkout is the release being exposed, with no local changes | `git -C /opt/honeysentinel status` clean; note `git rev-parse HEAD` |
| ☐ | An existing `docker-compose.override.yml` follows the current example (fixed network names and addresses) | `install.sh` stops at step 1 with the difference if not |
| ☐ | `SESSION_RETENTION_DAYS` is set to the approved period | `grep SESSION_RETENTION_DAYS deploy/server/.env` |
| ☐ | Backups are encrypted to a key that is **not** on the server, and copied off it | `BACKUP_AGE_RECIPIENT` and `BACKUP_OFFSITE_*` in `.env` |
| ☐ | A dead man's switch is configured (step 3) | `HEARTBEAT_URL` in `.env` |
| ☐ | `sudo bash deploy/server/install.sh` completes | It ends with the container list; it exits non-zero if any verification below fails |

What the installer verifies, and refuses to finish without:

- every application container carries the revision of the checkout
  (printed as a table);
- the loaded firewall ruleset is exactly the one the checkout defines, and
  every Docker network has the bridge name and subnet the rules expect;
- **the probe**: from inside each engine, connections to public addresses, to
  the host on every bridge and to the other containers all fail, and the
  connection to the ingest service succeeds. It prints `Probe passed`.

Then, by hand:

| | Step | Check |
|---|---|---|
| ☐ | Sign in, change the administrator password, enable two-factor sign-in | Sign out and in again with a code |
| ☐ | Remove `state/admin-credentials` if an earlier version left one | `ls deploy/server/state/` |
| ☐ | Take a backup and rehearse a restore | `sudo systemctl start honeysentinel-backup` then `sudo bash deploy/server/restore-drill.sh --identity <key>` ends with `Drill passed` |
| ☐ | Run the controlled end-to-end test | `sudo bash deploy/server/controlled-test.sh --purge` shows five sessions under `controlled-test-node` |
| ☐ | Both engines show online in Settings, with all isolation checks passing | Screenshot |
| ☐ | The classifier is the trained one | Verdicts say `model_source: "cicids2017"`, not `"synthetic"` |
| ☐ | Timers are scheduled | `systemctl list-timers 'honeysentinel-*'` lists egress-check, heartbeat, backup, geoip |
| ☐ | Docker cannot start without the firewall | `systemctl cat docker` shows `Requires=honeysentinel-egress.service` |
| ☐ | Removing the rules is noticed | `sudo nft delete table inet honeysentinel`, then `sudo systemctl start honeysentinel-egress-check`: the rules are back and a critical system alert is open in the dashboard. Resolve it. |

## 2. Choose the exposure route

### Route A: port forward on the organisation's firewall

The decoys on the server receive the traffic directly.

| Public (TCP) | To the server | Engine |
|---|---|---|
| 22 | 2222 | SSH |
| 23 | 2323 | Telnet |
| 21, and 50000-50009 | 2121, and 50000-50009 | FTP and its passive data ports |
| 80 | 8080 | HTTP |
| 443 | 8443 | HTTPS |

IPv4 only; the decoy ports are not published on IPv6. Forward nothing else,
and never the dashboard port. If the public address is not the one in
`PUBLIC_IP`, update `.env` and re-run `install.sh` (passive FTP advertises it).

- For: the simplest path; one machine; source addresses arrive unchanged
  when the firewall forwards without source NAT (**confirm this**: with
  source NAT every session shows the firewall's address and the data is
  worthless).
- Against: attack traffic enters the organisation's network, and the
  machine that holds all the data is the one being attacked. Containment
  rests on the engine sandbox and the host firewall.
- Ask the network owner to place the server in a segment from which the
  rest of the network is not reachable. The host firewall already stops the
  containers; a segment stops the host too.

### Route B: the VPS sensor kit

A sensor on a rented public address captures and forwards to the server over
a private overlay; nothing is forwarded on the organisation's firewall.
Follow [deploy/node/README.md](../deploy/node/README.md), including its own
checklist.

- For: attack traffic never enters the organisation's network; the exposed
  machine holds no data and no secret but its own token; the address is
  disposable.
- Against: a second machine to keep patched; a provider whose policy must
  allow it; the server cannot push mode changes or blocks to the sensor; the
  web decoys cannot front the shop from there. The kit has not yet been run
  on a VPS.

Both can run together; each sensor is its own node.

### Opening it

| | Step |
|---|---|
| ☐ | Note the time and the revision. Everything recorded before this moment is test traffic. |
| ☐ | Open **one** port first (SSH). From a machine outside the organisation, connect once. The session must appear with that machine's public address, not a private or gateway address. Note this connection as the team's own. |
| ☐ | If the address is wrong, close the port and fix the forwarding before going further. |
| ☐ | Open the remaining ports. |

## 3. The dead man's switch

Nothing inside the deployment can tell anyone that the deployment is down,
and its containers cannot send a notification at all. The host can.
`honeysentinel-heartbeat.timer` runs `host-heartbeat.sh` every five minutes;
when every container is healthy, the firewall rules are intact, the newest
backup is under 26 hours old, all containers run one revision and the disk
has room, it requests `HEARTBEAT_URL`. When any of that fails, or the host is
off, the requests stop, and the service on the other end raises the alarm.

Any service that alerts on a missed check-in works: healthchecks.io, an
Uptime Kuma "push" monitor on another machine, Better Stack heartbeats,
Cronitor. Create a check with a 5-minute period and a 10-minute grace time,
route its alert to a phone and to email, put its URL in `.env` as
`HEARTBEAT_URL`, and test it: `sudo systemctl stop docker`, wait for the
alert, start Docker again.

This is also how the 30-day availability requirement is evidenced. The
external service's log shows every interval in which the deployment was not
provably healthy, independently of the deployment; `state/availability.jsonl`
is the host's own record of the same checks, with the reason for each
failure. Availability over the period is computed from the two
([EVALUATION_PLAN.md](EVALUATION_PLAN.md)).

## 4. The first 24 hours

Look at one hour, four hours, and the next morning.

| Watch | Where | Expect | If not |
|---|---|---|---|
| Sessions arriving | Dashboard | SSH and Telnet logins from many addresses within the first hours | Check the forward; `docker compose logs honeypot` |
| Source addresses | Session list | Public addresses in many networks | All the same or private: the firewall is rewriting the source; close and fix |
| Blocked egress | `journalctl -k \| grep 'hs egress blocked'` | Lines appear as bots try to download their payloads; that is the firewall working | None at all after bots ran `wget`: confirm the rules are loaded (`honeysentinel-egress.sh check`) |
| Isolation checks | Settings → each engine | All passing | Any failing: take it down (below) and investigate |
| System alerts | Alerts, kind "system" | None | Each names its cause; `egress_rules_missing` and `egress_network_mismatch` mean take it down first |
| Heartbeat | The external service | A ping every five minutes | The reason is in `journalctl -u honeysentinel-heartbeat` |
| Disk | `df -h /var/lib/docker /var/backups` | Slow growth | Uploads are deduplicated by hash; a flood of large files fills the engine volume first (the engine alerts under 10 % free) |
| Queues | `curl -s localhost:8088/health` on the server | Enrichment and triage queues draining | The language model takes about two minutes a session; a growing queue is expected under load and loses nothing |
| CPU and memory | `docker stats --no-stream` | Engines well under 1 GiB | A container at its limit restarts; check its logs |
| Spool | Settings → engine status | `spool_pending` near zero | Growing: the ingest service is not accepting; `docker compose logs ingest` |
| Abuse mailbox | The assigned contact | Nothing | Answer with what DATA_HANDLING.md says |

Do not log in to the decoys yourself "to see", and do not scan them: that is
recorded as an attack. Use `controlled-test.sh`.

After 24 hours: run `restore-drill.sh` against the first backup that
contains real sessions, and review a sample of sessions by hand for anything
that should not have been captured.

## Taking it down

Fastest first. Any one of these stops new collection.

1. **Close the route.** Route A: remove the port forwards on the
   organisation's firewall (the network owner can do this without the team).
   Route B: `docker compose down` on the VPS, or destroy it.
2. **Stop the engines:**
   `cd /opt/honeysentinel/deploy/server && sudo docker compose stop honeypot honeypot-web`
3. **Stop everything:** `sudo docker compose down`. Data stays in the volumes
   and in the backups.

Then:

- tell the network owner and the abuse contact that it is down, and why;
- if a compromise is suspected: do not restart. Keep the volumes
  (`docker compose down` without `-v`), take a backup, record `nft list
  ruleset`, `docker ps -a` and the engines' logs, and recreate the engines'
  data volumes before any restart;
- revoke a sensor's token: `sudo python3 deploy/server/node_tokens.py remove <name>`
  then `docker compose up -d backend ingest`;
- to erase the data as well, see the kill switch in
  [DATA_HANDLING.md](DATA_HANDLING.md#kill-switch).

Bringing it back is section 1 again, from the top.
