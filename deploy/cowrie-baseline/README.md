# Cowrie baseline

A stock [Cowrie](https://github.com/cowrie/cowrie) run beside the
HoneySentinel engine, so that the two can be compared on the same traffic
conditions. This directory holds the method and the means to run it. **It
holds no results: the comparison has not been run.**

Cowrie is the reference medium-interaction SSH honeypot; a claim that this
engine captures more, or is harder to recognise, only means something against
it, measured the same way.

## Comparison protocol

| | |
|---|---|
| Same host | Both run on the reference server, from this repository's compose files. |
| Same period | Both are started and stopped together, for at least 14 consecutive days (30 if the availability run allows). A day on which either was down for more than an hour is excluded from both. |
| Adjacent ports or address | Preferred: a second public IPv4 address in the same subnet, with port 22 of each address forwarded to one honeypot. Otherwise adjacent ports of one address: 22 to the engine (2222), 2222 to Cowrie (2022). Which was used is stated in the report, because scanners visit port 22 far more often than 2222 and with one address the two do not see equal traffic. |
| Same containment | Cowrie's bridge (`hs-cowrie`) is under the same host firewall as the engine's: it may answer and nothing more. |
| Default configuration | The official `cowrie/cowrie` image with no `cowrie.cfg`, pinned by digest for the period. |
| SSH only | Cowrie's default configuration has Telnet disabled; only SSH sessions are compared, and the engine's Telnet, FTP and web sessions are left out. |
| Own traffic excluded | Connections the team made (set-up tests, the fingerprint self-audit) are listed by source address and removed from both sides. |

One deviation from stock behaviour follows from the containment and must be
stated with any result: Cowrie normally downloads the files attackers fetch
with `wget` or `curl`. Under the egress policy it cannot, so it records the
URL and no file, as this engine does by design.

### What is compared, and by which tool

`python -m app.tools.compare_cowrie`, run in the backend container, reads
Cowrie's JSON log and this deployment's sessions for one node and period and
reports, for each side:

| Metric | Why |
|---|---|
| Connections, sessions with a login, sessions with at least one command | How much each attracted and held |
| Distinct source addresses, and the overlap between the two sets | Whether the same actors visited both |
| Median and 90th-percentile session duration and commands per session | How long each kept an attacker engaged |
| Share of sessions that ended directly after a fingerprinting command sequence | Whether attackers recognised the honeypot and left |
| Distinct credentials tried, distinct commands, distinct download URLs | Breadth of what was recorded |
| Files captured (by SHA-256) | Only inbound uploads count on both sides; see the deviation above |

The tool's exact options are printed by `--help`; its output is a JSON file
that records the period, both versions (the engine's git revision and
Cowrie's image digest) and the excluded addresses. Quote that file.

### Running it

```bash
# 1. Pin the image for the period, and commit the change.
bash scripts/pin-images.sh --write

# 2. Start Cowrie (the engine is already running). The firewall must know
#    the bridge before the container starts: it does, hs-cowrie is in the plan.
cd /opt/honeysentinel/deploy/cowrie-baseline
docker compose up -d
sudo bash ../server/honeysentinel-egress.sh check

# 3. Forward the public port (or second address) to COWRIE_SSH_PORT (2022).
#    Note the time: the period starts when both are reachable.

# 4. At the end of the period, stop the forward for both, then:
sudo bash export-logs.sh
cd ../server
docker compose exec backend python -m app.tools.compare_cowrie --help
```

`COWRIE_BIND_IPV4` and `COWRIE_SSH_PORT` (in the environment or a `.env`
here) change the published address and port.

### Threats to validity, to state with the result

- Two honeypots on one address are not independent: an attacker who finds
  one may probe the other, and a scanner that blocklists the address after
  one visit never reaches the second port.
- Port 22 and a high port do not receive the same traffic. With one address,
  consider swapping the ports half-way through the period and reporting the
  halves separately.
- A single period on a single address is one sample; differences smaller
  than the day-to-day variation within it are not findings.
- Cowrie is compared in its default configuration, not as a tuned deployment.

## Taking it down

`docker compose down` (add `-v` to delete its logs). Remove the port forward
first.
