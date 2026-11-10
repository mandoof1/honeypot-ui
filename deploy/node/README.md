# Remote sensor kit

One engine on a small public VPS, delivering what it captures to a
HoneySentinel server elsewhere. This is the second of the two exposure routes
in [docs/EXPOSURE_RUNBOOK.md](../../docs/EXPOSURE_RUNBOOK.md): the server
stays unexposed, and the address attackers find belongs to a machine that
holds nothing but the engine.

```
 internet ──► VPS public IPv4 :22 :23 :21 :80 :443 ──DNAT──► sensor (engine)
                                                              │ hs-sensor bridge
              host firewall: replies, and ONE destination ────┘
                                   │
                    private overlay (WireGuard / Tailscale)
                                   ▼
                 server: ingest endpoint (API_ROLE=ingest, this node's token)
```

**Status.** The kit is new in 1.0.0. Its firewall rules are the server's and
are exercised by `deploy/server/tests/egress-netns-test.sh` (the "one
permitted destination" case). The kit as a whole has not yet been run on a
VPS; the checklist below is what establishes that it works on yours.

## What the sensor can and cannot do

| | |
|---|---|
| Holds | its own ingest token, the HTTPS decoy's key, sessions not yet delivered, uploaded files for `HONEYPOT_UPLOAD_RETENTION_DAYS` |
| Does not hold | the database, the encryption key, any other node's token, any dashboard credential |
| May connect to | `INGEST_ADDR:INGEST_PORT`, and nothing else (replies to inbound connections aside) |
| On the server it can | register and heartbeat as its own node name and submit sessions under it. A token used under another name is refused (403) |
| Runs as | uid 10001, no capabilities, read-only root, 512 MB, 256 processes |

The server cannot reach the sensor: its control API answers on loopback
inside the container only. A mode change saved in the dashboard reaches a
sensor when it next registers (at start); blocks set in the dashboard do not
reach it. That is the price of not opening a port towards the sensor.

## Why a bridge with direct binds, not host networking

Both keep the client's real address, which the previous kit lost (it
redirected ports into `docker-proxy`, so every session came from the bridge
gateway).

- **Direct binds on a bridge (what this kit does).** The decoy ports are
  published on the VPS's IPv4 address and forwarded by DNAT. The engine has
  its own network namespace and its own interface, so the host firewall can
  state exactly what may leave it, and nothing listening on the host's
  loopback is reachable from it. Limits: IPv4 only (no IPv6 port is
  published, because Docker would proxy it and hide the client), and a
  connection made from the VPS itself shows the gateway address.
- **Host networking.** Preserves addresses for IPv4 and IPv6 and needs no
  NAT, but the engine then shares the host's network namespace: every
  loopback service is one `connect()` away, and egress can only be filtered
  by user id. For the one component that is deliberately attacked, that is
  the wrong trade.

## Runbook

On the **server** (once per sensor):

1. Publish the ingest endpoint on the overlay: follow
   `deploy/server/docker-compose.remote-sensors.example.yml`, set
   `SENSOR_INGEST_BIND` and `SENSOR_INGEST_PORT` in `.env`, re-run
   `install.sh`.
2. Restrict that port to the sensors on the overlay (a Tailscale ACL, or
   WireGuard `AllowedIPs`).
3. Issue the token: `sudo python3 deploy/server/node_tokens.py add <node-name>`,
   then `docker compose up -d backend ingest`. The token is shown once.

On the **VPS**:

4. Provision it yourself (any provider whose acceptable-use policy permits a
   honeypot; see the checklist). 1 vCPU and 1 GB are enough. Debian 12/13 or
   Ubuntu 22.04/24.04. Open TCP 21, 22, 23, 80, 443, 50000-50009 and your
   administrative SSH port in the provider's firewall.
5. Install Docker, the Compose plugin and nftables
   (`apt install docker.io docker-compose-plugin nftables`), and join the
   overlay. Confirm the server's overlay address answers:
   `curl -s -o /dev/null -w '%{http_code}\n' http://<INGEST_ADDR>:<INGEST_PORT>/health`.
6. `sudo git clone https://github.com/mandoof1/honeypot-ui.git /opt/honeysentinel`
7. `cd /opt/honeysentinel/deploy/node && sudo cp .env.example .env && sudo chmod 600 .env`,
   then fill in `.env`.
8. `sudo bash bootstrap.sh`. It moves the real sshd to port 22022 (and makes
   you prove you can still log in), loads the firewall with the one permitted
   destination, installs the units that keep it loaded, and generates the
   decoy certificate. It does not start the engine.
9. Go through the checklist below.
10. Start and test:

    ```bash
    GIT_REVISION=$(git -C /opt/honeysentinel rev-parse HEAD) docker compose up -d --build
    sudo bash ../server/honeysentinel-egress.sh probe
    ```

    `probe` connects out from inside the engine: public addresses and the
    host must be blocked, the ingest endpoint must answer. Do not leave the
    engine running if it fails.

Updating: `git pull`, then step 10 again. Stopping: `docker compose down`
(the volume with undelivered sessions is kept; add `-v` to discard it).

## Pre-exposure checklist

- [ ] The provider's acceptable-use policy allows a honeypot, and the account
      is one you can afford to lose.
- [ ] The hosting organisation's approval covers this address
      ([docs/DATA_HANDLING.md](../../docs/DATA_HANDLING.md)).
- [ ] Nothing else runs on the VPS, and it holds no credential that works
      anywhere else (no cloud API key, no SSH key to other machines).
- [ ] Administrative SSH is on another port or reachable over the overlay
      only, and you have logged in that way.
- [ ] `sudo bash ../server/honeysentinel-egress.sh check` prints `ok`.
- [ ] `sudo bash ../server/honeysentinel-egress.sh probe` ends with
      `Probe passed`.
- [ ] `systemctl list-timers honeysentinel-egress-check.timer` shows the
      check scheduled, and `systemctl cat docker` shows
      `Requires=honeysentinel-egress.service`.
- [ ] The node appears in the dashboard (Settings) as online, with the engine
      version you expect and isolation checks passing.
- [ ] From a machine outside, `ssh -p 22 root@<public address>` reaches the
      decoy, and the session appears in the dashboard **with that machine's
      public address**, not `172.30.80.1`. Record this test connection as
      yours: it is controlled traffic, not an attack.
- [ ] `docker compose logs sensor` shows no failed isolation check.

## Taking it down

`docker compose down` stops the decoys at once. To remove the sensor for
good: on the server `sudo python3 deploy/server/node_tokens.py remove <name>`
and `docker compose up -d backend ingest` (the token stops working), then
destroy the VPS. Sessions already delivered stay in the server's database.

## If the firewall check fails on the VPS

`honeysentinel-egress-check.timer` re-applies the rules and writes to the
journal at priority `crit` (`journalctl -t honeysentinel-egress`). There is
no dashboard on a sensor to alert through; the engine reports its own
isolation checks in its heartbeat, and a failing check shows on the node in
the server's dashboard.
