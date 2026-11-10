# Legacy hosting files (unmaintained)

The first deployment of this project split it across three hosts: the API and
database on Render, the console on Vercel, and the engine on a separate VM.
These are the files that deployment used. They are kept for the record and
are **not maintained, not tested by CI, and not safe to expose**. Nothing in
the repository depends on them.

| File | Was |
|---|---|
| `render.yaml` | Render blueprint for the API and Postgres. |
| `vercel.json` | Vercel build settings and headers for the console. |
| `cloud-deploy.sh` | Pre-flight check that printed the manual steps for both. |
| `fetch_geoip.sh` | MaxMind GeoLite2 download (needs a licence key). |

Why they are not the supported path:

- The API ran on a public address with the whole API on one port, the engine
  routes included; the 1.0.0 design keeps the dashboard API off any network
  an engine can reach and serves engines from a separate, restricted process.
- It used one shared ingest token for every engine. The backend now expects
  a token per node (`HONEYPOT_NODE_TOKENS`) and a control token.
- Render's blueprint fitted the models at build time and had no place for
  the trained classifier, the two local model servers or the payload
  analyser's sandbox limits.
- The first administrator was created by `SEED_ON_STARTUP=true`, which also
  inserts 150 synthetic sessions next to whatever is captured.
- Nothing there limits the engine's outbound traffic.

To run the system, use [`deploy/server/`](../server/README.md) (everything on
one machine) and, for a sensor on a separate public host,
[`deploy/node/`](../node/README.md). The files here would need all of the
above addressed before they could be used again, and moving back to the
repository root (`render.yaml` and `vercel.json` are only read from there).
