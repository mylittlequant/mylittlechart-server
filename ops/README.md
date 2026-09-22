# ops/ — control plane for the mylittlechart.org production fleet

Three boxes since the 2026-08-30 split, not one. `mlc-opsd` (`crates/opsd`,
binary `mlc-opsd`) is the only control-plane tool: a local Rust daemon, API
on `127.0.0.1:18360`, that SSHes to the fleet on the operator's behalf. No
agent runs on any box (zero new attack surface there). Background:
`docs/mylittlechart-server/plans/data-backups-wasm-landing-2026-08-24.md`.

## The fleet

Public HTTP: Cloudflare DNS → nginx on **both edges** → WireGuard → control
`10.77.0.1:19200`. Control has no public web listener.

| Role | Name | Public IP | WireGuard | SSH key (`nemo/env/`) | Runs |
|---|---|---|---|---|---|
| **control** | `mlc-c2-1` | `144.172.97.2` | `10.77.0.1` | `mlc-c2-box` | `mlc-server` (`BIND_ADDR=10.77.0.1:19200`), identity + social + operational databases |
| edge (Utah) | `mlc-utah-1` | `144.172.97.222` | `10.77.0.11` | `mlc-utah-box` | nginx only, `/opt/mlc/static` (site, wasm, `/dl` release artifacts) |
| edge (Amsterdam) | `mlc-ams-1` | `107.189.17.13` | `10.77.0.12` | `mlc-ams-box` | same as Utah edge |

Code authority for these defaults: `crates/opsd/src/state.rs`
(`BOX_HOST`/`BOX_PORT`/`BOX_USER`/`BOX_SSH_KEY`/`BOX_CANON_DIR` for control,
`EDGE_DEFAULTS`/`resolve_edges` for the two edges — every field is
`MLC_BOX_*`/`MLC_EDGE_<NAME>_*` overridable, never hardcoded past that).
Verified live 2026-09-22 (SSH). Fuller background and the leftover
pre-split state: `../docs/mlc/handoffs/handoff-2026-09-11T154143Z-prod-fleet-and-identity-db-grok.md`.

Databases (`mylittlechart.db` identity+nicks, `social.db` forum/DMs/roles —
both SQLCipher, one key — plus plaintext `operational.db` and
`alert_daemon.db`) live **only** on control, `/var/lib/mlc/data/`. Neither
edge holds a copy or runs `mlc-server`; they serve static files only.

## Admin API listener

**NOT deployed yet** — code is merged (`routes::admin_api_router`,
`crates/server/src/main.rs`'s `ADMIN_BIND`/`ADMIN_PORT`), but production
still serves `/api/admin/*` on the same public path as `/api/posts`
(`10.77.0.1:19200`, behind Cloudflare → edge nginx → WireGuard, `ADMIN_SECRET`
the only lock) until the owner gives the word to deploy. Do not assume the
tunnel below works against the live box before that.

Once deployed: `mlc-server` on control binds a **third** listener,
loopback-only, control role only — `127.0.0.1:19238` by default
(`ADMIN_BIND` overrides the host, `ADMIN_PORT` the port; same override
idiom as the dashboard listener's `DASHBOARD_PORT`). Every
`ADMIN_SECRET`-gated route (`/api/admin/*`, ~28 endpoints — see
`.nemo-service.toml`) answers there and ONLY there; the main listener no
longer registers `/admin/*` at all, so an `/api/admin/*` probe against
`10.77.0.1:19200` gets the same bare 404 as any other unknown path — by
construction, not by masking (`routes/mod.rs`'s
`admin_paths_are_ordinary_unknown_paths_on_the_public_router` test proves
it).

An operator reaches it through an SSH tunnel to the box, never directly:

```sh
ssh -N -L 19238:127.0.0.1:19238 -i env/mlc-c2-box root@144.172.97.2
# then, in another shell:
curl -s -X POST -H "Authorization: Bearer $ADMIN_SECRET" http://127.0.0.1:19238/api/admin/restart
```

`ADMIN_SECRET` is still checked on every route through the tunnel — the
tunnel is the first lock, not a replacement for the bearer. `mlc-opsd`'s own
`POST /api/release/publish` reaches the admin API differently: it runs
`curl` from inside a box ssh session it already holds (not through this
tunnel), against a loopback base URL it resolves ON the box from the unit's
own `ADMIN_PORT` (same reasoning `APP_HEALTH_RESOLVE` already uses for the
main listener's `BIND_ADDR` — opsd runs on a workstation, not the box, so it
cannot know a port the operator overrode on the box without reading it
back) — see `crates/opsd/src/state.rs`'s `APP_ADMIN_RESOLVE` and
`crates/opsd/src/release.rs`'s `register_release`.

Background: `docs/mlc/audits/api-surface-hardening-2026-09-10.md` §3/§6
(the finding this closes — no separate listener carved out for
`/api/admin`, riding the same path as `/api/posts`).

## What's live vs retired

| Piece | Where | Status |
|---|---|---|
| `mlc-opsd` | `crates/opsd/` (binary `mlc-opsd`) | **live** — sole control-plane tool: local API `127.0.0.1:18360`, SSH to control + both edges, deploy/release-publish/unlock/backup-pull, own d-watchdog registration (`../d-watchdog/services.d/mlc-opsd.toml`) |
| `ops/mlcops.py`, `ops/mlc-guard.py` | (deleted) | **retired**, commit `d1c321f` — opsd v1.2 replaced both: the daemon's own watch loop does boot auto-unlock (60s tick, 5-min cooldown after any intervention) that `mlc-guard` used to do |
| `deploy/deploy.sh` | `../deploy/deploy.sh` | **retired**, refuses to run — built for the host instead of musl, `scp`+`systemctl restart` with no health probe and no rollback; cost seven account-to-device links on 2026-08-30. Kept only as a pointer into this file |
| backup key | `env/backups/backup-key` (gitignored, 0600) | live — AES-256-GCM key for pulled backups, opbox-side only |
| pulled backups | `E:\backups\mlc-c2-1\*.gcm` | live — opsd's hourly pull loop |
| box snapshots | `/var/lib/mlc/backups/` on `mlc-c2-1` | live — daily via `mlc-backup.timer` (03:17 UTC), 14 retained |

## Traps

These cost real incidents. Read before touching the fleet.

1. **Never query identity on an edge.** `mlc-utah-1` carried a full pre-split
   copy of `mylittlechart.db` (no `nick` column, stale row set) until
   2026-09-11; it now lives quarantined at
   `/var/lib/mlc/retired-pre-split-20260830/` (root, 0700) on that box. Prod
   identity is `144.172.97.2` only, never an edge.
2. `systemctl is-active mlc-server` returning `inactive` on an edge is
   **correct**, not an outage — edges run nginx only, and the unit there is
   disabled on purpose.
3. `curl 127.0.0.1:19200/health` on control does not work: the unit binds
   `10.77.0.1`, not loopback (`APP_HEALTH_RESOLVE` in
   `crates/opsd/src/state.rs` reads the bind address back from the unit's own
   environment for exactly this reason — reuse that instead of hardcoding
   loopback in a new script).
4. Ubuntu's stock `sqlcipher` CLI is format-incompatible with this project's
   bundled 4.5.7 build. Query the identity/social databases with:
   ```sh
   MLC_DBKEY_PATH=/run/mlc/dbkey /opt/mlc/mlc-dbadmin query <db-path> '<SQL>'
   ```
5. `GET /api/admin/users?q=` (and `../CICD/mlc/scripts/forum-roles.py find`)
   is a **substring search capped at 50 rows**, not a census — an empty `q`
   is a 400. Do not read it as "every user".
6. On Windows PowerShell, double quotes around a remote ssh command expand
   `$(...)` **locally** before the command ever reaches the box (a session
   once printed the local hostname into a remote script this way). Wrap the
   remote script in single quotes, or otherwise stop PowerShell from
   interpolating `$`.

Also noted 2026-09-22: `mylittlechart.db` on control was found at mode 644
under a `UMask=0077` systemd unit — a leftover from surviving the 2026-08-30
split with its pre-split permissions, not a live misconfiguration; corrected
to 600. New databases are created under 0077 already, so this should not
recur.

## `mlc-opsd`

Local axum API on `127.0.0.1:18360`. `GET /health` is open; everything under
`/api` requires `Authorization: Bearer <key>` (constant-time compare). The
key lives at `env/mlc-c2-1/opsd/api-key` — generated on first start, never
committed. State db: `env/mlc-c2-1/opsd/opsd.sqlite` (WAL; `audit_log`,
`builds`, `kv`).

| Endpoint | Auth | What |
|---|---|---|
| `GET /health` | open | liveness for d-watchdog |
| `GET /api/status` | bearer | systemd states (mlc-server/nginx/nftables/fail2ban) on control, app health, disk/mem, uptime — one ssh round-trip |
| `GET /api/box/state` | bearer | mlc-server state, dbkey in tmpfs?, journal stuck at key wait? |
| `GET /api/logs?unit=&lines=` | bearer | journal tail (unit whitelist, lines clamped to 1..500) |
| `POST /api/restart {"unit"}` | bearer | whitelist only: `mlc-server` / `nginx` / `nftables` / `fail2ban` |
| `POST /api/unlock` | bearer | boot-unlock: push canon `sqlcipher.key` + `server.env` to control's tmpfs (0600 root), start `mlc-server`, verify health |
| `POST /api/deploy {"path"}` | bearer | upload musl binary to **control** → sha256 check → save `.prev` → stop/mv/start → health-poll 30×3s against the unit's own `BIND_ADDR` → auto-rollback to `.prev` on failure; verdict + `builds`/`audit_log` records |
| `POST /api/release/publish {"path","platform","version","channel","release_notes","signature"}` | bearer | upload artifact to **every edge**, sha256-verify each, unwind what already landed if any edge fails, then register the manifest row on control (`POST /api/admin/register-release`, run from inside a box ssh session against the admin listener's loopback address — see "Admin API listener" below; NOT reachable over WireGuard at all since the 2026-09-22 split) |
| `POST /api/backup/now` | bearer | `systemctl start mlc-backup.service` on control + list `/var/lib/mlc/backups` |
| `POST /api/backup/pull` | bearer | SFTP-pull latest `*.db` + `config-*.tar.gz` from control → `E:\backups\mlc-c2-1\` → AES-256-GCM (`env/backups/backup-key`) → plaintext removed → keep 30 newest `*.db.gcm`. Box-reported filenames are whitelisted before touching the local fs |
| `GET /api/backup/list` | bearer | opbox-side archive listing (names, sizes, mtimes) |
| `GET /api/watch/state` | bearer | watch-loop counters: misses, last intervention, cooldown horizon |

`box/state` uses `systemctl show -p ActiveState,SubState,MainPID,ExecMainStatus`
(primary) with the journal grep as the fallback key-wait marker. The bind
address is overridable via `MLC_OPSD_BIND` (side-by-side test runs next to
the watchdog-managed production instance).

SSH hostkey is TOFU-pinned **per host**: control's fingerprint at
`env/mlc-c2-1/opsd/known_box_key`, each edge's own at
`env/mlc-c2-1/opsd/known_edge_key_<name>` — a compromised or rekeyed edge
cannot borrow the trust already established with another box. A later
mismatch refuses the connection, writes `hostkey_mismatch` to `audit_log`,
and fails every op against that host until the pin is reviewed by hand.

The hourly pull loop (supervised, 1h interval) lists control's
`/var/lib/mlc/backups`, compares the newest snapshot against kv
`backup_last_pulled`, and pulls only when there is something new. Verify it
ticks: `audit_log` rows with `action='backup_pull'`, log line `hourly backup
pull completed`, and kv `backup_last_pulled` advancing.

The daemon's watch loop ticks every 60s: public
`https://mylittlechart.org/health` via reqwest; two consecutive misses → ssh
probe against control → if the service waits for the key / is failed /
inactive → same unlock flow → re-verify → `audit_log`. 5-minute cooldown
after any intervention (persisted in `kv`, survives daemon restarts).

CLI (talks to the local daemon API, never ssh's directly):

```bash
cargo run -p mlc-opsd -- daemon          # serve API + watch loop
cargo run -p mlc-opsd -- status
cargo run -p mlc-opsd -- unlock
cargo run -p mlc-opsd -- restart mlc-server
cargo run -p mlc-opsd -- logs mlc-server 100
cargo run -p mlc-opsd -- deploy target/x86_64-unknown-linux-musl/release/mylittlechart-server
cargo run -p mlc-opsd -- publish <path> <platform> <version> [channel] [release_notes]
cargo run -p mlc-opsd -- backup-now
cargo run -p mlc-opsd -- backup-pull
cargo run -p mlc-opsd -- backup-list
cargo run -p mlc-opsd -- watch-state
```

d-watchdog registration: `../d-watchdog/services.d/mlc-opsd.toml` — a
process service `mlc-opsd`, healthcheck on `http://127.0.0.1:18360/health`.

Still deferred: machine-bound seal of box secrets (opsd reads the canonical
`env/` files at delivery time instead).

## Reboot semantics

`mlc-server` on control waits for the SQLCipher key BEFORE binding ports, so
a box reboot shows as health-down until unlocked. Opsd's watch loop detects
that state and delivers the key — no operator action needed. opbox is behind
home NAT and the box cannot reach it, so the model is "box signals state by
being down, opbox watch loop reacts", not a box-pulled queue.

## Daily use

The daemon's HTTP API is the interface; every mutating call carries the
bearer key from `env/mlc-c2-1/opsd/api-key`.

```bash
K=$(tr -d '[:space:]' < env/mlc-c2-1/opsd/api-key)   # CRLF in that file = a wrong bearer

curl -s -H "Authorization: Bearer $K" http://127.0.0.1:18360/api/status
curl -s -X POST -H "Authorization: Bearer $K" http://127.0.0.1:18360/api/backup/now
curl -s -X POST -H "Authorization: Bearer $K" http://127.0.0.1:18360/api/backup/pull
```

`/health` is the one endpoint that takes no key. Higher-level wrappers over
the same daemon, for the recurring jobs, live in `../CICD/mlc/scripts/`:
`deploy-server.sh`, `publish-artifact.py`, `deploy-nginx.sh`,
`deploy-app.sh` (in `mylittlechart-landing/scripts/`), `forum-roles.py`,
`nicks.py`, `notify.py`, `account-merge.py`, `publish-post.py`.

## Deploy pipeline — server binary

Build the musl binary (docker, canonical — the box runs Linux), then hand
it to opsd; it uploads to **control**, verifies sha256, keeps `.prev`,
swaps, then polls health 30×3s against the unit's own `BIND_ADDR` and rolls
back to `.prev` on failure. Two fixed commands, run from the `nemo` root:

```bash
bash CICD/mlc/scripts/build-server-musl.sh
bash CICD/mlc/scripts/deploy-server.sh
```

Do not hand-type the `docker run`. The workspace depends on the sibling
submodule `nemo-service` (`path = "../nemo-service"`, via `crates/opsd`),
and cargo reads every workspace member's manifest before building anything —
even with `-p mylittlechart-server`. A container with only this directory
mounted fails at resolution with `failed to read
/home/rust/nemo-service/Cargo.toml` (measured 2026-09-22). The build script
mounts the sibling at the matching path; a sibling dependency added later
needs its own mount there, not here.

Docker is needed for the *artifact*, not for checking the code. `cargo check
-p mylittlechart-server --release` runs natively on this Windows box in well
under a minute — SQLCipher builds against the system OpenSSL wired up in
`nemo/.cargo/config.toml`, and the `vendored-openssl` feature that used to
break the native build is scoped to the musl target only
(`crates/server/Cargo.toml`'s `cfg(target_env = "musl")` block). An earlier
version of this file claimed the docker image was the only working
`cargo check` for this crate; it is not, and gating on docker for a
type-check costs minutes per iteration.

`deploy-server.sh` waits up to 30 minutes — opsd runs the whole deploy inside the
HTTP request, and a client disconnect cancels it mid-flight (the SFTP leg
alone can take 5+ minutes on a slow link).

This is only the SERVER binary. Wasm/landing, signed native release
artifacts, and nginx config all have their own paths, none of them through
this endpoint — see `../CICD/mlc/scripts/` (`deploy-app.sh` in
`mylittlechart-landing/scripts/`, `publish-artifact.py`, `deploy-nginx.sh`)
and each script's own header comment for the full contract.

## Notes

- `key-push` (`POST /api/unlock`) is the SQLCipher boot design: key pushed to
  tmpfs `/run/mlc/dbkey` on control, the app reads and unlinks its own copy
  at boot, the key never touches box disk.
- Backups are PULL-model: the box holds no outbound credentials; compromise
  of the box cannot destroy or poison the backup archive.
- Public traffic does **not** run through a Cloudflare Tunnel on this
  Windows box — that was retired at the 2026-08-24 cutover in favor of
  direct DNS to the two edges' public IPs (`crates/server/src/main.rs`'s
  comment on `BIND_ADDR`). Any lingering local `cloudflared-mylittlechart`
  d-watchdog entry is not in the production serving path; do not treat it as
  a rollback target for the fleet described above without verifying first.
