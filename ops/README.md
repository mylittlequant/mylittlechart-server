# ops/ — opbox control plane for the mylittlechart.org production box

Separate infra from mirage — standalone. Thin SSH tooling, **no agent on the
box** (zero new attack surface). See the plan:
`docs/mylittlechart-server/plans/data-backups-wasm-landing-2026-08-24.md`.

## Pieces

| Piece | Where | What |
|---|---|---|
| `ops/mlcops.py` | this repo | **deprecated-by-opsd** (fallback only; main deletes after opsd acceptance). CLI: status / logs / restart / deploy / backup-now / backup-pull / backup-decrypt / key-push / ssh |
| box access key | `env/mlc-utah-box` (gitignored) | ed25519, root@144.172.97.222, only key allowed |
| backup key | `env/backups/backup-key` (gitignored, 0600) | AES-256-GCM key for pulled backups; opbox only |
| pulled backups | `E:\backups\mlc-utah-1\*.gcm` | encrypted; opsd `backup-pull` (hourly loop) / `backup-decrypt` to restore |
| box snapshots | `/var/lib/mlc/backups/` on mlc-utah-1 | daily via `mlc-backup.timer` (03:17 UTC), 14 retained |
| prod watch | d-watchdog `mlc-prod-vps` (external) | https://mylittlechart.org/health monitoring on opbox |
| auto-unlock | d-watchdog process `mlc-guard` (`ops/mlc-guard.py`) | **deprecated-by-opsd** — opsd's watch loop does this (60s tick, auto boot-unlock, 5-min cooldown) |
| opsd | `crates/opsd/` (binary `mlc-opsd`) | Rust daemon, local API 127.0.0.1:18360 + watch loop + hourly backup pull — **the sole owner of the pull cycle** |

> Retired once opsd v1.2 is accepted: the Windows Task Scheduler task
> `mlc-backup-pull` (python), `ops/mlc-guard.py`, and `ops/mlcops.py` as the
> daily driver. The `.py` files stay in the repo until main removes them.

## mlc-opsd (v1)

`mlc-opsd` is the Rust control plane replacing the Python tooling above (the
`.py` files stay as fallback until opsd is accepted). Local axum API on
`127.0.0.1:18360`; `GET /health` is open, everything under `/api` requires
`Authorization: Bearer <key>` (constant-time compare). The API key lives at
`env/mlc-utah-1/opsd/api-key` — generated on first start, never committed
(env/ is gitignored). State db: `env/mlc-utah-1/opsd/opsd.sqlite` (WAL;
`audit_log`, `builds`, `kv`).

Endpoints:

| Endpoint | Auth | What |
|---|---|---|
| `GET /health` | open | liveness for d-watchdog |
| `GET /api/status` | bearer | systemd states (mlc-server/nginx/nftables/fail2ban), app health, disk/mem, uptime — one ssh round-trip |
| `GET /api/box/state` | bearer | mlc-server state, dbkey in tmpfs?, journal stuck at key wait? |
| `GET /api/logs?unit=&lines=` | bearer | journal tail (unit whitelist, lines clamped to 1..500) |
| `POST /api/restart {"unit"}` | bearer | whitelist only: mlc-server / nginx / fail2ban |
| `POST /api/unlock` | bearer | boot-unlock: push canon `sqlcipher.key` + `server.env` to box tmpfs (0600 root), start mlc-server, verify health |
| `POST /api/deploy {"path"}` | bearer | upload musl binary → sha256 check → save `.prev` → stop/mv/start → health-poll 30×3s → auto-rollback to `.prev` on failure; verdict + `builds`/`audit_log` records |
| `POST /api/backup/now` | bearer | `systemctl start mlc-backup.service` + list `/var/lib/mlc/backups` |
| `POST /api/backup/pull` | bearer | SFTP-pull latest `*.db` + `config-*.tar.gz` → `E:\backups\mlc-utah-1\` → AES-256-GCM (`env/backups/backup-key`, same nonce\|\|ct format as mlcops.py) → plaintext removed → keep 30 newest `*.db.gcm`. Box-reported filenames are whitelisted before touching the local fs |
| `GET /api/backup/list` | bearer | opbox-side archive listing (names, sizes, mtimes) |
| `GET /api/watch/state` | bearer | watch-loop counters: misses, last intervention, cooldown horizon |

`box/state` uses `systemctl show -p ActiveState,SubState,MainPID,ExecMainStatus`
(primary) with the journal grep as the fallback key-wait marker. The bind
address is overridable via `MLC_OPSD_BIND` (side-by-side test runs next to
the watchdog-managed production instance).

SSH hostkey is TOFU-pinned: the first connect writes the box's SHA256
fingerprint to `env/mlc-utah-1/opsd/known_box_key`; a later mismatch refuses
the connection, writes `hostkey_mismatch` to `audit_log`, and fails every op
until the pin is reviewed by hand.

The hourly pull loop (supervised, 1h interval) lists `/var/lib/mlc/backups`,
compares the newest snapshot against kv `backup_last_pulled`, and pulls only
when there is something new. Verify it ticks: `audit_log` rows with
`action='backup_pull'`, log line `hourly backup pull completed`, and kv
`backup_last_pulled` advancing.

The daemon's watch loop ticks every 60s: public `https://mylittlechart.org/health`
via reqwest; two consecutive misses -> ssh probe -> if the service waits for
the key / is failed / inactive -> same unlock flow -> re-verify -> audit_log.
5-minute cooldown after any intervention (persisted in `kv`, survives daemon
restarts).

CLI (talks to the local daemon API, never ssh'es directly):

```bash
cargo run -p mlc-opsd -- daemon          # serve API + watch loop
cargo run -p mlc-opsd -- status
cargo run -p mlc-opsd -- unlock
cargo run -p mlc-opsd -- restart mlc-server
cargo run -p mlc-opsd -- logs mlc-server 100
cargo run -p mlc-opsd -- deploy target/x86_64-unknown-linux-musl/release/mylittlechart-server
cargo run -p mlc-opsd -- backup-now
cargo run -p mlc-opsd -- backup-pull
cargo run -p mlc-opsd -- backup-list
cargo run -p mlc-opsd -- watch-state
```

d-watchdog registration (planned at acceptance): a process service
`mlc-opsd` running the daemon, plus a healthcheck on
`http://127.0.0.1:18360/health`; `mlc-guard` is retired once opsd's watch
loop proves itself on a real box reboot.

Still deferred: machine-bound seal of box secrets (opsd reads the canonical
env/ files at delivery time instead).

## Reboot semantics

The server waits for the SQLCipher key BEFORE binding ports, so a box reboot
shows as health-down. `mlc-guard` detects that state and delivers the key —
no operator action needed. Note: opbox is behind home NAT, the box cannot
reach opbox, so the model is "box signals state by being down, opbox guard
reacts" rather than a box-pulled queue.

## Daily use

`ops/mlcops.py` was retired in `d1c321f` once opsd was accepted, and the file is
gone. The daemon's HTTP API is the interface; every mutating call carries the
bearer key from `env/mlc-c2-1/opsd/api-key`.

```bash
K=$(cat env/mlc-c2-1/opsd/api-key)

curl -s -H "Authorization: Bearer $K" http://127.0.0.1:18360/api/status
curl -s -X POST -H "Authorization: Bearer $K" http://127.0.0.1:18360/api/backup/now
curl -s -X POST -H "Authorization: Bearer $K" http://127.0.0.1:18360/api/backup/pull
```

`/health` is the one endpoint that takes no key.

## Deploy pipeline

Build the musl binary (docker, canonical) and hand opsd its absolute path — it
uploads, verifies sha256, keeps `.prev`, swaps, then polls health 30×3s and
rolls back to `.prev` on failure:

```bash
docker run --rm -v "$(pwd -W)":/home/rust/src messense/rust-musl-cross:x86_64-musl \
  cargo build --release --target x86_64-unknown-linux-musl

curl -s -X POST -H "Authorization: Bearer $K" -H "Content-Type: application/json" \
  -d '{"path":"<ABSOLUTE>/target/x86_64-unknown-linux-musl/release/mylittlechart-server"}' \
  http://127.0.0.1:18360/api/deploy
```

The same docker image runs `cargo check` — the native-Windows toolchain here
cannot build `openssl-sys` (its bundled Perl lacks `Locale::Maketext::Simple`),
so musl is the only working verification path on this box.

## Notes

- `key-push` is for the SQLCipher design (plan §1): key pushed to tmpfs
  `/run/mlc/dbkey`, app reads+unlinks at boot, key never touches box disk.
- Backups are PULL-model: the box holds no outbound credentials; compromise
  of the box cannot destroy or poison the backup archive.
- Rollback of prod serving: old Windows path stays disabled in d-watchdog
  (`mylittlechart-server`, `cloudflared-mylittlechart`) — re-enable + revert
  DNS via `env/cloudflare/cfctl.py` if the VPS dies.
