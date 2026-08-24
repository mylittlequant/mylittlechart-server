# ops/ — opbox control plane for the mylittlechart.org production box

Separate infra from mirage — standalone. Thin SSH tooling, **no agent on the
box** (zero new attack surface). See the plan:
`docs/mylittlechart-server/plans/data-backups-wasm-landing-2026-08-24.md`.

## Pieces

| Piece | Where | What |
|---|---|---|
| `ops/mlcops.py` | this repo | CLI: status / logs / restart / deploy / backup-now / backup-pull / backup-decrypt / key-push / ssh |
| box access key | `env/mlc-utah-box` (gitignored) | ed25519, root@144.172.97.222, only key allowed |
| backup key | `env/backups/backup-key` (gitignored, 0600) | AES-256-GCM key for pulled backups; opbox only |
| pulled backups | `env/backups/mlc-utah-1/*.gcm` | encrypted; `backup-decrypt` to restore |
| box snapshots | `/var/lib/mlc/backups/` on mlc-utah-1 | daily via `mlc-backup.timer` (03:17 UTC), 14 retained |
| prod watch | d-watchdog `mlc-prod-vps` (external) | https://mylittlechart.org/health monitoring on opbox |
| auto-unlock | d-watchdog process `mlc-guard` (`ops/mlc-guard.py`) | 60s loop: health down twice -> ssh probe -> if service waits for key / failed: boot-unlock (push key+secrets to box tmpfs, start), re-verify |
| opsd | `crates/opsd/` (binary `mlc-opsd`) | Rust daemon, local API 127.0.0.1:18360 + watch loop — the successor of mlcops.py/mlc-guard (v1) |

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
```

d-watchdog registration (planned at acceptance): a process service
`mlc-opsd` running the daemon, plus a healthcheck on
`http://127.0.0.1:18360/health`; `mlc-guard` is retired once opsd's watch
loop proves itself on a real box reboot.

Deferred to v1.1: `deploy` with rollback, `backup-pull` inside the daemon,
hostkey pinning, machine-bound seal of box secrets (v1 reads the canonical
env/ files at delivery time instead).

## Reboot semantics

The server waits for the SQLCipher key BEFORE binding ports, so a box reboot
shows as health-down. `mlc-guard` detects that state and delivers the key —
no operator action needed. Note: opbox is behind home NAT, the box cannot
reach opbox, so the model is "box signals state by being down, opbox guard
reacts" rather than a box-pulled queue.

## Daily use

```bash
python ops/mlcops.py status          # services, health, disk/mem
python ops/mlcops.py deploy target/x86_64-unknown-linux-musl/release/mylittlechart-server
python ops/mlcops.py backup-pull     # latest snapshot -> encrypted on opbox
```

## Deploy pipeline

Build musl binary on opbox (docker, canonical):

```bash
docker run --rm -v "$(pwd -W)":/home/rust/src messense/rust-musl-cross:x86_64-musl \
  cargo build --release --target x86_64-unknown-linux-musl
python ops/mlcops.py deploy target/x86_64-unknown-linux-musl/release/mylittlechart-server
```

## Notes

- `key-push` is for the SQLCipher design (plan §1): key pushed to tmpfs
  `/run/mlc/dbkey`, app reads+unlinks at boot, key never touches box disk.
- Backups are PULL-model: the box holds no outbound credentials; compromise
  of the box cannot destroy or poison the backup archive.
- Rollback of prod serving: old Windows path stays disabled in d-watchdog
  (`mylittlechart-server`, `cloudflared-mylittlechart`) — re-enable + revert
  DNS via `env/cloudflare/cfctl.py` if the VPS dies.
