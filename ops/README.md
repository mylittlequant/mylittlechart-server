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
