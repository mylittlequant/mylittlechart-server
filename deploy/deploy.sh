#!/usr/bin/env bash
# RETIRED. This script deployed production without a health probe and without
# a rollback, and it built for the host rather than for musl.
#
# On 2026-08-30 a deploy rolled itself back over a migration that had in fact
# succeeded, and the old binary it rolled back to was then declared unhealthy
# too — the tell that the probe, not the binary, was wrong. That incident cost
# seven account-to-device links. The lesson is that a deploy needs a probe
# aimed at the address the unit actually binds, and a rollback that proves its
# own success.
#
# `opsd` does all of that: it uploads, verifies sha256, keeps `.prev`, swaps,
# polls health 30×3s against `BIND_ADDR` read back from the systemd unit, rolls
# back on failure, and restores forward when the rollback is unhealthy too.
# This script does none of it, so it must not be the thing that is easy to run.
#
# The canonical path is in ops/README.md § Deploy pipeline:
#
#   docker run --rm -v "$(pwd -W)":/home/rust/src \
#       messense/rust-musl-cross:x86_64-musl \
#       cargo build --release --target x86_64-unknown-linux-musl
#
#   K=$(tr -d '[:space:]' < ../env/mlc-c2-1/opsd/api-key)
#   curl -s -X POST -H "Authorization: Bearer $K" -H "Content-Type: application/json" \
#        -d '{"path":"<ABSOLUTE>/target/x86_64-unknown-linux-musl/release/mylittlechart-server"}' \
#        http://127.0.0.1:18360/api/deploy
#
# musl is not a preference here: the native Windows toolchain on the dev box
# cannot build `openssl-sys` (its bundled Perl lacks Locale::Maketext::Simple),
# so the container is also the only working `cargo check` for this crate.

set -euo pipefail

cat >&2 <<'MSG'
deploy.sh is retired — it restarted production with no health probe and no
rollback. Use opsd instead; the exact commands are in ops/README.md under
"Deploy pipeline", and the reason is in the header of this file.
MSG
exit 1
