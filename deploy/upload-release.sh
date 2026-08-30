#!/usr/bin/env bash
# Publish a new release artifact for OTA distribution.
# Usage: ./upload-release.sh <platform> <version> <binary_path> [release_notes] [channel]
#
# 2026-08-30 publish redesign: the control box stores no release artifacts —
# publishing now goes through mlc-opsd (crates/opsd), which uploads the
# artifact to BOTH public edges, sha256-verifies each, and only then
# registers the manifest row on the control box. If either edge fails,
# nothing is registered — a manifest row pointing at a file that is not on
# every edge is worse than no release. See
# mylittlechart-server/crates/opsd/src/release.rs.
#
# Requires mlc-opsd built (cargo build --release -p mlc-opsd) and its daemon
# running locally with the ssh keys for both edges under env/ (see
# crates/opsd/src/state.rs) — this script is a thin wrapper over its CLI,
# which itself just calls the daemon's own `POST /api/release/publish`.
#
# Examples:
#   ./upload-release.sh win64 0.2.0 ../zengeld-terminal/target/release/chart-app-vello.exe "Bug fixes"
#   ./upload-release.sh linux64 0.2.0 ../zengeld-terminal/target/release/chart-app-vello "" stable

set -euo pipefail

PLATFORM="${1:?Usage: upload-release.sh <platform> <version> <binary_path> [release_notes] [channel]}"
VERSION="${2:?Specify version (e.g. 0.2.0)}"
BINARY="${3:?Specify path to binary}"
NOTES="${4:-Release v$VERSION}"
CHANNEL="${5:-dev}"

if [ ! -f "$BINARY" ]; then
    echo "Error: binary not found: $BINARY"
    exit 1
fi

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
ROOT_DIR="$(cd "$SCRIPT_DIR/.." && pwd)"

# mlc-opsd resolves the artifact path on its own filesystem — hand it an
# absolute one regardless of where this script was invoked from.
BINARY_ABS="$(cd "$(dirname "$BINARY")" && pwd)/$(basename "$BINARY")"

OPSD_BIN="${MLC_OPSD_BIN:-$ROOT_DIR/target/release/mlc-opsd}"
if [ ! -x "$OPSD_BIN" ] && [ -x "${OPSD_BIN}.exe" ]; then
    OPSD_BIN="${OPSD_BIN}.exe"
fi
if [ ! -x "$OPSD_BIN" ]; then
    echo "Error: mlc-opsd binary not found at $OPSD_BIN"
    echo "Build it first: cargo build --release -p mlc-opsd (or set MLC_OPSD_BIN)"
    exit 1
fi

echo "Publishing via mlc-opsd: $BINARY_ABS"
echo "Platform: $PLATFORM, Version: $VERSION, Channel: $CHANNEL"
echo ""

"$OPSD_BIN" publish "$BINARY_ABS" "$PLATFORM" "$VERSION" "$CHANNEL" "$NOTES"

echo ""
echo "Done. Verify: curl \"https://mylittlechart.org/api/updates/latest?platform=$PLATFORM&channel=$CHANNEL\""
