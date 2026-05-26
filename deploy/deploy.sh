#!/usr/bin/env bash
# Deploy new version to the server
# Usage: ./deploy.sh user@server
# Builds on local machine, uploads binary + static, restarts service

set -euo pipefail

SERVER="${1:?Usage: ./deploy.sh user@server}"
APP_DIR="/opt/mylittlechart"
SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
ROOT_DIR="$(cd "$SCRIPT_DIR/.." && pwd)"
NEMO_DIR="$(cd "$ROOT_DIR/.." && pwd)"

echo "=== Building mylittlechart-server (release) ==="
cd "$ROOT_DIR"
cargo build --release

echo "=== Uploading binary ==="
scp "$ROOT_DIR/target/release/mylittlechart-server" "$SERVER:$APP_DIR/mylittlechart-server.new"
ssh "$SERVER" "mv $APP_DIR/mylittlechart-server.new $APP_DIR/mylittlechart-server && chmod +x $APP_DIR/mylittlechart-server"

echo "=== Uploading landing page ==="
scp -r "$NEMO_DIR/mylittlechart-landing/web/"* "$SERVER:$APP_DIR/static/"

echo "=== Restarting service ==="
ssh "$SERVER" "sudo systemctl restart mylittlechart"

echo "=== Checking status ==="
ssh "$SERVER" "sudo systemctl status mylittlechart --no-pager"

echo ""
echo "=== Deploy complete ==="
