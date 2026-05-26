#!/bin/bash
# Wrapper script: runs mylittlechart-server in a restart loop.
#
# Key trick: copies the binary to a versioned name before running,
# so cargo can always overwrite target/release/mylittlechart-server.exe
# without "access denied" — the running process uses the copy.
#
# Deploy flow: cargo build --release → curl -X POST .../api/admin/restart
#
# To stop permanently: create a file "data/stop-server" before sending restart,
# or kill this wrapper script itself.

cd "$(dirname "$0")"

SOURCE_BINARY="./target/release/mylittlechart-server.exe"
STOP_FILE="./data/stop-server"

while true; do
    # Check for permanent stop request
    if [ -f "$STOP_FILE" ]; then
        echo "[wrapper] Stop file detected ($STOP_FILE) — exiting permanently."
        rm -f "$STOP_FILE"
        exit 0
    fi

    # Copy binary to a versioned name so cargo can freely overwrite the original
    RUNNING_BINARY="./target/release/mylittlechart-server-running.exe"
    cp -f "$SOURCE_BINARY" "$RUNNING_BINARY" 2>/dev/null

    echo "[wrapper] Starting mylittlechart-server..."
    "$RUNNING_BINARY"
    EXIT_CODE=$?
    echo "[wrapper] Server exited with code $EXIT_CODE"

    # Clean up the running copy (it's unlocked now)
    rm -f "$RUNNING_BINARY" 2>/dev/null

    # Check again after exit (admin might have created stop file before restart)
    if [ -f "$STOP_FILE" ]; then
        echo "[wrapper] Stop file detected — exiting permanently."
        rm -f "$STOP_FILE"
        exit 0
    fi

    echo "[wrapper] Restarting in 1 second..."
    sleep 1
done
