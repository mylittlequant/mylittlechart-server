#!/usr/bin/env bash
# Upload a new release binary for OTA distribution
# Usage: ./upload-release.sh <platform> <version> <binary_path> [release_notes]
#
# Examples:
#   ./upload-release.sh win64 0.2.0 ../zengeld-terminal/target/release/chart-app-vello.exe "Bug fixes"
#   ./upload-release.sh linux64 0.2.0 ../zengeld-terminal/target/release/chart-app-vello

set -euo pipefail

PLATFORM="${1:?Usage: upload-release.sh <platform> <version> <binary_path> [release_notes]}"
VERSION="${2:?Specify version (e.g. 0.2.0)}"
BINARY="${3:?Specify path to binary}"
NOTES="${4:-Release v$VERSION}"

SERVER_URL="${SERVER_URL:-https://mylittlechart.org}"
ADMIN_SECRET="${ADMIN_SECRET:?Set ADMIN_SECRET env var}"

if [ ! -f "$BINARY" ]; then
    echo "Error: binary not found: $BINARY"
    exit 1
fi

SIZE=$(stat -c%s "$BINARY" 2>/dev/null || stat -f%z "$BINARY")
echo "Uploading: $BINARY ($SIZE bytes)"
echo "Platform: $PLATFORM, Version: $VERSION"
echo "Server: $SERVER_URL"
echo ""

# URL-encode release notes (basic)
ENCODED_NOTES=$(python3 -c "import urllib.parse; print(urllib.parse.quote('$NOTES'))" 2>/dev/null || echo "$NOTES")

curl -X POST \
    -H "Authorization: Bearer $ADMIN_SECRET" \
    -H "Content-Type: application/octet-stream" \
    --data-binary "@$BINARY" \
    "$SERVER_URL/api/admin/upload?platform=$PLATFORM&version=$VERSION&release_notes=$ENCODED_NOTES" \
    | python3 -m json.tool 2>/dev/null || cat

echo ""
echo "Done. Verify: curl $SERVER_URL/api/updates/latest?platform=$PLATFORM"
