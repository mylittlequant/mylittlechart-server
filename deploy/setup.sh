#!/usr/bin/env bash
# Setup script for mylittlechart.org server
# Run on the target Linux server as root

set -euo pipefail

APP_USER="mlc"
APP_DIR="/opt/mylittlechart"
SERVICE_NAME="mylittlechart"

echo "=== Setting up mylittlechart.org server ==="

# 1. Create system user
if ! id "$APP_USER" &>/dev/null; then
    useradd --system --no-create-home --shell /usr/sbin/nologin "$APP_USER"
    echo "Created user: $APP_USER"
fi

# 2. Create directories
mkdir -p "$APP_DIR"/{data/binaries,static}
chown -R "$APP_USER:$APP_USER" "$APP_DIR"
echo "Created directories under $APP_DIR"

# 3. Create .env template (if not exists)
if [ ! -f "$APP_DIR/.env" ]; then
    cat > "$APP_DIR/.env" << 'ENVEOF'
# Admin secret for binary uploads (generate: openssl rand -hex 32)
ADMIN_SECRET=CHANGE_ME

# GitHub OAuth (https://github.com/settings/developers)
GITHUB_CLIENT_ID=
GITHUB_CLIENT_SECRET=

# Discord OAuth (https://discord.com/developers/applications)
DISCORD_CLIENT_ID=
DISCORD_CLIENT_SECRET=

# Telegram Bot Token (https://t.me/BotFather)
TELEGRAM_BOT_TOKEN=
ENVEOF
    chown "$APP_USER:$APP_USER" "$APP_DIR/.env"
    chmod 600 "$APP_DIR/.env"
    echo "Created .env template — EDIT IT before starting the service"
fi

# 4. Install systemd service
cp "$(dirname "$0")/mylittlechart.service" /etc/systemd/system/
systemctl daemon-reload
systemctl enable "$SERVICE_NAME"
echo "Installed and enabled systemd service: $SERVICE_NAME"

echo ""
echo "=== Setup complete ==="
echo ""
echo "Next steps:"
echo "  1. Edit /opt/mylittlechart/.env with your secrets"
echo "  2. Copy the binary: scp target/release/zengeld-server server:/opt/mylittlechart/"
echo "  3. Copy landing: scp -r landing-pure/web/* server:/opt/mylittlechart/static/"
echo "  4. Start: sudo systemctl start $SERVICE_NAME"
echo "  5. Check: sudo journalctl -u $SERVICE_NAME -f"
echo "  6. Setup Cloudflare tunnel to proxy 443 -> localhost:3000"
