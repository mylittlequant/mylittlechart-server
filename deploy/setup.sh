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

# dig2pay billing (control box only). Empty = checkout and plan changes are
# disabled (503). Production value (a public API; no tunnel):
#   DIG2PAY_BASE_URL=https://pay.zen-geldmaschine.net/api/v1
DIG2PAY_BASE_URL=
# Files (never the values) holding the merchant bearer key and the webhook
# HMAC secret(s); several secret files, comma-separated, during a rotation.
# Production paths, delivered to the box tmpfs by the opsd unlock:
#   DIG2PAY_API_KEY_FILE=/run/mlc/dig2pay-api-key
#   DIG2PAY_WEBHOOK_SECRET_FILES=/run/mlc/dig2pay-webhook-secret
DIG2PAY_API_KEY_FILE=
DIG2PAY_WEBHOOK_SECRET_FILES=
# Host name(s) of the onion vhost — the Tor plan variants are offered only to
# requests arriving with one of these Host headers.
MLC_BILLING_ONION_HOSTS=
# Quant quota per monthly tier: plan_id=quota, comma-separated.
MLC_BILLING_QUANT_QUOTAS=
# Abuse budgets of the anonymous-account routes (per hour): checkouts per
# client IP / across all IPs, and failed account-key attempts per client IP.
# Defaults 5 / 200 / 20.
#MLC_BILLING_ANON_PER_IP_PER_HOUR=
#MLC_BILLING_ANON_GLOBAL_PER_HOUR=
#MLC_BILLING_KEY_FAILS_PER_IP_PER_HOUR=
# The one-time account plan ids default to mlc-paid-account-v1,
# mlc-anon-account-v1, mlc-paid-account-tor-v1 and mlc-anon-account-tor-v1;
# override with MLC_BILLING_PLAN_PAID / _ANON / _PAID_TOR / _ANON_TOR.
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
echo "  2. Copy the binary: scp target/release/mylittlechart-server server:/opt/mylittlechart/"
echo "  3. Copy landing: scp -r landing-pure/web/* server:/opt/mylittlechart/static/"
echo "  4. Start: sudo systemctl start $SERVICE_NAME"
echo "  5. Check: sudo journalctl -u $SERVICE_NAME -f"
echo "  6. Setup Cloudflare tunnel to proxy 443 -> localhost:3000"
