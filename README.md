# mylittlechart-server

Backend server for mylittlechart.org — serves landing page, distributes OTA updates, collects telemetry, and handles OAuth authentication.

## Running

Production (via Cloudflare Tunnel on port 19200):
```bash
cd c:\Users\VA PC\CODING\ML_TRADING\nemo\mylittlechart-server
bash run-server.sh       # wrapper — auto-restarts on exit
```

Build:
```bash
cargo build --release
```

## Deploying (zero-downtime)

The server runs inside a wrapper script (`run-server.sh` / `run-server.bat`) that auto-restarts the process after graceful shutdown. Downtime: ~1.5 seconds (Cloudflare retries during this window).

**Key trick**: the wrapper copies the binary to `mylittlechart-server-running.exe` before launching, so cargo can always overwrite the original `target/release/mylittlechart-server.exe` without "access denied" — the running process uses the copy.

```bash
# 1. Build new binary (NEVER blocked — running process uses a copy)
cd c:\Users\VA PC\CODING\ML_TRADING\nemo\mylittlechart-server
cargo build --release

# 2. Trigger graceful restart (wrapper copies new binary → starts it)
curl -s -X POST http://127.0.0.1:19200/api/admin/restart \
  -H "Authorization: Bearer <ADMIN_SECRET>"
```

Flow: `cargo build` → overwrites `mylittlechart-server.exe` (unlocked) → `POST /admin/restart` → server exits → wrapper deletes old `-running` copy → copies new build to `-running` → starts it.

To stop permanently (no restart): `touch data/stop-server` before sending restart.

## Environment Variables

| Variable | Default | Required | Notes |
|----------|---------|----------|-------|
| `PORT` | `19200` | No | Listen port |
| `DATA_DIR` | `./data` | No | DB + binaries root |
| `ADMIN_SECRET` | `""` | Yes (for upload) | If empty, `/api/admin/upload` returns 503 |
| `GITHUB_CLIENT_ID` | `""` | For GitHub OAuth | |
| `GITHUB_CLIENT_SECRET` | `""` | For GitHub OAuth | |
| `DISCORD_CLIENT_ID` | `""` | For Discord OAuth | |
| `DISCORD_CLIENT_SECRET` | `""` | For Discord OAuth | |
| `GOOGLE_CLIENT_ID` | `""` | For Google OAuth | |
| `GOOGLE_CLIENT_SECRET` | `""` | For Google OAuth | |
| `TWITTER_CLIENT_ID` | `""` | For Twitter/X OAuth | PKCE (S256) required |
| `TWITTER_CLIENT_SECRET` | `""` | For Twitter/X OAuth | |
| `TELEGRAM_BOT_TOKEN` | `""` | For Telegram OAuth | |
| `STATIC_DIR` | auto-detect | No | Overrides static file path |
| `SYNC_ENCRYPTION_KEY` | `""` | Yes (for cloud sync) | 64-char hex key for AES-256-GCM at-rest encryption of sync items |
| `BUILD_ATTEST_PUBKEY` | `""` | No | Hex Ed25519 public key(s), comma-separated, for build attestation verification |
| `BUILD_ATTEST_ENFORCE` | `false` | No | If `true`, reject client requests that fail build attestation check |
| `BUILD_ATTEST_MAX_AGE_DAYS` | `365` | No | Maximum age of a build attestation token before it is considered expired |

## API Endpoints

| Method | Path | Auth | Description |
|--------|------|------|-------------|
| POST | `/api/admin/upload?platform=X&version=Y&release_notes=Z` | Bearer ADMIN_SECRET | Upload release binary (max 200MB) |
| POST | `/api/admin/restart` | Bearer ADMIN_SECRET | Trigger graceful shutdown (wrapper auto-restarts) |
| POST | `/api/heartbeat` | None | Device keep-alive |
| POST | `/api/telemetry` | Optional Bearer token | Submit usage metrics |
| GET | `/api/updates/latest?platform=win64` | None | Get latest version manifest |
| GET | `/api/updates/download/{platform}/{version}` | None | Download binary (`version` can be `"latest"`) |
| GET | `/api/oauth/{provider}/authorize` | None | Start OAuth flow (github/discord/google/twitter); expects `?redirect_port=PORT&device_id=UUID`. Pass `?link=1` to link a provider to an existing web session account. |
| GET | `/api/oauth/{provider}/web-callback` | None | OAuth callback for web flow (browser redirect from provider). If `link_user_id` was stored in state, merges provider into existing account. |
| POST | `/api/oauth/telegram/web-callback` | None | Telegram bot login callback (receives JSON from telegram-redirect page) |
| POST | `/api/oauth/{provider}/callback` | None | Complete OAuth flow (desktop app) |
| POST | `/api/oauth/telegram/callback` | None | Telegram auth callback (desktop app) |
| POST | `/api/auth/tg-login` | None | Create Telegram login token, returns `{token, bot_url}` (5-min TTL) |
| GET | `/api/auth/tg-login/poll?token=X` | None | Poll Telegram login status. Returns `{status: pending\|confirmed\|expired}`. On `confirmed`, sets session cookie. |
| POST | `/api/auth/device-code` | None | Generate 8-char device linking code (10-min TTL) |
| GET | `/api/auth/poll?code=X` | None | Poll device code status (exactly-once token delivery) |
| POST | `/api/auth/confirm` | Cookie session | Confirm device code from web dashboard |
| GET | `/api/auth/me` | Cookie session | Get current user info + all linked providers |
| POST | `/api/auth/logout` | Cookie session | Destroy web session |
| POST | `/api/auth/keys/generate` | Cookie session | Generate API key with label + permissions |
| POST | `/api/auth/agent-key/request` | None (rate limited) | Agent requests key (device code pattern) |
| GET | `/api/auth/agent-key/poll` | None | Poll key request status |
| POST | `/api/auth/agent-key/confirm` | Cookie session | User approves agent key request |
| POST | `/api/auth/agent-key/deny` | Cookie session | User denies agent key request |
| GET | `/api/auth/agent-key/info` | None | Get request info by code |
| GET | `/api/auth/keys` | Bearer | List all keys (device token auth) |
| DELETE | `/api/auth/keys/:hash_prefix` | Cookie session | Revoke a key |
| PATCH | `/api/auth/keys/usage` | Bearer | Batch update key usage (last_used_at, last_ip) |
| GET | `/api/auth/sessions` | Cookie session | List all active Bearer tokens for the user (label, source, last_ip, created_at, expires_at). Returns rows from `auth_tokens`. |
| DELETE | `/api/auth/sessions/:hash_prefix` | Cookie session | Revoke one token by hash prefix (min 8 chars). |
| GET | `/api/auth/account/export` | Cookie session | GDPR data export — returns `{ user, sync_items (metadata only), auth_tokens }` as a JSON file download. |
| POST | `/api/auth/account/delete` | Cookie session | Permanently delete account + all data. Requires `X-Confirm-Delete: yes` header AND `{ "confirm": "DELETE" }` body. Cascades: e2e_params → sync_items → auth_tokens → device_users → user_providers → web_sessions → users. |
| GET | `/api/sync/status` | Bearer | Sync status. Returns `{ has_cloud_data, item_count, last_modified, quota_used_bytes, quota_limit_bytes }`. `quota_limit_bytes` is 52428800 (50 MiB). |
| GET | `/api/sync/changes` | Bearer | Changes since cursor timestamp. Response includes `server_timestamp` (Unix ms) — clients use this as the cursor for the next incremental sync call. |
| POST | `/api/sync/push` | Bearer | Push sync items (AES-256-GCM encrypted at rest) |
| GET | `/api/sync/pull` | Bearer | Pull all sync items (decrypted) |
| DELETE | `/api/sync/item/:sync_id` | Bearer | Soft-delete sync item (tombstone) |
| DELETE | `/api/sync/all` | Bearer | Hard-delete all user sync data |
| GET | `/api/sync/e2e-params` | Bearer | Get E2E encryption params (salt, iterations) |
| POST | `/api/sync/e2e-setup` | Bearer | Set up E2E encryption |

## Directory Structure

```
c:\Users\VA PC\CODING\ML_TRADING\nemo\mylittlechart-server\
├── Cargo.toml                    # [workspace] — members = ["crates/*"]
├── .env                          # ADMIN_SECRET + OAuth credentials
├── run-server.sh                 # Restart-loop wrapper (bash). Copies exe to -running before launch.
├── run-server.bat                # Restart-loop wrapper (Windows). Same copy trick.
├── deploy/
│   ├── deploy.sh                 # Automated deploy script
│   ├── mylittlechart.service     # systemd service file (Linux VPS deployment)
│   ├── setup.sh                  # Server setup script
│   └── upload-release.sh         # Release upload helper
├── data/
│   ├── mylittlechart.db                # SQLite (WAL mode)
│   └── binaries/
│       └── win64/
│           └── {version}/zengeld-win64-{version}.exe
└── crates/
    ├── server/                   # Main Axum HTTP server
    │   ├── Cargo.toml
    │   └── src/
    │       ├── main.rs           # Entry point, router, static files, TG bot startup, graceful shutdown
    │       ├── lib.rs            # Crate root, shared re-exports
    │       ├── auth.rs           # Token hashing, bearer extraction, session/UA helpers
    │       ├── crypto.rs         # AES-256-GCM encryption/decryption for cloud sync at rest
    │       ├── db.rs             # SQLite schema + queries (auto-migration)
    │       ├── state.rs          # AppState struct
    │       ├── models/
    │       │   ├── mod.rs
    │       │   └── types.rs      # Request/response structs
    │       └── routes/
    │           ├── mod.rs        # api_router() assembly
    │           ├── admin.rs      # Binary upload
    │           ├── agent_keys.rs # Agent API key generate/request/confirm/poll/revoke
    │           ├── dashboard.rs  # Admin dashboard routes
    │           ├── device_auth.rs # Device code flow, web sessions
    │           ├── heartbeat.rs  # Device heartbeat
    │           ├── oauth.rs      # GitHub/Discord/Google/Twitter OAuth + web-callback
    │           ├── sessions.rs   # Session list/revoke + account export/delete (cookie-only auth)
    │           ├── sync.rs       # Cloud sync push/pull/changes/delete
    │           ├── tg_login.rs   # Telegram bot login (create token + poll status)
    │           ├── telemetry.rs  # Metrics ingestion
    │           └── updates.rs    # Version manifest + binary streaming
    └── tg-login-bot/             # Telegram login bot (long-polling)
        ├── Cargo.toml
        └── src/
            └── lib.rs            # Bot loop: getUpdates, /start web_<token> handler
```

## Database Tables

- **releases**: `(id, version, platform, sha256, file_path, file_size, release_notes, signature, created_at)` — UNIQUE(version, platform), upsert on conflict; `signature` is a base64-encoded Ed25519 signature over the binary bytes (for OTA code signing)
- **devices**: `(device_id PK, device_name, app_version, os, first_seen, last_seen, total_heartbeats)` — updated on each heartbeat
- **telemetry**: `(id, device_id, user_id, received_at, app_version, os, arch, gpu_name, screen_*, connector_count, window_count, avg_fps, uptime_secs, total_bars, ws_connections)` — append-only, one row per 5-min check-in
- **users**: `(id, public_id, provider, provider_user_id, display_name, created_at)` — UNIQUE(provider, provider_user_id); `public_id` is a 32-char random hex exposed in APIs instead of sequential `id`. Orphan rows (no linked providers) are auto-cleaned on startup.
- **user_providers**: `(id, user_id, provider, provider_user_id, display_name, linked_at)` — UNIQUE(provider, provider_user_id); maps multiple provider identities to one `user_id`. Auto-populated from `users` on first migration. Used by `/api/auth/me` to return all linked providers.
- **auth_tokens**: `(token_hash PK, user_id, created_at, expires_at)` — SHA-256 of raw token; tokens expire 30 days after creation
- **oauth_states**: `(state PK, provider, redirect_port, device_id, link_user_id, created_at)` — CSRF tokens stored during OAuth flow; `link_user_id` is set when `?link=1` is used (provider linking flow); auto-cleaned up after 10 minutes
- **device_users**: `(device_id, user_id, linked_at)` — PRIMARY KEY(device_id, user_id); links desktop devices to authenticated user accounts; one device resolves to one canonical user across multiple providers
- **web_sessions**: `(session_id PK, user_id, created_at, expires_at, ua_hash)` — HttpOnly cookie sessions for web dashboard; 24h TTL; bound to User-Agent fingerprint
- **device_codes**: `(code PK, device_id, user_id, status, created_at, expires_at)` — 8-char codes for device→web account linking; 10-min TTL; status: pending→confirmed→claimed (exactly-once token delivery)
- **tg_login_tokens**: `(token PK, status, telegram_user_id, display_name, link_user_id, created_at, expires_at)` — Telegram bot login tokens; 5-min TTL; status: pending→confirmed→claimed (exactly-once delivery via atomic UPDATE)
- **agent_key_requests**: pending agent API key requests initiated by the terminal (device code pattern); stores request code, requested permissions, TTL, and user confirmation status
- **sync_items**: `(sync_id, user_id, category, name, content, checksum, modified_at, deleted, created_at)` — cloud sync data store; `content` is AES-256-GCM encrypted at rest; `deleted=1` is a soft-delete tombstone
- **sync_e2e_params**: `(user_id PK, salt, iterations)` — per-user E2E encryption parameters; stored when user sets up end-to-end encryption on top of the at-rest layer

## Landing Page

Static files served from (in order of priority):
1. `STATIC_DIR` env var
2. `../mylittlechart-landing/web` (dev mode, relative path)
3. `./static` (production fallback)

Rebuild WASM landing:
```bash
cd c:\Users\VA PC\CODING\ML_TRADING\nemo\mylittlechart-landing
wasm-pack build crates/landing-canvas --target web --out-dir "$(pwd)/web/pkg"
```

## Upload a New Release

```bash
curl -X POST "https://mylittlechart.org/api/admin/upload?platform=win64&version=X.Y.Z&release_notes=..." \
  -H "Authorization: Bearer <ADMIN_SECRET>" \
  --data-binary @path/to/binary.exe
```

The server computes SHA-256, saves to `data/binaries/{platform}/{version}/`, and inserts/updates the DB record.

## Security

- Admin upload: constant-time secret comparison (`subtle` crate), path traversal protection, empty secret = endpoint disabled
- Telemetry: all string fields sanitized (printable ASCII only, length-capped), numeric fields clamped
- Device ID: UUID format validation (hex + hyphens, max 36 chars)
- OAuth: CSRF state validation via `consume_oauth_state()` — state token is single-use and expires after 10 minutes; tokens expire after 30 days
- Device linking: one `device_id` maps to one canonical user account; connecting additional OAuth providers merges into the existing account rather than creating a new one
- Telegram: bot login tokens are 32-char hex with 5-min TTL; bot verifies token exists and is pending before confirming; poll endpoint uses atomic claimed transition for exactly-once delivery
- Twitter/X: PKCE (S256 method) required — code verifier generated per-request, never stored server-side
- Web sessions: HttpOnly + Secure + SameSite=Strict cookies, 24h TTL, bound to User-Agent fingerprint (SHA-256)
- Public IDs: external APIs return 32-char random hex `public_id` instead of sequential autoincrement `id` to prevent enumeration
- Provider linking guard: `link_provider_to_user()` checks existing ownership before attaching — refuses to steal identity from another account
- Orphan cleanup: `cleanup_orphan_users()` runs on startup, deletes user rows with no linked providers
- No application-level rate limiting (handled at Cloudflare)
- Graceful shutdown: Ctrl+C / SIGTERM triggers clean shutdown with in-flight request draining

## Agent API Key System

API keys gate access to the terminal's local agent API (localhost:17420). Two flows:

**Manual flow (user-initiated):**
1. Logged-in user on `/dashboard` → `POST /api/auth/keys/generate` with `{label, permissions[]}`
2. Server returns a raw key (shown once). Key hash stored in `agent_keys` table.
3. Terminal polls `GET /api/auth/keys` (Bearer device token) to sync keys from the cloud.

**Agent-initiated flow (device code pattern):**
1. Terminal (or agent) calls `POST /api/auth/agent-key/request` with desired label + permissions → gets a short request code
2. User navigates to `/keys/confirm?code=X` — page shows what the agent is requesting
3. User clicks Approve → `POST /api/auth/agent-key/confirm` (cookie session required)
4. Agent polls `GET /api/auth/agent-key/poll?code=X` → receives the raw key on approval (exactly-once delivery)
5. User can deny instead → `POST /api/auth/agent-key/deny`

Keys can be revoked at any time via `DELETE /api/auth/keys/:hash_prefix` (cookie session). Usage tracking (last_used_at, last_ip) is updated via `PATCH /api/auth/keys/usage`.

## Cloud Sync

Settings and chart state are synced to the server, encrypted at rest with AES-256-GCM using `SYNC_ENCRYPTION_KEY`.

**Sync categories:** `preset`, `watchlist`, `template_primitive`, `template_indicator`, `settings_snapshot`

**Soft-delete pattern:** deleted items remain in `sync_items` with `deleted=1` (tombstone) so clients can detect deletions on pull. Hard-delete via `DELETE /api/sync/all` removes all rows for the user.

**Quota:** 100 items / 50 MB per user.

**Optional E2E encryption:** users can layer their own client-side encryption on top. `POST /api/sync/e2e-setup` stores PBKDF2 params (salt, iterations) in `sync_e2e_params`; clients derive the key locally — the server never sees the plaintext in this mode.

**Cursor-based sync:** `GET /api/sync/changes?since=<unix_ms>` returns only items modified after the given timestamp, enabling efficient incremental sync.

## Build Attestation

Protected endpoints can require clients to present a signed build token proving they are a legitimate release binary.

- Signature scheme: Ed25519
- Token contains: binary hash, build timestamp, version
- Server verifies signature against `BUILD_ATTEST_PUBKEY` (one or more public keys, comma-separated)
- If `BUILD_ATTEST_ENFORCE=true`, requests from unsigned or expired clients are rejected
- `BUILD_ATTEST_MAX_AGE_DAYS` sets how long a build token remains valid (default: 365 days)

## OTA Code Signing

Release binaries uploaded via `POST /api/admin/upload` can include an Ed25519 signature over the binary bytes. The signature is stored in the `signature` column of the `releases` table (base64-encoded).

The client (`updater` crate) verifies the signature against the embedded public key before applying an update. This prevents a compromised server or MITM from pushing tampered binaries. Unsigned releases (empty `signature`) are accepted unless the client is built with enforcement enabled.

## OAuth Flow

Supported providers: GitHub, Discord, Google, Twitter/X, Telegram

Desktop app flow:
1. Client opens browser → `GET /api/oauth/{provider}/authorize?redirect_port=17421&device_id=UUID`
2. Server stores CSRF state + `device_id` in `oauth_states`, redirects browser to provider
3. Provider authenticates user, redirects to `http://localhost:17421/callback?code=X&state=Y`
4. Client captures code, sends `POST /api/oauth/{provider}/callback` with code + state
5. Server validates CSRF via `consume_oauth_state()`, exchanges code for provider token, fetches user profile
6. Server links `device_id` → `user_id` in `device_users`, returns app token (30-day expiry)

Device linking: if `device_id` already has a linked user, new providers are merged into the existing account. The same app token is returned regardless of which provider was used to authenticate.

Web flow:
1. User visits `https://mylittlechart.org/login` → clicks provider button
2. Browser → `GET /api/oauth/{provider}/authorize` (no redirect_port) → provider login
3. Provider redirects to `GET /api/oauth/{provider}/web-callback`
4. Server exchanges code, upserts user, populates `user_providers`, creates web session cookie, redirects to `/dashboard`

Provider linking flow (add another OAuth to existing account):
1. Logged-in user on `/dashboard` clicks "Link GitHub" (or any unlinked provider)
2. Browser → `GET /api/oauth/{provider}/authorize?link=1`
3. Server extracts `user_id` from session cookie, stores it as `link_user_id` in `oauth_states`
4. Provider authenticates → redirect to `GET /api/oauth/{provider}/web-callback`
5. Server sees `link_user_id` in consumed state → calls `link_provider_to_user()` instead of creating new account
6. Session is recreated for same `user_id`, redirects to `/dashboard`

Telegram bot login flow:
1. User clicks "Continue with Telegram" → JS calls `POST /api/auth/tg-login` → gets `{token, bot_url}`
2. Page opens `bot_url` (`t.me/mylittlechart_login_bot?start=web_<token>`) → Telegram native app opens
3. User presses Start in bot → bot receives `/start web_<token>`
4. Bot validates token in DB, sets status = "confirmed" with user's telegram_user_id + display_name
5. Bot sends confirmation message to user
6. Page polls `GET /api/auth/tg-login/poll?token=X` every 2s → gets `confirmed` + session cookie → redirects to `/dashboard`

For provider linking: `POST /api/auth/tg-login?link=1` — stores session's user_id in the token, bot confirmation merges TG identity into existing account.

Device authorization flow (link desktop app to web account):
1. App generates 8-char code → `POST /api/auth/device-code`
2. User enters code on web dashboard → `POST /api/auth/confirm` (requires cookie session)
3. App polls `GET /api/auth/poll?code=X` — gets token on confirmation (exactly-once delivery)

## Web Pages

| URL | File | Description |
|-----|------|-------------|
| `/` | `mylittlechart-landing/web/index.html` | WASM canvas landing page. Navbar has "Login" link (desktop/tablet). |
| `/login` | `mylittlechart-landing/web/login.html` | 5 OAuth buttons (GitHub, Discord, Google, Twitter/X, Telegram via bot). Telegram opens native app. Cookie consent banner. |
| `/dashboard` | `mylittlechart-landing/web/dashboard.html` | User profile, all linked providers, "Link Another Provider" buttons, device code input. Cookie consent banner. |
| `/privacy` | `mylittlechart-landing/web/privacy.html` | Privacy policy with cookie disclosure (session_id). Cookie consent banner. |
| `/telegram-redirect` | `mylittlechart-landing/web/telegram-redirect.html` | Legacy fallback page (unused since bot login flow) |
| `/changelog` | `mylittlechart-landing/web/changelog.html` | Product changelog |
| `/roadmap` | `mylittlechart-landing/web/roadmap.html` | Public product roadmap |
| `/terms` | `mylittlechart-landing/web/terms.html` | Terms of service |
| `/keys/confirm` | `mylittlechart-landing/web/keys/confirm.html` | Agent key confirmation page (user approves/denies pending key request) |
| `/sync` | `mylittlechart-landing/web/sync.html` | Cloud sync management — quota bar, storage stats, E2E status. Links to `/e2e-guide`. |
| `/e2e-guide` | `mylittlechart-landing/web/e2e-guide.html` | E2E encryption guide — explains client-side encryption setup flow. Public, no auth required. |

## Infrastructure

- Domain: `mylittlechart.org`
- Cloudflare Tunnel UUID: `94299bbe-157d-4f46-8fd1-8bef164c79ef`
- Port: `19200`
- OTA check interval: 5 minutes (client-side, in `zengeld-terminal/crates/updater/`)
- Auto-update: client downloads + self-replaces + restarts automatically on new version
