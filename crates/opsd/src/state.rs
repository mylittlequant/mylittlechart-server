//! Daemon state: paths, API key, local sqlite store.
//!
//! State root discovery mirrors `ops/mlcops.py`: walk up from the current
//! directory until a directory containing `env/mlc-utah-1` is found — that is
//! the nemo checkout root. Everything opsd persists lives under
//! `env/mlc-utah-1/opsd/` (env/ is gitignored, so secrets never touch git).
//! `MLC_OPSD_STATE_DIR` overrides the state dir (tests, ad-hoc runs).

use std::path::{Path, PathBuf};
use std::sync::Mutex;

use rand::RngCore;
use rusqlite::Connection;

use crate::error::OpsdError;

// Defaults describe the box opsd was written for. Every one is overridable by
// environment, because the fleet stopped being one box on 2026-08-30: the
// database moved to a control box and these constants kept pointing at the
// old one, so the hourly pull was archiving a stale snapshot while looking
// healthy. A backup that silently goes stale is worse than one that is absent.
// The box opsd operates on is the one holding the database, and on 2026-08-30
// that stopped being mlc-utah-1: identity moved to the control box and
// mlc-utah-1 became a pure edge running nginx only. Pointing here at the old
// box would have kept the hourly pull archiving a snapshot that no longer
// changes — a backup that silently goes stale, which is worse than none.
pub const BOX_HOST: &str = "144.172.97.2";
pub const BOX_PORT: u16 = 22;
pub const BOX_USER: &str = "root";
/// Name of the per-box directory under `env/` holding that box's canonical
/// secrets (`sqlcipher.key`, `server.env`) and opsd state.
pub const BOX_CANON_DIR: &str = "mlc-c2-1";
/// SSH key file under `env/` used to reach the box.
pub const BOX_SSH_KEY: &str = "mlc-c2-box";
pub const PUBLIC_HEALTH_URL: &str = "https://mylittlechart.org/health";
pub const APP_HEALTH_REMOTE: &str = "http://127.0.0.1:19200/health";
pub const BIND_ADDR: &str = "127.0.0.1:18360";

/// Effective bind address. `MLC_OPSD_BIND` overrides the default for
/// side-by-side test runs next to the watchdog-managed production instance
/// (which owns 127.0.0.1:18360).
pub fn bind_addr() -> String {
    std::env::var("MLC_OPSD_BIND").unwrap_or_else(|_| BIND_ADDR.to_string())
}

/// Where pulled backups land on the opbox (encrypted at rest). The AES key
/// stays on C: (`env/backups/backup-key`) — E: alone leaks nothing.
pub const DEFAULT_BACKUP_PULL_DIR: &str = "E:\\backups\\mlc-utah-1";

/// systemd units opsd is allowed to touch remotely. Anything outside this
/// list is rejected before a command string is ever built (injection guard).
pub const UNIT_WHITELIST: [&str; 4] = ["mlc-server", "nginx", "nftables", "fail2ban"];

#[derive(Debug, Clone)]
pub struct BoxConfig {
    pub host: String,
    pub port: u16,
    pub user: String,
    pub ssh_key_path: PathBuf,
    /// Canonical SQLCipher key (64 hex chars), pushed to box tmpfs on unlock.
    pub canon_key_path: PathBuf,
    /// Canonical server.env secrets, pushed to box tmpfs on unlock.
    pub canon_env_path: PathBuf,
}

/// Live watch-loop counters, shared with `GET /api/watch/state`. The
/// intervention timestamp is NOT here — it lives in the `kv` table so it
/// survives daemon restarts.
#[derive(Debug, Default, Clone, Copy)]
pub struct WatchShared {
    pub misses: u32,
    pub last_public_ok: Option<bool>,
}

pub struct OpsdState {
    pub state_dir: PathBuf,
    pub api_key: String,
    pub box_cfg: BoxConfig,
    /// AES-256-GCM key for pulled-backup encryption (opbox only).
    pub backup_key_path: PathBuf,
    /// Pull destination on the opbox.
    pub backup_pull_dir: PathBuf,
    pub db: Mutex<Connection>,
    pub http: reqwest::Client,
    pub watch: Mutex<WatchShared>,
}

/// Walk up from `start` looking for the nemo root (a dir holding
/// `env/mlc-utah-1`). `ops/mlcops.py` uses the same convention.
fn find_nemo_root(start: &Path) -> Option<PathBuf> {
    let mut dir = start.to_path_buf();
    loop {
        if dir.join("env").join("mlc-utah-1").is_dir() {
            return Some(dir);
        }
        if !dir.pop() {
            return None;
        }
    }
}

pub fn resolve_paths() -> Result<(PathBuf, BoxConfig, PathBuf), OpsdError> {
    let root = find_nemo_root(&std::env::current_dir()?)
        .ok_or(OpsdError::NemoRootNotFound)?;
    let env_dir = root.join("env");
    // `MLC_BOX_CANON_DIR` selects which box's secrets and state this daemon
    // operates on; the host/user/key can be moved independently of it.
    let canon_dir = std::env::var("MLC_BOX_CANON_DIR")
        .unwrap_or_else(|_| BOX_CANON_DIR.to_string());
    let state_dir = match std::env::var("MLC_OPSD_STATE_DIR") {
        Ok(dir) => PathBuf::from(dir),
        Err(_) => env_dir.join(&canon_dir).join("opsd"),
    };
    let box_cfg = BoxConfig {
        host: std::env::var("MLC_BOX_HOST").unwrap_or_else(|_| BOX_HOST.to_string()),
        port: std::env::var("MLC_BOX_PORT")
            .ok()
            .and_then(|v| v.parse().ok())
            .unwrap_or(BOX_PORT),
        user: std::env::var("MLC_BOX_USER").unwrap_or_else(|_| BOX_USER.to_string()),
        ssh_key_path: env_dir.join(
            std::env::var("MLC_BOX_SSH_KEY").unwrap_or_else(|_| BOX_SSH_KEY.to_string()),
        ),
        canon_key_path: env_dir.join(&canon_dir).join("sqlcipher.key"),
        canon_env_path: env_dir.join(&canon_dir).join("server.env"),
    };
    Ok((state_dir, box_cfg, env_dir))
}

/// Resolve the git HEAD sha of the repo the daemon was launched from, by
/// reading `.git` directly — opsd never spawns external processes, and
/// `git rev-parse` would be one. `None` when not in a git worktree.
fn git_head_sha() -> Option<String> {
    let mut dir = std::env::current_dir().ok()?;
    loop {
        let git = dir.join(".git");
        if git.is_dir() {
            let head = std::fs::read_to_string(git.join("HEAD")).ok()?;
            let head = head.trim();
            if let Some(sha) = head.strip_prefix("ref: ") {
                // Loose ref first, then packed-refs.
                let loose = git.join(sha);
                if loose.is_file() {
                    return std::fs::read_to_string(loose)
                        .ok()
                        .map(|s| s.trim().to_string());
                }
                let packed = std::fs::read_to_string(git.join("packed-refs")).ok()?;
                for line in packed.lines() {
                    if let Some((sha_hex, name)) = line.split_once(' ') {
                        if name.trim() == sha {
                            return Some(sha_hex.to_string());
                        }
                    }
                }
                return None;
            }
            // Detached HEAD: the file holds the sha itself.
            return Some(head.to_string());
        }
        if !dir.pop() {
            return None;
        }
    }
}

/// Load the API bearer key from `<state_dir>/api-key`, generating a fresh
/// 32-byte hex key on first start. The file is the only auth secret opsd
/// holds locally; box secrets stay in their canonical env/ files.
fn load_or_generate_api_key(state_dir: &Path) -> Result<String, OpsdError> {
    let path = state_dir.join("api-key");
    if path.is_file() {
        let key = std::fs::read_to_string(&path)?.trim().to_string();
        if key.len() == 64 && key.chars().all(|c| c.is_ascii_hexdigit()) {
            return Ok(key);
        }
        return Err(OpsdError::BadApiKeyFile(path));
    }
    let mut raw = [0u8; 32];
    rand::rngs::OsRng.fill_bytes(&mut raw);
    let key = hex::encode(raw);
    std::fs::write(&path, format!("{key}\n"))?;
    // Owner-only. Best-effort on Windows (POSIX mode bits are a no-op there).
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600))?;
    }
    tracing::info!("generated new API key at {}", path.display());
    Ok(key)
}

fn init_db(state_dir: &Path) -> Result<Connection, OpsdError> {
    let conn = Connection::open(state_dir.join("opsd.sqlite"))?;
    conn.pragma_update(None, "journal_mode", "WAL")?;
    conn.execute_batch(
        "CREATE TABLE IF NOT EXISTS audit_log(
            ts      INTEGER NOT NULL,
            action  TEXT    NOT NULL,
            detail  TEXT    NOT NULL
        );
        CREATE TABLE IF NOT EXISTS builds(
            ts      INTEGER NOT NULL,
            git_sha TEXT    NOT NULL,
            path    TEXT    NOT NULL,
            size    INTEGER NOT NULL
        );
        CREATE TABLE IF NOT EXISTS kv(
            key   TEXT PRIMARY KEY,
            value TEXT NOT NULL
        );",
    )?;
    Ok(conn)
}

impl OpsdState {
    pub fn load() -> Result<Self, OpsdError> {
        let (state_dir, box_cfg, env_dir) = resolve_paths()?;
        std::fs::create_dir_all(&state_dir)?;
        let api_key = load_or_generate_api_key(&state_dir)?;
        let db = init_db(&state_dir)?;
        let http = reqwest::Client::builder()
            .user_agent("mlc-opsd/1.0")
            .timeout(std::time::Duration::from_secs(15))
            .build()
            .map_err(OpsdError::Http)?;
        let backup_pull_dir = match std::env::var("MLC_OPSD_BACKUP_DIR") {
            Ok(dir) => PathBuf::from(dir),
            Err(_) => PathBuf::from(DEFAULT_BACKUP_PULL_DIR),
        };
        Ok(Self {
            state_dir,
            api_key,
            box_cfg,
            backup_key_path: env_dir.join("backups").join("backup-key"),
            backup_pull_dir,
            db: Mutex::new(db),
            http,
            watch: Mutex::new(WatchShared::default()),
        })
    }

    /// SSH options for the box, including the TOFU hostkey pin file.
    pub fn ssh_options<'a>(&'a self, key_pem: &'a [u8]) -> crate::ssh::SshOptions<'a> {
        crate::ssh::SshOptions {
            host: &self.box_cfg.host,
            port: self.box_cfg.port,
            user: &self.box_cfg.user,
            key_pem,
            pin_path: self.state_dir.join("known_box_key"),
        }
    }

    /// Record a deployed build. Best-effort like [`Self::audit`].
    pub fn record_build(&self, path: &str, size: u64) {
        let sha = git_head_sha().unwrap_or_default();
        let conn = self.db.lock().unwrap_or_else(|e| e.into_inner());
        let ts = chrono::Utc::now().timestamp();
        if let Err(e) = conn.execute(
            "INSERT INTO builds(ts, git_sha, path, size) VALUES(?1, ?2, ?3, ?4)",
            rusqlite::params![ts, sha, path, size as i64],
        ) {
            tracing::error!("builds insert failed: {e}");
        }
    }

    /// Append an audit row. Auditing must never fail the operation it
    /// records — errors are logged, not propagated.
    pub fn audit(&self, action: &str, detail: &str) {
        let conn = self.db.lock().unwrap_or_else(|e| e.into_inner());
        let ts = chrono::Utc::now().timestamp();
        if let Err(e) = conn.execute(
            "INSERT INTO audit_log(ts, action, detail) VALUES(?1, ?2, ?3)",
            rusqlite::params![ts, action, detail],
        ) {
            tracing::error!("audit_log insert failed: {e}");
        }
    }

    pub fn kv_get(&self, key: &str) -> Option<String> {
        let conn = self.db.lock().unwrap_or_else(|e| e.into_inner());
        conn.query_row(
            "SELECT value FROM kv WHERE key = ?1",
            rusqlite::params![key],
            |row| row.get(0),
        )
        .ok()
    }

    pub fn kv_set(&self, key: &str, value: &str) {
        let conn = self.db.lock().unwrap_or_else(|e| e.into_inner());
        if let Err(e) = conn.execute(
            "INSERT INTO kv(key, value) VALUES(?1, ?2)
             ON CONFLICT(key) DO UPDATE SET value = excluded.value",
            rusqlite::params![key, value],
        ) {
            tracing::error!("kv set failed: {e}");
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn nemo_root_discovery_walks_up() {
        let tmp = std::env::temp_dir().join(format!("opsd-test-{}", std::process::id()));
        let nested = tmp.join("env").join("mlc-utah-1");
        std::fs::create_dir_all(&nested).unwrap();
        let deep = tmp.join("a").join("b");
        std::fs::create_dir_all(&deep).unwrap();
        assert_eq!(find_nemo_root(&deep), Some(tmp.clone()));
        assert_eq!(find_nemo_root(&nested), Some(tmp.clone()));
        std::fs::remove_dir_all(&tmp).ok();
    }

    #[test]
    fn nemo_root_absent_returns_none() {
        assert_eq!(find_nemo_root(Path::new("/")), None);
    }
}
