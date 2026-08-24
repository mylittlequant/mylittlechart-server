//! Backup operations: on-demand snapshot on the box (`/api/backup/now`) and
//! pull-to-opbox with encryption at rest (`/api/backup/pull`).
//!
//! Pull model (unchanged from mlcops.py): the box holds no outbound
//! credentials; compromise of the box cannot destroy or poison the archive.
//! The box IS a potentially hostile source, though — filenames coming back
//! from it are whitelisted byte-for-byte before they ever become a local
//! path ([`valid_backup_name`]).
//!
//! Encryption format matches `ops/mlcops.py` so old and new archives are
//! interchangeable: `nonce(12) || AES-256-GCM(key, nonce, plaintext)`,
//! key = 32 raw bytes at `env/backups/backup-key` (generated on first use,
//! opbox only; C: key + E: data — either alone leaks nothing).

use std::path::{Path, PathBuf};
use std::sync::Arc;

use aes_gcm::aead::{Aead, KeyInit};
use aes_gcm::{Aes256Gcm, Nonce};
use rand::RngCore;
use serde::Serialize;

use crate::error::OpsdError;
use crate::state::OpsdState;

const REMOTE_BACKUP_DIR: &str = "/var/lib/mlc/backups";
/// Keep this many newest `*.db.gcm` snapshots on the opbox (mlcops.py used
/// 30 for the pull side, 14 on the box).
const RETAIN_DB_SNAPSHOTS: usize = 30;

#[derive(Debug, Serialize)]
pub struct PullOutcome {
    pub pulled: Vec<String>,
    pub encrypted: Vec<String>,
    pub pruned: Vec<String>,
}

/// Whitelist a box-reported backup filename before it becomes a local path.
/// Equivalent to mlcops.py's `^[A-Za-z0-9.-]+\.(db|tar\.gz)$` plus a `..`
/// rejection (defense in depth — the charset alone already excludes `/`).
pub fn valid_backup_name(name: &str) -> bool {
    if name.is_empty() || name.len() > 128 {
        return false;
    }
    if !name.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'.' || b == b'-') {
        return false;
    }
    if name.contains("..") || name.starts_with('.') {
        return false;
    }
    name.ends_with(".db") || name.ends_with(".tar.gz")
}

/// From an `ls -1t` (newest first) listing pick the latest db snapshot and
/// the latest config tarball. Returns owned names, never paths.
pub fn select_latest(listing: &str) -> (Option<String>, Option<String>) {
    let mut db = None;
    let mut cfg = None;
    for line in listing.lines() {
        let name = line.trim();
        if !valid_backup_name(name) {
            continue;
        }
        if db.is_none() && name.ends_with(".db") {
            db = Some(name.to_string());
        }
        if cfg.is_none() && name.ends_with(".tar.gz") {
            cfg = Some(name.to_string());
        }
    }
    (db, cfg)
}

/// Which of `snapshots` (a `*.db.gcm` list, any order) survive retention.
/// Sorts by mtime descending internally; pure and unit-tested.
pub fn retention_prune(snapshots: &[(String, u64)]) -> Vec<String> {
    let mut sorted: Vec<&(String, u64)> = snapshots.iter().collect();
    sorted.sort_by(|a, b| b.1.cmp(&a.1));
    sorted
        .into_iter()
        .skip(RETAIN_DB_SNAPSHOTS)
        .map(|(name, _)| name.clone())
        .collect()
}

/// Load the backup encryption key, generating 32 random bytes on first use
/// (mirrors `_backup_key()` in mlcops.py).
fn backup_key(state: &OpsdState) -> Result<[u8; 32], OpsdError> {
    let path = &state.backup_key_path;
    if path.is_file() {
        let raw = std::fs::read(path)?;
        let key: [u8; 32] = raw
            .try_into()
            .map_err(|_| OpsdError::CanonSecret("backup-key is not 32 bytes".into()))?;
        return Ok(key);
    }
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent)?;
    }
    let mut key = [0u8; 32];
    rand::rngs::OsRng.fill_bytes(&mut key);
    std::fs::write(path, key)?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o600))?;
    }
    tracing::info!("generated new backup key at {}", path.display());
    Ok(key)
}

/// Encrypt `path` in place: write `<path>.gcm` (nonce||ct), remove the
/// plaintext. Returns the `.gcm` path.
fn encrypt_file(path: &Path, key: &[u8; 32]) -> Result<PathBuf, OpsdError> {
    let plaintext = std::fs::read(path)?;
    let mut nonce_bytes = [0u8; 12];
    rand::rngs::OsRng.fill_bytes(&mut nonce_bytes);
    let cipher = Aes256Gcm::new_from_slice(key)
        .map_err(|e| OpsdError::Remote(format!("backup key init: {e}")))?;
    let ct = cipher
        .encrypt(Nonce::from_slice(&nonce_bytes), plaintext.as_ref())
        .map_err(|e| OpsdError::Remote(format!("encrypt {}: {e}", path.display())))?;
    // Full original name + .gcm ("config-x.tar.gz.gcm") — same shape as
    // mlcops.py produces, so old and new archives stay interchangeable.
    let out = PathBuf::from(format!("{}.gcm", path.display()));
    let mut blob = Vec::with_capacity(12 + ct.len());
    blob.extend_from_slice(&nonce_bytes);
    blob.extend_from_slice(&ct);
    std::fs::write(&out, blob)?;
    std::fs::remove_file(path)?;
    Ok(out)
}

/// `POST /api/backup/now`: trigger the box-side oneshot backup unit, then
/// list the backup dir. `systemctl start` on a Type=oneshot unit blocks
/// until the backup completes, so no separate wait loop is needed (the ssh
/// exec timeout of 120s bounds it).
pub async fn backup_now(state: &Arc<OpsdState>) -> Result<Vec<String>, OpsdError> {
    let session = crate::ops::connect(state).await?;
    let out = session
        .exec(&format!(
            "systemctl start mlc-backup.service && ls -1t {REMOTE_BACKUP_DIR}/"
        ))
        .await?;
    if out.exit_code != Some(0) {
        return Err(OpsdError::Remote(format!(
            "mlc-backup.service rc={:?}: {}",
            out.exit_code,
            out.stderr.trim()
        )));
    }
    let listing: Vec<String> = out
        .stdout
        .lines()
        .map(|l| l.trim().to_string())
        .filter(|l| !l.is_empty())
        .collect();
    state.audit("backup_now", &format!("files={}", listing.len()));
    Ok(listing)
}

/// `POST /api/backup/pull`: download the latest db snapshot + config tarball
/// over SFTP, encrypt them at rest, prune old snapshots.
pub async fn backup_pull(state: &Arc<OpsdState>) -> Result<PullOutcome, OpsdError> {
    let session = crate::ops::connect(state).await?;
    let out = session.exec(&format!("ls -1t {REMOTE_BACKUP_DIR}/")).await?;
    let (db, cfg) = select_latest(&out.stdout);
    let names: Vec<String> = [db, cfg].into_iter().flatten().collect();
    if names.is_empty() {
        return Err(OpsdError::Remote("no backups on box".into()));
    }

    std::fs::create_dir_all(&state.backup_pull_dir)?;
    let key = backup_key(state)?;
    let mut pulled = Vec::new();
    let mut encrypted = Vec::new();
    for name in &names {
        let bytes = session
            .download(&format!("{REMOTE_BACKUP_DIR}/{name}"))
            .await?;
        let dst = state.backup_pull_dir.join(name); // name is whitelisted
        std::fs::write(&dst, bytes)?;
        pulled.push(name.clone());
        let gcm = encrypt_file(&dst, &key)?;
        encrypted.push(
            gcm.file_name()
                .map(|n| n.to_string_lossy().into_owned())
                .unwrap_or_default(),
        );
    }

    // Retention: keep the newest RETAIN_DB_SNAPSHOTS *.db.gcm by mtime.
    let mut snapshots: Vec<(String, u64)> = Vec::new();
    for entry in std::fs::read_dir(&state.backup_pull_dir)? {
        let entry = entry?;
        let name = entry.file_name().to_string_lossy().into_owned();
        if !name.ends_with(".db.gcm") {
            continue;
        }
        let mtime = entry
            .metadata()
            .and_then(|m| m.modified())
            .ok()
            .and_then(|t| t.duration_since(std::time::UNIX_EPOCH).ok())
            .map(|d| d.as_secs())
            .unwrap_or(0);
        snapshots.push((name, mtime));
    }
    let mut pruned = Vec::new();
    for name in retention_prune(&snapshots) {
        let p = state.backup_pull_dir.join(&name);
        if std::fs::remove_file(&p).is_ok() {
            pruned.push(name);
        }
    }

    state.audit(
        "backup_pull",
        &format!("pulled={} pruned={}", pulled.len(), pruned.len()),
    );
    Ok(PullOutcome {
        pulled,
        encrypted,
        pruned,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn backup_name_whitelist() {
        assert!(valid_backup_name("mylittlechart-20260824T031700Z.db"));
        assert!(valid_backup_name("config-20260824T031700Z.tar.gz"));
        assert!(!valid_backup_name("../etc/passwd"));
        assert!(!valid_backup_name("foo.db; rm -rf /"));
        assert!(!valid_backup_name("foo.db\nevil"));
        assert!(!valid_backup_name(".hidden.db"));
        assert!(!valid_backup_name("foo.tar.gz2"));
        assert!(!valid_backup_name(""));
    }

    #[test]
    fn select_latest_picks_newest_of_each_kind() {
        let listing = "mylittlechart-b.db\nconfig-b.tar.gz\nmylittlechart-a.db\nconfig-a.tar.gz\nevil;rm.db\n";
        let (db, cfg) = select_latest(listing);
        assert_eq!(db.as_deref(), Some("mylittlechart-b.db"));
        assert_eq!(cfg.as_deref(), Some("config-b.tar.gz"));
    }

    #[test]
    fn select_latest_empty_listing() {
        let (db, cfg) = select_latest("");
        assert!(db.is_none() && cfg.is_none());
    }

    #[test]
    fn retention_keeps_30_newest() {
        let snaps: Vec<(String, u64)> = (0..35)
            .map(|i| (format!("snap-{i:02}.db.gcm"), i as u64))
            .collect();
        let pruned = retention_prune(&snaps);
        assert_eq!(pruned.len(), 5);
        // Oldest five get pruned.
        assert!(pruned.contains(&"snap-00.db.gcm".to_string()));
        assert!(pruned.contains(&"snap-04.db.gcm".to_string()));
        assert!(!pruned.contains(&"snap-34.db.gcm".to_string()));
    }

    #[test]
    fn retention_noop_under_limit() {
        let snaps: Vec<(String, u64)> = (0..3)
            .map(|i| (format!("snap-{i}.db.gcm"), i as u64))
            .collect();
        assert!(retention_prune(&snaps).is_empty());
    }
}
