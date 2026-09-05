//! Hot file-backed store for chart-persistence sync categories.
//!
//! Split doctrine (operator directive 2026-08-25): SQLCipher keeps the
//! identity plane — users, tokens, sessions, device metadata, E2E params, and
//! the cold sync categories (`vault`, `recovery_key`, `salt`) that change
//! once in a lifetime. Chart persistence (presets, layouts, themes,
//! watchlists, …) can change every second per user; a thousand concurrent
//! users would turn the single-writer SQLite into a convoy. Those categories
//! live as one JSON file per item under `<data_dir>/sync/`:
//!
//! ```text
//! sync/<user_id>/<device_id>/<profile_id>/<category>/<sync_id>.json
//! ```
//!
//! Writer contention does not exist by construction: different users write
//! different files, one user's item is last-writer-wins on its own file via
//! atomic tmp+rename. Content is the client's E2E ciphertext verbatim — the
//! on-disk JSON is still ciphertext, exactly like the SQL blob was.
//!
//! All functions in this module take both the SQL `Connection` (cold plane)
//! and the `SyncStore` (hot plane) and merge results, so route handlers keep
//! their existing shapes. Errors are carried as `rusqlite::Error` so the
//! handlers' error mapping stays untouched.

use std::collections::{HashMap, HashSet};
use std::fs;
use std::io;
use std::path::{Path, PathBuf};
use std::sync::Mutex;

use rusqlite::{Connection, Error as SqlError};

use crate::db::{
    ProfileSyncInfo, SyncItem, SyncItemMeta, SyncPushItem, SyncPushResult, VALID_SYNC_CATEGORIES,
    max_item_bytes, SYNC_MAX_COLD_BYTES,
};

/// Categories routed to the hot file store. Everything chart-persistence:
/// changes often, opaque E2E blob, no relational need.
pub const HOT_CATEGORIES: &[&str] = &[
    "preset",
    "watchlist",
    "template",
    "template_primitive",
    "template_indicator",
    "template_compare",
    "template_indicator_set",
    "template_chart",
    "theme",
    "settings_snapshot",
    "notification_settings",
    "indicator_set_manager",
    "window_layout",
    "profile_meta",
];

/// Categories that stay in SQLCipher: identity/vault plane, written once in
/// a lifetime, benefit from transactional consistency with the account.
pub const COLD_CATEGORIES: &[&str] = &["vault", "recovery_key", "salt"];

/// Categories of which an account holds exactly ONE, by their own shape.
///
/// Each of these is "the whole file" on the client: `watchlist` is all of
/// `watchlists.json`, `window_layout` is every window at once, `vault` is
/// the entire encrypted container. There is no such thing as a second one,
/// so a second one is a client bug or an attack, and either way the answer
/// is to refuse it rather than to let it eat a general item budget.
///
/// Nine of the seventeen categories are bounded by this alone — no number to
/// tune, no tier to consult.
pub const SINGLETON_CATEGORIES: &[&str] = &[
    "watchlist",
    "settings_snapshot",
    "notification_settings",
    "window_layout",
    "indicator_set_manager",
    "theme",
    "profile_meta",
    "vault",
    "recovery_key",
    "salt",
];

pub fn is_singleton(category: &str) -> bool {
    SINGLETON_CATEGORIES.contains(&category)
}

pub fn is_hot(category: &str) -> bool {
    HOT_CATEGORIES.contains(&category)
}

/// One sync item as stored on disk. `content` is the client's verbatim
/// string (E2E ciphertext); the JSON file is the entire record.
///
/// `display_name` is set only for `profile_meta` items — that category is
/// pushed UNENCRYPTED by design (the server parses it, same as the old SQL
/// path did at `db::sync_push_items`) so the profile list can show a name.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct FileItem {
    pub sync_id: String,
    pub category: String,
    pub name: String,
    pub content: String,
    pub checksum: String,
    pub modified_at: i64,
    pub deleted: bool,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub display_name: Option<String>,
}

/// Hot store root + a single IO mutex (same serialisation pattern as the
/// `db` mutex — file ops are page-cache-fast).
pub struct SyncStore {
    root: PathBuf,
    io: Mutex<()>,
}

/// Map an IO error into the rusqlite carrier so handler error paths are
/// unchanged. Never surfaces internals to the client — handlers log and
/// answer "Database error".
fn io_err(e: io::Error) -> SqlError {
    SqlError::ToSqlConversionFailure(Box::new(e))
}

/// Sanitise one path component (device_id / profile_id / sync_id / category).
///
/// These arrive from HTTP headers and were historically safe only because
/// they were SQL bind parameters — as path components they are a traversal
/// vector, so the allowlist is strict: ASCII alnum plus `-_.`, never a
/// leading dot, never `..`, length-capped. Empty maps to `_` (the legacy
/// empty device/profile namespace keeps working).
///
/// `pub(crate)` so `routes/share.rs` runs screenshot blob-path components
/// (user_id, token) through the same allowlist even though both are
/// server-generated and already safe — one sanitizer, no second spelling of
/// "safe path component".
pub(crate) fn sanitize(component: &str) -> Result<String, SqlError> {
    if component.is_empty() {
        return Ok("_".to_string());
    }
    let ok = component.len() <= 128
        && component != ".."
        && !component.starts_with('.')
        && component
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || matches!(c, '-' | '_' | '.'));
    if ok {
        Ok(component.to_string())
    } else {
        Err(SqlError::ToSqlConversionFailure(Box::new(
            io::Error::new(
                io::ErrorKind::InvalidInput,
                format!("unsafe path component: {component:?}"),
            ),
        )))
    }
}

impl SyncStore {
    pub fn new(root: PathBuf) -> Self {
        Self {
            root,
            io: Mutex::new(()),
        }
    }

    fn user_dir(&self, user_id: i64) -> PathBuf {
        self.root.join(user_id.to_string())
    }

    fn scope_dir(&self, user_id: i64, device_id: &str, profile_id: &str) -> Result<PathBuf, SqlError> {
        Ok(self
            .user_dir(user_id)
            .join(sanitize(device_id)?)
            .join(sanitize(profile_id)?))
    }

    fn item_path(
        &self,
        user_id: i64,
        device_id: &str,
        profile_id: &str,
        category: &str,
        sync_id: &str,
    ) -> Result<PathBuf, SqlError> {
        Ok(self
            .scope_dir(user_id, device_id, profile_id)?
            .join(sanitize(category)?)
            .join(format!("{}.json", sanitize(sync_id)?)))
    }

    /// Read one item file, if present and parseable. Corrupt files are
    /// skipped (logged by caller's absence), never fatal.
    fn read_file(path: &Path) -> Option<FileItem> {
        let raw = fs::read(path).ok()?;
        serde_json::from_slice(&raw).ok()
    }

    /// Atomic write: tmp file in the same directory + rename.
    fn write_file(path: &Path, item: &FileItem) -> io::Result<()> {
        if let Some(dir) = path.parent() {
            fs::create_dir_all(dir)?;
        }
        let tmp = path.with_extension("json.tmp");
        let data = serde_json::to_vec(item)
            .map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e))?;
        fs::write(&tmp, data)?;
        fs::rename(&tmp, path)?;
        Ok(())
    }

    /// All items (incl. tombstones) for one (user, device, profile) scope.
    fn read_scope(&self, user_id: i64, device_id: &str, profile_id: &str) -> Result<Vec<FileItem>, SqlError> {
        let dir = self.scope_dir(user_id, device_id, profile_id)?;
        Ok(read_tree(&dir))
    }

    /// Every item the user has, across every device AND every profile.
    ///
    /// The quota's unit. `read_scope`/`read_profile` answer "what is stored
    /// at this address"; this answers "how much does this ACCOUNT hold",
    /// which is the only question a ceiling can sensibly be asked about —
    /// devices are addresses, and an account may have any number of them.
    fn read_user(&self, user_id: i64) -> Result<Vec<FileItem>, SqlError> {
        let mut out = Vec::new();
        let udir = self.user_dir(user_id);
        let Ok(devs) = fs::read_dir(&udir) else {
            return Ok(out);
        };
        for dev in devs.flatten() {
            let Ok(profs) = fs::read_dir(dev.path()) else {
                continue;
            };
            for prof in profs.flatten() {
                out.extend(read_tree(&prof.path()));
            }
        }
        Ok(out)
    }

    /// All items for one profile across every device of the user.
    fn read_profile(&self, user_id: i64, profile_id: &str) -> Result<Vec<FileItem>, SqlError> {
        let prof = sanitize(profile_id)?;
        let mut out = Vec::new();
        let udir = self.user_dir(user_id);
        let Ok(devs) = fs::read_dir(&udir) else {
            return Ok(out);
        };
        for dev in devs.flatten() {
            let pdir = dev.path().join(&prof);
            out.extend(read_tree(&pdir));
        }
        Ok(out)
    }

    /// Locate one item by sync_id inside a scope (category unknown to the
    /// caller — DELETE /api/sync/item/:sync_id carries no category).
    fn find_in_scope(
        &self,
        user_id: i64,
        device_id: &str,
        profile_id: &str,
        sync_id: &str,
    ) -> Result<Option<(FileItem, PathBuf)>, SqlError> {
        let fname = format!("{}.json", sanitize(sync_id)?);
        let dir = self.scope_dir(user_id, device_id, profile_id)?;
        let Ok(cats) = fs::read_dir(&dir) else {
            return Ok(None);
        };
        for cat in cats.flatten() {
            let p = cat.path().join(&fname);
            if p.is_file() {
                if let Some(item) = Self::read_file(&p) {
                    return Ok(Some((item, p)));
                }
            }
        }
        Ok(None)
    }
}

/// Walk a `<...>/<category>/*.json` tree, skipping anything unreadable.
fn read_tree(dir: &Path) -> Vec<FileItem> {
    let mut out = Vec::new();
    let Ok(cats) = fs::read_dir(dir) else {
        return out;
    };
    for cat in cats.flatten() {
        let Ok(files) = fs::read_dir(cat.path()) else {
            continue;
        };
        for f in files.flatten() {
            let p = f.path();
            if p.extension().and_then(|e| e.to_str()) == Some("json") {
                if let Some(item) = SyncStore::read_file(&p) {
                    out.push(item);
                }
            }
        }
    }
    out
}

/// LWW merge key for cross-store / cross-device merging.
fn lww_take(map: &mut HashMap<String, FileItem>, item: FileItem) {
    match map.get(&item.sync_id) {
        Some(cur)
            if cur.modified_at > item.modified_at
                || (cur.modified_at == item.modified_at && cur.checksum == item.checksum) => {}
        _ => {
            map.insert(item.sync_id.clone(), item);
        }
    }
}

impl FileItem {
    fn to_meta(&self) -> SyncItemMeta {
        SyncItemMeta {
            sync_id: self.sync_id.clone(),
            category: self.category.clone(),
            name: self.name.clone(),
            checksum: self.checksum.clone(),
            modified_at: self.modified_at,
            deleted: self.deleted,
        }
    }

    fn to_sync_item(&self, user_id: i64) -> SyncItem {
        SyncItem {
            sync_id: self.sync_id.clone(),
            user_id,
            category: self.category.clone(),
            name: self.name.clone(),
            content: self.content.clone().into_bytes(),
            checksum: self.checksum.clone(),
            modified_at: self.modified_at,
            deleted: self.deleted,
            created_at: String::new(),
        }
    }
}

// ── Merged dispatcher operations (cold SQL + hot files) ─────────────────────

/// Push with per-category routing. Hot items go to files, cold items to the
/// existing SQL upsert. Validation and quota mirror `db::sync_push_items`,
/// with quota counted across BOTH stores.
///
/// `is_paid` is the caller's already-resolved tier (`db::user_is_paid`): the
/// hot-plane ceilings — bytes, presets, templates — come from
/// `entitlements::{hot_bytes_limit, preset_limit, template_limit}` and are
/// ten times larger for a paid account. The cold plane is tier-blind.
pub fn push(
    conn: &Connection,
    store: &SyncStore,
    user_id: i64,
    device_id: &str,
    profile_id: &str,
    items: &[SyncPushItem],
    is_paid: bool,
) -> rusqlite::Result<SyncPushResult> {
    if items.is_empty() {
        return Ok(SyncPushResult {
            accepted: 0,
            rejected: vec![],
        });
    }

    // Item count is one budget across both stores. Bytes are not: the two
    // planes hold different things and are worth different amounts of trust.
    // The hot file store carries the bulk (presets, templates, layouts) and
    // holds `entitlements::hot_bytes_limit` (`SYNC_MAX_TOTAL_BYTES`, x10 for
    // paid). The cold plane is three keys inside the
    // backed-up identity database, and measuring it against a bulk ceiling is
    // how a 2 KiB working set ended up licensed to grow to 50 MiB of
    // backup — see `db::SYNC_MAX_COLD_BYTES`.
    let usage = account_usage(conn, store, user_id)?;
    let (cold_bytes, hot_bytes) = (usage.cold_bytes, usage.hot_bytes);

    // A singleton category holds exactly one item per account by its own
    // shape — `watchlist` IS the whole watchlists file, `vault` IS the whole
    // container. A second one is a client bug or an attack, and it is refused
    // here rather than allowed to consume a general item budget. Ten of the
    // seventeen categories need no number at all because of this.
    for item in items {
        if is_singleton(&item.category) && !item.deleted {
            let taken_by_other = usage
                .singletons
                .get(&item.category)
                .is_some_and(|held| held != &item.sync_id);
            if taken_by_other {
                return Err(SqlError::SqliteFailure(
                    rusqlite::ffi::Error::new(rusqlite::ffi::SQLITE_CONSTRAINT),
                    Some(format!(
                        "User {user_id}: category '{}' holds exactly one item per account",
                        item.category
                    )),
                ));
            }
        }
    }

    // Only presets and templates legitimately grow, so only they are counted.
    let preset_limit = crate::entitlements::preset_limit(is_paid);
    let adding_presets = items.iter().filter(|i| i.category == "preset" && !i.deleted).count() as i64;
    if adding_presets > 0 && usage.presets >= preset_limit {
        return Err(SqlError::SqliteFailure(
            rusqlite::ffi::Error::new(rusqlite::ffi::SQLITE_FULL),
            Some(format!(
                "User {user_id} has reached the preset limit ({preset_limit} across all devices and profiles)"
            )),
        ));
    }
    let adding_templates = items
        .iter()
        .filter(|i| i.category.starts_with("template") && !i.deleted)
        .count() as i64;
    let template_limit = crate::entitlements::template_limit(is_paid);
    if adding_templates > 0 && usage.templates >= template_limit {
        return Err(SqlError::SqliteFailure(
            rusqlite::ffi::Error::new(rusqlite::ffi::SQLITE_FULL),
            Some(format!(
                "User {user_id} has reached the template limit ({template_limit} across all devices and profiles)"
            )),
        ));
    }
    // Each ceiling only stops the plane it belongs to: a full preset store
    // must not block a vault push, and a full vault must not block presets.
    let batch_has_cold = items.iter().any(|i| !is_hot(&i.category));
    let batch_has_hot = items.iter().any(|i| is_hot(&i.category));
    if batch_has_cold && cold_bytes >= SYNC_MAX_COLD_BYTES {
        return Err(SqlError::SqliteFailure(
            rusqlite::ffi::Error::new(rusqlite::ffi::SQLITE_FULL),
            Some(format!(
                "User {user_id} has reached the identity-plane storage limit ({} KiB across all devices and profiles)",
                SYNC_MAX_COLD_BYTES / 1024
            )),
        ));
    }
    let hot_limit = crate::entitlements::hot_bytes_limit(is_paid);
    if batch_has_hot && hot_bytes >= hot_limit {
        return Err(SqlError::SqliteFailure(
            rusqlite::ffi::Error::new(rusqlite::ffi::SQLITE_FULL),
            Some(format!(
                "User {user_id} has reached the sync storage limit ({} MiB across all devices and profiles)",
                hot_limit / (1024 * 1024)
            )),
        ));
    }

    let mut cold: Vec<SyncPushItem> = Vec::new();
    let mut accepted = 0usize;
    let mut rejected: Vec<String> = Vec::new();
    let mut hot: Vec<&SyncPushItem> = Vec::new();

    for item in items {
        if !VALID_SYNC_CATEGORIES.contains(&item.category.as_str()) {
            rejected.push(format!("{}: unknown category '{}'", item.sync_id, item.category));
            continue;
        }
        if item.name.len() > 128 {
            rejected.push(format!("{}: name exceeds 128 bytes", item.sync_id));
            continue;
        }
        if item.name.chars().any(|c| c.is_control()) {
            rejected.push(format!("{}: name contains control chars", item.sync_id));
            continue;
        }
        let limit = max_item_bytes(&item.category);
        if item.content.len() > limit {
            rejected.push(format!(
                "{}: content exceeds {} KiB ({} bytes)",
                item.sync_id,
                limit / 1024,
                item.content.len()
            ));
            continue;
        }
        if is_hot(&item.category) {
            hot.push(item);
        } else {
            cold.push(item.clone());
        }
    }

    // Hot plane: per-item LWW write.
    if !hot.is_empty() {
        let _guard = store.io.lock().unwrap_or_else(|e| e.into_inner());
        for item in hot {
            let path = store.item_path(user_id, device_id, profile_id, &item.category, &item.sync_id)?;
            let dominated = SyncStore::read_file(&path).is_some_and(|cur| {
                cur.modified_at > item.modified_at
                    || (cur.modified_at == item.modified_at && cur.checksum == item.checksum)
            });
            if dominated {
                continue;
            }
            let content = String::from_utf8_lossy(&item.content).into_owned();
            // profile_meta is plaintext by design — lift display_name onto the
            // record so list_profiles can show it (mirrors the old SQL path).
            let display_name = if item.category == "profile_meta" {
                serde_json::from_str::<serde_json::Value>(&content)
                    .ok()
                    .and_then(|v| v.get("display_name")?.as_str().map(str::to_owned))
            } else {
                None
            };
            let fi = FileItem {
                sync_id: item.sync_id.clone(),
                category: item.category.clone(),
                name: item.name.clone(),
                content,
                checksum: item.checksum.clone(),
                modified_at: item.modified_at,
                deleted: item.deleted,
                display_name,
            };
            SyncStore::write_file(&path, &fi).map_err(io_err)?;
            accepted += 1;
        }
    }

    // Cold plane: existing SQL path (validation already done above; the SQL
    // layer re-checks harmlessly).
    if !cold.is_empty() {
        let r = crate::db::sync_push_items(conn, user_id, device_id, profile_id, &cold)?;
        accepted += r.accepted;
        rejected.extend(r.rejected);
    }

    Ok(SyncPushResult { accepted, rejected })
}

/// What the ACCOUNT holds: `(item_count, cold_bytes, hot_bytes)`, the two
/// planes kept apart, summed over every device and profile.
///
/// This is what the quota is checked against. It used to be scoped to one
/// `(user, device, profile)`, which meant every new device came with a fresh
/// full allowance — and since `X-Device-Id` is just a client-supplied
/// header, an account could mint as many allowances as it liked. Devices are
/// where data lives, not how much of it an account may keep.
///
/// SQL holds only cold categories and the file store only hot ones, so each
/// plane's own total is exactly what its own store reports — no filtering by
/// category is needed or would be correct here. [`status`] stays per-scope:
/// it answers "what is at this address", a different question.
fn account_usage(
    conn: &Connection,
    store: &SyncStore,
    user_id: i64,
) -> rusqlite::Result<AccountUsage> {
    let (_cold_count, cold_bytes) = crate::db::sync_usage_for_user(conn, user_id)?;
    let mut u = AccountUsage { cold_bytes, ..Default::default() };
    for (category, sync_id) in crate::db::sync_cold_ids_for_user(conn, user_id)? {
        if is_singleton(&category) {
            u.singletons.insert(category, sync_id);
        }
    }
    let _guard = store.io.lock().unwrap_or_else(|e| e.into_inner());
    for item in store.read_user(user_id)? {
        if item.deleted {
            continue;
        }
        u.hot_bytes += item.content.len() as i64;
        match item.category.as_str() {
            "preset" => u.presets += 1,
            c if c.starts_with("template") => u.templates += 1,
            _ => {}
        }
        if is_singleton(&item.category) {
            u.singletons.insert(item.category.clone(), item.sync_id.clone());
        }
    }
    Ok(u)
}

/// What one account currently holds. The cold plane is counted in bytes only:
/// every category in it is a singleton, so its count is bounded by shape.
#[derive(Default)]
struct AccountUsage {
    cold_bytes: i64,
    hot_bytes: i64,
    presets: i64,
    templates: i64,
    /// category → the `sync_id` already stored for it. Lets a push tell
    /// "updating the one vault I have" apart from "here is a second vault".
    singletons: std::collections::HashMap<String, String>,
}

/// `(item_count, last_modified_at, quota_used_bytes)` merged over both stores.
pub fn status(
    conn: &Connection,
    store: &SyncStore,
    user_id: i64,
    device_id: &str,
    profile_id: &str,
) -> rusqlite::Result<(i64, Option<i64>, i64)> {
    let (mut count, mut last, mut bytes) =
        crate::db::sync_status(conn, user_id, device_id, profile_id)?;
    let _guard = store.io.lock().unwrap_or_else(|e| e.into_inner());
    for item in store.read_scope(user_id, device_id, profile_id)? {
        if !item.deleted {
            count += 1;
            bytes += item.content.len() as i64;
        }
        last = Some(last.map_or(item.modified_at, |l: i64| l.max(item.modified_at)));
    }
    Ok((count, last, bytes))
}

/// Metadata of items changed after `since`, merged.
pub fn changes(
    conn: &Connection,
    store: &SyncStore,
    user_id: i64,
    device_id: &str,
    profile_id: &str,
    since: i64,
) -> rusqlite::Result<Vec<SyncItemMeta>> {
    let mut out = crate::db::sync_get_changes(conn, user_id, device_id, profile_id, since)?;
    let _guard = store.io.lock().unwrap_or_else(|e| e.into_inner());
    for item in store.read_scope(user_id, device_id, profile_id)? {
        if item.modified_at > since {
            out.push(item.to_meta());
        }
    }
    Ok(out)
}

/// Full pull (non-deleted), merged. SQL already holds only cold categories.
pub fn pull_all(
    conn: &Connection,
    store: &SyncStore,
    user_id: i64,
    device_id: &str,
    profile_id: &str,
) -> rusqlite::Result<Vec<SyncItem>> {
    let mut out = crate::db::sync_pull_all(conn, user_id, device_id, profile_id)?;
    let _guard = store.io.lock().unwrap_or_else(|e| e.into_inner());
    for item in store.read_scope(user_id, device_id, profile_id)? {
        if !item.deleted {
            out.push(item.to_sync_item(user_id));
        }
    }
    out.sort_by_key(|i| i.modified_at);
    Ok(out)
}

/// Cross-device pull of one profile with LWW by sync_id across both stores.
pub fn pull_by_profile(
    conn: &Connection,
    store: &SyncStore,
    user_id: i64,
    profile_id: &str,
) -> rusqlite::Result<Vec<SyncItem>> {
    let sql_items = crate::db::sync_pull_by_profile(conn, user_id, profile_id)?;
    let _guard = store.io.lock().unwrap_or_else(|e| e.into_inner());
    let mut merged: HashMap<String, FileItem> = HashMap::new();
    for item in sql_items {
        lww_take(
            &mut merged,
            FileItem {
                sync_id: item.sync_id,
                category: item.category,
                name: item.name,
                content: String::from_utf8_lossy(&item.content).into_owned(),
                checksum: item.checksum,
                modified_at: item.modified_at,
                deleted: item.deleted,
                display_name: None,
            },
        );
    }
    for item in store.read_profile(user_id, profile_id)? {
        if !item.deleted {
            lww_take(&mut merged, item);
        }
    }
    let mut out: Vec<SyncItem> = merged
        .into_values()
        .filter(|i| !i.deleted)
        .map(|i| i.to_sync_item(user_id))
        .collect();
    out.sort_by_key(|i| i.modified_at);
    Ok(out)
}

/// Tombstone one item by sync_id, whichever store holds it.
pub fn delete_item(
    conn: &Connection,
    store: &SyncStore,
    user_id: i64,
    device_id: &str,
    profile_id: &str,
    sync_id: &str,
    now_ms: i64,
) -> rusqlite::Result<bool> {
    if crate::db::sync_delete_item(conn, user_id, device_id, profile_id, sync_id, now_ms)? {
        return Ok(true);
    }
    let _guard = store.io.lock().unwrap_or_else(|e| e.into_inner());
    match store.find_in_scope(user_id, device_id, profile_id, sync_id)? {
        Some((mut item, path)) => {
            item.deleted = true;
            item.modified_at = now_ms;
            item.content.clear();
            SyncStore::write_file(&path, &item).map_err(io_err)?;
            Ok(true)
        }
        None => Ok(false),
    }
}

/// Hard-delete everything for the scope in both stores. Returns combined count.
pub fn delete_all(
    conn: &Connection,
    store: &SyncStore,
    user_id: i64,
    device_id: &str,
    profile_id: &str,
) -> rusqlite::Result<usize> {
    let mut n = crate::db::sync_delete_all(conn, user_id, device_id, profile_id)?;
    let dir = store.scope_dir(user_id, device_id, profile_id)?;
    let _guard = store.io.lock().unwrap_or_else(|e| e.into_inner());
    if dir.is_dir() {
        n += read_tree(&dir).len();
        fs::remove_dir_all(&dir).map_err(io_err)?;
        // Prune now-empty parents (device dir, then user dir). remove_dir
        // fails on non-empty — exactly the guard we want, no listing needed.
        let mut up = dir.parent();
        for _ in 0..2 {
            if let Some(p) = up {
                if fs::remove_dir(p).is_err() {
                    break;
                }
                up = p.parent();
            }
        }
    }
    Ok(n)
}

/// Hard-delete every hot file for a user (all devices, all profiles, all
/// categories). Called from account deletion (routes/sessions.rs::delete_account)
/// alongside `db::delete_account`'s SQL cascade — that cascade is SQL-only and
/// cannot see this filesystem tree (2026-08-30 gap fix: the hot store was the
/// one place a deleted user's data reliably survived deletion).
///
/// Reuses `SyncStore::user_dir` — the same path builder every other function
/// in this module uses — rather than assembling `<root>/<user_id>` again.
///
/// Idempotent: a missing directory (already purged, retried request, or a
/// user who never wrote a hot-category item) is success, not an error. The
/// caller must not fail account deletion over this — the SQL cascade above
/// already committed by the time this runs.
pub fn purge_user(store: &SyncStore, user_id: i64) -> rusqlite::Result<()> {
    let dir = store.user_dir(user_id);
    let _guard = store.io.lock().unwrap_or_else(|e| e.into_inner());
    match fs::remove_dir_all(&dir) {
        Ok(()) => Ok(()),
        Err(e) if e.kind() == io::ErrorKind::NotFound => Ok(()),
        Err(e) => Err(io_err(e)),
    }
}

/// Delete hot-store files for users who haven't synced in `inactive_days` days.
///
/// Counterpart to `db::cleanup_inactive_sync_data` for the hot plane: that
/// function only sees `sync_items` (cold categories), so a user who only ever
/// wrote hot categories (presets/layouts/watchlists/…) never shows up there
/// and their files under `<data_dir>/sync/<user_id>/` would otherwise
/// accumulate forever.
///
/// A user's whole directory is removed only when EVERY item under it — any
/// device, any profile, any category — has `modified_at` older than the
/// threshold, mirroring the "whole user, not partial" semantics of the SQL
/// sweep. A user directory with no readable items at all (e.g. only empty
/// leftover subdirectories) is left alone — there is no age signal to act on.
///
/// Returns the number of user directories removed.
pub fn cleanup_inactive(store: &SyncStore, inactive_days: i64) -> rusqlite::Result<usize> {
    let threshold_ms =
        (chrono::Utc::now() - chrono::Duration::days(inactive_days)).timestamp_millis();
    let _guard = store.io.lock().unwrap_or_else(|e| e.into_inner());
    let mut removed = 0usize;
    let Ok(users) = fs::read_dir(&store.root) else {
        return Ok(removed);
    };
    for user_entry in users.flatten() {
        let user_path = user_entry.path();
        if !user_path.is_dir() {
            continue;
        }
        let Some(max_modified) = user_max_modified(&user_path) else {
            continue;
        };
        if max_modified < threshold_ms && fs::remove_dir_all(&user_path).is_ok() {
            removed += 1;
        }
    }
    Ok(removed)
}

/// Most recent `modified_at` across every item under a user's directory
/// (`<user_id>/<device_id>/<profile_id>/<category>/*.json`), or `None` if the
/// tree holds no readable item.
fn user_max_modified(user_path: &Path) -> Option<i64> {
    let mut max: Option<i64> = None;
    let devs = fs::read_dir(user_path).ok()?;
    for dev in devs.flatten() {
        let Ok(profs) = fs::read_dir(dev.path()) else {
            continue;
        };
        for prof in profs.flatten() {
            for item in read_tree(&prof.path()) {
                max = Some(max.map_or(item.modified_at, |m| m.max(item.modified_at)));
            }
        }
    }
    max
}

/// Profile list merged across stores. `has_vault`/`has_recovery_key` and
/// `display_name` come from the SQL (cold) plane; file-side profiles add
/// counts/bytes/recency.
pub fn list_profiles(
    conn: &Connection,
    store: &SyncStore,
    user_id: i64,
) -> rusqlite::Result<Vec<ProfileSyncInfo>> {
    let mut by_profile: HashMap<String, ProfileSyncInfo> = HashMap::new();
    for p in crate::db::sync_list_profiles_for_user(conn, user_id)? {
        by_profile.insert(p.profile_id.clone(), p);
    }
    let _guard = store.io.lock().unwrap_or_else(|e| e.into_inner());
    let udir = store.user_dir(user_id);
    if let Ok(devs) = fs::read_dir(&udir) {
        for dev in devs.flatten() {
            let Ok(profs) = fs::read_dir(dev.path()) else {
                continue;
            };
            for prof in profs.flatten() {
                let pname = prof.file_name().to_string_lossy().into_owned();
                let profile_id = if pname == "_" { String::new() } else { pname };
                let entry = by_profile
                    .entry(profile_id.clone())
                    .or_insert_with(|| ProfileSyncInfo {
                        profile_id: profile_id.clone(),
                        display_name: None,
                        item_count: 0,
                        total_bytes: 0,
                        last_modified: 0,
                        has_vault: false,
                        has_recovery_key: false,
                    });
                for item in read_tree(&prof.path()) {
                    if item.deleted {
                        continue;
                    }
                    entry.item_count += 1;
                    entry.total_bytes += item.content.len() as i64;
                    entry.last_modified = entry.last_modified.max(item.modified_at);
                    if item.category == "profile_meta" && entry.display_name.is_none() {
                        entry.display_name = item.display_name.clone();
                    }
                }
            }
        }
    }
    Ok(by_profile.into_values().collect())
}

/// Every `profile_id` the server has ever stored an item under for this
/// user — the union of the cold SQL plane (`sync_items`, via
/// `db::sync_distinct_profile_ids`) and the hot file plane (profile
/// directories under `<data_dir>/sync/<user_id>/<device_id>/`).
///
/// This is the authoritative source for the multi-profile entitlement (see
/// `entitlements::profile_write_allowed`, called from `routes/sync.rs`):
/// "how many profiles does this user have" and "has the server ever seen
/// this profile_id" both answer from this set, because it is the number a
/// person would recognise as their own profile count and it stays correct
/// for a user whose data lives entirely in the hot store.
///
/// Deliberately does NOT read `sync_e2e_params`. Two measured facts on
/// production (2026-08-30) rule that out: it can hold rows for profile_ids
/// that exist nowhere else (counting from it would inflate a real user from
/// four profiles to six), and those extra rows are not safe to delete on
/// sight — they carry E2E key material (salt, iteration count, wrapped
/// master key) for a profile that may be sitting on a device's disk with no
/// server-side copy of its content yet, so deleting the row would make that
/// vault unrecoverable from another device. `sync_e2e_setup` therefore
/// remains an enforcement POINT (it can be the first write that introduces
/// a profile) without being a counting SOURCE — do not "simplify" this by
/// counting from the table it writes to.
pub fn known_profile_ids(
    conn: &Connection,
    store: &SyncStore,
    user_id: i64,
) -> rusqlite::Result<HashSet<String>> {
    let mut ids: HashSet<String> = crate::db::sync_distinct_profile_ids(conn, user_id)?
        .into_iter()
        .collect();

    let _guard = store.io.lock().unwrap_or_else(|e| e.into_inner());
    let udir = store.user_dir(user_id);
    if let Ok(devs) = fs::read_dir(&udir) {
        for dev in devs.flatten() {
            let Ok(profs) = fs::read_dir(dev.path()) else {
                continue;
            };
            for prof in profs.flatten() {
                let pname = prof.file_name().to_string_lossy().into_owned();
                // "_" is the sanitized on-disk form of the empty (legacy
                // default) profile_id — see `sanitize`.
                let profile_id = if pname == "_" { String::new() } else { pname };
                ids.insert(profile_id);
            }
        }
    }
    Ok(ids)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::{AtomicU64, Ordering};

    /// Unique temp dir per test, no external dev-dependency. Removed on drop.
    struct TestDir(PathBuf);
    static SEQ: AtomicU64 = AtomicU64::new(0);
    impl TestDir {
        fn new() -> Self {
            let p = std::env::temp_dir().join(format!(
                "mlc-syncstore-test-{}-{}",
                std::process::id(),
                SEQ.fetch_add(1, Ordering::Relaxed)
            ));
            fs::create_dir_all(&p).unwrap();
            Self(p)
        }
    }
    impl Drop for TestDir {
        fn drop(&mut self) {
            let _ = fs::remove_dir_all(&self.0);
        }
    }

    fn store(dir: &TestDir) -> SyncStore {
        SyncStore::new(dir.0.join("sync"))
    }

    fn item(sync_id: &str, cat: &str, modified: i64) -> SyncPushItem {
        SyncPushItem {
            sync_id: sync_id.into(),
            category: cat.into(),
            name: "n".into(),
            content: b"blob".to_vec(),
            checksum: "abc".into(),
            modified_at: modified,
            deleted: false,
        }
    }

    #[test]
    fn sanitize_rejects_traversal() {
        assert!(sanitize("..").is_err());
        assert!(sanitize("../x").is_err());
        assert!(sanitize("a/b").is_err());
        assert!(sanitize("a\\b").is_err());
        assert!(sanitize(".hidden").is_err());
        assert_eq!(sanitize("").unwrap(), "_");
        assert_eq!(sanitize("dev-1_x.y").unwrap(), "dev-1_x.y");
    }

    #[test]
    fn hot_write_and_lww() {
        let dir = TestDir::new();
        let s = store(&dir);
        let conn = crate::db::init_test_conn();

        // Hot item lands as a file, not in SQL.
        let r = push(&conn, &s, 1, "dev", "prof", &[item("p1", "preset", 100)], false).unwrap();
        assert_eq!(r.accepted, 1);
        let p = s.item_path(1, "dev", "prof", "preset", "p1").unwrap();
        assert!(p.is_file());
        let n: i64 = conn
            .query_row("SELECT COUNT(*) FROM sync_items", [], |r| r.get(0))
            .unwrap();
        assert_eq!(n, 0);

        // Older modified_at does not overwrite (LWW).
        let r = push(&conn, &s, 1, "dev", "prof", &[item("p1", "preset", 50)], false).unwrap();
        assert_eq!(r.accepted, 0);
        let cur = SyncStore::read_file(&p).unwrap();
        assert_eq!(cur.modified_at, 100);

        // Newer wins.
        let r = push(&conn, &s, 1, "dev", "prof", &[item("p1", "preset", 200)], false).unwrap();
        assert_eq!(r.accepted, 1);
        let cur = SyncStore::read_file(&p).unwrap();
        assert_eq!(cur.modified_at, 200);
    }

    #[test]
    fn cold_goes_to_sql() {
        let dir = TestDir::new();
        let s = store(&dir);
        let conn = crate::db::init_test_conn();

        let r = push(&conn, &s, 1, "dev", "prof", &[item("v1", "vault", 100)], false).unwrap();
        assert_eq!(r.accepted, 1);
        let n: i64 = conn
            .query_row("SELECT COUNT(*) FROM sync_items", [], |r| r.get(0))
            .unwrap();
        assert_eq!(n, 1);
        assert!(!s.item_path(1, "dev", "prof", "vault", "v1").unwrap().exists());
    }

    #[test]
    fn merged_pull_and_delete() {
        let dir = TestDir::new();
        let s = store(&dir);
        let conn = crate::db::init_test_conn();

        push(&conn, &s, 1, "dev", "prof", &[item("p1", "preset", 100)], false).unwrap();
        push(&conn, &s, 1, "dev", "prof", &[item("v1", "vault", 100)], false).unwrap();

        let all = pull_all(&conn, &s, 1, "dev", "prof").unwrap();
        assert_eq!(all.len(), 2);

        // delete_item finds the hot file without knowing its category.
        assert!(delete_item(&conn, &s, 1, "dev", "prof", "p1", 500).unwrap());
        let all = pull_all(&conn, &s, 1, "dev", "prof").unwrap();
        assert_eq!(all.len(), 1);
        // Tombstone visible in changes.
        let ch = changes(&conn, &s, 1, "dev", "prof", 400).unwrap();
        assert!(ch.iter().any(|m| m.sync_id == "p1" && m.deleted));

        // delete_all clears both stores.
        let n = delete_all(&conn, &s, 1, "dev", "prof").unwrap();
        assert_eq!(n, 2);
        assert!(pull_all(&conn, &s, 1, "dev", "prof").unwrap().is_empty());
    }

    #[test]
    fn cross_device_profile_lww() {
        let dir = TestDir::new();
        let s = store(&dir);
        let conn = crate::db::init_test_conn();

        push(&conn, &s, 1, "devA", "prof", &[item("p1", "preset", 100)], false).unwrap();
        push(&conn, &s, 1, "devB", "prof", &[item("p1", "preset", 300)], false).unwrap();
        let items = pull_by_profile(&conn, &s, 1, "prof").unwrap();
        assert_eq!(items.len(), 1);
        assert_eq!(items[0].modified_at, 300);
    }

    #[test]
    fn profile_meta_display_name_surfaces_in_list() {
        let dir = TestDir::new();
        let s = store(&dir);
        let conn = crate::db::init_test_conn();

        let mut meta = item("pm1", "profile_meta", 100);
        meta.content = br#"{"display_name":"Work"}"#.to_vec();
        push(&conn, &s, 1, "dev", "prof", &[meta], false).unwrap();

        let profiles = list_profiles(&conn, &s, 1).unwrap();
        let p = profiles.iter().find(|p| p.profile_id == "prof").unwrap();
        assert_eq!(p.display_name.as_deref(), Some("Work"));
        assert_eq!(p.item_count, 1);
    }

    #[test]
    fn known_profile_ids_unions_and_dedups_cold_and_hot() {
        let dir = TestDir::new();
        let s = store(&dir);
        let conn = crate::db::init_test_conn();

        // "hot-only": lives only as a file-store directory (preset category).
        push(&conn, &s, 1, "dev", "hot-only", &[item("p1", "preset", 100)], false).unwrap();
        // "cold-only": lives only in sync_items (vault category).
        push(&conn, &s, 1, "dev", "cold-only", &[item("v1", "vault", 100)], false).unwrap();
        // "both": present in both stores — must be counted once, not twice.
        // Cold half uses "salt", not a second "vault": vault/recovery_key/salt
        // are each an account-wide singleton (see SINGLETON_CATEGORIES), so
        // two vault pushes for the same user_id under different profile_ids
        // would collide on the singleton guard even though they are legally
        // distinct profiles here — a different singleton category has its own
        // independent slot and exercises the same cold+hot union/dedup path.
        push(&conn, &s, 1, "dev", "both", &[item("p2", "preset", 100)], false).unwrap();
        push(&conn, &s, 1, "dev", "both", &[item("s1", "salt", 100)], false).unwrap();

        let known = known_profile_ids(&conn, &s, 1).unwrap();
        assert_eq!(known.len(), 3);
        assert!(known.contains("hot-only"));
        assert!(known.contains("cold-only"));
        assert!(known.contains("both"));
    }

    #[test]
    fn known_profile_ids_ignores_sync_e2e_params_debris() {
        // A row in sync_e2e_params with no corresponding sync_items or
        // hot-store data must NOT count as a known profile — see this
        // function's doc comment for the production evidence that motivates
        // this (2026-08-30: two such rows exist for a real user).
        let dir = TestDir::new();
        let s = store(&dir);
        let conn = crate::db::init_test_conn();

        push(&conn, &s, 1, "dev", "real-profile", &[item("p1", "preset", 100)], false).unwrap();
        crate::db::sync_set_e2e_params(&conn, 1, "orphan-e2e-only", "0".repeat(32).as_str(), 600_000, None, "2026-01-01T00:00:00Z").unwrap();

        let known = known_profile_ids(&conn, &s, 1).unwrap();
        assert_eq!(known.len(), 1);
        assert!(known.contains("real-profile"));
        assert!(!known.contains("orphan-e2e-only"));
    }

    #[test]
    fn purge_user_removes_whole_tree_and_is_idempotent() {
        let dir = TestDir::new();
        let s = store(&dir);
        let conn = crate::db::init_test_conn();

        push(&conn, &s, 1, "devA", "prof1", &[item("p1", "preset", 100)], false).unwrap();
        push(&conn, &s, 1, "devB", "prof2", &[item("w1", "watchlist", 100)], false).unwrap();
        // A second user's data must survive user 1's purge.
        push(&conn, &s, 2, "devA", "prof1", &[item("p2", "preset", 100)], false).unwrap();

        assert!(s.user_dir(1).is_dir());
        purge_user(&s, 1).unwrap();
        assert!(!s.user_dir(1).exists());
        assert!(s.user_dir(2).is_dir());

        // Idempotent: purging an already-absent (or never-existed) user is Ok.
        purge_user(&s, 1).unwrap();
        purge_user(&s, 999).unwrap();
    }

    #[test]
    fn cleanup_inactive_removes_only_stale_users() {
        let dir = TestDir::new();
        let s = store(&dir);
        let conn = crate::db::init_test_conn();

        // User 1: stale — last write far in the past.
        push(&conn, &s, 1, "dev", "prof", &[item("p1", "preset", 1_000)], false).unwrap();
        // User 2: active — last write "now".
        let now_ms = chrono::Utc::now().timestamp_millis();
        push(&conn, &s, 2, "dev", "prof", &[item("p2", "preset", now_ms)], false).unwrap();

        let removed = cleanup_inactive(&s, 365).unwrap();
        assert_eq!(removed, 1);
        assert!(!s.user_dir(1).exists());
        assert!(s.user_dir(2).is_dir());

        // Second pass is a no-op — nothing left to remove.
        assert_eq!(cleanup_inactive(&s, 365).unwrap(), 0);
    }
    #[test]
    fn hot_ceilings_are_ten_times_larger_for_paid() {
        let dir = TestDir::new();
        let s = store(&dir);
        let conn = crate::db::init_test_conn();
        let free_limit = crate::entitlements::preset_limit(false);
        // Fill the free preset budget exactly.
        for i in 0..free_limit {
            let id = format!("p{i}");
            let r = push(&conn, &s, 1, "dev", "prof", &[item(&id, "preset", 100)], false).unwrap();
            assert_eq!(r.accepted, 1, "preset {i} within the free budget");
        }
        // One more is refused for a free account...
        let err = match push(&conn, &s, 1, "dev", "prof", &[item("overflow", "preset", 100)], false) {
            Err(e) => e,
            Ok(_) => panic!("free account past its preset ceiling was accepted"),
        };
        assert!(err.to_string().contains("preset limit"), "{err}");
        // ...and accepted for a paid one: same account, same store, only the
        // tier fact differs — the ceiling is ten times the free figure.
        let r = push(&conn, &s, 1, "dev", "prof", &[item("overflow", "preset", 100)], true).unwrap();
        assert_eq!(r.accepted, 1);
        assert_eq!(crate::entitlements::preset_limit(true), free_limit * 10);
    }
}
