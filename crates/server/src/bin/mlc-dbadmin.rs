//! mlc-dbadmin — offline DB operations with the SAME bundled SQLCipher build
//! the server uses (Ubuntu's sqlcipher CLI is format-incompatible with it —
//! proven 2026-08-24, do not use the CLI on our databases).
//!
//! Usage:
//!   mlc-dbadmin migrate <plain.db> <encrypted.db>   # plaintext -> SQLCipher
//!   mlc-dbadmin backup  <encrypted.db> <out.db>     # online-consistent snapshot
//!
//! Key is read from MLC_DBKEY_PATH (default /run/mlc/dbkey): 64 hex chars
//! or raw 32 bytes, trailing whitespace stripped.

use rusqlite::Connection;

/// Hot sync categories — MUST match `crates/server/src/syncstore.rs`
/// `HOT_CATEGORIES` (documented-not-derived contract: this bin cannot import
/// the server binary crate).
const HOT_CATEGORIES: &[&str] = &[
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

/// Same allowlist rules as `syncstore::sanitize` (empty → `_`). Panics on an
/// unsafe component: aborting the export is safer than silently dropping a row.
fn sanitize(component: &str) -> String {
    if component.is_empty() {
        return "_".to_string();
    }
    let ok = component.len() <= 128
        && component != ".."
        && !component.starts_with('.')
        && component
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || matches!(c, '-' | '_' | '.'));
    assert!(ok, "unsafe path component in sync_items: {component:?}");
    component.to_string()
}

fn key_hex() -> String {
    let path = std::env::var("MLC_DBKEY_PATH").unwrap_or_else(|_| "/run/mlc/dbkey".into());
    let raw = std::fs::read(&path).unwrap_or_else(|e| panic!("cannot read key {path}: {e}"));
    let mut end = raw.len();
    while end > 0 && raw[end - 1].is_ascii_whitespace() {
        end -= 1;
    }
    let t = &raw[..end];
    if t.len() == 64 && t.iter().all(|b| b.is_ascii_hexdigit()) {
        String::from_utf8_lossy(t).to_lowercase()
    } else {
        hex::encode(t)
    }
}

/// Is this a plain SQLite file rather than a SQLCipher one?
///
/// SQLCipher overwrites the first 16 bytes of page 1 with the salt, so the
/// `SQLite format 3\0` magic is present in exactly the unencrypted case.
/// Since the 2026-08-30 store split there are two databases side by side —
/// encrypted identity and plain `operational.db` — and applying `PRAGMA key`
/// to the plain one fails with an unhelpful error.
fn is_plain_sqlite(path: &str) -> bool {
    use std::io::Read;
    let mut magic = [0u8; 16];
    std::fs::File::open(path)
        .and_then(|mut f| f.read_exact(&mut magic))
        .map(|_| &magic == b"SQLite format 3\0")
        .unwrap_or(false)
}

/// Open a database, applying the key only when the file is actually encrypted.
fn open_encrypted(path: &str, key: &str) -> Connection {
    let conn = Connection::open(path).expect("open db");
    if !is_plain_sqlite(path) {
        let pragma = format!("PRAGMA key = \"x'{}'\";", key);
        conn.execute_batch(&pragma).expect("apply key");
    }
    conn
}

fn main() {
    let args: Vec<String> = std::env::args().collect();
    let key = key_hex();
    match args.get(1).map(String::as_str) {
        Some("migrate") => {
            let plain = args.get(2).expect("plain db").clone();
            let enc = args.get(3).expect("enc db").clone();
            assert!(std::path::Path::new(&plain).exists(), "plain db missing");
            assert!(!std::path::Path::new(&enc).exists(), "enc target exists — refusing");
            let conn = Connection::open(&plain).expect("open plain");
            let attach = format!("ATTACH DATABASE '{}' AS encrypted KEY \"x'{}'\";", enc, key);
            conn.execute_batch(&attach).expect("attach encrypted");
            conn.execute_batch("SELECT sqlcipher_export('encrypted');")
                .expect("sqlcipher_export");
            conn.execute_batch("DETACH DATABASE encrypted;").expect("detach");
            println!("MIGRATE-OK {plain} -> {enc}");
        }
        Some("backup") => {
            let src = args.get(2).expect("db").clone();
            let out = args.get(3).expect("out").clone();
            let src_conn = open_encrypted(&src, &key);
            src_conn
                .execute_batch("PRAGMA busy_timeout=10000;")
                .expect("busy_timeout");
            let mut dst = open_encrypted(&out, &key);
            let bk = rusqlite::backup::Backup::new(&src_conn, &mut dst).expect("backup init");
            bk.run_to_completion(16, std::time::Duration::from_millis(50), None)
                .expect("backup run");
            println!("BACKUP-OK {src} -> {out}");
        }
        Some("query") => {
            // Read-only inspection: `mlc-dbadmin query <db> "<sql>"` — rows
            // printed pipe-separated, one per line. Text/NULL rendering only;
            // blobs print as their byte length.
            let db = args.get(2).expect("db").clone();
            let sql = args.get(3).expect("sql").clone();
            let conn = open_encrypted(&db, &key);
            let mut stmt = conn.prepare(&sql).expect("prepare");
            let cols = stmt.column_count();
            let mut rows = stmt.query([]).expect("query");
            while let Some(row) = rows.next().expect("row") {
                let mut cells = Vec::with_capacity(cols);
                for i in 0..cols {
                    let v = row
                        .get_ref(i)
                        .map(|r| match r {
                            rusqlite::types::ValueRef::Null => "NULL".to_string(),
                            rusqlite::types::ValueRef::Integer(n) => n.to_string(),
                            rusqlite::types::ValueRef::Real(f) => f.to_string(),
                            rusqlite::types::ValueRef::Text(t) => {
                                String::from_utf8_lossy(t).into_owned()
                            }
                            rusqlite::types::ValueRef::Blob(b) => format!("<blob {}B>", b.len()),
                        })
                        .unwrap_or_else(|_| "?".into());
                    cells.push(v);
                }
                println!("{}", cells.join("|"));
            }
        }
        Some("exec") => {
            // Maintenance writes (telemetry cleanup, test fixtures):
            // `mlc-dbadmin exec <db> "<sql>"`. Root-only tool on the box.
            let db = args.get(2).expect("db").clone();
            let sql = args.get(3).expect("sql").clone();
            let conn = open_encrypted(&db, &key);
            conn.execute_batch(&sql).expect("exec");
            println!("EXEC-OK");
        }
        Some("export-hot") => {
            // Split migration step 1: `mlc-dbadmin export-hot <db> <dir>` —
            // dump every hot-category sync_items row as one JSON file per
            // item, in the exact layout syncstore serves:
            //   <dir>/<user>/<device>/<profile>/<category>/<sync_id>.json
            let db = args.get(2).expect("db").clone();
            let dir = args.get(3).expect("dir").clone();
            let conn = open_encrypted(&db, &key);
            let mut stmt = conn
                .prepare(
                    "SELECT user_id, device_id, profile_id, sync_id, category, name,
                            content, checksum, modified_at, deleted, display_name
                     FROM sync_items",
                )
                .expect("prepare");
            let mut rows = stmt.query([]).expect("query");
            let mut exported = 0u64;
            let mut skipped = 0u64;
            while let Some(row) = rows.next().expect("row") {
                let user_id: i64 = row.get(0).unwrap();
                let device_id: String = row.get(1).unwrap();
                let profile_id: String = row.get(2).unwrap();
                let sync_id: String = row.get(3).unwrap();
                let category: String = row.get(4).unwrap();
                if !HOT_CATEGORIES.contains(&category.as_str()) {
                    skipped += 1;
                    continue;
                }
                let name: String = row.get(5).unwrap();
                let content: Vec<u8> = row.get(6).unwrap();
                let checksum: String = row.get(7).unwrap();
                let modified_at: i64 = row.get(8).unwrap();
                let deleted: bool = row.get::<_, i64>(9).unwrap() != 0;
                let display_name: String = row.get(10).unwrap_or_default();
                let content = String::from_utf8_lossy(&content).into_owned();
                let mut obj = serde_json::json!({
                    "sync_id": sync_id,
                    "category": category,
                    "name": name,
                    "content": content,
                    "checksum": checksum,
                    "modified_at": modified_at,
                    "deleted": deleted,
                });
                if category == "profile_meta" && !display_name.is_empty() {
                    obj["display_name"] = serde_json::json!(display_name);
                }
                let path = std::path::Path::new(&dir)
                    .join(user_id.to_string())
                    .join(sanitize(&device_id))
                    .join(sanitize(&profile_id))
                    .join(sanitize(&category))
                    .join(format!("{}.json", sanitize(&sync_id)));
                std::fs::create_dir_all(path.parent().unwrap()).expect("mkdir");
                std::fs::write(&path, serde_json::to_vec_pretty(&obj).unwrap()).expect("write");
                exported += 1;
            }
            println!("EXPORT-HOT-OK exported={exported} skipped_cold={skipped}");
        }
        Some("purge-hot") => {
            // Split migration step 2: `mlc-dbadmin purge-hot <db>` — delete the
            // hot-category rows from SQL after export-hot was verified on disk.
            let db = args.get(2).expect("db").clone();
            let conn = open_encrypted(&db, &key);
            let list = HOT_CATEGORIES
                .iter()
                .map(|c| format!("'{c}'"))
                .collect::<Vec<_>>()
                .join(",");
            let n = conn
                .execute(
                    &format!("DELETE FROM sync_items WHERE category IN ({list})"),
                    [],
                )
                .expect("purge");
            println!("PURGE-HOT-OK deleted={n}");
        }
        _ => {
            eprintln!(
                "usage: mlc-dbadmin migrate <plain> <enc> | backup <db> <out> | query <db> <sql> | exec <db> <sql> | export-hot <db> <dir> | purge-hot <db>"
            );
            std::process::exit(2);
        }
    }
}
