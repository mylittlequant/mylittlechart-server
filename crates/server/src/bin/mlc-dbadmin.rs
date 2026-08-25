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

fn open_encrypted(path: &str, key: &str) -> Connection {
    let conn = Connection::open(path).expect("open db");
    let pragma = format!("PRAGMA key = \"x'{}'\";", key);
    conn.execute_batch(&pragma).expect("apply key");
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
        _ => {
            eprintln!(
                "usage: mlc-dbadmin migrate <plain> <enc> | backup <db> <out> | query <db> <sql>"
            );
            std::process::exit(2);
        }
    }
}
