//! Library target for `mylittlechart-server`, auto-discovered by Cargo
//! alongside the `mylittlechart-server`/`mlc-dbadmin` binaries (same
//! package, `src/main.rs` + `src/bin/mlc-dbadmin.rs`). Every table/route
//! module the server has ever had lives directly in the binary crate's own
//! module tree (`main.rs`'s `mod` list) — this file stayed empty until now.
//!
//! It exists now for one reason: a module whose `pub` API has no caller yet
//! inside THIS crate (only its own `#[cfg(test)]` unit tests reach it) is
//! flagged `dead_code` under `-D warnings` in a binary crate, because a bin
//! has no external consumer for the compiler to assume one exists — a
//! library crate's `pub` items are exempt from that same lint by design,
//! since an external crate might be the caller. The community messenger
//! arc's server pieces are deliberately split across separate work items
//! (`docs/mlc/plans/community-messenger-arc-2026-09-24.md` §4): `S1`
//! (`conversations_db`, schema + CRUD) and `S2` (`live`, the live-event
//! registry) ship before `S3`/`S4` (the routes that call them). Rather than
//! silence that lint (banned in this codebase) or fabricate a fake call
//! site in `main`, those two modules live here instead, where their `pub`
//! API is genuinely correct as a public surface awaiting its caller.
//!
//! `mylittlechart-server` (the binary) automatically links against this
//! same-package library crate — reach these modules from bin-crate code
//! (`main.rs`, `state.rs`, `social_db.rs`, and eventually `routes::
//! conversations`/`routes::rooms`) as `mylittlechart_server::conversations_db`/
//! `mylittlechart_server::live`, the same way any other external crate is
//! named. Neither module depends on anything in the binary crate's own
//! module tree — `conversations_db.rs` duplicates the handful of `dm_db.rs`
//! constants it needs by hand (documented at each duplicate) rather than
//! reaching back into the bin, the same documented-not-derived pattern
//! `src/bin/mlc-dbadmin.rs`'s `HOT_CATEGORIES` already uses in this crate
//! for the identical binary-cannot-import-binary problem.

pub mod conversations_db;
pub mod live;
