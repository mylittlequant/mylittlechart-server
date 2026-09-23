//! Library target for `mylittlechart-server`, auto-discovered by Cargo
//! alongside the `mylittlechart-server`/`mlc-dbadmin` binaries (same
//! package, `src/main.rs` + `src/bin/mlc-dbadmin.rs`). Every table/route
//! module the server has ever had lives directly in the binary crate's own
//! module tree (`main.rs`'s `mod` list) — this file stayed empty until the
//! community messenger arc needed it.
//!
//! It hosts `live` for one reason: a module whose `pub` API has no caller
//! yet inside THIS crate (only its own `#[cfg(test)]` unit tests reach it)
//! is flagged `dead_code` under `-D warnings` in a binary crate, because a
//! bin has no external consumer for the compiler to assume one exists — a
//! library crate's `pub` items are exempt from that same lint by design,
//! since an external crate might be the caller. The community messenger
//! arc's server pieces are deliberately split across separate work items
//! (`docs/mlc/plans/community-messenger-arc-2026-09-24.md` §4): `S2`
//! (`live`, the live-event registry) ships before `S3`/`S4` (the routes
//! that call it). Rather than silence that lint (banned in this codebase)
//! or fabricate a fake call site in `main`, that module lives here instead,
//! where its `pub` API is genuinely correct as a public surface awaiting
//! its caller. (`S1`, `conversations_db`, was retired 2026-09-24 in favour
//! of a Matrix-subset messenger design — see `_archive/conversations_db.rs`
//! at the repo root.)
//!
//! `mylittlechart-server` (the binary) automatically links against this
//! same-package library crate — reach this module from bin-crate code
//! (`main.rs`, `state.rs`, and eventually `routes::rooms`) as
//! `mylittlechart_server::live`, the same way any other external crate is
//! named. It depends on nothing in the binary crate's own module tree.

pub mod live;
pub mod matrix_store;
