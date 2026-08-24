//! Path validation primitives for user-controlled filesystem paths.
//!
//! Added after the 2026-07-27 incident: `GET /static/..%5c..%5c..%5c.env`
//! escaped the static root because axum percent-decodes `%5c` into `\` and
//! Windows treats `\` as a path separator *after* the naive validation.
//! Every user-supplied path must pass through these helpers before any
//! filesystem access.

use std::path::{Path, PathBuf};

/// Returns true only if `s` is a safe single path component: non-empty,
/// at most 64 chars, and containing only ASCII alphanumeric characters,
/// dots, hyphens, and underscores.
/// Rejects any form of path traversal characters (`/`, `\`, `%`, etc.).
/// Callers handling multi-segment paths must additionally reject the exact
/// components `.` and `..` — see `is_safe_relative_path`.
pub fn is_safe_path_component(s: &str) -> bool {
    !s.is_empty()
        && s.len() <= 64
        && s.chars()
            .all(|c| c.is_ascii_alphanumeric() || c == '.' || c == '-' || c == '_')
}

/// Returns true only if `path` is a safe relative path: at most 256 chars,
/// no backslashes (Windows separator bypass — see module docs), no empty
/// components, and every `/`-separated component passes
/// `is_safe_path_component` and is neither `.` nor `..`.
pub fn is_safe_relative_path(path: &str) -> bool {
    if path.is_empty() || path.len() > 256 || path.contains('\\') {
        return false;
    }
    path.split('/')
        .all(|comp| comp != "." && comp != ".." && is_safe_path_component(comp))
}

/// Joins `rel` onto `base` and verifies the canonicalized result stays
/// inside the canonicalized `base` (defense in depth on top of
/// `is_safe_relative_path`).
///
/// Returns `None` when validation fails, the target is not an existing
/// regular file, or canonicalization fails — callers must map `None` to a
/// bare 404 so no detail about the filesystem is leaked.
pub fn resolve_under(base: &Path, rel: &str) -> Option<PathBuf> {
    if !is_safe_relative_path(rel) {
        return None;
    }
    let base_canonical = base.canonicalize().ok()?;
    let candidate = base.join(rel);
    if !candidate.is_file() {
        return None;
    }
    let candidate_canonical = candidate.canonicalize().ok()?;
    if candidate_canonical.starts_with(&base_canonical) {
        Some(candidate_canonical)
    } else {
        None
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rejects_backslash_traversal() {
        // The original incident vector: %5c percent-decoded by axum into `\`.
        assert!(!is_safe_relative_path("..\\..\\..\\.env"));
        assert!(!is_safe_relative_path("static/..\\..\\..\\.env"));
        // Mixed separators.
        assert!(!is_safe_relative_path("a/b\\c"));
        assert!(!is_safe_relative_path("\\"));
    }

    #[test]
    fn rejects_dot_segments_and_empty_components() {
        assert!(!is_safe_relative_path(".."));
        assert!(!is_safe_relative_path("."));
        assert!(!is_safe_relative_path("../privacy"));
        assert!(!is_safe_relative_path("docs/../../etc/passwd"));
        assert!(!is_safe_relative_path("a//b"));
        assert!(!is_safe_relative_path("/leading"));
        assert!(!is_safe_relative_path("trailing/"));
        assert!(!is_safe_relative_path(""));
    }

    #[test]
    fn rejects_double_encoded_and_foreign_chars() {
        // Double encoding: validation sees the literal `%25...` string; `%`
        // is outside the allowlist.
        assert!(!is_safe_relative_path("%252e%252e"));
        assert!(!is_safe_relative_path("..%5c..%5c.env"));
        assert!(!is_safe_relative_path("%2e%2e/secret"));
        assert!(!is_safe_relative_path("file name.html"));
        assert!(!is_safe_relative_path("a?b"));
        assert!(!is_safe_relative_path("a\u{0}b"));
    }

    #[test]
    fn accepts_normal_paths() {
        assert!(is_safe_relative_path("privacy"));
        assert!(is_safe_relative_path("robots.txt"));
        assert!(is_safe_relative_path("docs/agent-api"));
        assert!(is_safe_relative_path("docs/agent-api.html"));
        assert!(is_safe_relative_path(".well-known/assetlinks.json"));
        assert!(is_safe_relative_path("assets/app_v2-final.min.css"));
    }

    #[test]
    fn resolve_under_contains_within_base() {
        let base = std::env::temp_dir().join("mlc-pathutil-test-base");
        std::fs::create_dir_all(base.join("docs")).unwrap();
        std::fs::write(base.join("robots.txt"), b"ok").unwrap();
        std::fs::write(base.join("docs/page.html"), b"ok").unwrap();

        let resolved = resolve_under(&base, "robots.txt").unwrap();
        assert!(resolved.starts_with(base.canonicalize().unwrap()));
        assert!(resolve_under(&base, "docs/page.html").is_some());

        // Traversal, backslashes and missing files all yield None.
        assert!(resolve_under(&base, "..\\robots.txt").is_none());
        assert!(resolve_under(&base, "../robots.txt").is_none());
        assert!(resolve_under(&base, "missing.txt").is_none());

        std::fs::remove_dir_all(&base).ok();
    }
}
