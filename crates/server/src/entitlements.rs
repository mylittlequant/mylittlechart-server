//! Named paid features and their resolution to a caller.
//!
//! Generalises the placeholder that used to live entirely in
//! `routes/proxy.rs` (a single `MLC_PROXY_GATE` boolean with no per-user
//! claim of any kind) into a named feature set with one resolution path.
//! `GET /api/entitlements` (routes/entitlements.rs) and
//! `GET /api/proxy/entitlement` (routes/proxy.rs) both read through
//! [`free_features`] / [`resolve_for_user`] — there is one mechanism, not
//! two living side by side.
//!
//! There is no billing system yet, so paid access today comes only from
//! `db::user_is_paid` (gift/trial code redemption — see `db.rs`'s
//! `gift_codes` table and `routes::account::redeem`). [`paid_features`] is
//! the seam: it takes the already-resolved paid/not-paid fact, not a
//! `user_id`, so this module never gains a database dependency and its tests
//! keep running with no database at all. [`resolve_for_user`]'s callers
//! (`routes/entitlements.rs`, `routes/sync.rs`) are the ones that look up
//! `db::user_is_paid` and pass the fact in.
//!
//! Default posture: with `MLC_FREE_FEATURES` unset, every feature is free
//! for every caller (anonymous and authenticated alike). That is what makes
//! shipping this module inert on a production deployment with no new env
//! var set — flipping a paywall later means removing one name from that
//! list, nothing more.

use std::collections::{BTreeSet, HashSet};

// ============================================================================
// Feature
// ============================================================================

/// A named paid feature.
///
/// Maps to a stable lowercase wire string via [`as_str`](Feature::as_str) /
/// [`from_wire_name`](Feature::from_wire_name) — both `GET /api/entitlements`
/// and `MLC_FREE_FEATURES` parsing depend on this exact spelling, so renaming
/// a variant is a wire-format change, not a refactor. Deliberately hand-
/// written rather than a `#[derive(Serialize)]` with `rename_all` so there is
/// exactly one place (this `impl` block) that owns the spelling in both
/// directions, instead of a serde attribute and a hand-rolled parser that
/// could drift apart.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum Feature {
    /// More than one profile per account. Free accounts (and anonymous
    /// callers, who have no account and one purely local profile) are
    /// limited to [`FREE_PROFILE_LIMIT`]; see [`profile_write_allowed`]
    /// and its callers in `routes/sync.rs`.
    MultiProfile,
    /// Use of `/archive-proxy` beyond the free must-proxy catalog. See
    /// `routes/proxy.rs`.
    ArchiveProxy,
}

impl Feature {
    /// Every feature that exists. Used as the default free set (see
    /// [`free_features`]) so an unconfigured deployment grants everything.
    const ALL: [Feature; 2] = [Feature::MultiProfile, Feature::ArchiveProxy];

    /// Stable wire name — also the spelling accepted in `MLC_FREE_FEATURES`.
    fn as_str(self) -> &'static str {
        match self {
            Feature::MultiProfile => "multi_profile",
            Feature::ArchiveProxy => "archive_proxy",
        }
    }

    fn from_wire_name(s: &str) -> Option<Feature> {
        match s {
            "multi_profile" => Some(Feature::MultiProfile),
            "archive_proxy" => Some(Feature::ArchiveProxy),
            _ => None,
        }
    }
}

// ============================================================================
// FeatureSet
// ============================================================================

/// The set of features a caller holds.
///
/// Not `Serialize` itself — `routes/entitlements.rs` builds its JSON
/// response from [`wire_names`](FeatureSet::wire_names) alongside other
/// fields (`expires_at`), rather than serialising this type verbatim.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct FeatureSet(BTreeSet<Feature>);

impl FeatureSet {
    /// The empty set — no features.
    pub fn empty() -> Self {
        Self(BTreeSet::new())
    }

    /// Every feature that exists.
    pub fn all() -> Self {
        Self(Feature::ALL.into_iter().collect())
    }

    /// Whether this set holds `feature`.
    pub fn contains(&self, feature: Feature) -> bool {
        self.0.contains(&feature)
    }

    fn insert(&mut self, feature: Feature) {
        self.0.insert(feature);
    }

    /// Merge `other`'s features into this set.
    fn extend_from(&mut self, other: &FeatureSet) {
        self.0.extend(other.0.iter().copied());
    }

    /// Stable-ordered wire names, for building a JSON response by hand
    /// (see `routes/entitlements.rs`).
    pub fn wire_names(&self) -> Vec<&'static str> {
        self.0.iter().map(|f| f.as_str()).collect()
    }
}

// ============================================================================
// Free-tier resolution (env var)
// ============================================================================

/// Env var naming the features granted to every caller — anonymous and
/// authenticated alike — with no paid claim. Comma-separated feature names,
/// e.g. `MLC_FREE_FEATURES=multi_profile,archive_proxy`.
///
/// Unset (the production default today): every feature. Replaces
/// `MLC_PROXY_GATE`, which named only the archive-proxy half of this same
/// idea; there is now exactly one env var that controls what is free.
const FREE_FEATURES_ENV: &str = "MLC_FREE_FEATURES";

/// The features granted to every caller with no paid claim, read from
/// [`FREE_FEATURES_ENV`]. Unset or empty defaults to [`FeatureSet::all`].
pub fn free_features() -> FeatureSet {
    match std::env::var(FREE_FEATURES_ENV) {
        Ok(raw) => parse_free_features(&raw),
        Err(_) => FeatureSet::all(),
    }
}

/// Parse a comma-separated feature list. Unknown tokens are logged and
/// skipped rather than rejected outright — a typo in the env var should
/// narrow the free set, not crash the process. An entirely empty or
/// all-unrecognised value yields the empty set (explicitly configuring
/// "no free features" is a valid, if unusual, deployment choice — it is
/// only the *unset* env var that defaults to everything).
fn parse_free_features(raw: &str) -> FeatureSet {
    let mut set = FeatureSet::empty();
    for token in raw.split(',') {
        let token = token.trim();
        if token.is_empty() {
            continue;
        }
        match Feature::from_wire_name(token) {
            Some(f) => set.insert(f),
            None => tracing::warn!(
                "{FREE_FEATURES_ENV}: unrecognised feature {:?} ignored",
                token
            ),
        }
    }
    set
}

// ============================================================================
// Per-user paid claims (seam — no billing system yet)
// ============================================================================

/// The entitlements a paid account holds beyond the free set.
///
/// Takes the already-resolved fact, not a `user_id` — the caller (currently
/// `routes/entitlements.rs` and `routes/sync.rs`) is the one that knows how
/// to ask the database (`db::user_is_paid`), so this module stays free of a
/// database dependency and its tests keep running without one. Everything
/// paid grants today; once billing introduces tiers narrower than "every
/// feature", this is the one place that changes.
fn paid_features(is_paid: bool) -> FeatureSet {
    if is_paid {
        FeatureSet::all()
    } else {
        FeatureSet::empty()
    }
}

/// Resolve the full feature set for a caller.
///
/// `is_paid` is the caller's already-resolved paid/not-paid fact (`false`
/// for an anonymous caller, who has no account to be paid on) — see
/// [`paid_features`]. Every caller starts from [`free_features`]; a paid
/// caller's set additionally includes whatever [`paid_features`] grants.
pub fn resolve_for_user(is_paid: bool) -> FeatureSet {
    let mut set = free_features();
    set.extend_from(&paid_features(is_paid));
    set
}

// ============================================================================
// Multi-profile enforcement rule
// ============================================================================

/// The number of distinct profiles a free account (or an anonymous caller)
/// may hold without [`Feature::MultiProfile`].
pub const FREE_PROFILE_LIMIT: usize = 1;

/// Decide whether a write carrying `profile_id` may proceed.
///
/// `known_profile_ids` is every profile_id the server has already seen for
/// this user (see `syncstore::known_profile_ids` — merged across the cold
/// SQL plane and the hot file store, NOT `sync_e2e_params`; see that
/// function's doc comment for why).
///
/// A `profile_id` already in `known_profile_ids` is never a profile
/// creation — it always passes, regardless of count or entitlement. This is
/// what grandfathers every profile that predates this rule: they are all
/// already "known" by construction.
///
/// A `profile_id` NOT in `known_profile_ids` IS a profile creation. It is
/// allowed only if the user currently holds fewer than
/// [`FREE_PROFILE_LIMIT`] known profiles, or `features` holds
/// [`Feature::MultiProfile`].
pub fn profile_write_allowed(
    known_profile_ids: &HashSet<String>,
    profile_id: &str,
    features: &FeatureSet,
) -> bool {
    if known_profile_ids.contains(profile_id) {
        return true;
    }
    known_profile_ids.len() < FREE_PROFILE_LIMIT || features.contains(Feature::MultiProfile)
}

// ============================================================================
// Share-link enforcement rule
// ============================================================================

/// The two kinds of share link an account can create (see the "Share links"
/// section in `db.rs` for the storage half).
///
/// [`as_str`](ShareKind::as_str) owns the spelling of the `kind` column in
/// the `share_links` table and of the `kind` field in the public viewer's
/// JSON — renaming a variant's string is a wire-format change, not a
/// refactor.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ShareKind {
    /// A frozen ChartPreset, rendered read-only by the web viewer.
    Live,
    /// A stored PNG blob, streamed back verbatim.
    Screenshot,
}

impl ShareKind {
    /// Stable wire/storage name.
    pub fn as_str(self) -> &'static str {
        match self {
            ShareKind::Live => "live",
            ShareKind::Screenshot => "screenshot",
        }
    }

    pub fn from_wire_name(s: &str) -> Option<ShareKind> {
        match s {
            "live" => Some(ShareKind::Live),
            "screenshot" => Some(ShareKind::Screenshot),
            _ => None,
        }
    }
}

/// Active (non-expired, non-revoked) shares an account may hold at once.
/// Free limits also apply to anonymous callers, who cannot create shares at
/// all (creation is authenticated-only) — they exist here so
/// `GET /api/entitlements` can still state a maximum for them.
pub const FREE_LIVE_SHARE_LIMIT: u64 = 1;
pub const PAID_LIVE_SHARE_LIMIT: u64 = 10;
pub const FREE_SCREENSHOT_SHARE_LIMIT: u64 = 10;
pub const PAID_SCREENSHOT_SHARE_LIMIT: u64 = 100;

/// Share lifetime in seconds, stamped into `expires_at` at creation. Reading
/// a share never extends it.
pub const LIVE_SHARE_TTL_FREE: u64 = 7 * 24 * 60 * 60;
pub const LIVE_SHARE_TTL_PAID: u64 = 90 * 24 * 60 * 60;
pub const SCREENSHOT_SHARE_TTL_FREE: u64 = 30 * 24 * 60 * 60;
pub const SCREENSHOT_SHARE_TTL_PAID: u64 = 365 * 24 * 60 * 60;

/// The active-share ceiling for one kind at one tier.
pub fn share_limit(kind: ShareKind, is_paid: bool) -> u64 {
    match (kind, is_paid) {
        (ShareKind::Live, false) => FREE_LIVE_SHARE_LIMIT,
        (ShareKind::Live, true) => PAID_LIVE_SHARE_LIMIT,
        (ShareKind::Screenshot, false) => FREE_SCREENSHOT_SHARE_LIMIT,
        (ShareKind::Screenshot, true) => PAID_SCREENSHOT_SHARE_LIMIT,
    }
}

/// Decide whether creating one more share of `kind` may proceed, given how
/// many active shares of that kind the account already holds (see
/// `db::share_usage`). Unlike [`profile_write_allowed`] there is no
/// grandfathering: every creation counts against the ceiling, and revocation
/// is how an account makes room again.
pub fn share_create_allowed(kind: ShareKind, current_count: u64, is_paid: bool) -> bool {
    current_count < share_limit(kind, is_paid)
}

/// The lifetime of a new share of `kind` at one tier, in seconds.
pub fn share_ttl_secs(kind: ShareKind, is_paid: bool) -> u64 {
    match (kind, is_paid) {
        (ShareKind::Live, false) => LIVE_SHARE_TTL_FREE,
        (ShareKind::Live, true) => LIVE_SHARE_TTL_PAID,
        (ShareKind::Screenshot, false) => SCREENSHOT_SHARE_TTL_FREE,
        (ShareKind::Screenshot, true) => SCREENSHOT_SHARE_TTL_PAID,
    }
}

// ============================================================================
// Hot-plane sync quota rule
// ============================================================================

/// Paid accounts hold ten times the free hot-plane budget (operator ruling
/// 2026-08-17, "paid x10 hot"). The hot plane is the file store — presets,
/// templates, layouts — measured in bytes AND in preset/template counts, and
/// all three scale together: a byte ceiling alone means nothing while the
/// item counts stay put (a hundred presets fit in 8 MiB many times over).
/// The cold identity plane (`db::SYNC_MAX_COLD_BYTES`) is deliberately NOT
/// scaled — it holds three singletons whose size does not depend on tier.
pub const PAID_HOT_MULTIPLIER: i64 = 10;

fn tier_scaled(free: i64, is_paid: bool) -> i64 {
    if is_paid {
        free * PAID_HOT_MULTIPLIER
    } else {
        free
    }
}

/// Hot-plane byte ceiling for one tier; the free figure is
/// `db::SYNC_MAX_TOTAL_BYTES` and its derivation lives there.
pub fn hot_bytes_limit(is_paid: bool) -> i64 {
    tier_scaled(crate::db::SYNC_MAX_TOTAL_BYTES, is_paid)
}

/// Preset-count ceiling for one tier (`db::SYNC_MAX_PRESETS` for free).
pub fn preset_limit(is_paid: bool) -> i64 {
    tier_scaled(crate::db::SYNC_MAX_PRESETS, is_paid)
}

/// Template-count ceiling for one tier (`db::SYNC_MAX_TEMPLATES` for free).
pub fn template_limit(is_paid: bool) -> i64 {
    tier_scaled(crate::db::SYNC_MAX_TEMPLATES, is_paid)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn feature_set_all_holds_every_variant() {
        // `MLC_FREE_FEATURES` unset falls straight to `FeatureSet::all()`
        // (see `free_features()`) — this is the default-inert posture.
        assert!(FeatureSet::all().contains(Feature::MultiProfile));
        assert!(FeatureSet::all().contains(Feature::ArchiveProxy));
    }

    #[test]
    fn parse_free_features_explicit_subset() {
        let set = parse_free_features("archive_proxy");
        assert!(set.contains(Feature::ArchiveProxy));
        assert!(!set.contains(Feature::MultiProfile));
    }

    #[test]
    fn parse_free_features_ignores_unknown_tokens() {
        let set = parse_free_features("multi_profile, bogus_feature ,,archive_proxy");
        assert_eq!(set, FeatureSet::all());
    }

    #[test]
    fn parse_free_features_empty_string_is_empty_set() {
        assert_eq!(parse_free_features(""), FeatureSet::empty());
        assert_eq!(parse_free_features("   "), FeatureSet::empty());
    }

    #[test]
    fn unpaid_caller_gets_exactly_the_configured_free_set() {
        // is_paid = false (anonymous, or an authenticated but never-paid
        // account) never consults paid_features for anything but the empty
        // set — its resolved set is exactly whatever MLC_FREE_FEATURES
        // currently configures, whatever that is in the test environment.
        assert_eq!(resolve_for_user(false), free_features());
    }

    #[test]
    fn paid_caller_gets_every_feature() {
        let paid = resolve_for_user(true);
        assert!(paid.contains(Feature::MultiProfile));
        assert!(paid.contains(Feature::ArchiveProxy));
    }

    #[test]
    fn new_profile_under_limit_passes() {
        let known: HashSet<String> = HashSet::new();
        let features = FeatureSet::empty();
        assert!(profile_write_allowed(&known, "prof-a", &features));
    }

    #[test]
    fn new_profile_over_limit_without_entitlement_is_refused() {
        let mut known = HashSet::new();
        known.insert("prof-a".to_string());
        let features = FeatureSet::empty();
        assert!(!profile_write_allowed(&known, "prof-b", &features));
    }

    #[test]
    fn new_profile_over_limit_with_multi_profile_entitlement_passes() {
        let mut known = HashSet::new();
        known.insert("prof-a".to_string());
        let mut features = FeatureSet::empty();
        features.insert(Feature::MultiProfile);
        assert!(profile_write_allowed(&known, "prof-b", &features));
    }

    #[test]
    fn already_known_profile_always_passes_regardless_of_count_or_entitlement() {
        let mut known = HashSet::new();
        known.insert("prof-a".to_string());
        known.insert("prof-b".to_string());
        known.insert("prof-c".to_string());
        known.insert("prof-d".to_string());
        let features = FeatureSet::empty();
        // Four known profiles already exceeds the free limit, but a write to
        // one of them (the grandfathering case — e.g. the production user
        // with four pre-existing profiles) is not a creation.
        assert!(profile_write_allowed(&known, "prof-b", &features));
    }

    #[test]
    fn share_create_allowed_free_tier_boundaries() {
        // Free: 1 live, 10 screenshots — the boundary count itself is refused.
        assert!(share_create_allowed(ShareKind::Live, 0, false));
        assert!(!share_create_allowed(ShareKind::Live, 1, false));
        assert!(share_create_allowed(ShareKind::Screenshot, 9, false));
        assert!(!share_create_allowed(ShareKind::Screenshot, 10, false));
    }

    #[test]
    fn share_create_allowed_paid_tier_boundaries() {
        // Paid: 10 live, 100 screenshots.
        assert!(share_create_allowed(ShareKind::Live, 9, true));
        assert!(!share_create_allowed(ShareKind::Live, 10, true));
        assert!(share_create_allowed(ShareKind::Screenshot, 99, true));
        assert!(!share_create_allowed(ShareKind::Screenshot, 100, true));
    }

    #[test]
    fn share_ttl_secs_matches_approved_values() {
        assert_eq!(share_ttl_secs(ShareKind::Live, false), 7 * 24 * 3600);
        assert_eq!(share_ttl_secs(ShareKind::Live, true), 90 * 24 * 3600);
        assert_eq!(share_ttl_secs(ShareKind::Screenshot, false), 30 * 24 * 3600);
        assert_eq!(share_ttl_secs(ShareKind::Screenshot, true), 365 * 24 * 3600);
    }

    #[test]
    fn share_kind_wire_names_roundtrip() {
        // The `kind` column in db's share_links table stores these exact
        // spellings — drift here splits the storage from the reader.
        assert_eq!(ShareKind::from_wire_name("live"), Some(ShareKind::Live));
        assert_eq!(
            ShareKind::from_wire_name("screenshot"),
            Some(ShareKind::Screenshot)
        );
        assert_eq!(ShareKind::from_wire_name("bogus"), None);
        for kind in [ShareKind::Live, ShareKind::Screenshot] {
            assert_eq!(ShareKind::from_wire_name(kind.as_str()), Some(kind));
        }
    }
    #[test]
    fn hot_limits_are_free_figures_for_free_and_ten_times_for_paid() {
        assert_eq!(hot_bytes_limit(false), crate::db::SYNC_MAX_TOTAL_BYTES);
        assert_eq!(preset_limit(false), crate::db::SYNC_MAX_PRESETS);
        assert_eq!(template_limit(false), crate::db::SYNC_MAX_TEMPLATES);
        assert_eq!(hot_bytes_limit(true), crate::db::SYNC_MAX_TOTAL_BYTES * 10);
        assert_eq!(preset_limit(true), crate::db::SYNC_MAX_PRESETS * 10);
        assert_eq!(template_limit(true), crate::db::SYNC_MAX_TEMPLATES * 10);
    }
}
