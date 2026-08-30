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
//! There is no billing system yet, so there is no per-user paid source.
//! [`paid_features_for_user`] is the seam where one will plug in later —
//! it returns the empty set today and nothing above it needs to change
//! when it stops doing that.
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

/// Per-user paid entitlements beyond the free set.
///
/// Always empty today — there is no billing system yet. This is the ONE
/// place a future billing lookup plugs in (a claims table keyed by
/// `user_id`, or a call to a billing service). Do not invent that schema
/// here, and do not add a second resolution path beside this function —
/// every caller of entitlement resolution goes through
/// [`resolve_for_user`], which calls this.
fn paid_features_for_user(_user_id: i64) -> FeatureSet {
    FeatureSet::empty()
}

/// Resolve the full feature set for a caller.
///
/// `user_id` is `None` for an anonymous caller (no account) and `Some` for
/// an authenticated one. Anonymous and authenticated callers both start
/// from [`free_features`]; an authenticated caller's set additionally
/// includes whatever [`paid_features_for_user`] grants — nothing, until
/// billing is wired, so today this is equivalent to `free_features()`
/// either way.
pub fn resolve_for_user(user_id: Option<i64>) -> FeatureSet {
    let mut set = free_features();
    if let Some(uid) = user_id {
        set.extend_from(&paid_features_for_user(uid));
    }
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
    fn anonymous_caller_gets_exactly_the_configured_free_set() {
        // Anonymous (user_id = None) never consults paid_features_for_user —
        // its resolved set is exactly whatever MLC_FREE_FEATURES currently
        // configures, whatever that is in the test environment.
        assert_eq!(resolve_for_user(None), free_features());
    }

    #[test]
    fn resolve_for_user_matches_free_features_today_authenticated_or_not() {
        // No billing wired yet: an authenticated user's resolved set equals
        // the anonymous one, because paid_features_for_user is empty.
        let anon = resolve_for_user(None);
        let authed = resolve_for_user(Some(42));
        assert_eq!(anon, authed);
        assert_eq!(anon, free_features());
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
}
