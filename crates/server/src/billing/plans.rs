//! The MLC plan catalog: which dig2pay plan ids exist, what each grants, and
//! to whom each is offered.
//!
//! The ids and USD prices below are the agreed contract with the dig2pay
//! processor (`docs/dig2pay/plans/mlc-integration-2026-09-25.md` §1), created
//! there by the processor admin; this table only mirrors them so the UI can
//! list them and the webhook can map a plan to a grant. The amounts a payer
//! actually owes always come back from dig2pay in the `pay[]` array — the
//! `price_usd` here is display-only.
//!
//! Two things are configuration rather than code (see `config.rs`):
//! * the ids of the four one-time account plans (`MLC_BILLING_PLAN_PAID`,
//!   `_ANON`, `_PAID_TOR`, `_ANON_TOR`; the constants below are only their
//!   defaults — the processor creates these plans, and a plan it does not
//!   have yet is answered as a clean `plan_unavailable`, see `flow.rs`), and
//! * the quant quota per monthly tier (`MLC_BILLING_QUANT_QUOTAS`) — no quota
//!   number lives in code.

use std::collections::BTreeMap;

/// What a settled plan grants the account.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Grant {
    /// A lifetime paid account (OAuth identity).
    LifetimePaid,
    /// A lifetime anonymous account (no OAuth): anonymous AND paid, for life.
    LifetimeAnon,
    /// A quant tier: paid status plus the tier's quota while the
    /// subscription's paid period is running.
    Quant,
}

impl Grant {
    /// Stable storage/wire spelling (`billing_invoices.grant_kind`).
    pub fn as_str(self) -> &'static str {
        match self {
            Grant::LifetimePaid => "lifetime_paid",
            Grant::LifetimeAnon => "lifetime_anon",
            Grant::Quant => "quant",
        }
    }

    /// Inverse of [`Grant::as_str`].
    pub fn parse(raw: &str) -> Option<Grant> {
        match raw {
            "lifetime_paid" => Some(Grant::LifetimePaid),
            "lifetime_anon" => Some(Grant::LifetimeAnon),
            "quant" => Some(Grant::Quant),
            _ => None,
        }
    }
}

/// How a plan is billed.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Interval {
    /// Settles once, then the dig2pay subscription is terminal `paid` and
    /// never renews.
    OneTime,
    /// Renews every period.
    Monthly,
}

impl Interval {
    /// Wire spelling used in `GET /api/billing/plans`.
    pub fn as_str(self) -> &'static str {
        match self {
            Interval::OneTime => "one_time",
            Interval::Monthly => "monthly",
        }
    }
}

/// Which request origin a plan is offered to.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Audience {
    /// Only requests that did NOT arrive through the onion vhost.
    Clearnet,
    /// Only requests that arrived through the onion vhost.
    Onion,
    /// Everyone.
    Both,
}

/// One purchasable plan.
#[derive(Debug, Clone)]
pub struct Plan {
    /// dig2pay plan id.
    pub id: String,
    /// What settling the plan grants.
    pub grant: Grant,
    /// One-time or monthly.
    pub interval: Interval,
    /// Which origin may buy it.
    pub audience: Audience,
    /// Display price in whole USD (dig2pay owns the real amount).
    pub price_usd: u32,
    /// Position among the quant tiers, 1 = cheapest; `None` for account plans.
    pub tier_rank: Option<u8>,
    /// Quant quota from configuration; `None` when the operator configured
    /// none for this tier (and always `None` for account plans).
    pub quota: Option<u64>,
}

impl Plan {
    /// Whether a request from the onion vhost (`onion == true`) or from the
    /// clearnet (`false`) may buy this plan.
    pub fn offered_to(&self, onion: bool) -> bool {
        match self.audience {
            Audience::Both => true,
            Audience::Onion => onion,
            Audience::Clearnet => !onion,
        }
    }
}

/// Default id of the clearnet paid account, 5 USD one-time, lifetime.
pub const DEFAULT_PAID_ID: &str = "mlc-paid-account-v1";
/// Default id of the clearnet anonymous account, 10 USD one-time, lifetime.
pub const DEFAULT_ANON_ID: &str = "mlc-anon-account-v1";
/// Default id of the Tor paid-account variant (10 USD). Final per dig2pay.
pub const DEFAULT_PAID_TOR_ID: &str = "mlc-paid-account-tor-v1";
/// Default id of the Tor anonymous-account variant (20 USD). Final per
/// dig2pay.
pub const DEFAULT_ANON_TOR_ID: &str = "mlc-anon-account-tor-v1";

/// The ids of the four one-time account plans as configured.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AccountPlanIds {
    /// Clearnet paid account.
    pub paid: String,
    /// Clearnet anonymous account.
    pub anon: String,
    /// Tor paid account.
    pub paid_tor: String,
    /// Tor anonymous account.
    pub anon_tor: String,
}

impl Default for AccountPlanIds {
    fn default() -> Self {
        Self {
            paid: DEFAULT_PAID_ID.to_string(),
            anon: DEFAULT_ANON_ID.to_string(),
            paid_tor: DEFAULT_PAID_TOR_ID.to_string(),
            anon_tor: DEFAULT_ANON_TOR_ID.to_string(),
        }
    }
}

const PAID_ACCOUNT_USD: u32 = 5;
const ANON_ACCOUNT_USD: u32 = 10;
const PAID_TOR_USD: u32 = 10;
const ANON_TOR_USD: u32 = 20;

/// The quant tiers in ascending price order: `(plan id, display USD)`.
pub const QUANT_TIERS: [(&str, u32); 4] = [
    ("mlc-monthly-20-v1", 20),
    ("mlc-monthly-50-v1", 50),
    ("mlc-monthly-100-v1", 100),
    ("mlc-monthly-200-v1", 200),
];

/// Every plan MLC sells, built once at boot from configuration.
pub struct Catalog {
    plans: Vec<Plan>,
}

impl Catalog {
    /// Build the catalog. `accounts` are the configured ids of the four
    /// account plans; `quotas` maps a quant plan id to its configured quota.
    pub fn build(accounts: &AccountPlanIds, quotas: &BTreeMap<String, u64>) -> Catalog {
        let account = |id: &str, grant: Grant, audience: Audience, price_usd: u32| Plan {
            id: id.to_string(),
            grant,
            interval: Interval::OneTime,
            audience,
            price_usd,
            tier_rank: None,
            quota: None,
        };
        let mut plans = vec![
            account(&accounts.paid, Grant::LifetimePaid, Audience::Clearnet, PAID_ACCOUNT_USD),
            account(&accounts.anon, Grant::LifetimeAnon, Audience::Clearnet, ANON_ACCOUNT_USD),
            account(&accounts.paid_tor, Grant::LifetimePaid, Audience::Onion, PAID_TOR_USD),
            account(&accounts.anon_tor, Grant::LifetimeAnon, Audience::Onion, ANON_TOR_USD),
        ];
        for (index, (id, price_usd)) in QUANT_TIERS.iter().enumerate() {
            plans.push(Plan {
                id: (*id).to_string(),
                grant: Grant::Quant,
                interval: Interval::Monthly,
                audience: Audience::Both,
                price_usd: *price_usd,
                tier_rank: u8::try_from(index + 1).ok(),
                quota: quotas.get(*id).copied(),
            });
        }
        Catalog { plans }
    }

    /// The plan with this id, whatever its audience.
    pub fn get(&self, id: &str) -> Option<&Plan> {
        self.plans.iter().find(|p| p.id == id)
    }

    /// The plans offered to a request from the onion vhost or the clearnet,
    /// in catalog order.
    pub fn offered(&self, onion: bool) -> impl Iterator<Item = &Plan> {
        self.plans.iter().filter(move |p| p.offered_to(onion))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn catalog() -> Catalog {
        let mut quotas = BTreeMap::new();
        quotas.insert("mlc-monthly-50-v1".to_string(), 7);
        Catalog::build(&AccountPlanIds::default(), &quotas)
    }

    fn ids(catalog: &Catalog, onion: bool) -> Vec<String> {
        catalog.offered(onion).map(|p| p.id.clone()).collect()
    }

    #[test]
    fn account_plans_grant_lifetime_and_never_renew() {
        let catalog = catalog();
        for (id, grant, usd) in [
            (DEFAULT_PAID_ID, Grant::LifetimePaid, 5),
            (DEFAULT_ANON_ID, Grant::LifetimeAnon, 10),
            (DEFAULT_PAID_TOR_ID, Grant::LifetimePaid, 10),
            (DEFAULT_ANON_TOR_ID, Grant::LifetimeAnon, 20),
        ] {
            let plan = catalog.get(id).expect("account plan present");
            assert_eq!(plan.grant, grant, "{id}");
            assert_eq!(plan.interval, Interval::OneTime, "{id}");
            assert_eq!(plan.price_usd, usd, "{id}");
            assert_eq!(plan.tier_rank, None, "{id}");
        }
    }

    #[test]
    fn quant_plans_grant_quant_monthly_with_ascending_rank() {
        let catalog = catalog();
        let mut last_rank = 0;
        for (id, usd) in [
            ("mlc-monthly-20-v1", 20),
            ("mlc-monthly-50-v1", 50),
            ("mlc-monthly-100-v1", 100),
            ("mlc-monthly-200-v1", 200),
        ] {
            let plan = catalog.get(id).expect("quant plan present");
            assert_eq!(plan.grant, Grant::Quant, "{id}");
            assert_eq!(plan.interval, Interval::Monthly, "{id}");
            assert_eq!(plan.price_usd, usd, "{id}");
            let rank = plan.tier_rank.expect("quant plans are ranked");
            assert!(rank > last_rank, "{id} must rank above the previous tier");
            last_rank = rank;
        }
    }

    #[test]
    fn quota_comes_only_from_the_supplied_config() {
        let catalog = catalog();
        assert_eq!(catalog.get("mlc-monthly-50-v1").and_then(|p| p.quota), Some(7));
        assert_eq!(catalog.get("mlc-monthly-20-v1").and_then(|p| p.quota), None);
        assert_eq!(catalog.get(DEFAULT_PAID_ID).and_then(|p| p.quota), None);
    }

    #[test]
    fn tor_variants_are_offered_on_the_onion_host_only() {
        let catalog = catalog();
        let clearnet = ids(&catalog, false);
        let onion = ids(&catalog, true);
        for tor in [DEFAULT_PAID_TOR_ID, DEFAULT_ANON_TOR_ID] {
            assert!(!clearnet.iter().any(|id| id == tor), "{tor} leaked to clearnet");
            assert!(onion.iter().any(|id| id == tor), "{tor} missing on onion");
        }
    }

    #[test]
    fn clearnet_account_plans_are_not_offered_on_the_onion_host() {
        let catalog = catalog();
        let onion = ids(&catalog, true);
        assert!(!onion.iter().any(|id| id == DEFAULT_PAID_ID));
        assert!(!onion.iter().any(|id| id == DEFAULT_ANON_ID));
        let clearnet = ids(&catalog, false);
        assert!(clearnet.iter().any(|id| id == DEFAULT_PAID_ID));
        assert!(clearnet.iter().any(|id| id == DEFAULT_ANON_ID));
    }

    #[test]
    fn quant_tiers_are_offered_on_both_origins() {
        let catalog = catalog();
        for onion in [false, true] {
            let offered = ids(&catalog, onion);
            for tier in ["mlc-monthly-20-v1", "mlc-monthly-50-v1", "mlc-monthly-100-v1", "mlc-monthly-200-v1"] {
                assert!(offered.iter().any(|id| id == tier), "{tier} missing (onion={onion})");
            }
        }
    }

    #[test]
    fn configured_account_ids_replace_the_defaults() {
        let ids = AccountPlanIds {
            paid: "p-x".to_string(),
            anon: "a-x".to_string(),
            paid_tor: "tor-paid-x".to_string(),
            anon_tor: "tor-anon-x".to_string(),
        };
        let catalog = Catalog::build(&ids, &BTreeMap::new());
        for id in ["p-x", "a-x", "tor-paid-x", "tor-anon-x"] {
            assert!(catalog.get(id).is_some(), "{id}");
        }
        for id in [DEFAULT_PAID_ID, DEFAULT_ANON_ID, DEFAULT_PAID_TOR_ID, DEFAULT_ANON_TOR_ID] {
            assert!(catalog.get(id).is_none(), "{id} must not linger once replaced");
        }
        // The audience follows the slot, not the id.
        assert!(catalog.get("tor-paid-x").is_some_and(|p| p.audience == Audience::Onion));
        assert!(catalog.get("p-x").is_some_and(|p| p.audience == Audience::Clearnet));
    }

    #[test]
    fn grant_spelling_round_trips() {
        for grant in [Grant::LifetimePaid, Grant::LifetimeAnon, Grant::Quant] {
            assert_eq!(Grant::parse(grant.as_str()), Some(grant));
        }
        assert_eq!(Grant::parse("nope"), None);
    }
}
