//! Billing configuration: environment parsing and the loaded runtime.
//!
//! | Variable | Meaning |
//! |---|---|
//! | `DIG2PAY_BASE_URL` | merchant API base; production `https://pay.zen-geldmaschine.net/api/v1` (public API). Empty (the default) leaves checkout/change disabled. |
//! | `DIG2PAY_API_KEY_FILE` | file holding the merchant bearer key, one line |
//! | `DIG2PAY_WEBHOOK_SECRET_FILES` | comma-separated files, one HMAC secret each; several live at once during a rotation |
//! | `DIG2PAY_TIMEOUT_SECS` | overall timeout of one merchant API call (default 15) |
//! | `MLC_BILLING_ONION_HOSTS` | comma-separated `Host` names of the onion vhost |
//! | `MLC_BILLING_PLAN_PAID` / `_ANON` / `_PAID_TOR` / `_ANON_TOR` | ids of the four one-time account plans (defaults: `mlc-paid-account-v1`, `mlc-anon-account-v1`, `mlc-paid-account-tor-v1`, `mlc-anon-account-tor-v1`) |
//! | `MLC_BILLING_QUANT_QUOTAS` | `plan_id=quota` pairs, comma-separated, one per quant tier |
//! | `MLC_BILLING_ANON_PER_IP_PER_HOUR` | anonymous checkouts one client IP may start per hour (default 5) |
//! | `MLC_BILLING_ANON_GLOBAL_PER_HOUR` | anonymous checkouts started per hour across all IPs (default 200) |
//! | `MLC_BILLING_KEY_FAILS_PER_IP_PER_HOUR` | failed account-key attempts one client IP may make per hour before it is refused (default 20) |
//!
//! Key and secret material is only ever read from files, never from a plain
//! environment value, and is never logged. A missing or unreadable file
//! degrades billing (routes answer `503`) instead of stopping the server:
//! identity and sync do not depend on the payment processor being wired.

use std::collections::BTreeMap;
use std::net::IpAddr;
use std::path::{Path, PathBuf};
use std::time::Duration;

use axum::http::{header, HeaderMap};

use super::client::Dig2payClient;
use super::plans::{AccountPlanIds, Catalog, QUANT_TIERS};
use super::throttle::SlidingLimiter;

const ENV_BASE_URL: &str = "DIG2PAY_BASE_URL";
const ENV_API_KEY_FILE: &str = "DIG2PAY_API_KEY_FILE";
const ENV_WEBHOOK_SECRET_FILES: &str = "DIG2PAY_WEBHOOK_SECRET_FILES";
const ENV_TIMEOUT_SECS: &str = "DIG2PAY_TIMEOUT_SECS";
const ENV_ONION_HOSTS: &str = "MLC_BILLING_ONION_HOSTS";
const ENV_PLAN_PAID: &str = "MLC_BILLING_PLAN_PAID";
const ENV_PLAN_ANON: &str = "MLC_BILLING_PLAN_ANON";
const ENV_PLAN_PAID_TOR: &str = "MLC_BILLING_PLAN_PAID_TOR";
const ENV_PLAN_ANON_TOR: &str = "MLC_BILLING_PLAN_ANON_TOR";
const ENV_QUANT_QUOTAS: &str = "MLC_BILLING_QUANT_QUOTAS";
const ENV_ANON_PER_IP: &str = "MLC_BILLING_ANON_PER_IP_PER_HOUR";
const ENV_ANON_GLOBAL: &str = "MLC_BILLING_ANON_GLOBAL_PER_HOUR";
const ENV_KEY_FAILS: &str = "MLC_BILLING_KEY_FAILS_PER_IP_PER_HOUR";

/// Defaults of the three abuse budgets (all per hour).
const DEFAULT_ANON_PER_IP: usize = 5;
const DEFAULT_ANON_GLOBAL: usize = 200;
const DEFAULT_KEY_FAILS: usize = 20;

/// The window every abuse budget above is measured over.
const ABUSE_WINDOW: Duration = Duration::from_secs(3600);

/// Overall timeout of one merchant API call when `DIG2PAY_TIMEOUT_SECS` is
/// unset or unparsable.
const DEFAULT_TIMEOUT_SECS: u64 = 15;

/// Everything read from the environment, before any file is opened.
#[derive(Debug, Clone, PartialEq)]
pub struct BillingSettings {
    /// Merchant API base URL; empty disables the outbound calls.
    pub base_url: String,
    /// Path of the merchant bearer key file.
    pub api_key_file: Option<PathBuf>,
    /// Paths of the webhook secret files.
    pub webhook_secret_files: Vec<PathBuf>,
    /// Overall timeout of one merchant API call.
    pub timeout: Duration,
    /// Lower-cased host names that identify the onion vhost.
    pub onion_hosts: Vec<String>,
    /// Ids of the four one-time account plans.
    pub account_plans: AccountPlanIds,
    /// Quant quota per monthly plan id.
    pub quant_quotas: BTreeMap<String, u64>,
    /// Anonymous checkouts per client IP per hour.
    pub anon_per_ip_per_hour: usize,
    /// Anonymous checkouts per hour across all IPs.
    pub anon_global_per_hour: usize,
    /// Failed account-key attempts per client IP per hour.
    pub key_fails_per_ip_per_hour: usize,
}

/// Split a comma-separated list, trimming and dropping empty items.
fn split_list(raw: &str) -> Vec<String> {
    raw.split(',')
        .map(str::trim)
        .filter(|item| !item.is_empty())
        .map(str::to_string)
        .collect()
}

/// Normalise a configured host: lower case, no trailing dot, no port.
fn normalise_host(raw: &str) -> String {
    let lower = raw.trim().to_ascii_lowercase();
    let no_port = match lower.rsplit_once(':') {
        Some((host, port)) if !port.is_empty() && port.bytes().all(|b| b.is_ascii_digit()) => host,
        _ => lower.as_str(),
    };
    no_port.trim_end_matches('.').to_string()
}

/// Parse `plan_id=quota,plan_id=quota`. Returns the accepted pairs and the
/// rejected items, so the caller can log what it skipped.
fn parse_quotas(raw: &str) -> (BTreeMap<String, u64>, Vec<String>) {
    let mut quotas = BTreeMap::new();
    let mut rejected = Vec::new();
    for item in split_list(raw) {
        let parsed = item
            .split_once('=')
            .and_then(|(id, quota)| Some((id.trim(), quota.trim().parse::<u64>().ok()?)))
            .filter(|(id, _)| !id.is_empty());
        match parsed {
            Some((id, quota)) => {
                quotas.insert(id.to_string(), quota);
            }
            None => rejected.push(item),
        }
    }
    (quotas, rejected)
}

/// The four account plan ids: each configured value, or its default when it
/// is empty or collides with a monthly tier id or an id chosen before it
/// (a collision would make one plan shadow another).
fn account_plan_ids(get: &impl Fn(&str) -> Option<String>) -> AccountPlanIds {
    let defaults = AccountPlanIds::default();
    let mut taken: Vec<String> = QUANT_TIERS.iter().map(|(id, _)| (*id).to_string()).collect();
    let mut pick = |var: &str, default: &str| -> String {
        let chosen = match get(var).map(|s| s.trim().to_string()).filter(|s| !s.is_empty()) {
            Some(id) if taken.contains(&id) => {
                tracing::warn!("{var}={id:?} collides with another plan id; using {default:?}");
                default.to_string()
            }
            Some(id) => id,
            None => default.to_string(),
        };
        taken.push(chosen.clone());
        chosen
    };
    AccountPlanIds {
        paid: pick(ENV_PLAN_PAID, &defaults.paid),
        anon: pick(ENV_PLAN_ANON, &defaults.anon),
        paid_tor: pick(ENV_PLAN_PAID_TOR, &defaults.paid_tor),
        anon_tor: pick(ENV_PLAN_ANON_TOR, &defaults.anon_tor),
    }
}

impl BillingSettings {
    /// Read the settings from the process environment.
    pub fn from_env() -> Self {
        Self::from_lookup(|name| std::env::var(name).ok())
    }

    /// Read the settings through `get` (the environment, or a map in tests).
    pub fn from_lookup(get: impl Fn(&str) -> Option<String>) -> Self {
        let base_url = get(ENV_BASE_URL)
            .map(|v| v.trim().trim_end_matches('/').to_string())
            .unwrap_or_default();
        let api_key_file = get(ENV_API_KEY_FILE)
            .map(|v| v.trim().to_string())
            .filter(|v| !v.is_empty())
            .map(PathBuf::from);
        let webhook_secret_files = get(ENV_WEBHOOK_SECRET_FILES)
            .map(|v| split_list(&v).into_iter().map(PathBuf::from).collect())
            .unwrap_or_default();
        let timeout = Duration::from_secs(
            get(ENV_TIMEOUT_SECS)
                .and_then(|v| v.trim().parse::<u64>().ok())
                .filter(|secs| *secs > 0)
                .unwrap_or(DEFAULT_TIMEOUT_SECS),
        );
        let onion_hosts = get(ENV_ONION_HOSTS)
            .map(|v| split_list(&v).iter().map(|h| normalise_host(h)).filter(|h| !h.is_empty()).collect())
            .unwrap_or_default();
        let account_plans = account_plan_ids(&get);
        let (quant_quotas, rejected) = get(ENV_QUANT_QUOTAS)
            .map(|v| parse_quotas(&v))
            .unwrap_or_default();
        for item in rejected {
            tracing::warn!("{ENV_QUANT_QUOTAS}: ignoring malformed entry {item:?} (expected plan_id=number)");
        }
        let budget = |var: &str, default: usize| {
            get(var)
                .and_then(|v| v.trim().parse::<usize>().ok())
                .filter(|n| *n > 0)
                .unwrap_or(default)
        };
        Self {
            base_url,
            api_key_file,
            webhook_secret_files,
            timeout,
            onion_hosts,
            account_plans,
            quant_quotas,
            anon_per_ip_per_hour: budget(ENV_ANON_PER_IP, DEFAULT_ANON_PER_IP),
            anon_global_per_hour: budget(ENV_ANON_GLOBAL, DEFAULT_ANON_GLOBAL),
            key_fails_per_ip_per_hour: budget(ENV_KEY_FAILS, DEFAULT_KEY_FAILS),
        }
    }
}

/// Read a one-line secret file: trimmed, and never empty.
fn read_secret_file(path: &Path) -> Result<String, String> {
    let raw = std::fs::read_to_string(path).map_err(|e| format!("cannot read {}: {e}", path.display()))?;
    let secret = raw.trim().to_string();
    if secret.is_empty() {
        return Err(format!("{} is empty", path.display()));
    }
    Ok(secret)
}

/// The loaded billing configuration held by `AppState`.
pub struct BillingRuntime {
    catalog: Catalog,
    client: Option<Dig2payClient>,
    webhook_secrets: Vec<Vec<u8>>,
    onion_hosts: Vec<String>,
    anon_create: SlidingLimiter<IpAddr>,
    key_failures: SlidingLimiter<IpAddr>,
}

impl BillingRuntime {
    /// Assemble a runtime from already-loaded parts.
    pub fn new(
        settings: &BillingSettings,
        client: Option<Dig2payClient>,
        webhook_secrets: Vec<Vec<u8>>,
    ) -> Self {
        Self {
            catalog: Catalog::build(&settings.account_plans, &settings.quant_quotas),
            client,
            webhook_secrets,
            onion_hosts: settings.onion_hosts.clone(),
            anon_create: SlidingLimiter::new(
                ABUSE_WINDOW,
                settings.anon_per_ip_per_hour,
                settings.anon_global_per_hour,
            ),
            key_failures: SlidingLimiter::new(ABUSE_WINDOW, settings.key_fails_per_ip_per_hour, 0),
        }
    }

    /// The budget on anonymous checkouts (per IP and overall).
    pub fn anon_create_limiter(&self) -> &SlidingLimiter<IpAddr> {
        &self.anon_create
    }

    /// The per-IP throttle on failed account-key attempts.
    pub fn key_failure_limiter(&self) -> &SlidingLimiter<IpAddr> {
        &self.key_failures
    }

    /// Read the environment and the key/secret files. Never fails: whatever
    /// cannot be loaded is logged and left disabled.
    pub fn from_env() -> Self {
        let settings = BillingSettings::from_env();

        let client = if settings.base_url.is_empty() {
            tracing::info!("Billing: {ENV_BASE_URL} unset — checkout and plan changes disabled");
            None
        } else {
            match settings.api_key_file.as_deref().map(read_secret_file) {
                Some(Ok(key)) => match Dig2payClient::new(&settings.base_url, &key, settings.timeout) {
                    Ok(client) => {
                        tracing::info!("Billing: dig2pay merchant API at {}", settings.base_url);
                        Some(client)
                    }
                    Err(e) => {
                        tracing::error!("Billing: cannot build the dig2pay client: {e}");
                        None
                    }
                },
                Some(Err(e)) => {
                    tracing::error!("Billing: {ENV_API_KEY_FILE}: {e} — checkout and plan changes disabled");
                    None
                }
                None => {
                    tracing::error!("Billing: {ENV_BASE_URL} is set but {ENV_API_KEY_FILE} is not — checkout and plan changes disabled");
                    None
                }
            }
        };

        let mut webhook_secrets = Vec::new();
        for path in &settings.webhook_secret_files {
            match read_secret_file(path) {
                Ok(secret) => webhook_secrets.push(secret.into_bytes()),
                Err(e) => tracing::error!("Billing: {ENV_WEBHOOK_SECRET_FILES}: {e}"),
            }
        }
        if webhook_secrets.is_empty() {
            tracing::warn!("Billing: no webhook secret loaded — POST /api/billing/webhook answers 503");
        } else {
            tracing::info!("Billing: {} webhook secret(s) loaded", webhook_secrets.len());
        }

        Self::new(&settings, client, webhook_secrets)
    }

    /// The plan catalog.
    pub fn catalog(&self) -> &Catalog {
        &self.catalog
    }

    /// The merchant API client, if outbound calls are configured.
    pub fn client(&self) -> Option<&Dig2payClient> {
        self.client.as_ref()
    }

    /// The live webhook secrets (several during a rotation).
    pub fn webhook_secrets(&self) -> &[Vec<u8>] {
        &self.webhook_secrets
    }

    /// Whether the request arrived through the onion vhost: its `Host`
    /// header (port stripped, case folded) is one of the configured onion
    /// hosts. `X-Forwarded-Host` is deliberately not consulted — a client can
    /// set it; nginx overwrites `Host` from the vhost that matched.
    pub fn is_onion_request(&self, headers: &HeaderMap) -> bool {
        let Some(host) = headers.get(header::HOST).and_then(|v| v.to_str().ok()) else {
            return false;
        };
        let host = normalise_host(host);
        self.onion_hosts.iter().any(|configured| *configured == host)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn settings(pairs: &[(&str, &str)]) -> BillingSettings {
        BillingSettings::from_lookup(|name| {
            pairs.iter().find(|(k, _)| *k == name).map(|(_, v)| (*v).to_string())
        })
    }

    #[test]
    fn everything_unset_leaves_billing_disabled_with_default_tor_ids() {
        let s = settings(&[]);
        assert_eq!(s.base_url, "");
        assert!(s.api_key_file.is_none());
        assert!(s.webhook_secret_files.is_empty());
        assert!(s.onion_hosts.is_empty());
        assert!(s.quant_quotas.is_empty());
        assert_eq!(s.account_plans, AccountPlanIds::default());
        assert_eq!(s.timeout, Duration::from_secs(DEFAULT_TIMEOUT_SECS));
        assert_eq!(
            (s.anon_per_ip_per_hour, s.anon_global_per_hour, s.key_fails_per_ip_per_hour),
            (DEFAULT_ANON_PER_IP, DEFAULT_ANON_GLOBAL, DEFAULT_KEY_FAILS)
        );
    }

    #[test]
    fn the_documented_variables_are_read() {
        let s = settings(&[
            (ENV_BASE_URL, " http://10.83.1.1:37300/ "),
            (ENV_API_KEY_FILE, "/run/secrets/key"),
            (ENV_WEBHOOK_SECRET_FILES, "/run/a, /run/b,,"),
            (ENV_TIMEOUT_SECS, "9"),
            (ENV_ONION_HOSTS, "ABC.onion:80, def.onion."),
            (ENV_PLAN_PAID, "plain-paid"),
            (ENV_PLAN_ANON, "plain-anon"),
            (ENV_PLAN_PAID_TOR, "tor-paid"),
            (ENV_PLAN_ANON_TOR, "tor-anon"),
            (ENV_QUANT_QUOTAS, "mlc-monthly-20-v1=10, mlc-monthly-50-v1 = 30"),
        ]);
        assert_eq!(s.base_url, "http://10.83.1.1:37300");
        assert_eq!(s.api_key_file, Some(PathBuf::from("/run/secrets/key")));
        assert_eq!(s.webhook_secret_files, vec![PathBuf::from("/run/a"), PathBuf::from("/run/b")]);
        assert_eq!(s.timeout, Duration::from_secs(9));
        assert_eq!(s.onion_hosts, vec!["abc.onion".to_string(), "def.onion".to_string()]);
        assert_eq!(s.account_plans.paid, "plain-paid");
        assert_eq!(s.account_plans.anon, "plain-anon");
        assert_eq!(s.account_plans.paid_tor, "tor-paid");
        assert_eq!(s.account_plans.anon_tor, "tor-anon");
        assert_eq!(s.quant_quotas.get("mlc-monthly-20-v1"), Some(&10));
        assert_eq!(s.quant_quotas.get("mlc-monthly-50-v1"), Some(&30));
    }

    #[test]
    fn the_abuse_budgets_are_configurable_and_zero_or_garbage_falls_back_to_the_default() {
        let s = settings(&[(ENV_ANON_PER_IP, "2"), (ENV_ANON_GLOBAL, " 30 "), (ENV_KEY_FAILS, "7")]);
        assert_eq!((s.anon_per_ip_per_hour, s.anon_global_per_hour, s.key_fails_per_ip_per_hour), (2, 30, 7));
        let s = settings(&[(ENV_ANON_PER_IP, "0"), (ENV_ANON_GLOBAL, "many"), (ENV_KEY_FAILS, "-3")]);
        assert_eq!(
            (s.anon_per_ip_per_hour, s.anon_global_per_hour, s.key_fails_per_ip_per_hour),
            (DEFAULT_ANON_PER_IP, DEFAULT_ANON_GLOBAL, DEFAULT_KEY_FAILS),
            "there is no way to configure the brake away"
        );
    }

    #[test]
    fn malformed_quota_entries_are_rejected_not_guessed() {
        let (quotas, rejected) = parse_quotas("a=1,b,c=x,=4,d=-2, e=5");
        assert_eq!(quotas.len(), 2);
        assert_eq!(quotas.get("a"), Some(&1));
        assert_eq!(quotas.get("e"), Some(&5));
        assert_eq!(rejected, vec!["b", "c=x", "=4", "d=-2"]);
    }

    #[test]
    fn a_colliding_or_empty_account_id_falls_back_to_the_default() {
        let defaults = AccountPlanIds::default();
        // Tor paid reuses the clearnet paid id; Tor anon is blank; clearnet
        // anon tries to take a monthly tier's id.
        let s = settings(&[
            (ENV_PLAN_PAID_TOR, "mlc-paid-account-v1"),
            (ENV_PLAN_ANON_TOR, "  "),
            (ENV_PLAN_ANON, "mlc-monthly-20-v1"),
        ]);
        assert_eq!(s.account_plans, defaults);
        // Two different variables asking for the same fresh id: the first wins.
        let s = settings(&[(ENV_PLAN_PAID, "shared"), (ENV_PLAN_ANON, "shared")]);
        assert_eq!(s.account_plans.paid, "shared");
        assert_eq!(s.account_plans.anon, defaults.anon);
    }

    #[test]
    fn host_normalisation_strips_case_port_and_trailing_dot() {
        assert_eq!(normalise_host("Example.ONION"), "example.onion");
        assert_eq!(normalise_host("example.onion:8080"), "example.onion");
        assert_eq!(normalise_host("example.onion."), "example.onion");
        assert_eq!(normalise_host(" example.onion "), "example.onion");
    }

    fn runtime_with_onion(hosts: &[&str]) -> BillingRuntime {
        let s = settings(&[(ENV_ONION_HOSTS, &hosts.join(","))]);
        BillingRuntime::new(&s, None, Vec::new())
    }

    fn headers_with_host(host: &str) -> HeaderMap {
        let mut headers = HeaderMap::new();
        headers.insert(header::HOST, host.parse().expect("valid header value"));
        headers
    }

    #[test]
    fn only_a_configured_host_is_the_onion_vhost() {
        let rt = runtime_with_onion(&["abcdef.onion"]);
        assert!(rt.is_onion_request(&headers_with_host("abcdef.onion")));
        assert!(rt.is_onion_request(&headers_with_host("ABCDEF.onion:80")));
        assert!(!rt.is_onion_request(&headers_with_host("mylittlechart.org")));
        assert!(!rt.is_onion_request(&headers_with_host("evil-abcdef.onion")));
        assert!(!rt.is_onion_request(&HeaderMap::new()));
    }

    #[test]
    fn a_forwarded_host_header_cannot_claim_the_onion_vhost() {
        let rt = runtime_with_onion(&["abcdef.onion"]);
        let mut headers = headers_with_host("mylittlechart.org");
        headers.insert("x-forwarded-host", "abcdef.onion".parse().expect("valid header value"));
        assert!(!rt.is_onion_request(&headers));
    }

    #[test]
    fn no_configured_onion_host_means_nobody_is_onion() {
        let rt = runtime_with_onion(&[]);
        assert!(!rt.is_onion_request(&headers_with_host("abcdef.onion")));
    }

    #[test]
    fn secret_files_are_trimmed_and_empty_ones_refused() {
        let dir = std::env::temp_dir().join(format!("mlc-billing-config-test-{}", std::process::id()));
        std::fs::create_dir_all(&dir).expect("create test dir");
        let good = dir.join("secret");
        let empty = dir.join("empty");
        std::fs::write(&good, "  s3cret\n").expect("write secret");
        std::fs::write(&empty, "\n").expect("write empty");
        assert_eq!(read_secret_file(&good).as_deref(), Ok("s3cret"));
        assert!(read_secret_file(&empty).is_err());
        assert!(read_secret_file(&dir.join("missing")).is_err());
        let _ = std::fs::remove_dir_all(&dir);
    }
}
