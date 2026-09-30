//! The dig2pay billing adapter: MLC is a dig2pay *merchant*.
//!
//! dig2pay (`nemo/dig2pay`) is the self-hosted crypto payment processor. MLC
//! holds the merchant API key, calls `POST /subscribers` and
//! `POST /subscriptions` server-side, and receives dig2pay's signed webhook on
//! `POST /api/billing/webhook`. The browser never talks to dig2pay. The
//! agreed integration is `docs/dig2pay/plans/mlc-integration-2026-09-25.md`;
//! the wire contract is `docs/dig2pay/plans/merchant-contract-2026-09-10.md`.
//!
//! Layout:
//! * [`plans`] — the plan catalog (ids, prices, what each grants, who is
//!   offered it);
//! * [`config`] — environment parsing and the loaded [`BillingRuntime`];
//! * [`client`] — the merchant API client (bearer key, timeouts,
//!   `Idempotency-Key`);
//! * [`signature`] — the `X-Dig2pay-Signature` verifier;
//! * [`store`] — schema (additive, idempotent migration) and plain row access;
//! * [`grants`] — the lifetime-grant ledger the lifetime flags derive from;
//! * [`entitle`] — what an account is entitled to, derived from billing state;
//! * [`webhook`] — applying a delivered event;
//! * [`flow`] — the signed-in operations behind `routes::billing`;
//! * [`anon`] — anonymous ("numbered") accounts, their keys and their GC;
//! * [`throttle`] — the per-IP hourly budgets on the unauthenticated anonymous routes.
//!
//! # Entitlement rules (owner-binding)
//!
//! * `mlc-paid-account-v1` (5 USD, one-time): a LIFETIME paid account
//!   (`lifetime_paid`).
//! * `mlc-anon-account-v1` (10 USD, one-time): a LIFETIME anonymous account
//!   — anonymous AND paid (`lifetime_anon` + `lifetime_paid`).
//! * The Tor variants (`mlc-paid-account-tor-v1` 10 USD,
//!   `mlc-anon-account-tor-v1` 20 USD, one-time) grant the same and are
//!   offered only to requests arriving through the onion vhost (a
//!   configured `Host`, see `config::BillingRuntime::is_onion_request`).
//! * A one-time plan settles with exactly one `payment_confirmed` (period
//!   `{from: settled_at, to: null}`), never renews, and its grant is
//!   permanent: no date column is written. A paid account is never sold
//!   twice (`409 already_owned`, nothing created on the processor); an
//!   anonymous purchase creates a new account, so it never collides.
//! * `mlc-monthly-{20,50,100,200}-v1`: quant tiers. While a paid period is
//!   running they carry paid status too, per day. The quota per tier comes
//!   from configuration only.
//! * "Paid" (see `entitle`) is no longer driven by a time-bound `paid_until`
//!   for account purchases: lifetime grants plus an active subscription.
//!
//! # Lifetime grants
//!
//! `lifetime_paid` / `lifetime_anon` are derived from the ledger
//! (`billing_grants`, see [`grants`]): an account holds one while at least
//! one non-revoked row says so. Rows come from a settled invoice
//! (`source = invoice`, `source_ref` = the invoice id) or from an operator
//! (`source = admin`, `source_ref` = the operator's account id and a note;
//! `POST /api/admin/users/{id}/grants`). A refund or a reverted payment
//! revokes only the rows whose `source_ref` is that invoice, and a re-settled
//! invoice restores only its own; an operator grant or a second purchase is
//! never touched. The columns on `users` are a cache rebuilt from the ledger
//! on every change and on every boot.
//!
//! # Legacy `paid_until`
//!
//! `users.paid_until` stays as the time-bound grant an operator or a gift/trial
//! code sets (`db::grant_paid_days`, `db::redeem_gift_code`): `db::user_is_paid`
//! still honours a future value and it simply runs out on its own. Nothing
//! sells time-bound paid access any more, and there is no cutover step that
//! converts it — an account that should keep paid status for life gets an
//! operator grant.
//!
//! # Anonymous accounts
//!
//! `mlc-anon-account*` is sold only through the public
//! `POST /api/billing/anon-checkout`, which creates the new account it
//! belongs to (see [`anon`]); the signed-in checkout refuses those plans. A
//! paid account is never sold twice (`409 already_owned`, nothing created on
//! the processor).

pub mod anon;
pub mod client;
pub mod config;
pub mod entitle;
pub mod flow;
pub mod grants;
pub mod invite;
pub mod plans;
pub mod signature;
pub mod store;
pub mod throttle;
pub mod webhook;

#[cfg(test)]
pub mod testkit;

pub use config::BillingRuntime;
