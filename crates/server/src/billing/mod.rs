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
//! * [`entitle`] — what an account is entitled to, derived from billing state;
//! * [`webhook`] — applying a delivered event;
//! * [`flow`] — the signed-in operations behind `routes::billing`.
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
//!   for account purchases: lifetime flags plus an active subscription. The
//!   legacy `users.paid_until` column keeps working unchanged.
//!
//! # Migration note — users who hold `paid_until` today
//!
//! Accounts that already have a `users.paid_until` (gift/trial codes,
//! operator grants, everything paid before billing shipped) STAY PAID:
//! `db::user_is_paid` still honours a future `paid_until`, so nobody loses
//! access when this ships. Under the new rule those current users become
//! LIFETIME. That conversion is a one-off statement the operator runs at
//! cutover, deliberately not executed at boot (`paid_until` also carries
//! short gift/trial grants, and which of them count as "current users" is
//! the operator's call):
//!
//! ```sql
//! UPDATE users SET lifetime_paid = 1
//!  WHERE paid_until IS NOT NULL AND datetime(paid_until) > datetime('now');
//! ```
//!
//! `paid_until` is left in place afterwards (never cleared), so a rollback
//! loses nothing. Caveat: a lifetime flag set this way is not backed by any
//! `billing_invoices` row, so if that same account later buys a lifetime plan
//! and is refunded, the refund clears the flag.
//!
//! # Not covered here
//!
//! The anonymous (no-OAuth) sign-up and sign-in flow itself is not part of
//! this adapter: checkout is a signed-in route, so an anonymous purchase
//! grants `lifetime_anon` + `lifetime_paid` to the account that buys it. A
//! public checkout that creates the new anonymous account (and hands its
//! credential to the payer) is a separate piece.

pub mod client;
pub mod config;
pub mod entitle;
pub mod flow;
pub mod plans;
pub mod signature;
pub mod store;
pub mod webhook;

#[cfg(test)]
pub mod testkit;

pub use config::BillingRuntime;
