//! `hearthd` — control plane for a private, home-only SimpleX relay node.
//!
//! # What this crate is
//!
//! ТЗ §0 draws a hard line: the SimpleX protocol, the relays and the crypto stay
//! upstream Haskell, untouched. This crate is only the part that has no predecessor —
//! the node's own plumbing:
//!
//! * [`supervisor`] — keep the stock relays running, with backoff and alerting;
//! * [`egress`] — watch nftables counters and live sockets so a "phone home" attempt
//!   is *observed*, not merely blocked (ТЗ §2.1 "Verify, don't trust");
//! * [`integrity`] — sha256 every pinned binary against [`model::manifest`];
//! * [`backup`] — daily age-encrypted archive pushed to the second machine at home;
//! * [`configgen`] — mint client bundles (ТЗ Приложение B) and QR codes;
//! * [`migrate`] — the ПК → mini-PC move that keeps the relay address constant;
//! * [`api`] — mTLS admin API on the WG-only admin subnet.
//!
//! # What this crate must never do
//!
//! * read relay message content or client addresses (ТЗ §7.4);
//! * open a connection outside `node.home_networks` — see [`net::EgressPolicy`];
//! * update itself, or reach any external service for any reason.

#![forbid(unsafe_code)]
#![cfg_attr(
    not(test),
    deny(
        clippy::unwrap_used,
        clippy::expect_used,
        clippy::panic,
        clippy::todo,
        clippy::unimplemented
    )
)]
#![warn(clippy::all, missing_debug_implementations, rust_2018_idioms)]

pub mod alerts;
pub mod api;
pub mod backup;
pub mod config;
pub mod configgen;
pub mod deviceapi;
pub mod egress;
pub mod error;
pub mod integrity;
pub mod migrate;
pub mod model;
pub mod net;
pub mod pki;
pub mod qr;
pub mod release;
pub mod state;
pub mod store;
pub mod supervisor;
pub mod sys;

/// Version of the daemon, reported by `/health` and stamped into backups.
pub const VERSION: &str = env!("CARGO_PKG_VERSION");

/// Default configuration path on the node.
pub const DEFAULT_CONFIG_PATH: &str = "/etc/hearth/hearthd.toml";
