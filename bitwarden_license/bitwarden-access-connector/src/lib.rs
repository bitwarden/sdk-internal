//! Bitwarden PAM access connector library.
//!
//! Implements the core logic for the `bwac` binary, which continuously rotates
//! PAM-managed credentials according to configured policies and schedules.

bitwarden_commercial_marker::commercial_crate!();

/// CLI argument definitions (exposed for `main.rs`).
pub mod cli;

/// Retry decisions, safe report details and startup errors.
#[allow(dead_code)]
pub mod error;

#[allow(dead_code)]
pub(crate) mod api;

#[allow(dead_code)]
pub(crate) mod auth;

#[allow(dead_code)]
pub(crate) mod crypto;

#[cfg(test)]
mod test_support;
