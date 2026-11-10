//! Bitwarden PAM access connector library.
//!
//! Implements the core logic for the `bwac` binary, which continuously rotates
//! PAM-managed credentials according to configured policies and schedules.

bitwarden_commercial_marker::commercial_crate!();

// Links bitwarden-crypto's global `ZeroizingAllocator`, which wipes heap memory on free.
use bitwarden_crypto as _;

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

#[allow(dead_code)]
pub(crate) mod integrations;

#[allow(dead_code)]
pub(crate) mod resolver;

#[allow(dead_code)]
pub(crate) mod sys;

#[cfg(test)]
mod test_support;
