//! Bitwarden PAM access connector library, the core of the `bwac` binary.
//!
//! Build an [`executor::AccessConnectorConfig`] with [`crate::config::Config::from_cli`], then pass
//! it to [`run`] with a cancellation token for graceful shutdown.

bitwarden_commercial_marker::commercial_crate!();

pub(crate) mod api;
pub(crate) mod auth;
/// CLI argument definitions (exposed for `main.rs`).
pub mod cli;
/// Configuration loading and validation (exposed for `main.rs`).
pub mod config;
/// Cryptographic helpers (exposed for integration tests and `examples/register.rs`).
pub mod crypto;
/// Top-level error types (exposed for `main.rs`).
pub mod error;
/// Connector run-loop and exit variants (exposed for `main.rs`).
pub mod executor;
pub(crate) mod integrations;
pub(crate) mod policy;
pub(crate) mod resolver;
pub(crate) mod sys;
/// Token parsing and key derivation (exposed for `examples/register.rs`).
pub mod token;

/// Start the connector poll loop. It runs until shutdown ([`executor::RunExit::Shutdown`]), a
/// rejected credential ([`executor::RunExit::CredentialRefused`]) or an ineligible connector
/// ([`executor::RunExit::NotEligible`]).
pub async fn run(
    cfg: executor::AccessConnectorConfig,
    cancel: bitwarden_threading::cancellation_token::CancellationToken,
) -> executor::RunExit {
    executor::run(cfg, cancel).await
}

/// Serialises every test that mutates process environment variables, since concurrent mutation is
/// UB (hence `unsafe` `set_var` in Rust 2024). Hold it for the whole mutation window.
#[cfg(test)]
pub(crate) static TEST_ENV_LOCK: std::sync::Mutex<()> = std::sync::Mutex::new(());
