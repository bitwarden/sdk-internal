//! Bitwarden PAM access connector library, the core of the `bwac` binary.

bitwarden_commercial_marker::commercial_crate!();

// Links bitwarden-crypto's global `ZeroizingAllocator`, which wipes heap memory on free.
use bitwarden_crypto as _;

pub(crate) mod api;
pub(crate) mod auth;
/// CLI arguments.
pub mod cli;
/// Configuration loading.
pub mod config;
pub(crate) mod crypto;
/// Startup errors.
pub mod error;
/// Run loop configuration and exit reasons.
pub mod executor;
pub(crate) mod integrations;
pub(crate) mod resolver;
pub(crate) mod sys;
#[cfg(test)]
mod test_support;

/// Run the connector poll loop until it exits; the result says why.
pub async fn run(
    cfg: executor::AccessConnectorConfig,
    cancel: bitwarden_threading::cancellation_token::CancellationToken,
) -> executor::RunExit {
    executor::run(cfg, cancel).await
}

/// Serialises tests that mutate environment variables. Hold it for the whole mutation.
#[cfg(test)]
pub(crate) static TEST_ENV_LOCK: std::sync::Mutex<()> = std::sync::Mutex::new(());
