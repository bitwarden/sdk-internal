//! Bitwarden PAM credential rotation daemon library.
//!
//! This crate implements the core logic for the `bw-rotation-daemon` binary,
//! which continuously rotates PAM-managed credentials according to configured
//! policies and schedules.
//!
//! # Entry point
//!
//! The primary entry point is [`run`], which starts the polling loop and
//! returns a [`executor::RunExit`] when the daemon shuts down cleanly.
//! Callers construct a [`executor::DaemonConfig`] via the CLI/config layer
//! (see [`config::Config::from_cli`]) and pass in a
//! [`bitwarden_threading::cancellation_token::CancellationToken`] for
//! graceful shutdown.
//!
//! # Spec-rule → executor mapping
//!
//! The following table maps spec rules from `rotation-daemon.allium` to the
//! executor module that implements them.
//!
//! | Spec rule                          | Implementation                                 |
//! |------------------------------------|------------------------------------------------|
//! | `DaemonStarts` / `OpenConnection`  | [`executor::run`] startup / session build      |
//! | `Reconnect` / `RefuseConnection`   | backoff loop + [`executor::RunExit`] variants  |
//! | `DaemonConnects`                   | [`auth::session::SessionManager::new`]         |
//! | `HandleAuthenticationSucceeded`    | [`auth::session::SessionManager`] refresh path |
//! | `SessionExpires` / `RefreshSession`| [`auth::session::SessionPhase::Expired`]       |
//! | `HandleAuthenticationRejected`     | [`auth::session::SessionLost::Revoked`]        |
//! | `HandleSessionRevoked`             | 404-probe in [`executor::run`]                 |
//! | `ClaimAvailableRotation`           | single-flight claim loop in [`executor::run`]  |
//! | `StartRotation`                    | [`executor::rotation::execute`]                |
//! | `ExecuteRotation` (steps 0–7)      | [`executor::rotation`] step pipeline           |
//! | `NoTargetActionPastSessionLoss`    | [`executor::rotation::make_gate`] + gated retry|
//! | `VerifiedBeforeSuccess`            | proof tokens in [`executor::rotation`]         |
//! | `TerminationNeverFailsRotation`    | step 6 returns `SessionTermination` value      |
//! | `RotationByAdministrativeReset`    | integration contracts (custom_script, entra)   |
//! | `ServerZeroKnowledge`              | token / crypto / safe-detail secret handling   |
//! | `AtMostOneActiveSession`           | singleton `SessionManager` by construction     |
//! | `ReportOutcomeToServer`            | step 7 + report finality rules                 |

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
/// Daemon run-loop and exit variants (exposed for `main.rs`).
pub mod executor;
pub(crate) mod integrations;
pub(crate) mod policy;
pub(crate) mod resolver;
/// Token parsing, key derivation, and C1 constants (exposed for `examples/register.rs`).
pub mod token;

// ---------------------------------------------------------------------------
// Public run surface
// ---------------------------------------------------------------------------

/// Start the daemon poll loop.
///
/// Runs until one of the following clean-exit conditions is reached:
///
/// - `cancel` is cancelled → [`executor::RunExit::Shutdown`]
/// - the daemon credential is rejected → [`executor::RunExit::CredentialRefused`]
/// - the daemon is not eligible for rotation endpoints →
///   [`executor::RunExit::NotEligible`]
pub async fn run(
    cfg: executor::DaemonConfig,
    cancel: bitwarden_threading::cancellation_token::CancellationToken,
) -> executor::RunExit {
    executor::run(cfg, cancel).await
}
