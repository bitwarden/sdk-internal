//! Entry point for the `bw-rotation-daemon` binary.
//!
//! Parses CLI arguments, initialises tracing, and delegates to
//! [`bitwarden_rotation_daemon::run`].
//!
//! # Exit codes
//!
//! | Code | Meaning                                                          |
//! |------|-------------------------------------------------------------------|
//! | `0`  | Clean shutdown (SIGTERM / Ctrl-C)                                |
//! | `1`  | Startup error (invalid config, I/O error, parse failure)         |
//! | `2`  | Credential refused; reissue via `ReissueDaemonCredential` and restart |
//! | `3`  | Not eligible for rotation endpoints (record, license, `UsePam`)  |

use bitwarden_rotation_daemon::{
    cli::{Cli, Command},
    config::Config,
    executor::RunExit,
};
use bitwarden_threading::cancellation_token::CancellationToken;
use clap::Parser;
use tracing_subscriber::{
    EnvFilter, prelude::__tracing_subscriber_SubscriberExt as _, util::SubscriberInitExt as _,
};

#[tokio::main(flavor = "current_thread")]
async fn main() {
    // from_env_lossy reads RUST_LOG at runtime, parsing filter strings leniently; an unset
    // or empty value falls back to the INFO default below.
    let filter = EnvFilter::builder()
        .with_default_directive(tracing_subscriber::filter::LevelFilter::INFO.into())
        .from_env_lossy();

    tracing_subscriber::registry()
        .with(tracing_subscriber::fmt::layer().with_writer(std::io::stderr))
        .with(filter)
        .init();

    let cli = Cli::parse();
    let Command::Run(run_args) = cli.command;

    let daemon_cfg = match Config::from_cli(run_args) {
        Ok(cfg) => cfg.into_daemon_config(),
        Err(e) => {
            tracing::error!("startup error: {e}");
            std::process::exit(1);
        }
    };

    let cancel = CancellationToken::new();

    // Spawn a watcher task that cancels the token on Ctrl-C or SIGTERM.
    let watcher_cancel = cancel.clone();
    tokio::spawn(async move {
        wait_for_shutdown_signal().await;
        tracing::info!("shutdown signal received; cancelling");
        watcher_cancel.cancel();
    });

    let exit = bitwarden_rotation_daemon::run(daemon_cfg, cancel).await;

    match exit {
        RunExit::Shutdown => {
            tracing::info!("daemon shut down cleanly");
            std::process::exit(0);
        }
        RunExit::CredentialRefused => {
            tracing::error!(
                "Daemon credential refused. Have an admin reissue the credential via \
                 ReissueDaemonCredential, then restart the daemon with the new token."
            );
            std::process::exit(2);
        }
        RunExit::NotEligible => {
            tracing::error!(
                "Daemon not eligible for rotation endpoints. Check: daemon record not \
                 revoked or disabled, organisation license active, UsePam enabled."
            );
            std::process::exit(3);
        }
    }
}

/// Wait for a graceful shutdown signal: Ctrl-C (all platforms) or SIGTERM
/// (Unix only).
async fn wait_for_shutdown_signal() {
    #[cfg(unix)]
    {
        use tokio::signal::unix::{SignalKind, signal};

        let mut sigterm = match signal(SignalKind::terminate()) {
            Ok(s) => s,
            Err(e) => {
                tracing::warn!("failed to install SIGTERM handler: {e}");
                // Fall back to Ctrl-C only.
                tokio::signal::ctrl_c()
                    .await
                    .unwrap_or_else(|e| tracing::warn!("ctrl_c error: {e}"));
                return;
            }
        };

        tokio::select! {
            _ = sigterm.recv() => {
                tracing::info!("received SIGTERM");
            }
            result = tokio::signal::ctrl_c() => {
                if let Err(e) = result {
                    tracing::warn!("ctrl_c error: {e}");
                } else {
                    tracing::info!("received Ctrl-C");
                }
            }
        }
    }

    #[cfg(not(unix))]
    {
        if let Err(e) = tokio::signal::ctrl_c().await {
            tracing::warn!("ctrl_c error: {e}");
        } else {
            tracing::info!("received Ctrl-C");
        }
    }
}
