//! Entry point for the `bwac` binary.
//!
//! Exit codes: 0 clean shutdown (SIGTERM or Ctrl-C), 1 invalid configuration or token, 2 credential
//! refused or first authentication failed, 3 not eligible for the rotation endpoints.

use bitwarden_access_connector::{
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
    // RUST_LOG is parsed leniently; unset or empty falls back to INFO.
    let filter = EnvFilter::builder()
        .with_default_directive(tracing_subscriber::filter::LevelFilter::INFO.into())
        .from_env_lossy();

    tracing_subscriber::registry()
        .with(tracing_subscriber::fmt::layer().with_writer(std::io::stderr))
        .with(filter)
        .init();

    let cli = Cli::parse();
    let Command::Run(run_args) = cli.command;

    let connector_cfg = match Config::from_cli(run_args) {
        Ok(cfg) => cfg.into_access_connector_config(),
        Err(e) => {
            tracing::error!("startup error: {e}");
            std::process::exit(1);
        }
    };

    let cancel = CancellationToken::new();

    let watcher_cancel = cancel.clone();
    tokio::spawn(async move {
        wait_for_shutdown_signal().await;
        tracing::info!("shutdown signal received; cancelling");
        watcher_cancel.cancel();
    });

    let exit = bitwarden_access_connector::run(connector_cfg, cancel).await;

    match exit {
        RunExit::Shutdown => {
            tracing::info!("access connector shut down cleanly");
            std::process::exit(0);
        }
        RunExit::CredentialRefused => {
            tracing::error!(
                "Access connector credential refused. Have an admin reissue the credential via \
                 ReissueConnectorCredential, then restart the connector with the new token."
            );
            std::process::exit(2);
        }
        RunExit::NotEligible => {
            tracing::error!(
                "Access connector not eligible for rotation endpoints. Check: connector record not \
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
