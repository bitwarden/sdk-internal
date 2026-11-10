//! Command-line interface argument parsing for the rotation daemon.
//!
//! # Security note on token intake
//!
//! The daemon token string contains the encryption key for the org key.  It is
//! **never** accepted as a CLI argument because `argv` is visible via `ps` and
//! `/proc/<pid>/cmdline`.  Supply it via the `BWRD_TOKEN` environment variable
//! or `--token-file` instead.  See [`Config::from_cli`] for the intake logic.

use std::path::PathBuf;

use clap::{Parser, Subcommand};

/// Bitwarden PAM credential rotation daemon.
#[derive(Debug, Parser)]
#[command(name = "bw-rotation-daemon", version)]
pub struct Cli {
    /// The subcommand to execute.
    #[command(subcommand)]
    pub command: Command,
}

/// Available subcommands.
#[derive(Debug, Subcommand)]
pub enum Command {
    /// Start the rotation daemon poll loop.
    Run(RunArgs),
}

/// Arguments for the `run` subcommand.
#[derive(Debug, Parser)]
pub struct RunArgs {
    /// Bitwarden API server URL.
    #[arg(long, env = "BWRD_API_URL")]
    pub api_url: String,

    /// Bitwarden identity server URL.
    #[arg(long, env = "BWRD_IDENTITY_URL")]
    pub identity_url: String,

    /// Path to a file containing the daemon token (alternative to `BWRD_TOKEN`).
    ///
    /// The file contents are trimmed of leading and trailing whitespace.
    /// On Unix the file permissions are checked; a warning is logged if the
    /// file is group- or world-readable.
    #[arg(long, value_name = "PATH")]
    pub token_file: Option<PathBuf>,

    /// How often the daemon polls for new rotation jobs (seconds, minimum 15).
    #[arg(long, default_value_t = 15, value_name = "SECS")]
    pub poll_interval: u64,

    /// How often the heartbeat fires during an executing rotation (seconds, must
    /// be less than 120).
    #[arg(long, default_value_t = 30, value_name = "SECS")]
    pub heartbeat_interval: u64,

    /// Maximum time without a successful server contact before target-side steps
    /// are paused (seconds).
    #[arg(long, default_value_t = 60, value_name = "SECS")]
    pub offline_grace: u64,

    /// Total number of attempts for each retryable rotation step (not extra
    /// retries — e.g. 5 means four backoff sleeps).
    #[arg(long, default_value_t = 5, value_name = "N")]
    pub max_retry_attempts: u32,

    /// Base delay for exponential backoff between retry attempts (seconds).
    #[arg(long, default_value_t = 1, value_name = "SECS")]
    pub retry_base_delay: u64,

    /// Root directory for custom scripts.  If set, script paths must resolve
    /// within this directory (symlink-safe via `canonicalize`).
    #[arg(long, value_name = "DIR")]
    pub script_root: Option<PathBuf>,

    /// Maximum execution time for a custom script (seconds).
    #[arg(long, default_value_t = 60, value_name = "SECS")]
    pub script_timeout: u64,

    /// Enable the Entra ROPC verify probe (off by default; requires MFA
    /// exclusion or conditional-access exemption for the service principal).
    #[arg(long, default_value_t = false)]
    pub entra_verify_probe: bool,
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn cli_run_parses_minimal_required_args() {
        let cli = Cli::try_parse_from([
            "bw-rotation-daemon",
            "run",
            "--api-url",
            "https://api.example.com",
            "--identity-url",
            "https://identity.example.com",
        ])
        .expect("should parse with required args");

        let Command::Run(args) = cli.command;
        assert_eq!(args.api_url, "https://api.example.com");
        assert_eq!(args.identity_url, "https://identity.example.com");
        assert!(args.token_file.is_none());
        assert_eq!(args.poll_interval, 15);
        assert_eq!(args.heartbeat_interval, 30);
        assert_eq!(args.offline_grace, 60);
        assert_eq!(args.max_retry_attempts, 5);
        assert_eq!(args.retry_base_delay, 1);
        assert!(args.script_root.is_none());
        assert_eq!(args.script_timeout, 60);
        assert!(!args.entra_verify_probe);
    }

    #[test]
    fn cli_run_parses_all_optional_args() {
        let cli = Cli::try_parse_from([
            "bw-rotation-daemon",
            "run",
            "--api-url",
            "https://api.example.com",
            "--identity-url",
            "https://identity.example.com",
            "--token-file",
            "/run/secrets/daemon-token",
            "--poll-interval",
            "30",
            "--heartbeat-interval",
            "45",
            "--offline-grace",
            "120",
            "--max-retry-attempts",
            "3",
            "--retry-base-delay",
            "2",
            "--script-root",
            "/opt/scripts",
            "--script-timeout",
            "90",
            "--entra-verify-probe",
        ])
        .expect("should parse all optional args");

        let Command::Run(args) = cli.command;
        assert_eq!(
            args.token_file,
            Some(std::path::PathBuf::from("/run/secrets/daemon-token"))
        );
        assert_eq!(args.poll_interval, 30);
        assert_eq!(args.heartbeat_interval, 45);
        assert_eq!(args.offline_grace, 120);
        assert_eq!(args.max_retry_attempts, 3);
        assert_eq!(args.retry_base_delay, 2);
        assert_eq!(
            args.script_root,
            Some(std::path::PathBuf::from("/opt/scripts"))
        );
        assert_eq!(args.script_timeout, 90);
        assert!(args.entra_verify_probe);
    }

    #[test]
    fn cli_rejects_unknown_token_arg() {
        // `--token` must not be accepted as a clap arg (would expose value via ps).
        let result = Cli::try_parse_from([
            "bw-rotation-daemon",
            "run",
            "--api-url",
            "https://api.example.com",
            "--identity-url",
            "https://identity.example.com",
            "--token",
            "0.daemon.some-id.secret:key==",
        ]);
        assert!(
            result.is_err(),
            "--token must not be an accepted arg; got: {result:?}"
        );
    }
}
