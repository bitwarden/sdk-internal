//! Command-line interface argument parsing for the rotation daemon.
//!
//! Minimal by design: daemon settings live in the TOML config file (`--config <PATH>` or
//! `BWRD_CONFIG`), not CLI flags. `BWRD_API_URL`/`BWRD_IDENTITY_URL` override the file's URLs;
//! `BWRD_TOKEN` supplies the token. See [`crate::config::Config::from_cli`] for precedence.
//!
//! The daemon token is never a CLI argument, since `argv` is visible via `ps` and
//! `/proc/<pid>/cmdline`, and never accepted in the config file; only `BWRD_TOKEN`.

use std::path::PathBuf;

use clap::{Args, Parser, Subcommand};

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
#[derive(Debug, Args)]
pub struct RunArgs {
    /// Path to the TOML configuration file.
    #[arg(long, env = "BWRD_CONFIG", value_name = "PATH")]
    pub config: Option<PathBuf>,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn cli_run_parses_with_no_flags() {
        let cli =
            Cli::try_parse_from(["bw-rotation-daemon", "run"]).expect("should parse with no flags");

        let Command::Run(args) = cli.command;
        assert!(args.config.is_none());
    }

    #[test]
    fn cli_config_path_parses() {
        let cli = Cli::try_parse_from([
            "bw-rotation-daemon",
            "run",
            "--config",
            "/etc/bwrd/config.toml",
        ])
        .expect("should parse --config");

        let Command::Run(args) = cli.command;
        assert_eq!(
            args.config,
            Some(std::path::PathBuf::from("/etc/bwrd/config.toml"))
        );
    }

    #[test]
    fn cli_rejects_unknown_token_arg() {
        // `--token` must not be accepted as a clap arg (would expose value via ps).
        let result = Cli::try_parse_from([
            "bw-rotation-daemon",
            "run",
            "--token",
            "0.daemon.some-id.secret:key==",
        ]);
        assert!(
            result.is_err(),
            "--token must not be an accepted arg; got: {result:?}"
        );
    }

    #[test]
    fn cli_rejects_unknown_token_file_arg() {
        // `--token-file` must not be accepted either; the token is env-only.
        let result = Cli::try_parse_from([
            "bw-rotation-daemon",
            "run",
            "--token-file",
            "/etc/bwrd/token",
        ]);
        assert!(
            result.is_err(),
            "--token-file must not be an accepted arg; got: {result:?}"
        );
    }

    #[test]
    fn cli_rejects_removed_settings_flags() {
        // Per-setting flags were removed; settings live in the config file only.
        for args in [
            ["bw-rotation-daemon", "run", "--poll-interval", "30"].as_slice(),
            [
                "bw-rotation-daemon",
                "run",
                "--api-url",
                "https://api.example.com",
            ]
            .as_slice(),
            ["bw-rotation-daemon", "run", "--entra-verify-probe"].as_slice(),
        ] {
            let result = Cli::try_parse_from(args.iter().copied());
            assert!(
                result.is_err(),
                "removed settings flag must not parse: {args:?}"
            );
        }
    }
}
