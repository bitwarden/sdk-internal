//! Command-line arguments for the access connector.
//!
//! Settings live in the TOML config file, not flags; see [`crate::config::Config::from_cli`]. The
//! token comes only from `BWAC_TOKEN`, since `argv` is visible through `ps` and
//! `/proc/<pid>/cmdline`.

use std::path::PathBuf;

use clap::{Args, Parser, Subcommand};

/// Bitwarden PAM access connector.
#[derive(Debug, Parser)]
#[command(name = "bwac", version)]
pub struct Cli {
    /// The subcommand to execute.
    #[command(subcommand)]
    pub command: Command,
}

/// Available subcommands.
#[derive(Debug, Subcommand)]
pub enum Command {
    /// Start the access connector poll loop.
    Run(RunArgs),
}

/// Arguments for the `run` subcommand.
#[derive(Debug, Args)]
pub struct RunArgs {
    /// Path to the TOML configuration file.
    #[arg(long, env = "BWAC_CONFIG", value_name = "PATH")]
    pub config: Option<PathBuf>,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn cli_run_parses_with_no_flags() {
        let cli = Cli::try_parse_from(["bwac", "run"]).expect("should parse with no flags");

        let Command::Run(args) = cli.command;
        assert!(args.config.is_none());
    }

    #[test]
    fn cli_config_path_parses() {
        let cli = Cli::try_parse_from(["bwac", "run", "--config", "/etc/bwac/config.toml"])
            .expect("should parse --config");

        let Command::Run(args) = cli.command;
        assert_eq!(
            args.config,
            Some(std::path::PathBuf::from("/etc/bwac/config.toml"))
        );
    }

    #[test]
    fn cli_rejects_unknown_token_arg() {
        // A token flag would expose the value through `ps`.
        let result = Cli::try_parse_from([
            "bwac",
            "run",
            "--token",
            "0.access-connector.some-id.secret:key==",
        ]);
        assert!(
            result.is_err(),
            "--token must not be an accepted arg; got: {result:?}"
        );
    }

    #[test]
    fn cli_rejects_unknown_token_file_arg() {
        // The token is env-only.
        let result = Cli::try_parse_from(["bwac", "run", "--token-file", "/etc/bwac/token"]);
        assert!(
            result.is_err(),
            "--token-file must not be an accepted arg; got: {result:?}"
        );
    }

    #[test]
    fn cli_rejects_removed_settings_flags() {
        // Settings live in the config file only.
        for args in [
            ["bwac", "run", "--poll-interval", "30"].as_slice(),
            ["bwac", "run", "--api-url", "https://api.example.com"].as_slice(),
            ["bwac", "run", "--entra-verify-probe"].as_slice(),
        ] {
            let result = Cli::try_parse_from(args.iter().copied());
            assert!(
                result.is_err(),
                "removed settings flag must not parse: {args:?}"
            );
        }
    }
}
