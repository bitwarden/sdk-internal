//! Configuration loading and validation for the rotation daemon.
//!
//! [`crate::config::Config::from_cli`] reads and validates all configuration from the parsed
//! CLI arguments and the process environment, producing the `Config` struct
//! that is passed to `crate::executor::run`.
//!
//! # Token intake
//!
//! The daemon token is consumed from **exactly one** of:
//!
//! 1. `BWRD_TOKEN` environment variable (read via [`std::env::var`]).
//! 2. `--token-file <path>` (file contents are trimmed).
//!
//! Supplying both or neither is a hard error
//! ([`crate::error::RotationDaemonError::InvalidConfig`]). The token string is **never echoed** in
//! error messages.
//!
//! On Unix, if `--token-file` is used, the file permissions are checked; a
//! `warn!` is emitted if the file is group- or world-readable (mode bits
//! 0o044).

use std::time::Duration;

use crate::{
    cli::RunArgs,
    error::RotationDaemonError,
    executor::{DaemonConfig, retry::RetryCfg},
    token::DaemonToken,
};

/// Minimum poll interval the daemon will accept (spec `HeartbeatMinInterval`).
const MIN_POLL_INTERVAL_SECS: u64 = 15;

/// Maximum heartbeat interval the daemon will accept.
const MAX_HEARTBEAT_INTERVAL_SECS: u64 = 120;

/// Validated configuration for the daemon run loop.
///
/// Constructed from [`RunArgs`] by [`Config::from_cli`].
pub struct Config {
    inner: DaemonConfig,
}

impl std::fmt::Debug for Config {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Config")
            .field("api_url", &self.inner.api_url)
            .field("identity_url", &self.inner.identity_url)
            .finish_non_exhaustive()
    }
}

impl Config {
    /// Build a validated [`Config`] from the parsed CLI arguments.
    ///
    /// # Errors
    ///
    /// Returns [`RotationDaemonError::InvalidConfig`] for any validation
    /// failure, or [`RotationDaemonError::InvalidToken`] if the token string
    /// cannot be parsed.  Error messages never echo secret values.
    pub fn from_cli(args: RunArgs) -> Result<Self, RotationDaemonError> {
        // ── Token intake (exactly one source) ─────────────────────────────
        // SAFETY: This code runs during single-threaded daemon startup before
        // the async runtime and any additional threads are spawned.  Mutating
        // the process environment here is sound because no other thread can
        // concurrently observe or mutate BWRD_TOKEN at this point.  The
        // variable is removed immediately after reading to prevent child
        // processes (e.g. custom scripts) from inheriting the token value.
        let env_token = std::env::var("BWRD_TOKEN").ok();
        if env_token.is_some() {
            unsafe {
                std::env::remove_var("BWRD_TOKEN");
            }
        }
        let file_token = args.token_file.as_ref().map(read_token_file).transpose()?;

        let token_str: String = match (env_token, file_token) {
            (Some(_), Some(_)) => {
                return Err(RotationDaemonError::InvalidConfig(
                    "supply the daemon token via BWRD_TOKEN or --token-file, not both".into(),
                ));
            }
            (None, None) => {
                return Err(RotationDaemonError::InvalidConfig(
                    "daemon token required: set BWRD_TOKEN or use --token-file".into(),
                ));
            }
            (Some(t), None) => t,
            (None, Some(t)) => t,
        };

        // Validate file permissions after we know token-file was the source.
        #[cfg(unix)]
        if let Some(tf) = args.token_file.as_ref() {
            check_token_file_permissions(tf);
        }

        // Parse the token — error message must not echo the token string.
        let token: DaemonToken = token_str
            .trim()
            .parse()
            .map_err(|e| RotationDaemonError::InvalidToken(format!("{e}")))?;

        // Drop the plaintext token string as soon as we have the parsed form.
        drop(token_str);

        // ── Interval validations ───────────────────────────────────────────
        if args.poll_interval < MIN_POLL_INTERVAL_SECS {
            return Err(RotationDaemonError::InvalidConfig(format!(
                "--poll-interval must be >= {MIN_POLL_INTERVAL_SECS} seconds (got {})",
                args.poll_interval
            )));
        }

        if args.heartbeat_interval >= MAX_HEARTBEAT_INTERVAL_SECS {
            return Err(RotationDaemonError::InvalidConfig(format!(
                "--heartbeat-interval must be < {MAX_HEARTBEAT_INTERVAL_SECS} seconds (got {})",
                args.heartbeat_interval
            )));
        }

        Ok(Config {
            inner: DaemonConfig {
                api_url: args.api_url,
                identity_url: args.identity_url,
                token,
                poll_interval: Duration::from_secs(args.poll_interval),
                heartbeat_interval: Duration::from_secs(args.heartbeat_interval),
                offline_grace: Duration::from_secs(args.offline_grace),
                retry_cfg: RetryCfg {
                    max_retry_attempts: args.max_retry_attempts,
                    retry_base_delay: Duration::from_secs(args.retry_base_delay),
                },
                script_root: args.script_root,
                script_timeout: Duration::from_secs(args.script_timeout),
                entra_verify_probe: args.entra_verify_probe,
            },
        })
    }

    /// Consume the [`Config`] and return the inner [`DaemonConfig`].
    pub fn into_daemon_config(self) -> DaemonConfig {
        self.inner
    }
}

/// Read and trim the contents of a token file.
fn read_token_file(path: &std::path::PathBuf) -> Result<String, RotationDaemonError> {
    let contents = std::fs::read_to_string(path)?;
    Ok(contents.trim().to_owned())
}

/// On Unix, warn if the token file is group- or world-readable.
#[cfg(unix)]
fn check_token_file_permissions(path: &std::path::PathBuf) {
    use std::os::unix::fs::PermissionsExt;

    match std::fs::metadata(path) {
        Ok(meta) => {
            let mode = meta.permissions().mode();
            // Bits 0o044: group-read (0o040) + world-read (0o004).
            if mode & 0o044 != 0 {
                tracing::warn!(
                    path = %path.display(),
                    "token file is group- or world-readable (mode {:o}); \
                     consider restricting permissions with `chmod 600`",
                    mode & 0o777,
                );
            }
        }
        Err(e) => {
            // Non-fatal; we already successfully read the file.
            tracing::warn!("could not check token file permissions: {e}");
        }
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use std::{io::Write, sync::Mutex};

    use super::*;

    /// A valid token string for testing (same vector used in token.rs tests).
    const VALID_TOKEN: &str = "0.daemon.ec2c1d46-6a4b-4751-a310-af9601317f2d.C2IgxjjLF7qSshsbwe8JGcbM075YXw:X8vbvA0bduihIDe/qrzIQQ==";

    /// Mutex to serialise tests that mutate `BWRD_TOKEN`.
    ///
    /// `std::env::set_var`/`remove_var` are `unsafe` in Rust 2024 because
    /// concurrent mutation is UB in a multi-threaded process.  Holding this
    /// lock around every env-mutating test ensures the tests do not interfere.
    static ENV_LOCK: Mutex<()> = Mutex::new(());

    /// Minimal valid [`RunArgs`] with no token source (caller must add one).
    fn base_args() -> RunArgs {
        RunArgs {
            api_url: "https://api.example.com".into(),
            identity_url: "https://identity.example.com".into(),
            token_file: None,
            poll_interval: 15,
            heartbeat_interval: 30,
            offline_grace: 60,
            max_retry_attempts: 5,
            retry_base_delay: 1,
            script_root: None,
            script_timeout: 60,
            entra_verify_probe: false,
        }
    }

    #[test]
    fn env_token_path_succeeds() {
        let _guard = ENV_LOCK.lock().unwrap();
        // SAFETY: protected by ENV_LOCK; no other thread mutates BWRD_TOKEN concurrently.
        unsafe {
            std::env::set_var("BWRD_TOKEN", VALID_TOKEN);
        }
        let result = Config::from_cli(base_args());
        // SAFETY: same guard.
        unsafe {
            std::env::remove_var("BWRD_TOKEN");
        }
        assert!(result.is_ok(), "expected Ok, got {result:?}");
    }

    #[test]
    fn file_token_path_succeeds() {
        let _guard = ENV_LOCK.lock().unwrap();
        let mut f = tempfile::NamedTempFile::new().unwrap();
        writeln!(f, "{VALID_TOKEN}").unwrap();

        let mut args = base_args();
        args.token_file = Some(f.path().to_path_buf());

        // SAFETY: protected by ENV_LOCK.
        unsafe {
            std::env::remove_var("BWRD_TOKEN");
        }
        let result = Config::from_cli(args);
        assert!(result.is_ok(), "expected Ok, got {result:?}");
    }

    #[test]
    fn file_token_whitespace_trimmed() {
        let _guard = ENV_LOCK.lock().unwrap();
        let mut f = tempfile::NamedTempFile::new().unwrap();
        // Leading/trailing whitespace must be trimmed.
        write!(f, "  \n{VALID_TOKEN}\n  ").unwrap();

        let mut args = base_args();
        args.token_file = Some(f.path().to_path_buf());
        // SAFETY: protected by ENV_LOCK.
        unsafe {
            std::env::remove_var("BWRD_TOKEN");
        }

        let result = Config::from_cli(args);
        assert!(
            result.is_ok(),
            "token file whitespace was not trimmed: {result:?}"
        );
    }

    #[test]
    fn both_token_sources_is_invalid_config() {
        let _guard = ENV_LOCK.lock().unwrap();
        let mut f = tempfile::NamedTempFile::new().unwrap();
        writeln!(f, "{VALID_TOKEN}").unwrap();

        let mut args = base_args();
        args.token_file = Some(f.path().to_path_buf());
        // SAFETY: protected by ENV_LOCK.
        unsafe {
            std::env::set_var("BWRD_TOKEN", VALID_TOKEN);
        }
        let result = Config::from_cli(args);
        // SAFETY: same guard.
        unsafe {
            std::env::remove_var("BWRD_TOKEN");
        }

        assert!(
            matches!(result, Err(RotationDaemonError::InvalidConfig(_))),
            "expected InvalidConfig, got {result:?}"
        );
    }

    #[test]
    fn neither_token_source_is_invalid_config() {
        let _guard = ENV_LOCK.lock().unwrap();
        // SAFETY: protected by ENV_LOCK.
        unsafe {
            std::env::remove_var("BWRD_TOKEN");
        }
        let result = Config::from_cli(base_args());
        assert!(
            matches!(result, Err(RotationDaemonError::InvalidConfig(_))),
            "expected InvalidConfig, got {result:?}"
        );
    }

    #[test]
    fn malformed_token_is_invalid_token_and_does_not_echo_value() {
        let _guard = ENV_LOCK.lock().unwrap();
        let bad_token = "not-a-valid-token-string";
        // SAFETY: protected by ENV_LOCK.
        unsafe {
            std::env::set_var("BWRD_TOKEN", bad_token);
        }
        let result = Config::from_cli(base_args());
        // SAFETY: same guard.
        unsafe {
            std::env::remove_var("BWRD_TOKEN");
        }

        match result {
            Err(RotationDaemonError::InvalidToken(msg)) => {
                assert!(
                    !msg.contains(bad_token),
                    "error message must not echo the token string; got: {msg}"
                );
            }
            other => panic!("expected InvalidToken, got {other:?}"),
        }
    }

    #[test]
    fn poll_interval_below_minimum_is_invalid_config() {
        let _guard = ENV_LOCK.lock().unwrap();
        // SAFETY: protected by ENV_LOCK.
        unsafe {
            std::env::set_var("BWRD_TOKEN", VALID_TOKEN);
        }
        let mut args = base_args();
        args.poll_interval = 14; // below the 15 s minimum
        let result = Config::from_cli(args);
        // SAFETY: same guard.
        unsafe {
            std::env::remove_var("BWRD_TOKEN");
        }

        assert!(
            matches!(result, Err(RotationDaemonError::InvalidConfig(_))),
            "expected InvalidConfig for poll_interval < 15, got {result:?}"
        );
    }

    #[test]
    fn poll_interval_at_minimum_is_valid() {
        let _guard = ENV_LOCK.lock().unwrap();
        // SAFETY: protected by ENV_LOCK.
        unsafe {
            std::env::set_var("BWRD_TOKEN", VALID_TOKEN);
        }
        let mut args = base_args();
        args.poll_interval = 15;
        let result = Config::from_cli(args);
        // SAFETY: same guard.
        unsafe {
            std::env::remove_var("BWRD_TOKEN");
        }
        assert!(
            result.is_ok(),
            "poll_interval=15 should be valid: {result:?}"
        );
    }

    #[test]
    fn heartbeat_interval_at_120_is_invalid_config() {
        let _guard = ENV_LOCK.lock().unwrap();
        // SAFETY: protected by ENV_LOCK.
        unsafe {
            std::env::set_var("BWRD_TOKEN", VALID_TOKEN);
        }
        let mut args = base_args();
        args.heartbeat_interval = 120; // must be STRICTLY less than 120
        let result = Config::from_cli(args);
        // SAFETY: same guard.
        unsafe {
            std::env::remove_var("BWRD_TOKEN");
        }

        assert!(
            matches!(result, Err(RotationDaemonError::InvalidConfig(_))),
            "expected InvalidConfig for heartbeat_interval >= 120, got {result:?}"
        );
    }

    #[test]
    fn heartbeat_interval_at_119_is_valid() {
        let _guard = ENV_LOCK.lock().unwrap();
        // SAFETY: protected by ENV_LOCK.
        unsafe {
            std::env::set_var("BWRD_TOKEN", VALID_TOKEN);
        }
        let mut args = base_args();
        args.heartbeat_interval = 119;
        let result = Config::from_cli(args);
        // SAFETY: same guard.
        unsafe {
            std::env::remove_var("BWRD_TOKEN");
        }
        assert!(
            result.is_ok(),
            "heartbeat_interval=119 should be valid: {result:?}"
        );
    }

    #[test]
    fn env_token_removed_from_environment_after_config_load() {
        let _guard = ENV_LOCK.lock().unwrap();
        // SAFETY: protected by ENV_LOCK; no other thread mutates BWRD_TOKEN concurrently.
        unsafe {
            std::env::set_var("BWRD_TOKEN", VALID_TOKEN);
        }
        // Verify the var is present before the call.
        assert!(
            std::env::var("BWRD_TOKEN").is_ok(),
            "BWRD_TOKEN must be present before from_cli"
        );
        let result = Config::from_cli(base_args());
        assert!(result.is_ok(), "expected Ok, got {result:?}");
        // BWRD_TOKEN must have been removed inside from_cli.
        assert!(
            std::env::var("BWRD_TOKEN").is_err(),
            "BWRD_TOKEN must be absent from environment after from_cli consumes it"
        );
    }
}
