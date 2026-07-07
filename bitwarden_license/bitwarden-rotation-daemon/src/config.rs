//! Configuration loading and validation for the rotation daemon.
//!
//! [`crate::config::Config::from_cli`] resolves configuration from three layers in priority order:
//!
//! 1. **Environment variables** — `BWRD_API_URL` / `BWRD_IDENTITY_URL` override the config file's
//!    URLs.  Empty or whitespace-only values are treated as unset.
//! 2. **Config file** — a TOML file specified with `--config <PATH>` or `BWRD_CONFIG`.  Every key
//!    is optional; unknown keys (including `token`) are a hard startup error.
//! 3. **Built-in defaults** — see the `Default` impl on the private `FileConfig` struct in this
//!    module.
//!
//! # Token intake
//!
//! The daemon token is consumed from the `BWRD_TOKEN` environment variable
//! (read via [`std::env::var`]).  If the variable is absent or empty, startup
//! is a hard error ([`crate::error::RotationDaemonError::InvalidConfig`]).
//! The token string is **never echoed** in error messages.
//!
//! The daemon token **cannot** be supplied via the config file.  Any config file containing a
//! `token` key will be rejected at parse time (`deny_unknown_fields`).

use std::{path::PathBuf, time::Duration};

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

// ---------------------------------------------------------------------------
// On-disk config file struct
// ---------------------------------------------------------------------------

/// On-disk daemon configuration (TOML).  Every key is optional; the `BWRD_API_URL` /
/// `BWRD_IDENTITY_URL` environment variables override the file's URLs.
///
/// Keys missing from the file are filled in from [`FileConfig::default`] (the daemon's
/// built-in defaults) via `#[serde(default)]`, so the tunable fields are concrete values.
/// `api_url`, `identity_url`, and `script_root` have no built-in default and stay `Option`.
///
/// The daemon token **cannot** be supplied via this file — any `token` key is a hard startup
/// error (`deny_unknown_fields`).  Use the `BWRD_TOKEN` environment variable instead.
#[derive(Debug, serde::Deserialize)]
#[serde(default, deny_unknown_fields)]
struct FileConfig {
    /// Bitwarden API server URL.  No built-in default; required from `BWRD_API_URL` or this file.
    api_url: Option<String>,
    /// Bitwarden identity server URL.  No built-in default; required from `BWRD_IDENTITY_URL` or
    /// this file.
    identity_url: Option<String>,
    /// Poll interval in seconds.
    poll_interval: u64,
    /// Heartbeat interval in seconds.
    heartbeat_interval: u64,
    /// Offline grace period in seconds.
    offline_grace: u64,
    /// Total number of attempts for each retryable rotation step.
    max_retry_attempts: u32,
    /// Base delay for exponential backoff in seconds.
    retry_base_delay: u64,
    /// Root directory for custom scripts.  No built-in default.
    script_root: Option<PathBuf>,
    /// Custom-script timeout in seconds.
    script_timeout: u64,
    /// Whether the Entra ROPC verify probe is enabled.
    entra_verify_probe: bool,
}

/// The daemon's built-in defaults — the lowest-priority configuration layer
/// (env URLs > config file > these values).
impl Default for FileConfig {
    fn default() -> Self {
        Self {
            api_url: None,
            identity_url: None,
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
}

impl FileConfig {
    /// Load a [`FileConfig`] from a TOML file at `path`.
    ///
    /// Returns `Err(RotationDaemonError::InvalidConfig(...))` if the file cannot be read or
    /// parsed.  Only the last line of the TOML error (the human-readable description, e.g.
    /// "unknown field `token`") is included; the source-code snippet — which could echo config
    /// values — is stripped.  `BWRD_TOKEN` never reaches this function.
    fn load(path: &std::path::Path) -> Result<Self, RotationDaemonError> {
        let contents = std::fs::read_to_string(path).map_err(|e| {
            RotationDaemonError::InvalidConfig(format!(
                "cannot read config file {}: {e}",
                path.display()
            ))
        })?;
        toml::from_str(&contents).map_err(|e| {
            // Use only the last line of the TOML error: it contains the human-readable
            // description (e.g. "unknown field `token`, expected ...") without the
            // source-code snippet (lines 1-4) that echoes the raw config-file value.
            let summary = e.to_string();
            let description = summary.lines().last().unwrap_or("parse error");
            RotationDaemonError::InvalidConfig(format!(
                "config file {} is invalid TOML: {description}",
                path.display()
            ))
        })
    }
}

// ---------------------------------------------------------------------------
// Validated config
// ---------------------------------------------------------------------------

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
    /// Loads an optional TOML config file if `args.config` is set.  The `BWRD_API_URL` /
    /// `BWRD_IDENTITY_URL` environment variables override the file's URLs; all other
    /// settings come from the file, falling back to built-in defaults.
    ///
    /// # Errors
    ///
    /// Returns [`RotationDaemonError::InvalidConfig`] for any validation
    /// failure, or [`RotationDaemonError::InvalidToken`] if the token string
    /// cannot be parsed.  Error messages never echo secret values.
    pub fn from_cli(args: RunArgs) -> Result<Self, RotationDaemonError> {
        // ── Token intake ───────────────────────────────────────────────────
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

        // An empty or whitespace-only value is treated the same as an absent
        // one.  The filter runs after the removal above so the variable is
        // stripped from the environment even when its value is empty.
        let token_str: String = match env_token.filter(|t| !t.trim().is_empty()) {
            Some(t) => t,
            None => {
                return Err(RotationDaemonError::InvalidConfig(
                    "daemon token must be supplied via the BWRD_TOKEN environment variable".into(),
                ));
            }
        };

        // Parse the token — error message must not echo the token string.
        let token: DaemonToken = token_str
            .trim()
            .parse()
            .map_err(|e| RotationDaemonError::InvalidToken(format!("{e}")))?;

        // Drop the plaintext token string as soon as we have the parsed form.
        drop(token_str);

        // ── Config file ────────────────────────────────────────────────────
        let file = match &args.config {
            Some(path) => FileConfig::load(path)?,
            None => FileConfig::default(),
        };

        // ── URL intake: env > file ─────────────────────────────────────────
        // BWRD_API_URL / BWRD_IDENTITY_URL are not secrets: plain reads, and
        // the variables are left in the environment.  Empty or whitespace-only
        // values are treated as unset, consistent with BWRD_TOKEN.
        let env_url = |name: &str| std::env::var(name).ok().filter(|v| !v.trim().is_empty());

        let api_url = env_url("BWRD_API_URL").or(file.api_url).ok_or_else(|| {
            RotationDaemonError::InvalidConfig(
                "api_url must be supplied via the BWRD_API_URL environment variable or the config file".into(),
            )
        })?;

        let identity_url = env_url("BWRD_IDENTITY_URL")
            .or(file.identity_url)
            .ok_or_else(|| RotationDaemonError::InvalidConfig(
                "identity_url must be supplied via the BWRD_IDENTITY_URL environment variable or the config file".into(),
            ))?;

        // ── Interval validations ───────────────────────────────────────────
        // Tunables come straight from the config file; keys missing from the
        // TOML were pre-filled with the built-in defaults via `#[serde(default)]`
        // on `FileConfig`.
        if file.poll_interval < MIN_POLL_INTERVAL_SECS {
            return Err(RotationDaemonError::InvalidConfig(format!(
                "poll_interval must be >= {MIN_POLL_INTERVAL_SECS} seconds (got {})",
                file.poll_interval
            )));
        }

        if file.heartbeat_interval >= MAX_HEARTBEAT_INTERVAL_SECS {
            return Err(RotationDaemonError::InvalidConfig(format!(
                "heartbeat_interval must be < {MAX_HEARTBEAT_INTERVAL_SECS} seconds (got {})",
                file.heartbeat_interval
            )));
        }

        Ok(Config {
            inner: DaemonConfig {
                api_url,
                identity_url,
                token,
                poll_interval: Duration::from_secs(file.poll_interval),
                heartbeat_interval: Duration::from_secs(file.heartbeat_interval),
                offline_grace: Duration::from_secs(file.offline_grace),
                retry_cfg: RetryCfg {
                    max_retry_attempts: file.max_retry_attempts,
                    retry_base_delay: Duration::from_secs(file.retry_base_delay),
                },
                script_root: file.script_root,
                script_timeout: Duration::from_secs(file.script_timeout),
                entra_verify_probe: file.entra_verify_probe,
            },
        })
    }

    /// Consume the [`Config`] and return the inner [`DaemonConfig`].
    pub fn into_daemon_config(self) -> DaemonConfig {
        self.inner
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    /// A valid token string for testing (same vector used in token.rs tests).
    const VALID_TOKEN: &str = "0.daemon.ec2c1d46-6a4b-4751-a310-af9601317f2d.C2IgxjjLF7qSshsbwe8JGcbM075YXw:X8vbvA0bduihIDe/qrzIQQ==";

    /// Use the process-wide env lock so config tests and custom_script tests
    /// serialise all environment mutations across modules.
    use crate::TEST_ENV_LOCK as ENV_LOCK;

    /// [`RunArgs`] pointing at no config file.
    fn empty_args() -> RunArgs {
        RunArgs { config: None }
    }

    /// [`RunArgs`] pointing at the given config file.
    fn file_args(f: &tempfile::NamedTempFile) -> RunArgs {
        RunArgs {
            config: Some(f.path().to_path_buf()),
        }
    }

    // ── Helpers ─────────────────────────────────────────────────────────────

    /// Write a TOML string to a tempfile and return the file (kept open for lifetime).
    fn write_toml(contents: &str) -> tempfile::NamedTempFile {
        use std::io::Write as _;
        let mut f = tempfile::NamedTempFile::new().expect("tempfile");
        f.write_all(contents.as_bytes()).expect("write toml");
        f
    }

    // ── Token intake (unchanged behaviour) ───────────────────────────────────

    #[test]
    fn env_token_path_succeeds() {
        let _guard = ENV_LOCK.lock().unwrap();
        // SAFETY: protected by ENV_LOCK; no other thread mutates the environment concurrently.
        unsafe {
            std::env::set_var("BWRD_TOKEN", VALID_TOKEN);
            std::env::set_var("BWRD_API_URL", "https://api.example.com");
            std::env::set_var("BWRD_IDENTITY_URL", "https://identity.example.com");
        }
        let result = Config::from_cli(empty_args());
        // SAFETY: same guard.
        unsafe {
            std::env::remove_var("BWRD_TOKEN");
            std::env::remove_var("BWRD_API_URL");
            std::env::remove_var("BWRD_IDENTITY_URL");
        }
        assert!(result.is_ok(), "expected Ok, got {result:?}");
    }

    #[test]
    fn missing_bwrd_token_is_invalid_config() {
        let _guard = ENV_LOCK.lock().unwrap();
        // SAFETY: protected by ENV_LOCK.
        unsafe {
            std::env::remove_var("BWRD_TOKEN");
        }
        let result = Config::from_cli(empty_args());
        assert!(
            matches!(result, Err(RotationDaemonError::InvalidConfig(_))),
            "expected InvalidConfig, got {result:?}"
        );
    }

    #[test]
    fn empty_bwrd_token_is_invalid_config() {
        let _guard = ENV_LOCK.lock().unwrap();
        // SAFETY: protected by ENV_LOCK.
        unsafe {
            std::env::set_var("BWRD_TOKEN", "  ");
        }
        let result = Config::from_cli(empty_args());
        // SAFETY: same guard.
        unsafe {
            std::env::remove_var("BWRD_TOKEN");
        }
        assert!(
            matches!(result, Err(RotationDaemonError::InvalidConfig(_))),
            "expected InvalidConfig for whitespace-only BWRD_TOKEN, got {result:?}"
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
        let result = Config::from_cli(empty_args());
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
    fn env_token_removed_from_environment_after_config_load() {
        let _guard = ENV_LOCK.lock().unwrap();
        // SAFETY: protected by ENV_LOCK; no other thread mutates the environment concurrently.
        unsafe {
            std::env::set_var("BWRD_TOKEN", VALID_TOKEN);
            std::env::set_var("BWRD_API_URL", "https://api.example.com");
            std::env::set_var("BWRD_IDENTITY_URL", "https://identity.example.com");
        }
        // Verify the var is present before the call.
        assert!(
            std::env::var("BWRD_TOKEN").is_ok(),
            "BWRD_TOKEN must be present before from_cli"
        );
        let result = Config::from_cli(empty_args());
        // SAFETY: same guard.
        unsafe {
            std::env::remove_var("BWRD_API_URL");
            std::env::remove_var("BWRD_IDENTITY_URL");
        }
        assert!(result.is_ok(), "expected Ok, got {result:?}");
        // BWRD_TOKEN must have been removed inside from_cli.
        assert!(
            std::env::var("BWRD_TOKEN").is_err(),
            "BWRD_TOKEN must be absent from environment after from_cli consumes it"
        );
    }

    // ── Interval validation ──────────────────────────────────────────────────

    #[test]
    fn poll_interval_below_minimum_is_invalid_config() {
        let _guard = ENV_LOCK.lock().unwrap();
        // SAFETY: protected by ENV_LOCK; no other thread mutates the environment concurrently.
        unsafe {
            std::env::set_var("BWRD_TOKEN", VALID_TOKEN);
            // Defensive: leaked URL env vars must not override the config file under test.
            std::env::remove_var("BWRD_API_URL");
            std::env::remove_var("BWRD_IDENTITY_URL");
        }

        // poll_interval is below the 15 s minimum.
        let toml = r#"
api_url = "https://api.example.com"
identity_url = "https://identity.example.com"
poll_interval = 14
"#;
        let f = write_toml(toml);
        let result = Config::from_cli(file_args(&f));
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
        // SAFETY: protected by ENV_LOCK; no other thread mutates the environment concurrently.
        unsafe {
            std::env::set_var("BWRD_TOKEN", VALID_TOKEN);
            // Defensive: leaked URL env vars must not override the config file under test.
            std::env::remove_var("BWRD_API_URL");
            std::env::remove_var("BWRD_IDENTITY_URL");
        }

        let toml = r#"
api_url = "https://api.example.com"
identity_url = "https://identity.example.com"
poll_interval = 15
"#;
        let f = write_toml(toml);
        let result = Config::from_cli(file_args(&f));
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
        // SAFETY: protected by ENV_LOCK; no other thread mutates the environment concurrently.
        unsafe {
            std::env::set_var("BWRD_TOKEN", VALID_TOKEN);
            // Defensive: leaked URL env vars must not override the config file under test.
            std::env::remove_var("BWRD_API_URL");
            std::env::remove_var("BWRD_IDENTITY_URL");
        }

        // heartbeat_interval must be STRICTLY less than 120.
        let toml = r#"
api_url = "https://api.example.com"
identity_url = "https://identity.example.com"
heartbeat_interval = 120
"#;
        let f = write_toml(toml);
        let result = Config::from_cli(file_args(&f));
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
        // SAFETY: protected by ENV_LOCK; no other thread mutates the environment concurrently.
        unsafe {
            std::env::set_var("BWRD_TOKEN", VALID_TOKEN);
            // Defensive: leaked URL env vars must not override the config file under test.
            std::env::remove_var("BWRD_API_URL");
            std::env::remove_var("BWRD_IDENTITY_URL");
        }

        let toml = r#"
api_url = "https://api.example.com"
identity_url = "https://identity.example.com"
heartbeat_interval = 119
"#;
        let f = write_toml(toml);
        let result = Config::from_cli(file_args(&f));
        // SAFETY: same guard.
        unsafe {
            std::env::remove_var("BWRD_TOKEN");
        }
        assert!(
            result.is_ok(),
            "heartbeat_interval=119 should be valid: {result:?}"
        );
    }

    // ── URL resolution (env > file) ──────────────────────────────────────────

    #[test]
    fn env_urls_without_file_are_used() {
        let _guard = ENV_LOCK.lock().unwrap();
        // SAFETY: protected by ENV_LOCK; no other thread mutates the environment concurrently.
        unsafe {
            std::env::set_var("BWRD_TOKEN", VALID_TOKEN);
            std::env::set_var("BWRD_API_URL", "https://api.env.example.com");
            std::env::set_var("BWRD_IDENTITY_URL", "https://identity.env.example.com");
        }
        let result = Config::from_cli(empty_args());
        // SAFETY: same guard.
        unsafe {
            std::env::remove_var("BWRD_TOKEN");
            std::env::remove_var("BWRD_API_URL");
            std::env::remove_var("BWRD_IDENTITY_URL");
        }

        let inner = result.expect("expected Ok").into_daemon_config();
        assert_eq!(inner.api_url, "https://api.env.example.com");
        assert_eq!(inner.identity_url, "https://identity.env.example.com");
    }

    #[test]
    fn env_urls_override_file() {
        let _guard = ENV_LOCK.lock().unwrap();
        // SAFETY: protected by ENV_LOCK; no other thread mutates the environment concurrently.
        unsafe {
            std::env::set_var("BWRD_TOKEN", VALID_TOKEN);
            std::env::set_var("BWRD_API_URL", "https://api.env.example.com");
            std::env::set_var("BWRD_IDENTITY_URL", "https://identity.env.example.com");
        }

        let toml = r#"
api_url = "https://api.file.example.com"
identity_url = "https://identity.file.example.com"
"#;
        let f = write_toml(toml);

        let result = Config::from_cli(file_args(&f));
        // SAFETY: same guard.
        unsafe {
            std::env::remove_var("BWRD_TOKEN");
            std::env::remove_var("BWRD_API_URL");
            std::env::remove_var("BWRD_IDENTITY_URL");
        }

        let inner = result.expect("expected Ok").into_daemon_config();
        // Environment URLs win over file URLs.
        assert_eq!(inner.api_url, "https://api.env.example.com");
        assert_eq!(inner.identity_url, "https://identity.env.example.com");
    }

    #[test]
    fn whitespace_env_url_is_treated_as_unset() {
        let _guard = ENV_LOCK.lock().unwrap();
        // SAFETY: protected by ENV_LOCK; no other thread mutates the environment concurrently.
        unsafe {
            std::env::set_var("BWRD_TOKEN", VALID_TOKEN);
            std::env::set_var("BWRD_API_URL", "  ");
            // Defensive: a leaked BWRD_IDENTITY_URL would override the file value under test.
            std::env::remove_var("BWRD_IDENTITY_URL");
        }

        let toml = r#"
api_url = "https://api.file.example.com"
identity_url = "https://identity.file.example.com"
"#;
        let f = write_toml(toml);

        let result = Config::from_cli(file_args(&f));
        // SAFETY: same guard.
        unsafe {
            std::env::remove_var("BWRD_TOKEN");
            std::env::remove_var("BWRD_API_URL");
        }

        let inner = result.expect("expected Ok").into_daemon_config();
        // Whitespace-only BWRD_API_URL falls through to the file value.
        assert_eq!(inner.api_url, "https://api.file.example.com");
        assert_eq!(inner.identity_url, "https://identity.file.example.com");
    }

    #[test]
    fn missing_api_url_from_all_layers_is_invalid_config() {
        let _guard = ENV_LOCK.lock().unwrap();
        // SAFETY: protected by ENV_LOCK; no other thread mutates the environment concurrently.
        unsafe {
            std::env::set_var("BWRD_TOKEN", VALID_TOKEN);
            // Defensive: a leaked URL env var would satisfy the requirement under test.
            std::env::remove_var("BWRD_API_URL");
            std::env::remove_var("BWRD_IDENTITY_URL");
        }

        // File only has identity_url; api_url is missing everywhere.
        let toml = r#"
identity_url = "https://identity.example.com"
"#;
        let f = write_toml(toml);

        let result = Config::from_cli(file_args(&f));
        // SAFETY: same guard.
        unsafe {
            std::env::remove_var("BWRD_TOKEN");
        }

        match result {
            Err(RotationDaemonError::InvalidConfig(msg)) => {
                assert!(
                    msg.contains("api_url"),
                    "error should mention the missing field 'api_url'; got: {msg}"
                );
            }
            other => panic!("expected InvalidConfig for missing api_url, got {other:?}"),
        }
    }

    #[test]
    fn missing_identity_url_from_all_layers_is_invalid_config() {
        let _guard = ENV_LOCK.lock().unwrap();
        // SAFETY: protected by ENV_LOCK; no other thread mutates the environment concurrently.
        unsafe {
            std::env::set_var("BWRD_TOKEN", VALID_TOKEN);
            // Defensive: a leaked URL env var would satisfy the requirement under test.
            std::env::remove_var("BWRD_API_URL");
            std::env::remove_var("BWRD_IDENTITY_URL");
        }

        // File only has api_url; identity_url is missing everywhere.
        let toml = r#"
api_url = "https://api.example.com"
"#;
        let f = write_toml(toml);

        let result = Config::from_cli(file_args(&f));
        // SAFETY: same guard.
        unsafe {
            std::env::remove_var("BWRD_TOKEN");
        }

        match result {
            Err(RotationDaemonError::InvalidConfig(msg)) => {
                assert!(
                    msg.contains("identity_url"),
                    "error should mention the missing field 'identity_url'; got: {msg}"
                );
            }
            other => panic!("expected InvalidConfig for missing identity_url, got {other:?}"),
        }
    }

    // ── Config file tests ────────────────────────────────────────────────────

    #[test]
    fn file_only_values_are_used() {
        let _guard = ENV_LOCK.lock().unwrap();
        // SAFETY: protected by ENV_LOCK; no other thread mutates the environment concurrently.
        unsafe {
            std::env::set_var("BWRD_TOKEN", VALID_TOKEN);
            // Defensive: leaked URL env vars must not override the config file under test.
            std::env::remove_var("BWRD_API_URL");
            std::env::remove_var("BWRD_IDENTITY_URL");
        }

        let toml = r#"
api_url = "https://api.file.example.com"
identity_url = "https://identity.file.example.com"
poll_interval = 30
heartbeat_interval = 45
offline_grace = 90
max_retry_attempts = 3
retry_base_delay = 2
script_timeout = 120
entra_verify_probe = true
"#;
        let f = write_toml(toml);

        let result = Config::from_cli(file_args(&f));
        // SAFETY: same guard.
        unsafe {
            std::env::remove_var("BWRD_TOKEN");
        }

        let cfg = result.expect("expected Ok from file-only config");
        let inner = cfg.into_daemon_config();
        assert_eq!(inner.api_url, "https://api.file.example.com");
        assert_eq!(inner.identity_url, "https://identity.file.example.com");
        assert_eq!(inner.poll_interval, Duration::from_secs(30));
        assert_eq!(inner.heartbeat_interval, Duration::from_secs(45));
        assert_eq!(inner.offline_grace, Duration::from_secs(90));
        assert_eq!(inner.retry_cfg.max_retry_attempts, 3);
        assert_eq!(inner.retry_cfg.retry_base_delay, Duration::from_secs(2));
        assert_eq!(inner.script_timeout, Duration::from_secs(120));
        assert!(inner.entra_verify_probe);
    }

    #[test]
    fn defaults_apply_when_file_omits_tunables() {
        let _guard = ENV_LOCK.lock().unwrap();
        // SAFETY: protected by ENV_LOCK; no other thread mutates the environment concurrently.
        unsafe {
            std::env::set_var("BWRD_TOKEN", VALID_TOKEN);
            // Defensive: leaked URL env vars must not override the config file under test.
            std::env::remove_var("BWRD_API_URL");
            std::env::remove_var("BWRD_IDENTITY_URL");
        }

        // Only provide required fields; everything else should fall to defaults.
        let toml = r#"
api_url = "https://api.example.com"
identity_url = "https://identity.example.com"
"#;
        let f = write_toml(toml);

        let result = Config::from_cli(file_args(&f));
        // SAFETY: same guard.
        unsafe {
            std::env::remove_var("BWRD_TOKEN");
        }

        let cfg = result.expect("expected Ok with defaults");
        let inner = cfg.into_daemon_config();
        let defaults = FileConfig::default();
        assert_eq!(
            inner.poll_interval,
            Duration::from_secs(defaults.poll_interval)
        );
        assert_eq!(
            inner.heartbeat_interval,
            Duration::from_secs(defaults.heartbeat_interval)
        );
        assert_eq!(
            inner.offline_grace,
            Duration::from_secs(defaults.offline_grace)
        );
        assert_eq!(
            inner.retry_cfg.max_retry_attempts,
            defaults.max_retry_attempts
        );
        assert_eq!(
            inner.retry_cfg.retry_base_delay,
            Duration::from_secs(defaults.retry_base_delay)
        );
        assert_eq!(
            inner.script_timeout,
            Duration::from_secs(defaults.script_timeout)
        );
        assert_eq!(inner.entra_verify_probe, defaults.entra_verify_probe);
    }

    #[test]
    fn token_in_file_is_denied_by_unknown_fields() {
        let _guard = ENV_LOCK.lock().unwrap();
        // SAFETY: protected by ENV_LOCK; no other thread mutates BWRD_TOKEN concurrently.
        unsafe {
            std::env::set_var("BWRD_TOKEN", VALID_TOKEN);
        }

        let token_value = "0.x.y:z";
        let toml = format!(
            r#"
api_url = "https://api.example.com"
identity_url = "https://identity.example.com"
token = "{token_value}"
"#
        );
        let f = write_toml(&toml);

        let result = Config::from_cli(file_args(&f));
        // SAFETY: same guard.
        unsafe {
            std::env::remove_var("BWRD_TOKEN");
        }

        match result {
            Err(RotationDaemonError::InvalidConfig(msg)) => {
                assert!(
                    !msg.contains(token_value),
                    "error must NOT echo the token value; got: {msg}"
                );
            }
            other => panic!(
                "expected InvalidConfig for unknown 'token' field in config file, got {other:?}"
            ),
        }
    }

    #[test]
    fn nonexistent_config_path_is_invalid_config() {
        let _guard = ENV_LOCK.lock().unwrap();
        // SAFETY: protected by ENV_LOCK; no other thread mutates BWRD_TOKEN concurrently.
        unsafe {
            std::env::set_var("BWRD_TOKEN", VALID_TOKEN);
        }

        let args = RunArgs {
            config: Some(PathBuf::from("/nonexistent/path/to/config.toml")),
        };

        let result = Config::from_cli(args);
        // SAFETY: same guard.
        unsafe {
            std::env::remove_var("BWRD_TOKEN");
        }

        assert!(
            matches!(result, Err(RotationDaemonError::InvalidConfig(_))),
            "expected InvalidConfig for nonexistent config path, got {result:?}"
        );
    }

    #[test]
    fn file_entra_verify_probe_true_is_used() {
        let _guard = ENV_LOCK.lock().unwrap();
        // SAFETY: protected by ENV_LOCK; no other thread mutates the environment concurrently.
        unsafe {
            std::env::set_var("BWRD_TOKEN", VALID_TOKEN);
            // Defensive: leaked URL env vars must not override the config file under test.
            std::env::remove_var("BWRD_API_URL");
            std::env::remove_var("BWRD_IDENTITY_URL");
        }

        let toml = r#"
api_url = "https://api.example.com"
identity_url = "https://identity.example.com"
entra_verify_probe = true
"#;
        let f = write_toml(toml);

        let result = Config::from_cli(file_args(&f));
        // SAFETY: same guard.
        unsafe {
            std::env::remove_var("BWRD_TOKEN");
        }

        let cfg = result.expect("expected Ok");
        let inner = cfg.into_daemon_config();
        assert!(
            inner.entra_verify_probe,
            "entra_verify_probe from file should be true"
        );
    }
}
