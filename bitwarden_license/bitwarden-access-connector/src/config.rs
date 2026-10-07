//! Configuration loading and validation for the access connector.
//!
//! Unknown TOML keys are a startup error. `[targets]` entries override per-target environment
//! variables, except `client_secret`, which only the environment can supply.

use std::{collections::HashMap, path::PathBuf, time::Duration};

use crate::{
    cli::RunArgs,
    error::AccessConnectorError,
    executor::{AccessConnectorConfig, retry::RetryCfg},
    token::AccessConnectorToken,
};

const MIN_POLL_INTERVAL_SECS: u64 = 15;

/// Exclusive upper bound on the heartbeat interval.
const MAX_HEARTBEAT_INTERVAL_SECS: u64 = 120;

/// The `[environment]` TOML section. Each URL resolves from its env var, then its field here, then
/// `base`; with none of them, startup fails.
#[derive(Debug, Default, serde::Deserialize)]
#[serde(default, deny_unknown_fields)]
struct EnvironmentConfig {
    /// Self-hosted base URL (e.g. `https://bitwarden.example.com`) from which `api` and `identity`
    /// derive. Trailing slashes are stripped.
    base: Option<String>,
    /// Bitwarden API server URL. Overrides a `base`-derived value.
    api: Option<String>,
    /// Bitwarden identity server URL. Overrides a `base`-derived value.
    identity: Option<String>,
}

impl EnvironmentConfig {
    fn derive_api(&self) -> Option<String> {
        self.api.clone().or_else(|| {
            self.base
                .as_deref()
                .map(|b| format!("{}/api", b.trim_end_matches('/')))
        })
    }

    fn derive_identity(&self) -> Option<String> {
        self.identity.clone().or_else(|| {
            self.base
                .as_deref()
                .map(|b| format!("{}/identity", b.trim_end_matches('/')))
        })
    }
}

/// On-disk connector configuration (TOML); every key is optional. A `token` key is rejected as
/// unknown, since the token comes only from `BWAC_TOKEN`.
#[derive(Debug, serde::Deserialize)]
#[serde(default, deny_unknown_fields)]
struct FileConfig {
    environment: EnvironmentConfig,
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
    /// Root directory for custom scripts. No built-in default.
    script_root: Option<PathBuf>,
    /// Custom-script timeout in seconds.
    script_timeout: u64,
    /// Explicit PowerShell host path. `None` discovers `pwsh`, then `powershell.exe`, on `PATH`.
    powershell_path: Option<PathBuf>,
    /// `-ExecutionPolicy` for the PowerShell host. Defaults to `Bypass`, since Windows Server
    /// ships `RemoteSigned`, which refuses an unsigned `.ps1`, and `script_root` already pins
    /// the path. Sites that sign their scripts should set `AllSigned`.
    powershell_execution_policy: String,
    /// Whether the Entra ROPC verify probe is enabled.
    entra_verify_probe: bool,
    /// Per-target credential overrides from the `[targets]` section.
    #[serde(default)]
    targets: HashMap<uuid::Uuid, crate::resolver::config::TargetEntry>,
}

/// Built-in defaults for keys the file omits.
impl Default for FileConfig {
    fn default() -> Self {
        Self {
            environment: EnvironmentConfig::default(),
            poll_interval: 15,
            heartbeat_interval: 30,
            offline_grace: 60,
            max_retry_attempts: 5,
            retry_base_delay: 1,
            script_root: None,
            script_timeout: 60,
            powershell_path: None,
            powershell_execution_policy: "Bypass".to_string(),
            entra_verify_probe: false,
            targets: HashMap::new(),
        }
    }
}

impl FileConfig {
    /// Load a [`FileConfig`] from `path`. A parse error keeps only its last line, since the source
    /// snippet could echo config values.
    fn load(path: &std::path::Path) -> Result<Self, AccessConnectorError> {
        let contents = std::fs::read_to_string(path).map_err(|e| {
            AccessConnectorError::InvalidConfig(format!(
                "cannot read config file {}: {e}",
                path.display()
            ))
        })?;
        toml::from_str(&contents).map_err(|e| {
            let summary = e.to_string();
            let description = summary.lines().last().unwrap_or("parse error");
            AccessConnectorError::InvalidConfig(format!(
                "config file {} is invalid TOML: {description}",
                path.display()
            ))
        })
    }
}

/// Validated configuration for the connector run loop, built by [`Config::from_cli`].
pub struct Config {
    inner: AccessConnectorConfig,
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
    /// Build a validated [`Config`] from the CLI arguments. `BWAC_API_URL` and `BWAC_IDENTITY_URL`
    /// override the file's URLs.
    ///
    /// # Errors
    ///
    /// [`AccessConnectorError::InvalidConfig`] or [`AccessConnectorError::InvalidToken`], never
    /// echoing secrets.
    pub fn from_cli(args: RunArgs) -> Result<Self, AccessConnectorError> {
        // SAFETY: single-threaded startup; no other thread can observe or mutate
        // BWAC_TOKEN. Removed immediately after reading so child processes don't inherit it.
        let env_token = std::env::var("BWAC_TOKEN").ok();
        if env_token.is_some() {
            unsafe {
                std::env::remove_var("BWAC_TOKEN");
            }
        }

        let token_str: String = match env_token.filter(|t| !t.trim().is_empty()) {
            Some(t) => t,
            None => {
                return Err(AccessConnectorError::InvalidConfig(
                    "access connector token must be supplied via the BWAC_TOKEN environment variable".into(),
                ));
            }
        };

        // Token parse errors must not echo the token string.
        let token: AccessConnectorToken = token_str
            .trim()
            .parse()
            .map_err(|e| AccessConnectorError::InvalidToken(format!("{e}")))?;

        // Drop the plaintext token as soon as it is parsed.
        drop(token_str);

        let file = match &args.config {
            Some(path) => FileConfig::load(path)?,
            None => FileConfig::default(),
        };

        let env_url = |name: &str| std::env::var(name).ok().filter(|v| !v.trim().is_empty());

        let api_url = env_url("BWAC_API_URL")
            .or_else(|| file.environment.derive_api())
            .ok_or_else(|| {
                AccessConnectorError::InvalidConfig(
                    "api URL must be supplied via the BWAC_API_URL environment variable, \
                     [environment].api, or [environment].base in the config file"
                        .into(),
                )
            })?;

        let identity_url = env_url("BWAC_IDENTITY_URL")
            .or_else(|| file.environment.derive_identity())
            .ok_or_else(|| {
                AccessConnectorError::InvalidConfig(
                    "identity URL must be supplied via the BWAC_IDENTITY_URL environment \
                     variable, [environment].identity, or [environment].base in the config file"
                        .into(),
                )
            })?;

        if file.poll_interval < MIN_POLL_INTERVAL_SECS {
            return Err(AccessConnectorError::InvalidConfig(format!(
                "poll_interval must be >= {MIN_POLL_INTERVAL_SECS} seconds (got {})",
                file.poll_interval
            )));
        }

        if file.heartbeat_interval >= MAX_HEARTBEAT_INTERVAL_SECS {
            return Err(AccessConnectorError::InvalidConfig(format!(
                "heartbeat_interval must be < {MAX_HEARTBEAT_INTERVAL_SECS} seconds (got {})",
                file.heartbeat_interval
            )));
        }

        Ok(Config {
            inner: AccessConnectorConfig {
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
                powershell_path: file.powershell_path,
                powershell_execution_policy: file.powershell_execution_policy,
                entra_verify_probe: file.entra_verify_probe,
                targets: file.targets,
            },
        })
    }

    /// Consume the [`Config`] and return the inner [`AccessConnectorConfig`].
    pub fn into_access_connector_config(self) -> AccessConnectorConfig {
        self.inner
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const VALID_TOKEN: &str = "0.access-connector.ec2c1d46-6a4b-4751-a310-af9601317f2d.C2IgxjjLF7qSshsbwe8JGcbM075YXw:X8vbvA0bduihIDe/qrzIQQ==";

    use crate::TEST_ENV_LOCK as ENV_LOCK;

    fn empty_args() -> RunArgs {
        RunArgs { config: None }
    }

    fn file_args(f: &tempfile::NamedTempFile) -> RunArgs {
        RunArgs {
            config: Some(f.path().to_path_buf()),
        }
    }

    /// Keep the returned file alive; dropping it deletes the file.
    fn write_toml(contents: &str) -> tempfile::NamedTempFile {
        use std::io::Write as _;
        let mut f = tempfile::NamedTempFile::new().expect("tempfile");
        f.write_all(contents.as_bytes()).expect("write toml");
        f
    }

    #[test]
    fn env_token_path_succeeds() {
        let _guard = ENV_LOCK.lock().unwrap();
        // SAFETY: protected by ENV_LOCK; no other thread mutates the environment concurrently.
        unsafe {
            std::env::set_var("BWAC_TOKEN", VALID_TOKEN);
            std::env::set_var("BWAC_API_URL", "https://api.example.com");
            std::env::set_var("BWAC_IDENTITY_URL", "https://identity.example.com");
        }
        let result = Config::from_cli(empty_args());
        // SAFETY: same guard.
        unsafe {
            std::env::remove_var("BWAC_TOKEN");
            std::env::remove_var("BWAC_API_URL");
            std::env::remove_var("BWAC_IDENTITY_URL");
        }
        assert!(result.is_ok(), "expected Ok, got {result:?}");
    }

    #[test]
    fn missing_bwac_token_is_invalid_config() {
        let _guard = ENV_LOCK.lock().unwrap();
        // SAFETY: protected by ENV_LOCK.
        unsafe {
            std::env::remove_var("BWAC_TOKEN");
        }
        let result = Config::from_cli(empty_args());
        assert!(
            matches!(result, Err(AccessConnectorError::InvalidConfig(_))),
            "expected InvalidConfig, got {result:?}"
        );
    }

    #[test]
    fn empty_bwac_token_is_invalid_config() {
        let _guard = ENV_LOCK.lock().unwrap();
        // SAFETY: protected by ENV_LOCK.
        unsafe {
            std::env::set_var("BWAC_TOKEN", "  ");
        }
        let result = Config::from_cli(empty_args());
        // SAFETY: same guard.
        unsafe {
            std::env::remove_var("BWAC_TOKEN");
        }
        assert!(
            matches!(result, Err(AccessConnectorError::InvalidConfig(_))),
            "expected InvalidConfig for whitespace-only BWAC_TOKEN, got {result:?}"
        );
    }

    #[test]
    fn malformed_token_is_invalid_token_and_does_not_echo_value() {
        let _guard = ENV_LOCK.lock().unwrap();
        let bad_token = "not-a-valid-token-string";
        // SAFETY: protected by ENV_LOCK.
        unsafe {
            std::env::set_var("BWAC_TOKEN", bad_token);
        }
        let result = Config::from_cli(empty_args());
        // SAFETY: same guard.
        unsafe {
            std::env::remove_var("BWAC_TOKEN");
        }

        match result {
            Err(AccessConnectorError::InvalidToken(msg)) => {
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
            std::env::set_var("BWAC_TOKEN", VALID_TOKEN);
            std::env::set_var("BWAC_API_URL", "https://api.example.com");
            std::env::set_var("BWAC_IDENTITY_URL", "https://identity.example.com");
        }
        assert!(
            std::env::var("BWAC_TOKEN").is_ok(),
            "BWAC_TOKEN must be present before from_cli"
        );
        let result = Config::from_cli(empty_args());
        // SAFETY: same guard.
        unsafe {
            std::env::remove_var("BWAC_API_URL");
            std::env::remove_var("BWAC_IDENTITY_URL");
        }
        assert!(result.is_ok(), "expected Ok, got {result:?}");
        assert!(
            std::env::var("BWAC_TOKEN").is_err(),
            "BWAC_TOKEN must be absent from environment after from_cli consumes it"
        );
    }

    #[test]
    fn poll_interval_below_minimum_is_invalid_config() {
        let _guard = ENV_LOCK.lock().unwrap();
        // SAFETY: protected by ENV_LOCK; no other thread mutates the environment concurrently.
        unsafe {
            std::env::set_var("BWAC_TOKEN", VALID_TOKEN);
            // Leaked URL env vars would override the config file under test.
            std::env::remove_var("BWAC_API_URL");
            std::env::remove_var("BWAC_IDENTITY_URL");
        }

        let toml = r#"
poll_interval = 14

[environment]
api      = "https://api.example.com"
identity = "https://identity.example.com"
"#;
        let f = write_toml(toml);
        let result = Config::from_cli(file_args(&f));
        // SAFETY: same guard.
        unsafe {
            std::env::remove_var("BWAC_TOKEN");
        }

        assert!(
            matches!(result, Err(AccessConnectorError::InvalidConfig(_))),
            "expected InvalidConfig for poll_interval < 15, got {result:?}"
        );
    }

    #[test]
    fn poll_interval_at_minimum_is_valid() {
        let _guard = ENV_LOCK.lock().unwrap();
        // SAFETY: protected by ENV_LOCK; no other thread mutates the environment concurrently.
        unsafe {
            std::env::set_var("BWAC_TOKEN", VALID_TOKEN);
            // Leaked URL env vars would override the config file under test.
            std::env::remove_var("BWAC_API_URL");
            std::env::remove_var("BWAC_IDENTITY_URL");
        }

        let toml = r#"
poll_interval = 15

[environment]
api      = "https://api.example.com"
identity = "https://identity.example.com"
"#;
        let f = write_toml(toml);
        let result = Config::from_cli(file_args(&f));
        // SAFETY: same guard.
        unsafe {
            std::env::remove_var("BWAC_TOKEN");
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
            std::env::set_var("BWAC_TOKEN", VALID_TOKEN);
            // Leaked URL env vars would override the config file under test.
            std::env::remove_var("BWAC_API_URL");
            std::env::remove_var("BWAC_IDENTITY_URL");
        }

        // The bound is exclusive.
        let toml = r#"
heartbeat_interval = 120

[environment]
api      = "https://api.example.com"
identity = "https://identity.example.com"
"#;
        let f = write_toml(toml);
        let result = Config::from_cli(file_args(&f));
        // SAFETY: same guard.
        unsafe {
            std::env::remove_var("BWAC_TOKEN");
        }

        assert!(
            matches!(result, Err(AccessConnectorError::InvalidConfig(_))),
            "expected InvalidConfig for heartbeat_interval >= 120, got {result:?}"
        );
    }

    #[test]
    fn heartbeat_interval_at_119_is_valid() {
        let _guard = ENV_LOCK.lock().unwrap();
        // SAFETY: protected by ENV_LOCK; no other thread mutates the environment concurrently.
        unsafe {
            std::env::set_var("BWAC_TOKEN", VALID_TOKEN);
            // Leaked URL env vars would override the config file under test.
            std::env::remove_var("BWAC_API_URL");
            std::env::remove_var("BWAC_IDENTITY_URL");
        }

        let toml = r#"
heartbeat_interval = 119

[environment]
api      = "https://api.example.com"
identity = "https://identity.example.com"
"#;
        let f = write_toml(toml);
        let result = Config::from_cli(file_args(&f));
        // SAFETY: same guard.
        unsafe {
            std::env::remove_var("BWAC_TOKEN");
        }
        assert!(
            result.is_ok(),
            "heartbeat_interval=119 should be valid: {result:?}"
        );
    }

    #[test]
    fn env_urls_without_file_are_used() {
        let _guard = ENV_LOCK.lock().unwrap();
        // SAFETY: protected by ENV_LOCK; no other thread mutates the environment concurrently.
        unsafe {
            std::env::set_var("BWAC_TOKEN", VALID_TOKEN);
            std::env::set_var("BWAC_API_URL", "https://api.env.example.com");
            std::env::set_var("BWAC_IDENTITY_URL", "https://identity.env.example.com");
        }
        let result = Config::from_cli(empty_args());
        // SAFETY: same guard.
        unsafe {
            std::env::remove_var("BWAC_TOKEN");
            std::env::remove_var("BWAC_API_URL");
            std::env::remove_var("BWAC_IDENTITY_URL");
        }

        let inner = result.expect("expected Ok").into_access_connector_config();
        assert_eq!(inner.api_url, "https://api.env.example.com");
        assert_eq!(inner.identity_url, "https://identity.env.example.com");
    }

    #[test]
    fn env_urls_override_file() {
        let _guard = ENV_LOCK.lock().unwrap();
        // SAFETY: protected by ENV_LOCK; no other thread mutates the environment concurrently.
        unsafe {
            std::env::set_var("BWAC_TOKEN", VALID_TOKEN);
            std::env::set_var("BWAC_API_URL", "https://api.env.example.com");
            std::env::set_var("BWAC_IDENTITY_URL", "https://identity.env.example.com");
        }

        let toml = r#"
[environment]
api      = "https://api.file.example.com"
identity = "https://identity.file.example.com"
"#;
        let f = write_toml(toml);

        let result = Config::from_cli(file_args(&f));
        // SAFETY: same guard.
        unsafe {
            std::env::remove_var("BWAC_TOKEN");
            std::env::remove_var("BWAC_API_URL");
            std::env::remove_var("BWAC_IDENTITY_URL");
        }

        let inner = result.expect("expected Ok").into_access_connector_config();
        assert_eq!(inner.api_url, "https://api.env.example.com");
        assert_eq!(inner.identity_url, "https://identity.env.example.com");
    }

    #[test]
    fn whitespace_env_url_is_treated_as_unset() {
        let _guard = ENV_LOCK.lock().unwrap();
        // SAFETY: protected by ENV_LOCK; no other thread mutates the environment concurrently.
        unsafe {
            std::env::set_var("BWAC_TOKEN", VALID_TOKEN);
            std::env::set_var("BWAC_API_URL", "  ");
            // A leaked BWAC_IDENTITY_URL would override the file value under test.
            std::env::remove_var("BWAC_IDENTITY_URL");
        }

        let toml = r#"
[environment]
api      = "https://api.file.example.com"
identity = "https://identity.file.example.com"
"#;
        let f = write_toml(toml);

        let result = Config::from_cli(file_args(&f));
        // SAFETY: same guard.
        unsafe {
            std::env::remove_var("BWAC_TOKEN");
            std::env::remove_var("BWAC_API_URL");
        }

        let inner = result.expect("expected Ok").into_access_connector_config();
        assert_eq!(inner.api_url, "https://api.file.example.com");
        assert_eq!(inner.identity_url, "https://identity.file.example.com");
    }

    #[test]
    fn missing_api_url_from_all_layers_is_invalid_config() {
        let _guard = ENV_LOCK.lock().unwrap();
        // SAFETY: protected by ENV_LOCK; no other thread mutates the environment concurrently.
        unsafe {
            std::env::set_var("BWAC_TOKEN", VALID_TOKEN);
            // A leaked URL env var would satisfy the requirement under test.
            std::env::remove_var("BWAC_API_URL");
            std::env::remove_var("BWAC_IDENTITY_URL");
        }

        let toml = r#"
[environment]
identity = "https://identity.example.com"
"#;
        let f = write_toml(toml);

        let result = Config::from_cli(file_args(&f));
        // SAFETY: same guard.
        unsafe {
            std::env::remove_var("BWAC_TOKEN");
        }

        match result {
            Err(AccessConnectorError::InvalidConfig(msg)) => {
                assert!(
                    msg.contains("api URL"),
                    "error should mention the missing 'api URL'; got: {msg}"
                );
            }
            other => panic!("expected InvalidConfig for missing api URL, got {other:?}"),
        }
    }

    #[test]
    fn missing_identity_url_from_all_layers_is_invalid_config() {
        let _guard = ENV_LOCK.lock().unwrap();
        // SAFETY: protected by ENV_LOCK; no other thread mutates the environment concurrently.
        unsafe {
            std::env::set_var("BWAC_TOKEN", VALID_TOKEN);
            // A leaked URL env var would satisfy the requirement under test.
            std::env::remove_var("BWAC_API_URL");
            std::env::remove_var("BWAC_IDENTITY_URL");
        }

        let toml = r#"
[environment]
api = "https://api.example.com"
"#;
        let f = write_toml(toml);

        let result = Config::from_cli(file_args(&f));
        // SAFETY: same guard.
        unsafe {
            std::env::remove_var("BWAC_TOKEN");
        }

        match result {
            Err(AccessConnectorError::InvalidConfig(msg)) => {
                assert!(
                    msg.contains("identity URL"),
                    "error should mention the missing 'identity URL'; got: {msg}"
                );
            }
            other => panic!("expected InvalidConfig for missing identity URL, got {other:?}"),
        }
    }

    #[test]
    fn file_only_values_are_used() {
        let _guard = ENV_LOCK.lock().unwrap();
        // SAFETY: protected by ENV_LOCK; no other thread mutates the environment concurrently.
        unsafe {
            std::env::set_var("BWAC_TOKEN", VALID_TOKEN);
            // Leaked URL env vars would override the config file under test.
            std::env::remove_var("BWAC_API_URL");
            std::env::remove_var("BWAC_IDENTITY_URL");
        }

        let toml = r#"
poll_interval      = 30
heartbeat_interval = 45
offline_grace      = 90
max_retry_attempts = 3
retry_base_delay   = 2
script_timeout     = 120
entra_verify_probe = true

[environment]
api      = "https://api.file.example.com"
identity = "https://identity.file.example.com"
"#;
        let f = write_toml(toml);

        let result = Config::from_cli(file_args(&f));
        // SAFETY: same guard.
        unsafe {
            std::env::remove_var("BWAC_TOKEN");
        }

        let cfg = result.expect("expected Ok from file-only config");
        let inner = cfg.into_access_connector_config();
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
            std::env::set_var("BWAC_TOKEN", VALID_TOKEN);
            // Leaked URL env vars would override the config file under test.
            std::env::remove_var("BWAC_API_URL");
            std::env::remove_var("BWAC_IDENTITY_URL");
        }

        let toml = r#"
[environment]
api      = "https://api.example.com"
identity = "https://identity.example.com"
"#;
        let f = write_toml(toml);

        let result = Config::from_cli(file_args(&f));
        // SAFETY: same guard.
        unsafe {
            std::env::remove_var("BWAC_TOKEN");
        }

        let cfg = result.expect("expected Ok with defaults");
        let inner = cfg.into_access_connector_config();
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
        // SAFETY: protected by ENV_LOCK; no other thread mutates BWAC_TOKEN concurrently.
        unsafe {
            std::env::set_var("BWAC_TOKEN", VALID_TOKEN);
        }

        let token_value = "0.x.y:z";
        let toml = format!(
            r#"
token = "{token_value}"

[environment]
api      = "https://api.example.com"
identity = "https://identity.example.com"
"#
        );
        let f = write_toml(&toml);

        let result = Config::from_cli(file_args(&f));
        // SAFETY: same guard.
        unsafe {
            std::env::remove_var("BWAC_TOKEN");
        }

        match result {
            Err(AccessConnectorError::InvalidConfig(msg)) => {
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
        // SAFETY: protected by ENV_LOCK; no other thread mutates BWAC_TOKEN concurrently.
        unsafe {
            std::env::set_var("BWAC_TOKEN", VALID_TOKEN);
        }

        let args = RunArgs {
            config: Some(PathBuf::from("/nonexistent/path/to/config.toml")),
        };

        let result = Config::from_cli(args);
        // SAFETY: same guard.
        unsafe {
            std::env::remove_var("BWAC_TOKEN");
        }

        assert!(
            matches!(result, Err(AccessConnectorError::InvalidConfig(_))),
            "expected InvalidConfig for nonexistent config path, got {result:?}"
        );
    }

    #[test]
    fn file_entra_verify_probe_true_is_used() {
        let _guard = ENV_LOCK.lock().unwrap();
        // SAFETY: protected by ENV_LOCK; no other thread mutates the environment concurrently.
        unsafe {
            std::env::set_var("BWAC_TOKEN", VALID_TOKEN);
            // Leaked URL env vars would override the config file under test.
            std::env::remove_var("BWAC_API_URL");
            std::env::remove_var("BWAC_IDENTITY_URL");
        }

        let toml = r#"
entra_verify_probe = true

[environment]
api      = "https://api.example.com"
identity = "https://identity.example.com"
"#;
        let f = write_toml(toml);

        let result = Config::from_cli(file_args(&f));
        // SAFETY: same guard.
        unsafe {
            std::env::remove_var("BWAC_TOKEN");
        }

        let cfg = result.expect("expected Ok");
        let inner = cfg.into_access_connector_config();
        assert!(
            inner.entra_verify_probe,
            "entra_verify_probe from file should be true"
        );
    }

    #[test]
    fn base_only_derives_api_and_identity() {
        let _guard = ENV_LOCK.lock().unwrap();
        // SAFETY: protected by ENV_LOCK; no other thread mutates the environment concurrently.
        unsafe {
            std::env::set_var("BWAC_TOKEN", VALID_TOKEN);
            // Leaked URL env vars would override the config file under test.
            std::env::remove_var("BWAC_API_URL");
            std::env::remove_var("BWAC_IDENTITY_URL");
        }

        let toml = r#"
[environment]
base = "https://bitwarden.example.com"
"#;
        let f = write_toml(toml);

        let result = Config::from_cli(file_args(&f));
        // SAFETY: same guard.
        unsafe {
            std::env::remove_var("BWAC_TOKEN");
        }

        let inner = result
            .expect("base-only config should succeed")
            .into_access_connector_config();
        assert_eq!(inner.api_url, "https://bitwarden.example.com/api");
        assert_eq!(inner.identity_url, "https://bitwarden.example.com/identity");
    }

    #[test]
    fn base_with_trailing_slash_derives_clean_urls() {
        let _guard = ENV_LOCK.lock().unwrap();
        // SAFETY: protected by ENV_LOCK; no other thread mutates the environment concurrently.
        unsafe {
            std::env::set_var("BWAC_TOKEN", VALID_TOKEN);
            std::env::remove_var("BWAC_API_URL");
            std::env::remove_var("BWAC_IDENTITY_URL");
        }

        let toml = r#"
[environment]
base = "https://bitwarden.example.com/"
"#;
        let f = write_toml(toml);

        let result = Config::from_cli(file_args(&f));
        // SAFETY: same guard.
        unsafe {
            std::env::remove_var("BWAC_TOKEN");
        }

        let inner = result
            .expect("trailing-slash base should succeed")
            .into_access_connector_config();
        assert_eq!(inner.api_url, "https://bitwarden.example.com/api");
        assert_eq!(inner.identity_url, "https://bitwarden.example.com/identity");
    }

    #[test]
    fn explicit_api_overrides_base_while_identity_derives() {
        let _guard = ENV_LOCK.lock().unwrap();
        // SAFETY: protected by ENV_LOCK; no other thread mutates the environment concurrently.
        unsafe {
            std::env::set_var("BWAC_TOKEN", VALID_TOKEN);
            std::env::remove_var("BWAC_API_URL");
            std::env::remove_var("BWAC_IDENTITY_URL");
        }

        let toml = r#"
[environment]
base = "https://bitwarden.example.com"
api  = "https://custom-api.example.com/v2"
"#;
        let f = write_toml(toml);

        let result = Config::from_cli(file_args(&f));
        // SAFETY: same guard.
        unsafe {
            std::env::remove_var("BWAC_TOKEN");
        }

        let inner = result
            .expect("mixed explicit+base config should succeed")
            .into_access_connector_config();
        assert_eq!(inner.api_url, "https://custom-api.example.com/v2");
        assert_eq!(inner.identity_url, "https://bitwarden.example.com/identity");
    }

    #[test]
    fn env_vars_override_explicit_environment_section() {
        let _guard = ENV_LOCK.lock().unwrap();
        // SAFETY: protected by ENV_LOCK; no other thread mutates the environment concurrently.
        unsafe {
            std::env::set_var("BWAC_TOKEN", VALID_TOKEN);
            std::env::set_var("BWAC_API_URL", "https://override.env.example.com/api");
            std::env::set_var(
                "BWAC_IDENTITY_URL",
                "https://override.env.example.com/identity",
            );
        }

        let toml = r#"
[environment]
base     = "https://bitwarden.example.com"
api      = "https://api.file.example.com"
identity = "https://identity.file.example.com"
"#;
        let f = write_toml(toml);

        let result = Config::from_cli(file_args(&f));
        // SAFETY: same guard.
        unsafe {
            std::env::remove_var("BWAC_TOKEN");
            std::env::remove_var("BWAC_API_URL");
            std::env::remove_var("BWAC_IDENTITY_URL");
        }

        let inner = result
            .expect("env override should succeed")
            .into_access_connector_config();
        assert_eq!(inner.api_url, "https://override.env.example.com/api");
        assert_eq!(
            inner.identity_url,
            "https://override.env.example.com/identity"
        );
    }

    #[test]
    fn old_top_level_api_url_key_is_rejected() {
        let _guard = ENV_LOCK.lock().unwrap();
        // SAFETY: protected by ENV_LOCK; no other thread mutates the environment concurrently.
        unsafe {
            std::env::set_var("BWAC_TOKEN", VALID_TOKEN);
            std::env::remove_var("BWAC_API_URL");
            std::env::remove_var("BWAC_IDENTITY_URL");
        }

        let toml = r#"
api_url      = "https://api.example.com"
identity_url = "https://identity.example.com"
"#;
        let f = write_toml(toml);

        let result = Config::from_cli(file_args(&f));
        // SAFETY: same guard.
        unsafe {
            std::env::remove_var("BWAC_TOKEN");
        }

        assert!(
            matches!(result, Err(AccessConnectorError::InvalidConfig(_))),
            "top-level api_url/identity_url must be rejected as unknown fields, got {result:?}"
        );
    }

    #[test]
    fn no_environment_section_and_no_env_vars_is_invalid_config() {
        let _guard = ENV_LOCK.lock().unwrap();
        // SAFETY: protected by ENV_LOCK; no other thread mutates the environment concurrently.
        unsafe {
            std::env::set_var("BWAC_TOKEN", VALID_TOKEN);
            std::env::remove_var("BWAC_API_URL");
            std::env::remove_var("BWAC_IDENTITY_URL");
        }

        let toml = r#"
poll_interval = 15
"#;
        let f = write_toml(toml);

        let result = Config::from_cli(file_args(&f));
        // SAFETY: same guard.
        unsafe {
            std::env::remove_var("BWAC_TOKEN");
        }

        match result {
            Err(AccessConnectorError::InvalidConfig(msg)) => {
                assert!(
                    msg.contains("BWAC_API_URL") && msg.contains("[environment]"),
                    "error should name how to supply the api URL; got: {msg}"
                );
            }
            other => panic!(
                "expected InvalidConfig for no environment section and no env vars, got {other:?}"
            ),
        }
    }

    #[test]
    fn targets_script_entry_parsed() {
        let _guard = ENV_LOCK.lock().unwrap();
        unsafe {
            std::env::set_var("BWAC_TOKEN", VALID_TOKEN);
            std::env::remove_var("BWAC_API_URL");
            std::env::remove_var("BWAC_IDENTITY_URL");
        }
        let toml = r#"
[environment]
api      = "https://api.example.com"
identity = "https://identity.example.com"

[targets.85808642-baba-4b8e-8c34-b48000d60a0a]
script = "/opt/scripts/rotate.sh"
"#;
        let f = write_toml(toml);
        let result = Config::from_cli(file_args(&f));
        unsafe {
            std::env::remove_var("BWAC_TOKEN");
        }
        let cfg = result
            .expect("targets section should parse")
            .into_access_connector_config();
        let uuid: uuid::Uuid = "85808642-baba-4b8e-8c34-b48000d60a0a".parse().unwrap();
        assert!(cfg.targets.contains_key(&uuid));
        assert_eq!(
            cfg.targets[&uuid].script.as_deref(),
            Some("/opt/scripts/rotate.sh")
        );
    }

    #[test]
    fn targets_entra_entry_parsed() {
        let _guard = ENV_LOCK.lock().unwrap();
        unsafe {
            std::env::set_var("BWAC_TOKEN", VALID_TOKEN);
            std::env::remove_var("BWAC_API_URL");
            std::env::remove_var("BWAC_IDENTITY_URL");
        }
        let toml = r#"
[environment]
api      = "https://api.example.com"
identity = "https://identity.example.com"

[targets.00000000-0000-0000-0000-000000000001]
tenant_id = "my-tenant"
client_id = "my-client"
"#;
        let f = write_toml(toml);
        let result = Config::from_cli(file_args(&f));
        unsafe {
            std::env::remove_var("BWAC_TOKEN");
        }
        let cfg = result
            .expect("entra target entry should parse")
            .into_access_connector_config();
        let uuid: uuid::Uuid = "00000000-0000-0000-0000-000000000001".parse().unwrap();
        assert_eq!(cfg.targets[&uuid].tenant_id.as_deref(), Some("my-tenant"));
        assert_eq!(cfg.targets[&uuid].client_id.as_deref(), Some("my-client"));
    }

    #[test]
    fn targets_client_secret_in_file_is_rejected_and_does_not_echo_value() {
        let _guard = ENV_LOCK.lock().unwrap();
        unsafe {
            std::env::set_var("BWAC_TOKEN", VALID_TOKEN);
            std::env::remove_var("BWAC_API_URL");
            std::env::remove_var("BWAC_IDENTITY_URL");
        }
        let secret_value = "supersecret";
        let toml = format!(
            r#"
[environment]
api      = "https://api.example.com"
identity = "https://identity.example.com"

[targets.00000000-0000-0000-0000-000000000001]
client_secret = "{secret_value}"
"#
        );
        let f = write_toml(&toml);
        let result = Config::from_cli(file_args(&f));
        unsafe {
            std::env::remove_var("BWAC_TOKEN");
        }
        match result {
            Err(AccessConnectorError::InvalidConfig(msg)) => {
                assert!(
                    !msg.contains(secret_value),
                    "error must not echo secret value; got: {msg}"
                );
            }
            other => {
                panic!("expected InvalidConfig for client_secret in targets entry, got {other:?}")
            }
        }
    }

    #[test]
    fn targets_invalid_uuid_key_is_rejected() {
        let _guard = ENV_LOCK.lock().unwrap();
        unsafe {
            std::env::set_var("BWAC_TOKEN", VALID_TOKEN);
            std::env::remove_var("BWAC_API_URL");
            std::env::remove_var("BWAC_IDENTITY_URL");
        }
        let toml = r#"
[environment]
api      = "https://api.example.com"
identity = "https://identity.example.com"

[targets.not-a-uuid]
script = "/some/script.sh"
"#;
        let f = write_toml(toml);
        let result = Config::from_cli(file_args(&f));
        unsafe {
            std::env::remove_var("BWAC_TOKEN");
        }
        assert!(
            matches!(result, Err(AccessConnectorError::InvalidConfig(_))),
            "non-UUID key in [targets] must be rejected, got {result:?}"
        );
    }

    #[test]
    fn targets_absent_defaults_to_empty_map() {
        let _guard = ENV_LOCK.lock().unwrap();
        unsafe {
            std::env::set_var("BWAC_TOKEN", VALID_TOKEN);
            std::env::remove_var("BWAC_API_URL");
            std::env::remove_var("BWAC_IDENTITY_URL");
        }
        let toml = r#"
[environment]
api      = "https://api.example.com"
identity = "https://identity.example.com"
"#;
        let f = write_toml(toml);
        let result = Config::from_cli(file_args(&f));
        unsafe {
            std::env::remove_var("BWAC_TOKEN");
        }
        let cfg = result
            .expect("no targets section should be fine")
            .into_access_connector_config();
        assert!(
            cfg.targets.is_empty(),
            "absent [targets] section must default to empty map"
        );
    }
}
