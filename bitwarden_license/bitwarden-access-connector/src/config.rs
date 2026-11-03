//! Configuration loading and validation for the access connector.
//!
//! Unknown TOML keys are a startup error. `[targets]` entries override per-target environment
//! variables, except `client_secret`, which only the environment can supply.

use std::{
    collections::HashMap,
    path::{Path, PathBuf},
    time::Duration,
};

use bitwarden_access_token::{AccessToken, AccessTokenKind};
use uuid::Uuid;

use crate::{
    cli::RunArgs,
    error::AccessConnectorError,
    executor::{AccessConnectorConfig, retry::RetryCfg},
    resolver::config::TargetEntry,
};

const MIN_POLL_INTERVAL_SECS: u64 = 15;

/// Exclusive upper bound on the heartbeat interval.
const MAX_HEARTBEAT_INTERVAL_SECS: u64 = 120;

/// The `[environment]` TOML section. Each URL resolves from its env var, then its field here, then
/// `base`. With no `base`, an unset URL fails startup unless neither URL is set, which defaults to
/// US cloud.
#[derive(Debug, Default, serde::Deserialize)]
#[serde(default, deny_unknown_fields)]
struct EnvironmentConfig {
    /// Base URL from which `api` and `identity` derive: a self-hosted URL (e.g.
    /// `https://bitwarden.example.com`, trailing slashes stripped) or a Bitwarden cloud host
    /// (`bitwarden.com`, `vault.bitwarden.eu`, ...), which maps to that cloud's URLs.
    base: Option<String>,
    /// Bitwarden API server URL. Overrides a `base`-derived value.
    api: Option<String>,
    /// Bitwarden identity server URL. Overrides a `base`-derived value.
    identity: Option<String>,
}

/// Where the Bitwarden server is.
enum Environment {
    Us,
    Eu,
    SelfHosted { api: String, identity: String },
}

impl Environment {
    /// A cloud host picks its region; anything else is self-hosted, with `/api` and `/identity`
    /// under `base`. Hosts match exactly, never by suffix: a suffix match would let
    /// `bitwarden.com.evil.example` route the connector's credentials to an attacker's server.
    fn from_base(base: &str) -> Self {
        let url = url::Url::parse(base).ok();
        match url.as_ref().and_then(url::Url::host_str) {
            Some("bitwarden.com" | "vault.bitwarden.com") => Self::Us,
            Some("bitwarden.eu" | "vault.bitwarden.eu") => Self::Eu,
            _ => {
                let base = base.trim_end_matches('/');
                Self::SelfHosted {
                    api: format!("{base}/api"),
                    identity: format!("{base}/identity"),
                }
            }
        }
    }

    fn api_url(&self) -> &str {
        match self {
            Self::Us => "https://api.bitwarden.com",
            Self::Eu => "https://api.bitwarden.eu",
            Self::SelfHosted { api, .. } => api,
        }
    }

    fn identity_url(&self) -> &str {
        match self {
            Self::Us => "https://identity.bitwarden.com",
            Self::Eu => "https://identity.bitwarden.eu",
            Self::SelfHosted { identity, .. } => identity,
        }
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
    /// PowerShell host path. `None` discovers `pwsh`, then `powershell.exe`, on `PATH`.
    powershell_path: Option<PathBuf>,
    /// `-ExecutionPolicy` for the PowerShell host. Defaults to `Bypass` because Windows Server's
    /// `RemoteSigned` refuses unsigned `.ps1` and `script_root` already pins the path; sites that
    /// sign scripts should set `AllSigned`.
    powershell_execution_policy: String,
    /// Whether the Entra ROPC verify probe is enabled.
    entra_verify_probe: bool,
    /// Per-target credential overrides from the `[targets]` section.
    targets: HashMap<Uuid, TargetEntry>,
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
    /// Read and parse the file at `path`.
    fn load(path: &Path) -> Result<Self, AccessConnectorError> {
        let contents = std::fs::read_to_string(path).map_err(|e| {
            AccessConnectorError::InvalidConfig(format!(
                "cannot read config file {}: {e}",
                path.display()
            ))
        })?;
        Self::parse(&contents, path)
    }

    /// Parse TOML `contents`; `path` is for error messages only. A parse error keeps only its last
    /// line, since the source snippet could echo config values.
    fn parse(contents: &str, path: &Path) -> Result<Self, AccessConnectorError> {
        toml::from_str(contents).map_err(|e| {
            let summary = e.to_string();
            let description = summary.lines().last().unwrap_or("parse error");
            AccessConnectorError::InvalidConfig(format!(
                "config file {} is invalid TOML: {description}",
                path.display()
            ))
        })
    }
}

/// Treat a blank value as unset.
fn non_blank(v: Option<String>) -> Option<String> {
    v.filter(|v| !v.trim().is_empty())
}

/// Parse the raw `BWAC_TOKEN` value. Errors never echo the token.
fn parse_token(raw: Option<String>) -> Result<AccessToken, AccessConnectorError> {
    let raw = non_blank(raw).ok_or_else(|| {
        AccessConnectorError::InvalidConfig(
            "access connector token must be supplied via the BWAC_TOKEN environment variable"
                .into(),
        )
    })?;
    AccessToken::parse(raw.trim(), AccessTokenKind::AccessConnector)
        .map_err(|e| AccessConnectorError::InvalidToken(format!("{e}")))
}

/// Error for a service URL that no layer supplied.
fn missing_url(name: &str) -> AccessConnectorError {
    AccessConnectorError::InvalidConfig(format!(
        "{name} URL must be supplied via the BWAC_{}_URL environment variable, \
         [environment].{name}, or [environment].base in the config file",
        name.to_uppercase()
    ))
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
        // SAFETY: single-threaded startup. Removed right after reading so child processes don't
        // inherit it.
        let env_token = std::env::var("BWAC_TOKEN").ok();
        if env_token.is_some() {
            unsafe {
                std::env::remove_var("BWAC_TOKEN");
            }
        }

        let token = parse_token(env_token)?;

        let file = match &args.config {
            Some(path) => FileConfig::load(path)?,
            None => FileConfig::default(),
        };

        let env_url = |name: &str| non_blank(std::env::var(name).ok());
        Self::build(
            token,
            file,
            env_url("BWAC_API_URL"),
            env_url("BWAC_IDENTITY_URL"),
        )
    }

    /// Resolve URLs (env, then `[environment]`, then `base`) and validate `file` into a
    /// [`Config`]. With no URL source at all, both URLs default to US cloud.
    fn build(
        token: AccessToken,
        file: FileConfig,
        env_api: Option<String>,
        env_identity: Option<String>,
    ) -> Result<Self, AccessConnectorError> {
        let api = env_api.or(file.environment.api.clone());
        let identity = env_identity.or(file.environment.identity.clone());
        // Without a base, a lone api or identity URL must not pair with US cloud for the other.
        if file.environment.base.is_none() {
            match (&api, &identity) {
                (Some(_), None) => return Err(missing_url("identity")),
                (None, Some(_)) => return Err(missing_url("api")),
                _ => {}
            }
        }
        let server = file
            .environment
            .base
            .as_deref()
            .map(Environment::from_base)
            .unwrap_or(Environment::Us);
        let api_url = api.unwrap_or_else(|| server.api_url().to_owned());
        let identity_url = identity.unwrap_or_else(|| server.identity_url().to_owned());

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

        // A zero heartbeat panics `tokio::time::interval`, a zero grace holds every rotation, and a
        // zero timeout kills every script.
        for (name, value) in [
            ("heartbeat_interval", file.heartbeat_interval),
            ("offline_grace", file.offline_grace),
            ("script_timeout", file.script_timeout),
        ] {
            if value == 0 {
                return Err(AccessConnectorError::InvalidConfig(format!(
                    "{name} must be > 0 seconds"
                )));
            }
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
    use crate::TEST_ENV_LOCK as ENV_LOCK;

    const VALID_TOKEN: &str = "0.access-connector.ec2c1d46-6a4b-4751-a310-af9601317f2d.C2IgxjjLF7qSshsbwe8JGcbM075YXw:X8vbvA0bduihIDe/qrzIQQ==";

    /// The common `[environment]` block.
    const URLS: &str = r#"
[environment]
api      = "https://api.example.com"
identity = "https://identity.example.com"
"#;

    fn token() -> AccessToken {
        parse_token(Some(VALID_TOKEN.into())).expect("valid token")
    }

    fn file(toml: &str) -> FileConfig {
        FileConfig::parse(toml, Path::new("test.toml")).expect("valid config file")
    }

    fn parse_err(toml: &str) -> AccessConnectorError {
        match FileConfig::parse(toml, Path::new("test.toml")) {
            Err(e) => e,
            Ok(_) => panic!("expected parse error for {toml:?}"),
        }
    }

    fn build(toml: &str) -> Result<Config, AccessConnectorError> {
        Config::build(token(), file(toml), None, None)
    }

    fn invalid_config_message(e: AccessConnectorError) -> String {
        match e {
            AccessConnectorError::InvalidConfig(msg) => msg,
            other => panic!("expected InvalidConfig, got {other:?}"),
        }
    }

    #[test]
    fn interval_bounds() {
        let rows = [
            ("poll 14", "poll_interval = 14", false),
            ("poll 15", "poll_interval = 15", true),
            ("heartbeat 119", "heartbeat_interval = 119", true),
            ("heartbeat 120", "heartbeat_interval = 120", false),
            ("heartbeat 0", "heartbeat_interval = 0", false),
            ("offline_grace 0", "offline_grace = 0", false),
            ("script_timeout 0", "script_timeout = 0", false),
        ];
        for (label, line, ok) in rows {
            let result = build(&format!("{line}\n{URLS}"));
            if ok {
                assert!(result.is_ok(), "{label}: expected Ok, got {result:?}");
            } else {
                assert!(
                    matches!(result, Err(AccessConnectorError::InvalidConfig(_))),
                    "{label}: expected InvalidConfig, got {result:?}"
                );
            }
        }
    }

    #[test]
    fn url_resolution() {
        const BASE: &str = "[environment]\nbase = \"https://bitwarden.example.com\"\n";
        const ENV_API: &str = "https://api.env.example.com";
        const ENV_ID: &str = "https://identity.env.example.com";
        const DERIVED_API: &str = "https://bitwarden.example.com/api";
        const DERIVED_ID: &str = "https://bitwarden.example.com/identity";
        let blank = || Some("  ".to_string());
        let env = |v: &str| Some(v.to_string());

        // (label, toml, env api, env identity, expected api, expected identity)
        let us_api = Environment::Us.api_url();
        let us_id = Environment::Us.identity_url();
        let eu_api = Environment::Eu.api_url();
        let eu_id = Environment::Eu.identity_url();
        let rows = [
            ("env only", "", env(ENV_API), env(ENV_ID), ENV_API, ENV_ID),
            ("nothing configured", "", None, None, us_api, us_id),
            (
                "no environment section",
                "poll_interval = 15\n",
                None,
                None,
                us_api,
                us_id,
            ),
            (
                "us cloud base",
                "[environment]\nbase = \"https://bitwarden.com\"\n",
                None,
                None,
                us_api,
                us_id,
            ),
            (
                "us vault base with trailing slash",
                "[environment]\nbase = \"https://vault.bitwarden.com/\"\n",
                None,
                None,
                us_api,
                us_id,
            ),
            (
                "scheme-less cloud host is self-hosted",
                "[environment]\nbase = \"bitwarden.eu\"\n",
                None,
                None,
                "bitwarden.eu/api",
                "bitwarden.eu/identity",
            ),
            (
                "eu base with port",
                "[environment]\nbase = \"https://bitwarden.eu:8443\"\n",
                None,
                None,
                eu_api,
                eu_id,
            ),
            (
                "cloud host as subdomain of attacker derives paths",
                "[environment]\nbase = \"https://bitwarden.com.evil.example\"\n",
                None,
                None,
                "https://bitwarden.com.evil.example/api",
                "https://bitwarden.com.evil.example/identity",
            ),
            (
                "eu base mixed case",
                "[environment]\nbase = \"https://VAULT.Bitwarden.EU\"\n",
                None,
                None,
                eu_api,
                eu_id,
            ),
            (
                "eu base with explicit api",
                "[environment]\nbase = \"https://bitwarden.eu\"\napi = \"https://custom-api.example.com\"\n",
                None,
                None,
                "https://custom-api.example.com",
                eu_id,
            ),
            (
                "cloud base with env api",
                "[environment]\nbase = \"https://bitwarden.eu\"\n",
                env(ENV_API),
                None,
                ENV_API,
                eu_id,
            ),
            (
                "cloud lookalike derives paths",
                "[environment]\nbase = \"https://notbitwarden.com\"\n",
                None,
                None,
                "https://notbitwarden.com/api",
                "https://notbitwarden.com/identity",
            ),
            (
                "env over file",
                URLS,
                env(ENV_API),
                env(ENV_ID),
                ENV_API,
                ENV_ID,
            ),
            (
                "blank env is unset",
                URLS,
                blank(),
                blank(),
                "https://api.example.com",
                "https://identity.example.com",
            ),
            ("base only", BASE, None, None, DERIVED_API, DERIVED_ID),
            (
                "base with trailing slash",
                "[environment]\nbase = \"https://bitwarden.example.com/\"\n",
                None,
                None,
                DERIVED_API,
                DERIVED_ID,
            ),
            (
                "explicit api over base",
                "[environment]\nbase = \"https://bitwarden.example.com\"\napi = \"https://custom-api.example.com/v2\"\n",
                None,
                None,
                "https://custom-api.example.com/v2",
                DERIVED_ID,
            ),
            (
                "env over explicit and base",
                "[environment]\nbase = \"https://bitwarden.example.com\"\napi = \"https://api.file.example.com\"\nidentity = \"https://identity.file.example.com\"\n",
                env(ENV_API),
                env(ENV_ID),
                ENV_API,
                ENV_ID,
            ),
        ];
        for (label, toml, env_api, env_identity, api, identity) in rows {
            let cfg = Config::build(
                token(),
                file(toml),
                non_blank(env_api),
                non_blank(env_identity),
            )
            .unwrap_or_else(|e| panic!("{label}: expected Ok, got {e:?}"))
            .into_access_connector_config();
            assert_eq!(cfg.api_url, api, "{label}: api");
            assert_eq!(cfg.identity_url, identity, "{label}: identity");
        }
    }

    #[test]
    fn missing_urls() {
        // (label, toml, substrings the error must contain)
        let rows: [(&str, &str, &[&str]); 2] = [
            (
                "missing api",
                "[environment]\nidentity = \"https://identity.example.com\"\n",
                &["api URL"],
            ),
            (
                "missing identity",
                "[environment]\napi = \"https://api.example.com\"\n",
                &["identity URL"],
            ),
        ];
        for (label, toml, expected) in rows {
            let msg = invalid_config_message(build(toml).unwrap_err());
            for needle in expected {
                assert!(
                    msg.contains(needle),
                    "{label}: expected {needle:?} in {msg:?}"
                );
            }
        }

        // A lone env API URL must not pair with US cloud for identity.
        let env_api = Some("https://api.env.example.com".to_string());
        let msg =
            invalid_config_message(Config::build(token(), file(""), env_api, None).unwrap_err());
        assert!(msg.contains("identity URL"), "env api only: {msg:?}");
    }

    #[test]
    fn non_blank_treats_whitespace_as_unset() {
        assert_eq!(non_blank(Some("  ".into())), None);
        assert_eq!(non_blank(Some("".into())), None);
        assert_eq!(non_blank(None), None);
        assert_eq!(non_blank(Some("x".into())), Some("x".into()));
    }

    #[test]
    fn rejected_keys() {
        // (label, toml, secret value the error must not echo)
        let rows = [
            ("token key", "token = \"0.x.y:z\"\n", Some("0.x.y:z")),
            (
                "old top-level urls",
                "api_url = \"https://api.example.com\"\nidentity_url = \"https://identity.example.com\"\n",
                None,
            ),
            (
                "target client_secret",
                "[targets.00000000-0000-0000-0000-000000000001]\nclient_secret = \"supersecret\"\n",
                Some("supersecret"),
            ),
            (
                "target non-uuid key",
                "[targets.not-a-uuid]\nscript = \"/some/script.sh\"\n",
                None,
            ),
        ];
        for (label, toml, secret) in rows {
            let msg = invalid_config_message(parse_err(&format!("{toml}{URLS}")));
            if let Some(secret) = secret {
                assert!(!msg.contains(secret), "{label}: error echoed value: {msg}");
            }
        }
    }

    #[test]
    fn token_parsing() {
        for (label, raw) in [("missing", None), ("blank", Some("  ".to_string()))] {
            assert!(
                matches!(
                    parse_token(raw),
                    Err(AccessConnectorError::InvalidConfig(_))
                ),
                "{label}: expected InvalidConfig"
            );
        }

        let bad = "not-a-valid-token-string";
        match parse_token(Some(bad.into())) {
            Err(AccessConnectorError::InvalidToken(msg)) => {
                assert!(!msg.contains(bad), "malformed: error echoed token: {msg}");
            }
            _ => panic!("malformed: expected InvalidToken"),
        }
    }

    #[test]
    fn file_values_are_used() {
        let toml = format!(
            r#"
poll_interval      = 30
heartbeat_interval = 45
offline_grace      = 90
max_retry_attempts = 3
retry_base_delay   = 2
script_timeout     = 120
entra_verify_probe = true
{URLS}
[targets.85808642-baba-4b8e-8c34-b48000d60a0a]
script = "/opt/scripts/rotate.sh"

[targets.00000000-0000-0000-0000-000000000001]
tenant_id = "my-tenant"
client_id = "my-client"
"#
        );
        let cfg = build(&toml)
            .expect("expected Ok")
            .into_access_connector_config();
        assert_eq!(cfg.api_url, "https://api.example.com");
        assert_eq!(cfg.identity_url, "https://identity.example.com");
        assert_eq!(cfg.poll_interval, Duration::from_secs(30));
        assert_eq!(cfg.heartbeat_interval, Duration::from_secs(45));
        assert_eq!(cfg.offline_grace, Duration::from_secs(90));
        assert_eq!(cfg.retry_cfg.max_retry_attempts, 3);
        assert_eq!(cfg.retry_cfg.retry_base_delay, Duration::from_secs(2));
        assert_eq!(cfg.script_timeout, Duration::from_secs(120));
        assert!(cfg.entra_verify_probe);

        assert_eq!(cfg.targets.len(), 2);
        let script: Uuid = "85808642-baba-4b8e-8c34-b48000d60a0a".parse().unwrap();
        assert_eq!(
            cfg.targets[&script].script.as_deref(),
            Some("/opt/scripts/rotate.sh")
        );
        let entra: Uuid = "00000000-0000-0000-0000-000000000001".parse().unwrap();
        assert_eq!(cfg.targets[&entra].tenant_id.as_deref(), Some("my-tenant"));
        assert_eq!(cfg.targets[&entra].client_id.as_deref(), Some("my-client"));
    }

    #[test]
    fn defaults_apply_when_file_omits_tunables() {
        let cfg = build(URLS)
            .expect("expected Ok")
            .into_access_connector_config();
        let defaults = FileConfig::default();
        assert_eq!(
            cfg.poll_interval,
            Duration::from_secs(defaults.poll_interval)
        );
        assert_eq!(
            cfg.heartbeat_interval,
            Duration::from_secs(defaults.heartbeat_interval)
        );
        assert_eq!(
            cfg.offline_grace,
            Duration::from_secs(defaults.offline_grace)
        );
        assert_eq!(
            cfg.retry_cfg.max_retry_attempts,
            defaults.max_retry_attempts
        );
        assert_eq!(
            cfg.retry_cfg.retry_base_delay,
            Duration::from_secs(defaults.retry_base_delay)
        );
        assert_eq!(
            cfg.script_timeout,
            Duration::from_secs(defaults.script_timeout)
        );
        assert_eq!(cfg.entra_verify_probe, defaults.entra_verify_probe);
        assert!(
            cfg.targets.is_empty(),
            "absent [targets] must be an empty map"
        );
    }

    #[test]
    fn from_cli_removes_token_from_environment() {
        let _guard = ENV_LOCK.lock().unwrap();
        // SAFETY: guarded by ENV_LOCK.
        unsafe {
            std::env::set_var("BWAC_TOKEN", VALID_TOKEN);
            std::env::set_var("BWAC_API_URL", "https://api.example.com");
            std::env::set_var("BWAC_IDENTITY_URL", "https://identity.example.com");
        }
        let result = Config::from_cli(RunArgs { config: None });
        // SAFETY: guarded by ENV_LOCK.
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

    /// Covers `from_cli` honouring `args.config` and treating a blank URL variable as unset.
    #[test]
    fn from_cli_reads_config_file_and_ignores_blank_env_urls() {
        use std::io::Write;

        let _guard = ENV_LOCK.lock().unwrap();
        let mut config_file = tempfile::NamedTempFile::new().expect("temp config file");
        config_file
            .write_all(URLS.as_bytes())
            .expect("write config file");
        config_file.flush().expect("flush config file");
        // SAFETY: guarded by ENV_LOCK.
        unsafe {
            std::env::set_var("BWAC_TOKEN", VALID_TOKEN);
            std::env::set_var("BWAC_API_URL", "  ");
            std::env::remove_var("BWAC_IDENTITY_URL");
        }
        let result = Config::from_cli(RunArgs {
            config: Some(config_file.path().to_path_buf()),
        });
        // SAFETY: guarded by ENV_LOCK.
        unsafe {
            std::env::remove_var("BWAC_API_URL");
            std::env::remove_var("BWAC_TOKEN");
        }
        let cfg = result.expect("expected Ok").into_access_connector_config();
        assert_eq!(cfg.api_url, "https://api.example.com");
        assert_eq!(cfg.identity_url, "https://identity.example.com");
    }

    #[test]
    fn nonexistent_config_path_is_invalid_config() {
        let result = FileConfig::load(Path::new("/nonexistent/path/to/config.toml"));
        assert!(
            matches!(result, Err(AccessConnectorError::InvalidConfig(_))),
            "expected InvalidConfig for nonexistent config path, got {result:?}"
        );
    }
}
