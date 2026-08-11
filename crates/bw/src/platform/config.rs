use std::path::{Path, PathBuf};

use clap::Subcommand;
use color_eyre::eyre::{Result, WrapErr, eyre};
use serde::{Deserialize, Serialize};

use crate::{
    client_state::{AnyState, BwCommand},
    platform::appdata::appdata_dir,
    render::CommandResult,
};

#[derive(Subcommand, Clone)]
pub enum ConfigCommand {
    Server {
        base_url: Option<String>,
        #[arg(
            long,
            help = "Provides a custom web vault URL that differs from the base URL."
        )]
        web_vault: Option<String>,
        #[arg(
            long,
            help = "Provides a custom API URL that differs from the base URL."
        )]
        api: Option<String>,
        #[arg(
            long,
            help = "Provides a custom identity URL that differs from the base URL."
        )]
        identity: Option<String>,
        #[arg(
            long,
            help = "Provides a custom icons service URL that differs from the base URL."
        )]
        icons: Option<String>,
        #[arg(
            long,
            help = "Provides a custom notifications URL that differs from the base URL."
        )]
        notifications: Option<String>,
        #[arg(
            long,
            help = "Provides a custom events URL that differs from the base URL."
        )]
        events: Option<String>,

        #[arg(long, help = "Provides the URL for your Key Connector server.")]
        key_connector: Option<String>,
    },
}

impl BwCommand for ConfigCommand {
    type Client = AnyState;

    async fn run(self, state: AnyState) -> CommandResult {
        // If we're not provided any values, then this is a request to get the current server URL.
        if self.is_get() {
            let server = read_config_json()?
                .and_then(|c| c.server)
                .unwrap_or_else(|| "https://bitwarden.com".into());
            return Ok(server.into());
        }

        // If we are provided any values, then this is a request to set the server URL,
        // which can only be done when no user is logged in.
        if state.user.is_some() {
            return Err(eyre!("Logout required before server config update."));
        }

        let config: ConfigFile = self.into();
        write_config_json(&config)?;

        Ok("Saved setting `config`.".into())
    }
}

impl ConfigCommand {
    /// True when the invocation should return the saved server URL instead of writing one.
    ///
    /// GET when the base URL is missing or empty AND no per-service URL flag is set.
    /// Node CLI's `config.command.ts` omits `--key-connector` from this check, so passing
    /// only that flag silently no-ops. We treat that as a Node CLI bug rather than parity
    /// to preserve: `--key-connector X` alone takes the SET path here.
    fn is_get(&self) -> bool {
        let ConfigCommand::Server {
            base_url,
            web_vault,
            api,
            identity,
            icons,
            notifications,
            events,
            key_connector,
        } = self;

        base_url.as_deref().is_none_or(|s| s.trim().is_empty())
            && web_vault.is_none()
            && api.is_none()
            && identity.is_none()
            && icons.is_none()
            && notifications.is_none()
            && events.is_none()
            && key_connector.is_none()
    }
}

/// On-disk shape of the CLI's legacy server-URL config, written by
/// `bw config server` and read by `bw status` when no user is logged in.
///
/// Field names are snake_case so the file is human-editable and matches the
/// breakdown's documented layout (see PM-37214).
#[derive(Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub struct ConfigFile {
    pub server: Option<String>,
    pub web_vault: Option<String>,
    pub api: Option<String>,
    pub identity: Option<String>,
    pub icons: Option<String>,
    pub notifications: Option<String>,
    pub events: Option<String>,
    pub key_connector: Option<String>,
}

fn config_json_path() -> Result<PathBuf> {
    Ok(appdata_dir()?.join("config.json"))
}

/// Reads the config JSON from disk
pub fn read_config_json() -> Result<Option<ConfigFile>> {
    read_config_json_from(&config_json_path()?)
}

/// Writes the config JSON to disk, creating parent directories as needed
pub fn write_config_json(config: &ConfigFile) -> Result<()> {
    write_config_json_to(&config_json_path()?, config)
}

fn read_config_json_from(path: &Path) -> Result<Option<ConfigFile>> {
    let bytes = match std::fs::read(path) {
        Ok(b) => b,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(None),
        Err(e) => {
            return Err(e).wrap_err_with(|| format!("Failed to read {}", path.display()));
        }
    };
    serde_json::from_slice(&bytes)
        .map(Some)
        .wrap_err_with(|| format!("Failed to parse {}", path.display()))
}

fn write_config_json_to(path: &Path, config: &ConfigFile) -> Result<()> {
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent)
            .wrap_err_with(|| format!("Failed to create {}", parent.display()))?;
    }
    let json = serde_json::to_vec_pretty(config)?;
    std::fs::write(path, json).wrap_err_with(|| format!("Failed to write {}", path.display()))
}

/// Builds the on-disk `ConfigFile` from a SET invocation. Only meaningful after
/// [`ConfigCommand::is_get`] has returned `false` — the GET path does not write.
///
/// URL fields are normalized to match the Node CLI: the base URL's cloud-default
/// aliases collapse to `None`, then every URL is run through [`format_url`].
impl From<ConfigCommand> for ConfigFile {
    fn from(cmd: ConfigCommand) -> Self {
        let ConfigCommand::Server {
            base_url,
            web_vault,
            api,
            identity,
            icons,
            notifications,
            events,
            key_connector,
        } = cmd;

        ConfigFile {
            server: base_url
                .and_then(collapse_default_alias)
                .and_then(format_url),
            web_vault: web_vault.and_then(format_url),
            api: api.and_then(format_url),
            identity: identity.and_then(format_url),
            icons: icons.and_then(format_url),
            notifications: notifications.and_then(format_url),
            events: events.and_then(format_url),
            key_connector: key_connector.and_then(format_url),
        }
    }
}

/// Reproduces Node CLI's literal-string check in `config.command.ts`: the strings
/// `"null"`, `"bitwarden.com"`, and `"https://bitwarden.com"` collapse to a missing
/// server (i.e. fall back to the default cloud URL on read).
fn collapse_default_alias(url: String) -> Option<String> {
    match url.as_str() {
        "null" | "bitwarden.com" | "https://bitwarden.com" => None,
        _ => Some(url),
    }
}

/// Reproduces Node CLI's `formatUrl` from `default-environment.service.ts`:
/// empty input collapses to `None`, trailing slashes are stripped, `https://`
/// is prepended when no scheme is present, and surrounding whitespace is trimmed.
fn format_url(url: String) -> Option<String> {
    if url.is_empty() {
        return None;
    }
    let stripped = url.trim_end_matches('/');
    let with_scheme = if stripped.starts_with("http://") || stripped.starts_with("https://") {
        stripped.to_string()
    } else {
        format!("https://{stripped}")
    };
    Some(with_scheme.trim().to_string())
}

#[cfg(test)]
mod tests {
    use std::path::PathBuf;

    use super::*;

    fn tempdir() -> PathBuf {
        let dir = std::env::temp_dir().join(format!(
            "bw-config-test-{}-{}",
            std::process::id(),
            uuid::Uuid::new_v4(),
        ));
        std::fs::create_dir_all(&dir).expect("tempdir");
        dir
    }

    #[test]
    fn read_returns_none_when_file_missing() {
        let path = tempdir().join("config.json");
        assert!(read_config_json_from(&path).unwrap().is_none());
    }

    #[test]
    fn write_then_read_roundtrips_all_fields() {
        let path = tempdir().join("config.json");
        let original = ConfigFile {
            server: Some("https://self-hosted.example.com".into()),
            web_vault: Some("https://vault.example.com".into()),
            api: Some("https://api.example.com".into()),
            identity: Some("https://identity.example.com".into()),
            icons: Some("https://icons.example.com".into()),
            notifications: Some("https://notifications.example.com".into()),
            events: Some("https://events.example.com".into()),
            key_connector: Some("https://kc.example.com".into()),
        };

        write_config_json_to(&path, &original).unwrap();
        let loaded = read_config_json_from(&path).unwrap().unwrap();

        assert_eq!(loaded, original);
    }

    #[test]
    fn write_creates_parent_directory() {
        let path = tempdir().join("nested").join("dir").join("config.json");
        write_config_json_to(&path, &ConfigFile::default()).unwrap();
        assert!(path.exists());
    }

    #[test]
    fn serialized_keys_are_snake_case() {
        let config = ConfigFile {
            web_vault: Some("a".into()),
            key_connector: Some("b".into()),
            ..ConfigFile::default()
        };
        let json = serde_json::to_string(&config).unwrap();
        assert!(json.contains("\"web_vault\""), "got: {json}");
        assert!(json.contains("\"key_connector\""), "got: {json}");
    }

    #[test]
    fn collapse_default_alias_drops_cloud_aliases() {
        assert_eq!(collapse_default_alias("null".into()), None);
        assert_eq!(collapse_default_alias("bitwarden.com".into()), None);
        assert_eq!(collapse_default_alias("https://bitwarden.com".into()), None);
        assert_eq!(
            collapse_default_alias("https://self-hosted.example.com".into()),
            Some("https://self-hosted.example.com".into()),
        );
    }

    #[test]
    fn format_url_returns_none_for_empty() {
        assert_eq!(format_url(String::new()), None);
    }

    #[test]
    fn format_url_prepends_https_when_scheme_missing() {
        assert_eq!(
            format_url("bw.example.com".into()),
            Some("https://bw.example.com".into()),
        );
    }

    #[test]
    fn format_url_preserves_existing_scheme() {
        assert_eq!(
            format_url("http://bw.example.com".into()),
            Some("http://bw.example.com".into()),
        );
        assert_eq!(
            format_url("https://bw.example.com".into()),
            Some("https://bw.example.com".into()),
        );
    }

    #[test]
    fn format_url_strips_trailing_slashes() {
        assert_eq!(
            format_url("https://bw.example.com/".into()),
            Some("https://bw.example.com".into()),
        );
        assert_eq!(
            format_url("https://bw.example.com///".into()),
            Some("https://bw.example.com".into()),
        );
    }

    #[test]
    fn format_url_from_command_normalizes_every_url_field() {
        let cmd = ConfigCommand::Server {
            base_url: Some("bw.example.com/".into()),
            web_vault: Some("vault.example.com/".into()),
            api: Some("api.example.com/".into()),
            identity: Some("id.example.com/".into()),
            icons: Some("icons.example.com/".into()),
            notifications: Some("notify.example.com/".into()),
            events: Some("events.example.com/".into()),
            key_connector: Some("kc.example.com/".into()),
        };
        let file: ConfigFile = cmd.into();
        assert_eq!(file.server.as_deref(), Some("https://bw.example.com"));
        assert_eq!(file.web_vault.as_deref(), Some("https://vault.example.com"));
        assert_eq!(file.api.as_deref(), Some("https://api.example.com"));
        assert_eq!(file.identity.as_deref(), Some("https://id.example.com"));
        assert_eq!(file.icons.as_deref(), Some("https://icons.example.com"));
        assert_eq!(
            file.notifications.as_deref(),
            Some("https://notify.example.com"),
        );
        assert_eq!(file.events.as_deref(), Some("https://events.example.com"));
        assert_eq!(
            file.key_connector.as_deref(),
            Some("https://kc.example.com")
        );
    }

    #[test]
    fn from_command_collapses_base_url_alias_before_formatting() {
        let cmd = ConfigCommand::Server {
            base_url: Some("https://bitwarden.com".into()),
            web_vault: None,
            api: None,
            identity: None,
            icons: None,
            notifications: None,
            events: None,
            key_connector: None,
        };
        let file: ConfigFile = cmd.into();
        assert_eq!(file.server, None);
    }
}
