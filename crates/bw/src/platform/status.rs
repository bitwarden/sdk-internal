//! `bw status` — server, last sync, user information, and vault lock state.
//!
//! Runs in every auth state, so the command takes [`AnyState`] and branches internally rather than
//! letting a typestate extractor reject the unauthenticated case.
//!
//! `serverUrl` is resolved from `config.json` alone (see [`resolve_server_url`]). The persisted
//! `BASE_URLS` setting holds only the derived api/identity URLs, from which the user-entered base
//! URL is not recoverable for split-domain deployments. Consequence: a self-hosted login performed
//! through
//! `bw login --server <url>` (which persists no base URL at all today) reports the cloud default
//! until the server is also set with `bw config server <url>`. Same underlying gap as the TODO on
//! `web_vault_url` in `crate::tools::send`.

use bitwarden_core::{
    UserId,
    client::persisted_state::{USER_EMAIL, USER_ID},
};
use chrono::SecondsFormat;
use clap::Args;
use serde::Serialize;

use crate::{
    client_state::{AnyState, BwCommand},
    platform::config::resolve_server_url,
    render::{CommandOutput, CommandResult},
};

#[derive(Args, Clone)]
#[command(
    about = "Show server, last sync, user information, and vault status.",
    after_help = r#"Example return value:
  {
    "serverUrl": "https://bitwarden.example.com",
    "lastSync": "2020-06-16T06:33:51.419Z",
    "userEmail": "user@example.com",
    "userId": "00000000-0000-0000-0000-000000000000",
    "status": "locked"
  }

Notes:
  `status` is one of:
    - `unauthenticated` when you are not logged in
    - `locked` when you are logged in and the vault is locked
    - `unlocked` when you are logged in and the vault is unlocked
"#
)]
pub struct StatusArgs;

/// Output of `bw status`. The camelCase field names are consumed by scripts written against the
/// Node CLI, so they must not change.
#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct StatusResponse {
    server_url: String,
    /// RFC3339 with millisecond precision to match the old CLI's format; `null` when never synced.
    last_sync: Option<String>,
    user_email: Option<String>,
    user_id: Option<UserId>,
    status: &'static str,
}

impl BwCommand for StatusArgs {
    type Client = AnyState;

    async fn run(self, state: AnyState) -> CommandResult {
        let response = build_status(resolve_server_url()?, state.user).await?;
        Ok(CommandOutput::Object(Box::new(response)))
    }
}

/// Assemble the response for an already-resolved server URL, so the state-dependent mapping is
/// testable without touching the caller's appdata directory.
async fn build_status(
    server_url: String,
    user: Option<bitwarden_pm::PasswordManagerClient>,
) -> color_eyre::eyre::Result<StatusResponse> {
    let Some(user) = user else {
        return Ok(StatusResponse {
            server_url,
            last_sync: None,
            user_email: None,
            user_id: None,
            status: "unauthenticated",
        });
    };

    let status = if user.is_unlocked() {
        "unlocked"
    } else {
        "locked"
    };

    let last_sync = user
        .sync()
        .last_sync()
        .await
        .map(|t| t.to_rfc3339_opts(SecondsFormat::Millis, true));

    // Reading persisted settings does not require an unlocked vault, so the locked state reports
    // the user's identity and last sync just like the Node CLI does.
    let persisted = user.platform().state();

    Ok(StatusResponse {
        server_url,
        last_sync,
        user_email: persisted.setting(USER_EMAIL)?.get().await?,
        user_id: persisted.setting(USER_ID)?.get().await?,
        status,
    })
}

#[cfg(test)]
mod tests {
    use std::sync::Once;

    use bitwarden_core::{DeviceType, HostPlatformInfo, init_host_platform_info};
    use bitwarden_pm::PasswordManagerClient;

    use super::*;

    // Multiple test binaries in this crate may concurrently call `init_host_platform_info`;
    // a single guarded init keeps cross-test ordering deterministic.
    static INIT: Once = Once::new();

    fn ensure_platform_info() {
        INIT.call_once(|| {
            init_host_platform_info(HostPlatformInfo {
                user_agent: "bw-tests".to_string(),
                device_type: DeviceType::SDK,
                device_identifier: None,
                bitwarden_client_version: None,
                bitwarden_package_type: None,
            });
        });
    }

    async fn status_json(user: Option<PasswordManagerClient>) -> serde_json::Value {
        ensure_platform_info();
        let response = build_status("https://example.com".to_string(), user)
            .await
            .unwrap();
        serde_json::to_value(&response).unwrap()
    }

    #[tokio::test]
    async fn logged_out_reports_unauthenticated_with_null_user_fields() {
        let json = status_json(None).await;

        assert_eq!(json["status"], "unauthenticated");
        assert!(json["lastSync"].is_null());
        assert!(json["userEmail"].is_null());
        assert!(json["userId"].is_null());
    }

    #[tokio::test]
    async fn field_names_match_the_node_cli() {
        let json = status_json(None).await;

        let keys: Vec<&str> = json
            .as_object()
            .unwrap()
            .keys()
            .map(String::as_str)
            .collect();
        assert_eq!(
            keys,
            ["serverUrl", "lastSync", "userEmail", "userId", "status"],
        );
    }

    #[tokio::test]
    async fn user_without_a_loaded_key_reports_locked() {
        // A freshly-built `PasswordManagerClient` has no user key loaded.
        let json = status_json(Some(PasswordManagerClient::new(None))).await;

        assert_eq!(json["status"], "locked");
    }
}
