use clap::{Args, Subcommand};

use crate::render::CommandResult;
mod sync;
pub(crate) use sync::SyncArgs;
mod serve;
pub(crate) use serve::ServeArgs;

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

#[derive(Args, Clone)]
pub struct GetFingerprintArgs {
    #[arg(default_value = "me", help = "User ID or 'me' for current user")]
    pub user: String,
}

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

impl ConfigCommand {
    #[allow(clippy::unused_async)]
    pub async fn run(self) -> CommandResult {
        todo!()
    }
}
