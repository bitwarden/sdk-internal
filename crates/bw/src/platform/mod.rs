use bw_macro::bw_command;
use clap::{Args, Subcommand};

mod serve;
mod sync;

#[derive(Args, Clone)]
#[bw_command(
    path = "status",
    todo,
    about = "Show server, last sync, user information, and vault status.",
    after_help = "Example return value:\n  {\n    \"serverUrl\": \"https://bitwarden.example.com\",\n    \"lastSync\": \"2020-06-16T06:33:51.419Z\",\n    \"userEmail\": \"user@example.com\",\n    \"userId\": \"00000000-0000-0000-0000-000000000000\",\n    \"status\": \"locked\"\n  }\n\nNotes:\n  `status` is one of:\n    - `unauthenticated` when you are not logged in\n    - `locked` when you are logged in and the vault is locked\n    - `unlocked` when you are logged in and the vault is unlocked"
)]
pub struct StatusArgs;

#[derive(Args, Clone)]
#[bw_command(
    path = "get fingerprint",
    todo,
    about = "Get the fingerprint for the current user or a specified user."
)]
pub struct GetFingerprintArgs {
    #[arg(default_value = "me", help = "User ID or 'me' for current user")]
    pub user: String,
}

#[derive(Args, Clone)]
#[bw_command(path = "config", todo, about = "Configure CLI settings.")]
pub struct ConfigArgs {
    #[command(subcommand)]
    pub command: ConfigCommand,
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
