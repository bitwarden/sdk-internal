use clap::Args;

mod completion;
mod config;
mod encode;
mod serve;
mod sync;

pub(crate) use completion::CompletionArgs;
pub(crate) use config::ConfigCommand;
pub(crate) use encode::EncodeArgs;
pub(crate) use serve::ServeArgs;
pub(crate) use sync::SyncArgs;

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
