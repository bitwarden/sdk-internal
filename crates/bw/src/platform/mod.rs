use clap::Args;

pub(crate) mod appdata;
mod completion;
mod config;
mod encode;
mod serve;
mod status;
mod sync;

pub(crate) use appdata::appdata_dir;
pub(crate) use completion::CompletionArgs;
pub(crate) use config::{ConfigCommand, ConfigFile, read_config_json};
pub(crate) use encode::EncodeArgs;
pub(crate) use serve::ServeArgs;
pub(crate) use status::StatusArgs;
pub(crate) use sync::SyncArgs;

#[derive(Args, Clone)]
pub struct GetFingerprintArgs {
    #[arg(default_value = "me", help = "User ID or 'me' for current user")]
    pub user: String,
}
