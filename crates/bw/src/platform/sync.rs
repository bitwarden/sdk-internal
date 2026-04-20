use bitwarden_sync::SyncRequest;
use bw_macro::bw_command;
use clap::Args;

use crate::{client_state::LoggedIn, render::CommandResult};

#[derive(Args, Clone)]
#[bw_command(
    path = "sync",
    state = LoggedIn,
    about = "Pull the latest vault data from server."
)]
pub struct SyncArgs {
    #[arg(short = 'f', long, help = "Force a full sync.")]
    pub force: bool,

    #[arg(long, help = "Get the last sync date.")]
    pub last: bool,
}

impl SyncArgs {
    async fn run(self, LoggedIn { client, .. }: LoggedIn) -> CommandResult {
        client
            .sync()
            .sync(SyncRequest {
                exclude_subdomains: None,
            })
            .await?;

        Ok(("Syncing complete.").into())
    }
}
