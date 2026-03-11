use bitwarden_pm::PasswordManagerClient;
use bitwarden_sync::SyncRequest;
use clap::Args;

use crate::render::CommandResult;

#[derive(Args, Clone)]
pub struct SyncArgs {
    #[arg(short = 'f', long, help = "Force a full sync.")]
    pub force: bool,

    #[arg(long, help = "Get the last sync date.")]
    pub last: bool,
}

/// Temporary sync implementation so you can call `bw sync` and have it do something.
pub(crate) async fn execute_sync(client: PasswordManagerClient, _args: SyncArgs) -> CommandResult {
    client
        .sync()
        .sync(SyncRequest {
            exclude_subdomains: None,
        })
        .await?;

    Ok(("Syncing complete.").into())
}
