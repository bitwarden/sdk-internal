use bitwarden_sync::{SyncError, SyncRequest};
use chrono::SecondsFormat;
use clap::Args;
use color_eyre::eyre::eyre;

use crate::{
    client_state::{BwCommand, LoggedIn},
    render::CommandResult,
};

#[derive(Args, Clone)]
pub struct SyncArgs {
    #[arg(short = 'f', long, help = "Force a full sync.")]
    pub force: bool,

    #[arg(long, help = "Get the last sync date.")]
    pub last: bool,
}

impl BwCommand for SyncArgs {
    type Client = LoggedIn;

    async fn run(self, LoggedIn { user, .. }: LoggedIn) -> CommandResult {
        if self.last {
            let output = user
                .sync()
                .last_sync()
                .await
                // Convert to RFC3339 with millisecond precision, to match the old CLI's format.
                .map(|t| t.to_rfc3339_opts(SecondsFormat::Millis, true))
                .unwrap_or_else(|| "None".to_string());
            return Ok(output.into());
        }

        match user
            .sync()
            .sync(SyncRequest {
                force: self.force,
                exclude_subdomains: None,
            })
            .await
        {
            Ok(_) => Ok("Syncing complete.".into()),
            Err(SyncError::AccountDeleted) => {
                // TODO: This should wipe the session in the same way as bw logout, but it's not
                // implemented yet
                user.invalidate_session_key().await.ok();
                Err(eyre!(
                    "This account has been deleted. Local session state has been cleared."
                ))
            }
            Err(e) => Err(e.into()),
        }
    }
}
