use clap::Args;

use crate::{
    client_state::{BwCommand, LoggedIn},
    render::CommandResult,
};

#[derive(Args, Clone)]
pub struct LockArgs;

impl BwCommand for LockArgs {
    // `LoggedIn` (rather than `Unlocked`) is intentional: the legacy node CLI accepts `bw lock`
    // when the vault is already locked, and we preserve that behavior for compatibility.
    type Client = LoggedIn;

    async fn run(self, LoggedIn { user, .. }: LoggedIn) -> CommandResult {
        user.unlock().invalidate_session_key().await?;
        Ok("Your vault is now locked.".into())
    }
}
