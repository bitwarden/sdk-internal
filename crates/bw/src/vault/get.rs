//! `get item` and `get folder`.

use crate::{
    client_state::{BwCommand, Unlocked},
    render::{CommandOutput, CommandResult},
    vault::{GetFolderArgs, GetItemArgs, resolve_cipher, resolve_folder},
};

impl BwCommand for GetItemArgs {
    type Client = Unlocked;

    async fn run(self, Unlocked { user, .. }: Unlocked) -> CommandResult {
        // TODO(PM-35687): surface cipher types hidden by the Restricted Item Types policy as
        // NotFound (TS parity). Blocked: the policy client has no state-backed API yet, and
        // `RestrictedItemTypesPolicy` carries no data describing which types are restricted.
        let cipher = resolve_cipher(&user, &self.id, None).await?;
        Ok(CommandOutput::Object(Box::new(cipher)))
    }
}

impl BwCommand for GetFolderArgs {
    type Client = Unlocked;

    async fn run(self, Unlocked { user, .. }: Unlocked) -> CommandResult {
        let folder = resolve_folder(&user, &self.id).await?;
        Ok(CommandOutput::Object(Box::new(folder)))
    }
}
