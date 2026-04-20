use clap::Subcommand;

use crate::{
    admin_console::CreateCollectionArgs,
    client_state::ClientContext,
    render::CommandResult,
    vault::{CreateAttachmentArgs, CreateFolderArgs, CreateItemArgs},
};

#[derive(Subcommand, Clone)]
#[clap(rename_all = "kebab-case")]
pub enum CreateCommands {
    #[command(about = "Create an item in the vault.")]
    Item(CreateItemArgs),

    #[command(about = "Create an attachment for an item.")]
    Attachment(CreateAttachmentArgs),

    #[command(about = "Create a folder.")]
    Folder(CreateFolderArgs),

    #[command(about = "Create an organization collection.")]
    OrgCollection(CreateCollectionArgs),
}

/// Create command is unowned as it spans multiple teams.
///
/// Sub-commands should delegate to team owned implementations.
impl CreateCommands {
    pub async fn run(self, _ctx: ClientContext) -> CommandResult {
        match self {
            CreateCommands::Item(_args) => todo!(),
            CreateCommands::Attachment(_args) => todo!(),
            CreateCommands::Folder(_args) => todo!(),
            CreateCommands::OrgCollection(_args) => todo!(),
        }
    }
}
