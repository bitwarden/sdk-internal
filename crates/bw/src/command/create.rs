use clap::Subcommand;

use crate::{
    admin_console::CreateCollectionArgs,
    render::CommandOutput,
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
    pub fn run(&self) -> color_eyre::eyre::Result<CommandOutput> {
        match self {
            CreateCommands::Item(_args) => unimplemented!("Create item not implemented yet"),
            CreateCommands::Attachment(_args) => {
                unimplemented!("Create attachment not implemented yet")
            }
            CreateCommands::Folder(_args) => unimplemented!("Create folder not implemented yet"),
            CreateCommands::OrgCollection(_args) => {
                unimplemented!("Create organization collection not implemented yet")
            }
        }
    }
}
