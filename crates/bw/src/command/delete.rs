use clap::Subcommand;

use crate::{
    admin_console::DeleteOrgCollectionArgs,
    vault::{DeleteAttachmentArgs, DeleteFolderArgs, DeleteItemArgs},
};

#[derive(Subcommand, Clone)]
pub enum DeleteCommands {
    #[command(about = "Delete an item from the vault.")]
    Item(DeleteItemArgs),

    #[command(about = "Delete an attachment from an item.")]
    Attachment(DeleteAttachmentArgs),

    #[command(about = "Delete a folder.")]
    Folder(DeleteFolderArgs),

    #[command(about = "Delete an organization collection.")]
    OrgCollection(DeleteOrgCollectionArgs),
}
