use clap::Subcommand;

use crate::{
    admin_console::EditOrgCollectionArgs,
    vault::{EditFolderArgs, EditItemArgs, EditItemCollectionsArgs},
};

#[derive(Subcommand, Clone)]
pub enum EditCommands {
    #[command(about = "Edit an item in the vault.")]
    Item(EditItemArgs),

    #[command(about = "Edit an item's collections.")]
    ItemCollections(EditItemCollectionsArgs),

    #[command(about = "Edit a folder.")]
    Folder(EditFolderArgs),

    #[command(about = "Edit an organization collection.")]
    OrgCollection(EditOrgCollectionArgs),
}
