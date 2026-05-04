use clap::Subcommand;

use crate::{
    admin_console::{
        ListCollectionsArgs, ListOrgCollectionsArgs, ListOrgMembersArgs, ListOrganizationsArgs,
    },
    vault::{ListFoldersArgs, ListItemsArgs},
};

#[derive(Subcommand, Clone)]
pub enum ListCommands {
    #[command(about = "List items from the vault.")]
    Items(ListItemsArgs),

    #[command(about = "List folders from the vault.")]
    Folders(ListFoldersArgs),

    #[command(about = "List collections from the vault.")]
    Collections(ListCollectionsArgs),

    #[command(about = "List organizations.")]
    Organizations(ListOrganizationsArgs),

    #[command(about = "List organization collections.")]
    OrgCollections(ListOrgCollectionsArgs),

    #[command(about = "List organization members.")]
    OrgMembers(ListOrgMembersArgs),
}
