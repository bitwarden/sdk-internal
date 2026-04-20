use bw_macro::bw_command;
use clap::{Args, Subcommand};

use crate::{
    client_state::AnyState,
    render::{CommandOutput, CommandResult},
};

#[derive(Subcommand, Clone, Debug)]
pub enum TemplateCommands {
    #[command(name = "item")]
    Item,
    #[command(name = "item.field")]
    ItemField,
    #[command(name = "item.login")]
    ItemLogin,
    #[command(name = "item.login.uri")]
    ItemLoginUri,
    #[command(name = "item.card")]
    ItemCard,
    #[command(name = "item.identity")]
    ItemIdentity,
    #[command(name = "item.securenote")]
    ItemSecureNote,
    #[command(name = "folder")]
    Folder,
    #[command(name = "collection")]
    Collection,
    #[command(name = "item-collections")]
    ItemCollections,
    #[command(name = "org-collection")]
    OrgCollection,
    #[command(name = "send.text")]
    SendText,
    #[command(name = "send.file")]
    SendFile,
}

impl TemplateCommands {
    pub fn run(&self) -> CommandResult {
        match self {
            Self::Folder => {
                #[derive(serde::Serialize)]
                struct FolderTemplate {
                    name: String,
                }

                Ok(CommandOutput::Object(Box::new(FolderTemplate {
                    name: "Folder name".to_string(),
                })))
            }
            _ => todo!(),
        }
    }
}

#[derive(Args, Clone)]
#[bw_command(
    path = "get template",
    state = AnyState,
    about = "Get a JSON template for creating objects."
)]
pub struct GetTemplateArgs {
    #[command(subcommand)]
    pub command: TemplateCommands,
}

impl GetTemplateArgs {
    #[allow(clippy::unused_async)]
    async fn run(self, _state: AnyState) -> CommandResult {
        self.command.run()
    }
}

#[derive(Args, Clone)]
#[bw_command(path = "list items", todo, about = "List items from the vault.")]
pub struct ListItemsArgs {
    #[arg(long, help = "Filter items by URL")]
    pub url: Option<String>,

    #[arg(long, alias = "folderid", help = "Filter items by folder ID")]
    pub folder_id: Option<String>,

    #[arg(long, alias = "collectionid", help = "Filter items by collection ID")]
    pub collection_id: Option<String>,

    #[arg(
        long,
        alias = "organizationid",
        help = "Filter items by organization ID"
    )]
    pub organization_id: Option<String>,

    #[arg(long, help = "Filter items in trash")]
    pub trash: bool,

    #[arg(long, help = "Search term")]
    pub search: Option<String>,
}

#[derive(Args, Clone)]
#[bw_command(path = "list folders", todo, about = "List folders from the vault.")]
pub struct ListFoldersArgs {
    #[arg(long, help = "Search term")]
    pub search: Option<String>,
}

#[derive(Args, Clone)]
#[bw_command(path = "delete item", todo, about = "Delete an item from the vault.")]
pub struct DeleteItemArgs {
    pub id: String,
    #[arg(short = 'p', long, help = "Permanently delete the item (skip trash)")]
    pub permanent: bool,
}

#[derive(Args, Clone)]
#[bw_command(
    path = "delete attachment",
    todo,
    about = "Delete an attachment from an item."
)]
pub struct DeleteAttachmentArgs {
    pub id: String,
    #[arg(long, help = "Item ID that the attachment belongs to")]
    pub itemid: String,
}

#[derive(Args, Clone)]
#[bw_command(path = "delete folder", todo, about = "Delete a folder.")]
pub struct DeleteFolderArgs {
    pub id: String,
    #[arg(short = 'p', long, help = "Permanently delete the folder (skip trash)")]
    pub permanent: bool,
}

#[derive(Args, Clone)]
#[bw_command(path = "edit item", todo, about = "Edit an item in the vault.")]
pub struct EditItemArgs {
    /// Object ID
    pub id: String,
    /// Base64-encoded JSON object (optional, can read from stdin)
    pub encoded_json: Option<String>,
}

#[derive(Args, Clone)]
#[bw_command(
    path = "edit item-collections",
    todo,
    about = "Edit an item's collections."
)]
pub struct EditItemCollectionsArgs {
    /// Object ID
    pub id: String,
    /// Base64-encoded JSON object (optional, can read from stdin)
    pub encoded_json: Option<String>,
}

#[derive(Args, Clone)]
#[bw_command(path = "edit folder", todo, about = "Edit a folder.")]
pub struct EditFolderArgs {
    /// Object ID
    pub id: String,
    /// Base64-encoded JSON object (optional, can read from stdin)
    pub encoded_json: Option<String>,
}

#[derive(Args, Clone)]
#[bw_command(path = "get item", todo, about = "Get an item from the vault.")]
pub struct GetItemArgs {
    pub id: String,
}

#[derive(Args, Clone)]
#[bw_command(path = "get username", todo, about = "Get the username for an item.")]
pub struct GetUsernameArgs {
    pub id: String,
}

#[derive(Args, Clone)]
#[bw_command(path = "get password", todo, about = "Get the password for an item.")]
pub struct GetPasswordArgs {
    pub id: String,
}

#[derive(Args, Clone)]
#[bw_command(path = "get uri", todo, about = "Get the URI for an item.")]
pub struct GetUriArgs {
    pub id: String,
}

#[derive(Args, Clone)]
#[bw_command(path = "get totp", todo, about = "Get the TOTP code for an item.")]
pub struct GetTotpArgs {
    pub id: String,
}

#[derive(Args, Clone)]
#[bw_command(path = "get notes", todo, about = "Get the notes for an item.")]
pub struct GetNotesArgs {
    pub id: String,
}

#[derive(Args, Clone)]
#[bw_command(path = "get folder", todo, about = "Get a folder from the vault.")]
pub struct GetFolderArgs {
    pub id: String,
}

#[derive(Args, Clone)]
#[bw_command(
    path = "get attachment",
    todo,
    about = "Get an attachment from an item."
)]
pub struct GetAttachmentArgs {
    pub filename: String,
    #[arg(long, help = "Item ID that the attachment belongs to.")]
    pub itemid: String,
    #[arg(long, help = "Output file path. If not specified, outputs to stdout.")]
    pub output: Option<String>,
}

#[derive(clap::Args, Clone)]
#[bw_command(path = "restore", todo, about = "Restores an object from the trash.")]
pub struct RestoreArgs {
    /// Type of object to restore
    pub object: RestoreObject,
    /// Object ID to restore
    pub id: String,
}

#[derive(clap::ValueEnum, Clone, Debug)]
#[value(rename_all = "kebab-case")]
pub enum RestoreObject {
    Item,
}

#[derive(clap::Args, Clone)]
#[bw_command(path = "create item", todo, about = "Create an item in the vault.")]
pub struct CreateItemArgs {
    #[arg(help = "Base64-encoded JSON item object")]
    encoded_json: String,
}

#[derive(clap::Args, Clone)]
#[bw_command(
    path = "create attachment",
    todo,
    about = "Create an attachment for an item."
)]
pub struct CreateAttachmentArgs {
    #[arg(long, help = "Path to the file to attach")]
    file: String,
    #[arg(long, help = "Item ID to attach the file to")]
    itemid: String,
}

#[derive(clap::Args, Clone)]
#[bw_command(path = "create folder", todo, about = "Create a folder.")]
pub struct CreateFolderArgs {
    #[arg(help = "Base64-encoded JSON folder object")]
    encoded_json: String,
}
