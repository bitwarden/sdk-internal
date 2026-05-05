use clap::{Args, Subcommand};

use crate::render::{CommandOutput, CommandResult};

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
pub struct ListFoldersArgs {
    #[arg(long, help = "Search term")]
    pub search: Option<String>,
}

#[derive(Args, Clone)]
pub struct DeleteItemArgs {
    pub id: String,
    #[arg(short = 'p', long, help = "Permanently delete the item (skip trash)")]
    pub permanent: bool,
}

#[derive(Args, Clone)]
pub struct DeleteAttachmentArgs {
    pub id: String,
    #[arg(
        long,
        alias = "itemid",
        help = "Item ID that the attachment belongs to"
    )]
    pub item_id: String,
}

#[derive(Args, Clone)]
pub struct DeleteFolderArgs {
    pub id: String,
    #[arg(short = 'p', long, help = "Permanently delete the folder (skip trash)")]
    pub permanent: bool,
}

#[derive(Args, Clone)]
pub struct EditItemArgs {
    /// Object ID
    pub id: String,
    /// Base64-encoded JSON object (optional, can read from stdin)
    pub encoded_json: Option<String>,
}

#[derive(Args, Clone)]
pub struct EditItemCollectionsArgs {
    /// Object ID
    pub id: String,
    /// Base64-encoded JSON object (optional, can read from stdin)
    pub encoded_json: Option<String>,
}

#[derive(Args, Clone)]
pub struct EditFolderArgs {
    /// Object ID
    pub id: String,
    /// Base64-encoded JSON object (optional, can read from stdin)
    pub encoded_json: Option<String>,
}

#[derive(Args, Clone)]
pub struct GetItemArgs {
    pub id: String,
}

#[derive(Args, Clone)]
pub struct GetUsernameArgs {
    pub id: String,
}

#[derive(Args, Clone)]
pub struct GetPasswordArgs {
    pub id: String,
}

#[derive(Args, Clone)]
pub struct GetUriArgs {
    pub id: String,
}

#[derive(Args, Clone)]
pub struct GetTotpArgs {
    pub id: String,
}

#[derive(Args, Clone)]
pub struct GetNotesArgs {
    pub id: String,
}

#[derive(Args, Clone)]
pub struct GetFolderArgs {
    pub id: String,
}

#[derive(Args, Clone)]
pub struct GetAttachmentArgs {
    pub filename: String,
    #[arg(
        long,
        alias = "itemid",
        help = "Item ID that the attachment belongs to."
    )]
    pub item_id: String,
    #[arg(long, help = "Output file path. If not specified, outputs to stdout.")]
    pub output: Option<String>,
}

#[derive(clap::Args, Clone)]
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
pub struct CreateItemArgs {
    #[arg(help = "Base64-encoded JSON item object")]
    encoded_json: String,
}

#[derive(clap::Args, Clone)]
pub struct CreateAttachmentArgs {
    #[arg(long, help = "Path to the file to attach")]
    file: String,
    #[arg(long, alias = "itemid", help = "Item ID to attach the file to")]
    item_id: String,
}

#[derive(clap::Args, Clone)]
pub struct CreateFolderArgs {
    #[arg(help = "Base64-encoded JSON folder object")]
    encoded_json: String,
}
