use clap::Subcommand;

use crate::render::{CommandOutput, CommandResult};

mod sync;

pub(crate) use sync::{SyncRequest, sync};

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
