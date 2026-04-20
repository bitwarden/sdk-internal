use bw_macro::bw_command;
use clap::{Args, Subcommand};

use crate::{
    client_state::{AnyState, BwCommand},
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
    about = "Get a JSON template for creating objects."
)]
pub struct GetTemplateArgs {
    #[command(subcommand)]
    pub command: TemplateCommands,
}

impl BwCommand for GetTemplateArgs {
    type Client = AnyState;

    #[allow(clippy::unused_async)]
    async fn run(self, _state: AnyState) -> CommandResult {
        self.command.run()
    }
}
