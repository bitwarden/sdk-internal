use clap::Subcommand;

use crate::{
    admin_console::{GetCollectionArgs, GetOrgCollectionArgs, GetOrganizationArgs},
    dirt::GetExposedArgs,
    platform::GetFingerprintArgs,
    render::CommandOutput,
    tools::GetSendArgs,
    vault::{
        GetAttachmentArgs, GetFolderArgs, GetItemArgs, GetNotesArgs, GetPasswordArgs, GetTotpArgs,
        GetUriArgs, GetUsernameArgs, TemplateCommands,
    },
};

#[derive(Subcommand, Clone)]
pub enum GetCommands {
    #[command(about = "Get an item from the vault.")]
    Item(GetItemArgs),

    #[command(about = "Get the username for an item.")]
    Username(GetUsernameArgs),

    #[command(about = "Get the password for an item.")]
    Password(GetPasswordArgs),

    #[command(about = "Get the URI for an item.")]
    Uri(GetUriArgs),

    #[command(about = "Get the TOTP code for an item.")]
    Totp(GetTotpArgs),

    #[command(about = "Check if an item password has been exposed in a data breach.")]
    Exposed(GetExposedArgs),

    #[command(about = "Get the notes for an item.")]
    Notes(GetNotesArgs),

    #[command(about = "Get a folder from the vault.")]
    Folder(GetFolderArgs),

    #[command(about = "Get a collection from the vault.")]
    Collection(GetCollectionArgs),

    #[command(about = "Get an organization.")]
    Organization(GetOrganizationArgs),

    #[command(about = "Get an organization collection.")]
    OrgCollection(GetOrgCollectionArgs),

    #[command(about = "Get an attachment from an item.")]
    Attachment(GetAttachmentArgs),

    #[command(about = "Get the fingerprint for the current user or a specified user.")]
    Fingerprint(GetFingerprintArgs),

    #[command(about = "Get a JSON template for creating objects.")]
    Template {
        #[command(subcommand)]
        command: TemplateCommands,
    },

    #[command(about = "Get a Bitwarden Send.")]
    Send(GetSendArgs),
}

/// Get command is unowned as it spans multiple teams.
///
/// Sub-commands should delegate to team owned implementations.
impl GetCommands {
    pub fn run(&self) -> color_eyre::eyre::Result<CommandOutput> {
        match self {
            GetCommands::Template { command } => command.run(),
            _ => todo!(),
        }
    }
}
