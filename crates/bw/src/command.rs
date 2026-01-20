use bitwarden_cli::Color;
use clap::{Parser, Subcommand};

use crate::{
    admin_console::{ConfirmCommand, MoveArgs},
    auth::LoginArgs,
    key_management::UnlockArgs,
    platform::{ConfigCommand, SyncArgs},
    render::Output,
    tools::{ExportArgs, GenerateArgs, ImportArgs, ReceiveArgs, SendArgs},
    vault::{RestoreArgs, TemplateCommands},
};

pub const SESSION_ENV: &str = "BW_SESSION";

#[derive(Parser, Clone)]
#[command(name = "Bitwarden CLI", version, about = "Bitwarden CLI", long_about = None, disable_version_flag = true)]
pub struct Cli {
    // Optional as a workaround for https://github.com/clap-rs/clap/issues/3572
    #[command(subcommand)]
    pub command: Option<Commands>,

    #[arg(short = 'o', long, global = true, value_enum, default_value_t = Output::JSON)]
    pub output: Output,

    #[arg(short = 'c', long, global = true, value_enum, default_value_t = Color::Auto)]
    pub color: Color,

    // TODO(CLI): Pretty/raw/response options
    #[arg(
        long,
        global = true,
        env = SESSION_ENV,
        help = "The session key used to decrypt your vault data. Can be obtained with `bw login` or `bw unlock`."
    )]
    pub session: Option<String>,

    #[arg(
        long,
        global = true,
        help = "Exit with a success exit code (0) unless an error is thrown."
    )]
    pub cleanexit: bool,

    #[arg(
        short = 'q',
        long,
        global = true,
        help = "Don't return anything to stdout."
    )]
    pub quiet: bool,

    #[arg(
        long,
        global = true,
        help = "Do not prompt for interactive user input."
    )]
    pub nointeraction: bool,

    // Clap uses uppercase V for the short flag by default, but we want lowercase v
    // for compatibility with the node CLI:
    // https://github.com/clap-rs/clap/issues/138
    #[arg(short = 'v', long, action = clap::builder::ArgAction::Version)]
    pub version: (),
}

#[derive(Subcommand, Clone)]
pub enum Commands {
    // Auth commands
    #[command(long_about = "Log into a user account.")]
    Login(LoginArgs),

    #[command(long_about = "Log out of the current user account.")]
    Logout,

    #[command(long_about = "Lock the vault and destroy active session keys.")]
    Lock,

    // KM commands
    #[command(long_about = "Unlock the vault and return a session key.")]
    Unlock(UnlockArgs),

    // Platform commands
    #[command(long_about = "Pull the latest vault data from server.")]
    Sync(SyncArgs),

    #[command(long_about = "Base 64 encode stdin.")]
    Encode,

    #[command(long_about = "Configure CLI settings.")]
    Config {
        #[command(subcommand)]
        command: ConfigCommand,
    },

    #[command(long_about = "Check for updates.")]
    Update {
        #[arg(long, help = "Return only the download URL for the update.")]
        raw: bool,
    },

    #[command(long_about = "Generate shell completions.")]
    Completion {
        #[arg(long, help = "The shell to generate completions for.")]
        shell: Option<clap_complete::Shell>,
    },

    #[command(
        long_about = "Show server, last sync, user information, and vault status.",
        after_help = r#"Example return value:
  {
    "serverUrl": "https://bitwarden.example.com",
    "lastSync": "2020-06-16T06:33:51.419Z",
    "userEmail": "user@example.com",
    "userId": "00000000-0000-0000-0000-000000000000",
    "status": "locked"
  }

Notes:
  `status` is one of:
    - `unauthenticated` when you are not logged in
    - `locked` when you are logged in and the vault is locked
    - `unlocked` when you are logged in and the vault is unlocked
"#
    )]
    Status,

    // These are the old style action-name commands, to be replaced by name-action commands in the
    // future
    #[command(long_about = "List an array of objects from the vault.")]
    List(ListArgs),
    #[command(long_about = "Get an object from the vault.")]
    Get {
        #[command(subcommand)]
        command: GetCommands,
    },
    #[command(long_about = "Create an object in the vault.")]
    Create {
        #[command(subcommand)]
        command: CreateCommands,
    },
    #[command(long_about = "Edit an object from the vault.")]
    Edit(EditArgs),
    #[command(long_about = "Delete an object from the vault.")]
    Delete {
        #[command(subcommand)]
        command: DeleteCommands,
    },
    #[command(long_about = "Restores an object from the trash.")]
    Restore(RestoreArgs),
    #[command(long_about = "Move an item to an organization.")]
    Move(MoveArgs),

    // Admin console commands
    #[command(long_about = "Confirm an object to the organization.")]
    Confirm {
        #[command(subcommand)]
        command: ConfirmCommand,
    },

    // Tools commands
    #[command(long_about = "Generate a password/passphrase.")]
    #[command(after_help = r#"Notes:
    Default options are `-uln --length 14`.
    Minimum `length` is 5.
    Minimum `words` is 3.

Examples:
    bw generate
    bw generate -u -l --length 18
    bw generate -ulns --length 25
    bw generate -ul
    bw generate -p --separator _
    bw generate -p --words 5 --separator space
    bw generate -p --words 5 --separator empty
    "#)]
    Generate(GenerateArgs),
    #[command(long_about = "Import vault data from a file.")]
    Import(ImportArgs),
    #[command(long_about = "Export vault data to a CSV, JSON or ZIP file.")]
    Export(ExportArgs),
    #[command(
        long_about = "Work with Bitwarden sends. A Send can be quickly created using this command or subcommands can be used to fine-tune the Send."
    )]
    Send(SendArgs),
    #[command(long_about = "Access a Bitwarden Send from a url.")]
    Receive(ReceiveArgs),

    // Device approval commands
    #[command(
        long_about = "Manage device approval requests sent to organizations that use SSO with trusted devices."
    )]
    DeviceApproval,

    // Server commands
    #[command(long_about = "Start a RESTful API webserver.")]
    Serve(ServeArgs),
}

#[derive(clap::Args, Clone)]
pub struct ServeArgs {
    #[arg(long, help = "Port number to listen on.", default_value = "8087")]
    pub port: u16,

    #[arg(long, help = "Hostname to bind to.", default_value = "localhost")]
    pub hostname: String,

    #[arg(
        long,
        help = "Disable origin protection (not recommended for production use)."
    )]
    pub disable_origin_protection: bool,
}

#[derive(clap::Args, Clone)]
pub struct ListArgs {
    /// The type of object to list
    pub object: ListObject,

    #[arg(long, help = "Filter items by URL")]
    pub url: Option<String>,

    #[arg(long, help = "Filter items by folder ID")]
    pub folderid: Option<String>,

    #[arg(long, help = "Filter items by collection ID")]
    pub collectionid: Option<String>,

    #[arg(long, help = "Filter items by organization ID")]
    pub organizationid: Option<String>,

    #[arg(long, help = "Filter items in trash")]
    pub trash: bool,

    #[arg(long, help = "Search term")]
    pub search: Option<String>,
}

#[derive(clap::Args, Clone)]
pub struct EditArgs {
    /// The type of object to edit
    pub object: EditObject,
    /// Object ID
    pub id: String,
    /// Base64-encoded JSON object (optional, can read from stdin)
    pub encoded_json: Option<String>,

    #[arg(long, help = "Organization ID for an organization object")]
    pub organizationid: Option<String>,
}

#[derive(clap::ValueEnum, Clone, Debug)]
#[value(rename_all = "kebab-case")]
pub enum ListObject {
    Items,
    Folders,
    Collections,
    Organizations,
    OrgCollections,
    OrgMembers,
}

#[derive(clap::ValueEnum, Clone, Debug)]
#[value(rename_all = "kebab-case")]
pub enum EditObject {
    Item,
    ItemCollections,
    Folder,
    OrgCollection,
}

#[derive(Subcommand, Clone, Debug)]
pub enum GetCommands {
    #[command(long_about = "Get an item from the vault.")]
    Item { id: String },

    #[command(long_about = "Get the username for an item.")]
    Username { id: String },

    #[command(long_about = "Get the password for an item.")]
    Password { id: String },

    #[command(long_about = "Get the URI for an item.")]
    Uri { id: String },

    #[command(long_about = "Get the TOTP code for an item.")]
    Totp { id: String },

    #[command(long_about = "Check if an item password has been exposed in a data breach.")]
    Exposed { id: String },

    #[command(long_about = "Get the notes for an item.")]
    Notes { id: String },

    #[command(long_about = "Get a folder from the vault.")]
    Folder { id: String },

    #[command(long_about = "Get a collection from the vault.")]
    Collection { id: String },

    #[command(long_about = "Get an organization.")]
    Organization { id: String },

    #[command(long_about = "Get an organization collection.")]
    #[command(name = "org-collection")]
    OrgCollection { id: String },

    #[command(long_about = "Get an attachment from an item.")]
    Attachment {
        filename: String,
        #[arg(long, help = "Item ID that the attachment belongs to.")]
        itemid: String,
        #[arg(long, help = "Output file path. If not specified, outputs to stdout.")]
        output: Option<String>,
    },

    #[command(long_about = "Get the fingerprint for the current user or a specified user.")]
    Fingerprint {
        #[arg(default_value = "me", help = "User ID or 'me' for current user")]
        user: String,
    },

    #[command(long_about = "Get a JSON template for creating objects.")]
    Template {
        #[command(subcommand)]
        command: TemplateCommands,
    },

    #[command(long_about = "Get a Bitwarden Send.")]
    Send { id: String },
}

#[derive(Subcommand, Clone, Debug)]
pub enum CreateCommands {
    #[command(long_about = "Create an item in the vault.")]
    Item {
        #[arg(help = "Base64-encoded JSON item object")]
        encoded_json: String,
    },

    #[command(long_about = "Create an attachment for an item.")]
    Attachment {
        #[arg(long, help = "Path to the file to attach")]
        file: String,
        #[arg(long, help = "Item ID to attach the file to")]
        itemid: String,
    },

    #[command(long_about = "Create a folder.")]
    Folder {
        #[arg(help = "Base64-encoded JSON folder object")]
        encoded_json: String,
    },

    #[command(long_about = "Create an organization collection.")]
    #[command(name = "org-collection")]
    OrgCollection {
        #[arg(help = "Base64-encoded JSON collection object")]
        encoded_json: String,

        #[arg(long, help = "Organization ID")]
        organizationid: Option<String>,
    },
}

#[derive(Subcommand, Clone, Debug)]
pub enum DeleteCommands {
    #[command(long_about = "Delete an item from the vault.")]
    Item {
        id: String,
        #[arg(short = 'p', long, help = "Permanently delete the item (skip trash)")]
        permanent: bool,
    },

    #[command(long_about = "Delete an attachment from an item.")]
    Attachment {
        id: String,
        #[arg(long, help = "Item ID that the attachment belongs to")]
        itemid: String,
    },

    #[command(long_about = "Delete a folder.")]
    Folder {
        id: String,
        #[arg(short = 'p', long, help = "Permanently delete the folder (skip trash)")]
        permanent: bool,
    },

    #[command(long_about = "Delete an organization collection.")]
    #[command(name = "org-collection")]
    OrgCollection {
        id: String,
        #[arg(long, help = "Organization ID")]
        organizationid: String,
    },
}
