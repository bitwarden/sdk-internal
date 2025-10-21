use bitwarden_cli::Color;
use clap::{Args, Parser, Subcommand};

use crate::{
    admin_console::ConfirmCommand,
    auth::{LoginArgs, RegisterArgs},
    platform::ConfigCommand,
    render::Output,
    tools::GenerateArgs,
    vault::{ItemCommands, TemplateCommands},
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

    #[command(long_about = "Register a new user account.")]
    Register(RegisterArgs),

    // KM commands
    #[command(long_about = "Unlock the vault and return a session key.")]
    Unlock(UnlockArgs),

    // Platform commands
    #[command(long_about = "Pull the latest vault data from server.")]
    Sync {
        #[arg(short = 'f', long, help = "Force a full sync.")]
        force: bool,

        #[arg(long, help = "Get the last sync date.")]
        last: bool,
    },

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

    // Vault commands
    #[command(long_about = "Manage vault objects.")]
    Item {
        #[command(subcommand)]
        command: ItemCommands,
    },
    #[command(long_about = "Get the available templates")]
    Template {
        #[command(subcommand)]
        command: TemplateCommands,
    },

    // These are the old style action-name commands, to be replaced by name-action commands in the
    // future
    #[command(long_about = "List an array of objects from the vault.")]
    List,
    #[command(long_about = "Get an object from the vault.")]
    Get,
    #[command(long_about = "Create an object in the vault.")]
    Create,
    #[command(long_about = "Edit an object from the vault.")]
    Edit,
    #[command(long_about = "Delete an object from the vault.")]
    Delete,
    #[command(long_about = "Restores an object from the trash.")]
    Restore,
    #[command(long_about = "Move an item to an organization.")]
    Move,

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
    Import,
    #[command(long_about = "Export vault data to a CSV, JSON or ZIP file.")]
    Export,
    #[command(long_about = "--DEPRECATED-- Move an item to an organization.")]
    Share,
    #[command(
        long_about = "Work with Bitwarden sends. A Send can be quickly created using this command or subcommands can be used to fine-tune the Send."
    )]
    Send,
    #[command(long_about = "Access a Bitwarden Send from a url.")]
    Receive,
}

#[derive(Args, Clone)]
pub struct UnlockArgs {
    pub password: Option<String>,

    #[arg(long, help = "Environment variable storing your password.")]
    pub passwordenv: Option<String>,

    #[arg(
        long,
        help = "Path to a file containing your password as its first line."
    )]
    pub passwordfile: Option<String>,

    #[arg(long, help = "Only return the session key.")]
    pub raw: bool,
}
