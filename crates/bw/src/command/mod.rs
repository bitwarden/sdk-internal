//! CLI command definitions and argument parsing for the Bitwarden CLI (`bw`).
//!
//! This module defines the top-level [`Cli`] struct and the [`Commands`] enum that together
//! describe every subcommand accepted by the CLI. Parsing is handled by
//! [clap](https://docs.rs/clap) using its derive API.
//!
//! Subcommand that have an explicit owner lives under the team's corresponding module, such as the
//! `sync` subcommand living under the `platform` module. Subcommands that don't have a clear owner,
//! such as `get item`, live in this module. Each subcommand has a `run` method that executes the
//! command's logic and returns a [`crate::render::CommandOutput`].

use bitwarden_cli::Color;
use clap::{Parser, Subcommand};

use crate::{
    admin_console::{ConfirmCommand, MoveArgs},
    auth::LoginArgs,
    key_management::UnlockArgs,
    platform::{ConfigCommand, ServeArgs, StatusArgs, SyncArgs},
    render::Output,
    tools::{ExportArgs, GenerateArgs, ImportArgs, ReceiveArgs, SendArgs},
    vault::RestoreArgs,
};

mod create;
mod delete;
mod edit;
mod get;
mod list;

pub(crate) use create::CreateCommands;
pub(crate) use delete::DeleteCommands;
pub(crate) use edit::EditCommands;
pub(crate) use get::GetCommands;
pub(crate) use list::ListCommands;

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
        alias = "cleanexit",
        help = "Exit with a success exit code (0) unless an error is thrown."
    )]
    pub clean_exit: bool,

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
        alias = "nointeraction",
        help = "Do not prompt for interactive user input."
    )]
    pub no_interaction: bool,

    // Clap uses uppercase V for the short flag by default, but we want lowercase v
    // for compatibility with the node CLI:
    // https://github.com/clap-rs/clap/issues/138
    #[arg(short = 'v', long, action = clap::builder::ArgAction::Version)]
    pub version: (),
}

#[derive(Subcommand, Clone)]
pub enum Commands {
    // Auth commands
    #[command(about = "Log into a user account.")]
    Login(LoginArgs),

    #[command(about = "Log out of the current user account.")]
    Logout,

    #[command(about = "Lock the vault and destroy active session keys.")]
    Lock,

    // KM commands
    #[command(about = "Unlock the vault and return a session key.")]
    Unlock(UnlockArgs),

    // Platform commands
    #[command(about = "Pull the latest vault data from server.")]
    Sync(SyncArgs),

    #[command(about = "Base 64 encode stdin.")]
    Encode,

    #[command(about = "Configure CLI settings.")]
    Config {
        #[command(subcommand)]
        command: ConfigCommand,
    },

    #[command(about = "Check for updates.")]
    Update {
        #[arg(long, help = "Return only the download URL for the update.")]
        raw: bool,
    },

    #[command(about = "Generate shell completions.")]
    Completion {
        #[arg(long, help = "The shell to generate completions for.")]
        shell: Option<clap_complete::Shell>,
    },

    Status(StatusArgs),

    // These are the old style action-name commands, to be replaced by name-action commands in the
    // future
    #[command(about = "List an array of objects from the vault.")]
    List {
        #[command(subcommand)]
        command: ListCommands,
    },
    #[command(about = "Get an object from the vault.")]
    Get {
        #[command(subcommand)]
        command: GetCommands,
    },
    #[command(about = "Create an object in the vault.")]
    Create {
        #[command(subcommand)]
        command: CreateCommands,
    },
    #[command(about = "Edit an object from the vault.")]
    Edit {
        #[command(subcommand)]
        command: EditCommands,
    },
    #[command(about = "Delete an object from the vault.")]
    Delete {
        #[command(subcommand)]
        command: DeleteCommands,
    },
    #[command(about = "Restores an object from the trash.")]
    Restore(RestoreArgs),
    #[command(about = "Move an item to an organization.")]
    Move(MoveArgs),

    // Admin console commands
    #[command(about = "Confirm an object to the organization.")]
    Confirm {
        #[command(subcommand)]
        command: ConfirmCommand,
    },

    // Tools commands
    Generate(GenerateArgs),
    #[command(about = "Import vault data from a file.")]
    Import(ImportArgs),
    #[command(about = "Export vault data to a CSV, JSON or ZIP file.")]
    Export(ExportArgs),
    #[command(
        long_about = "Work with Bitwarden sends. A Send can be quickly created using this command or subcommands can be used to fine-tune the Send."
    )]
    Send(SendArgs),
    #[command(about = "Access a Bitwarden Send from a url.")]
    Receive(ReceiveArgs),

    // Device approval commands
    #[command(
        long_about = "Manage device approval requests sent to organizations that use SSO with trusted devices."
    )]
    DeviceApproval,

    // Server commands
    #[command(about = "Start a RESTful API webserver.")]
    Serve(ServeArgs),
}
