//! Top-level CLI globals for the Bitwarden CLI (`bw`).
//!
//! The [`Cli`] struct defines global flags (`--output`, `--color`, `--session`, etc.).
//! Subcommands are registered via the [`crate::cli_runtime`] inventory and assembled at startup,
//! so no `Commands` enum is defined here.

use bitwarden_cli::Color;
use bw_macro::bw_command;
use clap::{Args, Parser};

use crate::render::Output;

pub const SESSION_ENV: &str = "BW_SESSION";

#[derive(Parser, Clone, Debug)]
#[command(
    name = "Bitwarden CLI",
    version,
    about = "Bitwarden CLI",
    long_about = None,
    disable_version_flag = true,
)]
pub struct Cli {
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

// Top-level commands with no natural team owner. Each registers itself into the command inventory
// via `#[bw_command]` so it surfaces in the CLI alongside team-owned commands.

#[derive(Args, Clone)]
#[bw_command(path = "logout", todo, about = "Log out of the current user account.")]
pub struct LogoutArgs;

#[derive(Args, Clone)]
#[bw_command(
    path = "lock",
    todo,
    about = "Lock the vault and destroy active session keys."
)]
pub struct LockArgs;

#[derive(Args, Clone)]
#[bw_command(path = "encode", todo, about = "Base 64 encode stdin.")]
pub struct EncodeArgs;

#[derive(Args, Clone)]
#[bw_command(path = "update", todo, about = "Check for updates.")]
pub struct UpdateArgs {
    #[arg(long, help = "Return only the download URL for the update.")]
    pub raw: bool,
}

#[derive(Args, Clone)]
#[bw_command(
    path = "device-approval",
    todo,
    about = "Manage device approval requests sent to organizations that use SSO with trusted devices."
)]
pub struct DeviceApprovalArgs;

#[derive(Args, Clone)]
#[bw_command(path = "completion", todo, about = "Generate shell completions.")]
pub struct CompletionArgs {
    #[arg(long, help = "The shell to generate completions for.")]
    pub shell: Option<String>,
}
