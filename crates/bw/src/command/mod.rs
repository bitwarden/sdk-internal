//! Top-level CLI globals for the Bitwarden CLI (`bw`).
//!
//! The [`Cli`] struct defines global flags (`--output`, `--color`, `--session`, etc.).
//! Subcommands are registered via the [`crate::cli_runtime`] inventory and assembled at startup,
//! so no `Commands` enum is defined here.

use bitwarden_cli::Color;
use clap::Parser;

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
