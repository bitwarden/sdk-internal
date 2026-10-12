//! Binary entry point for the Bitwarden PAM access connector.

use bitwarden_access_connector::cli::{Cli, Command};
use clap::Parser;

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let cli = Cli::parse();

    match cli.command {
        Command::Run(_args) => Err("the access connector poll loop is not yet implemented".into()),
    }
}
