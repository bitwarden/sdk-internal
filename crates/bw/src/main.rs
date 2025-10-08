#![doc = include_str!("../README.md")]

use base64::{Engine, engine::general_purpose::STANDARD};
use bitwarden_cli::install_color_eyre;
use clap::{CommandFactory, Parser};
use clap_complete::Shell;
use color_eyre::eyre::Result;
use env_logger::Target;

use crate::{command::*, render::CommandResult};

mod admin_console;
mod auth;
mod command;
mod platform;
mod render;
mod tools;
mod vault;

#[tokio::main(flavor = "current_thread")]
async fn main() -> Result<()> {
    env_logger::Builder::from_env(env_logger::Env::default().default_filter_or("info"))
        .target(Target::Stderr)
        .init();

    let cli = Cli::parse();
    install_color_eyre(cli.color)?;
    let render_config = render::RenderConfig::new(&cli);

    let Some(command) = cli.command else {
        let mut cmd = Cli::command();
        cmd.print_help()?;
        return Ok(());
    };

    let result = process_commands(command, cli.session).await;

    // Render the result of the command
    render_config.render_result(result)
}

async fn process_commands(command: Commands, _session: Option<String>) -> CommandResult {
    // Try to initialize the client with the session if provided
    // Ideally we'd have separate clients and this would be an enum, something like:
    // enum CliClient {
    //   Unlocked(_),  // If the user already logged in and the provided session is valid
    //   Locked(_),    // If the user is logged in, but the session hasn't been provided
    //   LoggedOut(_), // If the user is not logged in
    // }
    // If the session was invalid, we'd just return an error immediately
    // This would allow each command to match on the client type that they need, and we don't need
    // to do two matches over the whole command tree
    let client = bitwarden_pm::PasswordManagerClient::new(None);

    match command {
        // Auth commands
        Commands::Login(args) => args.run().await,
        Commands::Logout => todo!(),
        Commands::Register(register) => register.run().await,

        // KM commands
        Commands::Unlock(_args) => todo!(),

        // Platform commands
        Commands::Sync { .. } => todo!(),

        Commands::Encode => {
            let input = std::io::read_to_string(std::io::stdin())?;
            let encoded = STANDARD.encode(input);
            Ok(encoded.into())
        }

        Commands::Config { command } => command.run().await,

        Commands::Update { .. } => todo!(),

        Commands::Completion { shell } => {
            let Some(shell) = shell.or_else(Shell::from_env) else {
                return Ok(
                    "Couldn't autodetect a valid shell. Run `bw completion --help` for more info."
                        .into(),
                );
            };

            let mut cmd = Cli::command();
            let name = cmd.get_name().to_string();
            clap_complete::generate(shell, &mut cmd, name, &mut std::io::stdout());
            Ok(().into())
        }

        Commands::Status => todo!(),

        // Vault commands
        Commands::Item { command: _ } => todo!(),
        Commands::Template { command } => command.run(),

        Commands::List => todo!(),
        Commands::Get => todo!(),
        Commands::Create => todo!(),
        Commands::Edit => todo!(),
        Commands::Delete => todo!(),
        Commands::Restore => todo!(),
        Commands::Move => todo!(),

        // Admin console commands
        Commands::Confirm { .. } => todo!(),

        // Tools commands
        Commands::Generate(arg) => arg.run(&client),
        Commands::Import => todo!(),
        Commands::Export => todo!(),
        Commands::Share => todo!(),
        Commands::Send => todo!(),
        Commands::Receive => todo!(),
    }
}
