#![doc = include_str!("../README.md")]

use base64::{Engine, engine::general_purpose::STANDARD};
use bitwarden_cli::install_color_eyre;
use clap::{CommandFactory, Parser};
use clap_complete::Shell;
use color_eyre::eyre::Result;
use tracing_subscriber::{
    EnvFilter, prelude::__tracing_subscriber_SubscriberExt as _, util::SubscriberInitExt as _,
};

use crate::{command::*, render::CommandResult};

mod admin_console;
mod auth;
mod command;
mod key_management;
mod platform;
mod render;
mod tools;
mod vault;

#[tokio::main(flavor = "current_thread")]
async fn main() -> Result<()> {
    // the log level hierarchy is determined by:
    //    - if RUST_LOG is detected at runtime
    //    - if RUST_LOG is provided at compile time
    //    - default to INFO
    let filter = EnvFilter::builder()
        .with_default_directive(
            option_env!("RUST_LOG")
                .unwrap_or("info")
                .parse()
                .expect("should provide valid log level at compile time."),
        )
        // parse directives from the RUST_LOG environment variable,
        // overriding the default directive for matching targets.
        .from_env_lossy();

    tracing_subscriber::registry()
        .with(tracing_subscriber::fmt::layer().with_writer(std::io::stderr))
        .with(filter)
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

        // KM commands
        Commands::Lock => todo!(),
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
        Commands::List(_args) => todo!(),
        Commands::Get { command } => match command {
            GetCommands::Template { command } => command.run(),
            _ => todo!("Get command implementation with {:?}", command),
        },
        Commands::Create { .. } => todo!(),
        Commands::Edit(_args) => todo!(),
        Commands::Delete { .. } => todo!(),
        Commands::Restore(_args) => todo!(),
        Commands::Move(_args) => todo!(),

        // Admin console commands
        Commands::Confirm { .. } => todo!(),
        Commands::DeviceApproval => todo!(),

        // Tools commands
        Commands::Generate(arg) => arg.run(&client),
        Commands::Import(_args) => todo!(),
        Commands::Export(_args) => todo!(),
        Commands::Send(_args) => todo!(),
        Commands::Receive(_args) => todo!(),

        // Server commands
        Commands::Serve(_args) => todo!(),
    }
}
