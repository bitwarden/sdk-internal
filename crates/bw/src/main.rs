#![doc = include_str!("../README.md")]
#![allow(
    clippy::print_stdout,
    clippy::print_stderr,
    reason = "The CLI uses stdout/stderr for user interaction"
)]

use bitwarden_cli::install_color_eyre;
use bitwarden_core::global::GlobalClient;
use bitwarden_pm::PasswordManagerClient;
use clap::{CommandFactory, FromArgMatches};
use color_eyre::eyre::Result;
use tracing_subscriber::{
    EnvFilter, prelude::__tracing_subscriber_SubscriberExt as _, util::SubscriberInitExt as _,
};

use crate::{client_state::ClientContext, command::Cli, render::CommandResult};

mod admin_console;
mod auth;
mod cli_runtime;
mod client_state;
mod command;
mod dirt;
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

    let cli_command = cli_runtime::assemble_cli(Cli::command());
    let matches = cli_command.get_matches();
    let cli = Cli::from_arg_matches(&matches)?;

    install_color_eyre(cli.color)?;
    let render_config = render::RenderConfig::new(&cli);

    if matches.subcommand().is_none() {
        let mut cmd = cli_runtime::assemble_cli(Cli::command());
        cmd.print_help()?;
        return Ok(());
    }

    let result = process_command(&matches).await;
    render_config.render_result(result)
}

async fn process_command(matches: &clap::ArgMatches) -> CommandResult {
    // Temporary until rehydration
    let user_client = if let (Ok(email), Ok(password)) =
        (std::env::var("BW_EMAIL"), std::env::var("BW_PASSWORD"))
    {
        let client = PasswordManagerClient::new(None);
        temp_login(&client.0, email, password).await?;
        Some(client)
    } else {
        None
    };

    let ctx = ClientContext {
        global: GlobalClient::new(None),
        user: user_client,
    };

    cli_runtime::dispatch(matches, ctx).await
}

// Stop-gap solution for login until we have a proper session management solution in place. This
// allows us to test the commands that require authentication without having to implement
// rehydration.
async fn temp_login(
    client: &bitwarden_core::Client,
    email: String,
    password: String,
) -> color_eyre::eyre::Result<()> {
    use bitwarden_core::auth::login::PasswordLoginRequest;

    let result = client
        .auth()
        .login_password(&PasswordLoginRequest {
            email,
            password,
            two_factor: None,
        })
        .await?;

    tracing::info!("Login result: {:?}", result);

    Ok(())
}
