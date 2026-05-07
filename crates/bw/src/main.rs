#![doc = include_str!("../README.md")]
#![allow(
    clippy::print_stdout,
    clippy::print_stderr,
    reason = "The CLI uses stdout/stderr for user interaction"
)]

use bitwarden_cli::install_color_eyre;
use bitwarden_core::{DeviceType, GlobalClient, HostPlatformInfo, init_host_platform_info};
use clap::{CommandFactory, Parser};
use color_eyre::eyre::Result;
use tracing_subscriber::{
    EnvFilter, prelude::__tracing_subscriber_SubscriberExt as _, util::SubscriberInitExt as _,
};

use crate::{
    client_state::{BwCommandExt, ClientContext},
    command::*,
    render::CommandResult,
};

mod admin_console;
mod auth;
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

    init_cli_platform_info();

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
    let global = GlobalClient::new();

    // Temporary until session persistence (PM-35206): if the legacy env vars are present, eagerly
    // construct + log in a `PasswordManagerClient` so commands that need a logged-in user can run.
    let user = if let (Ok(email), Ok(password)) =
        (std::env::var("BW_EMAIL"), std::env::var("BW_PASSWORD"))
    {
        let client = bitwarden_pm::PasswordManagerClient::new(None);
        temp_login(&client.0, email, password).await?;
        Some(client)
    } else {
        None
    };

    let ctx = ClientContext { global, user };

    match command {
        // Auth commands
        Commands::Login(args) => args.run().await,
        Commands::Logout => todo!(),

        // KM commands
        Commands::Lock => todo!(),
        Commands::Unlock(_args) => todo!(),

        // Platform commands
        Commands::Sync(args) => args.dispatch(ctx).await,
        Commands::Encode(args) => args.dispatch(ctx).await,
        Commands::Config { command } => command.dispatch(ctx).await,
        Commands::Completion(args) => args.dispatch(ctx).await,

        Commands::Update { .. } => todo!(),

        Commands::Status(_) => todo!(),

        // Vault commands
        Commands::List { .. } => todo!(),
        Commands::Get { command } => command.run(),
        Commands::Create { command } => command.run(),
        Commands::Edit { .. } => todo!(),
        Commands::Delete { .. } => todo!(),
        Commands::Restore(_args) => todo!(),

        // Admin console commands
        Commands::Confirm { .. } => todo!(),
        Commands::DeviceApproval => todo!(),
        Commands::Move(_args) => todo!(),

        // Tools commands
        Commands::Generate(args) => {
            let client = ctx
                .user
                .unwrap_or_else(|| bitwarden_pm::PasswordManagerClient::new(None));
            args.run(&client)
        }
        Commands::Import(_args) => todo!(),
        Commands::Export(_args) => todo!(),
        Commands::Send(_args) => todo!(),
        Commands::Receive(_args) => todo!(),

        // Server commands
        Commands::Serve(_args) => todo!(),
    }
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

fn init_cli_platform_info() {
    let device_type = if cfg!(target_os = "windows") {
        DeviceType::WindowsCLI
    } else if cfg!(target_os = "macos") {
        DeviceType::MacOsCLI
    } else {
        DeviceType::LinuxCLI
    };

    init_host_platform_info(HostPlatformInfo {
        user_agent: format!("Bitwarden_CLI/{}", env!("CARGO_PKG_VERSION")),
        device_type,
        // Stable identifier comes from session persistence (PM-35206).
        device_identifier: None,
        bitwarden_client_version: Some(env!("CARGO_PKG_VERSION").to_string()),
        bitwarden_package_type: Some("cli".to_string()),
    });
}
