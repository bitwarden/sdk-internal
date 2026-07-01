#![doc = include_str!("../README.md")]
#![allow(
    clippy::print_stdout,
    clippy::print_stderr,
    reason = "The CLI uses stdout/stderr for user interaction"
)]

use std::sync::Arc;

use bitwarden_auth::token_management::PasswordManagerTokenHandler;
use bitwarden_cli::install_color_eyre;
use bitwarden_core::{
    DeviceType, GlobalClient, HostPlatformInfo, client::persisted_state::BaseUrls,
    get_host_platform_info, init_host_platform_info,
};
use bitwarden_pm::{
    PasswordManagerClient, SaveStateData, SessionKey, UnlockMethod,
    migrations::get_sdk_managed_migrations,
};
use bitwarden_state::{DatabaseConfiguration, registry::StateRegistry};
use clap::{CommandFactory, Parser};
use color_eyre::eyre::Result;
use tracing_subscriber::{
    EnvFilter, prelude::__tracing_subscriber_SubscriberExt as _, util::SubscriberInitExt as _,
};

use crate::{
    client_state::{BwCommandExt, ClientContext},
    command::*,
    platform::appdata_dir,
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

async fn process_commands(command: Commands, session: Option<SessionKey>) -> CommandResult {
    let global = GlobalClient::new();

    let user = match rehydrate_user(session).await? {
        Some(client) => Some(client),
        // Legacy stop-gap: with no persisted session, bootstrap one from the BW_EMAIL / BW_PASSWORD
        // env vars. `legacy_temp_login` logs in, persists the session, and prints a `BW_SESSION`
        // key; we then exit so the user can export it and re-run. Removed once `bw login` writes
        // its own session state.
        None => {
            legacy_temp_login().await?;
            None
        }
    };

    let ctx = ClientContext { global, user };

    match command {
        // Auth commands
        Commands::Login(args) => args.run().await,
        Commands::Logout => todo!(),

        // KM commands
        Commands::Lock(args) => args.dispatch(ctx).await,
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
        Commands::Send(args) => args.dispatch(ctx).await,
        Commands::Receive(_args) => todo!(),

        // Server commands
        Commands::Serve(_args) => todo!(),
    }
}

/// Rehydrate a [`PasswordManagerClient`] from the persisted session database.
///
/// Returns `Ok(None)` when no session has been persisted yet. Failures to load from state or unlock
/// with the provided session key are logged as warnings and fail gracefully into a logged out or
/// locked state respectively, to match the old CLI behavior.
async fn rehydrate_user(session: Option<SessionKey>) -> Result<Option<PasswordManagerClient>> {
    let registry =
        match StateRegistry::new_with_db(db_config()?, get_sdk_managed_migrations()).await {
            Ok(r) => r,
            Err(e) => {
                tracing::warn!("Failed to open session database: {e}");
                return Ok(None);
            }
        };

    let token_handler = Arc::new(PasswordManagerTokenHandler::default());
    let client = match PasswordManagerClient::load_from_state(token_handler, registry).await {
        Ok(c) => c,
        Err(e) => {
            tracing::warn!("Failed to initialize from session: {e}");
            return Ok(None);
        }
    };

    if let Some(key) = session
        && let Err(e) = client.unlock().unlock(UnlockMethod::SessionKey(key)).await
    {
        tracing::warn!("Failed to unlock with provided session key: {e}");
        return Ok(Some(client));
    }

    Ok(Some(client))
}

fn db_config() -> Result<DatabaseConfiguration> {
    Ok(DatabaseConfiguration::Sqlite {
        db_name: "user".to_string(),
        folder_path: appdata_dir()?,
    })
}

/// One-shot bootstrap login for commands that need an authenticated user before `bw login` writes
/// its own session state. When the `BW_EMAIL` / `BW_PASSWORD` env vars are set, logs in against the
/// persisted session database, persists the resulting session state (tokens, login method, account
/// crypto state, and a session-key envelope), and mints a session key which it prints for the user
/// to export as `BW_SESSION` and reuse on subsequent runs. Does nothing when the env vars are
/// unset.
async fn legacy_temp_login() -> Result<()> {
    use bitwarden_core::{
        ClientBuilder, UserId,
        auth::{JwtToken, login::PasswordLoginRequest},
        client::persisted_state::AUTHENTICATION_TOKENS,
        key_management::account_cryptographic_state::WrappedAccountCryptographicState,
    };
    use color_eyre::eyre::eyre;

    let (Ok(email), Ok(password)) = (std::env::var("BW_EMAIL"), std::env::var("BW_PASSWORD"))
    else {
        return Ok(());
    };

    let urls = BaseUrls {
        api_url: "https://api.bitwarden.com".into(),
        identity_url: "https://identity.bitwarden.com".into(),
    };

    let settings = get_host_platform_info()
        .to_client_settings(urls.api_url.clone(), urls.identity_url.clone());

    // Clear any existing session state
    StateRegistry::new_with_db(db_config()?, get_sdk_managed_migrations())
        .await?
        .wipe()
        .await
        .ok();

    // `wipe` leaves its registry unusable, so open a fresh one to back the login client.
    let registry = StateRegistry::new_with_db(db_config()?, get_sdk_managed_migrations()).await?;
    let client = PasswordManagerClient(
        ClientBuilder::new()
            .with_settings(settings)
            .with_token_handler(Arc::new(PasswordManagerTokenHandler::default()))
            .with_state(registry)
            .build(),
    );

    client
        .0
        .auth()
        .login_password(&PasswordLoginRequest {
            email: email.clone(),
            password,
            two_factor: None,
        })
        .await?;

    let tokens = client
        .platform()
        .state()
        .setting(AUTHENTICATION_TOKENS)?
        .get()
        .await?
        .ok_or_else(|| eyre!("login did not persist authentication tokens"))?;

    let user_id: UserId = tokens.access_token.parse::<JwtToken>()?.sub.parse()?;

    let crypto_state = {
        let store = client.0.internal.get_key_store();
        WrappedAccountCryptographicState::get_from_key_store(&store.context())?
    };

    let save_registry =
        StateRegistry::new_with_db(db_config()?, get_sdk_managed_migrations()).await?;
    PasswordManagerClient::save_to_state(
        SaveStateData {
            user_id,
            email: email.clone(),
            urls,
            crypto_state,
        },
        &save_registry,
    )
    .await?;

    let session = client.unlock().generate_session_key().await?;

    println!("Logged in as {email} via legacy temp login");
    println!("Use the following session key to unlock your vault:");
    println!("export BW_SESSION={session}");
    std::process::exit(0);
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
