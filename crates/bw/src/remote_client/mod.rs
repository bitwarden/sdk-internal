//! Remote client CLI command
//!
//! Provides a CLI interface for connecting to a user-client through a proxy
//! to request credentials over a secure Noise Protocol channel.

use bitwarden_noise_client::{
    RemoteClient, RemoteClientConfig, RemoteClientEvent, SessionCache, clear_all_keypairs,
    list_devices,
};
use clap::{Args, Subcommand};
use color_eyre::eyre::{Result, bail};
use inquire::Text;
use tokio::sync::mpsc;
use tracing::info;

use crate::render::CommandResult;

const DEFAULT_PROXY_URL: &str = "ws://localhost:8080";

/// Remote client command arguments
#[derive(Args, Clone)]
pub struct RemoteClientArgs {
    #[command(subcommand)]
    pub command: Option<RemoteClientCommand>,

    /// Proxy server URL
    #[arg(long, default_value = DEFAULT_PROXY_URL)]
    pub proxy_url: String,

    /// Pairing code (format: password:metadata)
    #[arg(long)]
    pub pair_code: Option<String>,

    /// Client ID for this device
    #[arg(long)]
    pub client_id: Option<String>,

    /// Disable session caching
    #[arg(long)]
    pub no_cache: bool,
}

/// Remote client subcommands
#[derive(Subcommand, Clone)]
pub enum RemoteClientCommand {
    /// Clear all cached sessions
    ClearCache,
    /// List cached sessions
    ListCache,
    /// List stored device keypairs
    ListDevices,
    /// Clear all device keypairs
    ClearKeypairs,
}

impl RemoteClientArgs {
    /// Run the remote-client command
    pub async fn run(self) -> CommandResult {
        // Handle subcommands first
        if let Some(cmd) = self.command {
            return match cmd {
                RemoteClientCommand::ClearCache => {
                    let cache = SessionCache::default();
                    cache
                        .clear_all()
                        .map_err(|e| color_eyre::eyre::eyre!(e.to_string()))?;
                    Ok("Session cache cleared successfully".into())
                }
                RemoteClientCommand::ListCache => {
                    let cache = SessionCache::default();
                    let sessions = cache.list();
                    if sessions.is_empty() {
                        Ok("No cached sessions found".into())
                    } else {
                        let mut output = format!("Found {} cached session(s):\n", sessions.len());
                        for session in sessions {
                            let client_info = session
                                .client_id
                                .map(|c| format!(" [{}]", c))
                                .unwrap_or_default();
                            output.push_str(&format!(
                                "  - {}{} (created: {})\n",
                                session.username,
                                client_info,
                                format_timestamp(session.created_at)
                            ));
                        }
                        Ok(output.into())
                    }
                }
                RemoteClientCommand::ListDevices => {
                    let devices =
                        list_devices().map_err(|e| color_eyre::eyre::eyre!(e.to_string()))?;
                    if devices.is_empty() {
                        Ok("No stored device keypairs found".into())
                    } else {
                        let mut output = format!("Found {} device keypair(s):\n", devices.len());
                        for device in devices {
                            output.push_str(&format!("  - {}\n", device));
                        }
                        Ok(output.into())
                    }
                }
                RemoteClientCommand::ClearKeypairs => {
                    clear_all_keypairs().map_err(|e| color_eyre::eyre::eyre!(e.to_string()))?;
                    Ok("All device keypairs cleared successfully".into())
                }
            };
        }

        // Interactive session mode
        run_interactive_session(self).await
    }
}

async fn run_interactive_session(args: RemoteClientArgs) -> CommandResult {
    let cache = SessionCache::default();

    // Get pairing code
    let pairing_code = if let Some(code) = args.pair_code {
        code
    } else {
        // Check for cached sessions
        let sessions = cache.list();
        if !sessions.is_empty() && !args.no_cache {
            println!("Found {} cached session(s):", sessions.len());
            for (i, session) in sessions.iter().enumerate().take(5) {
                let client_info = session
                    .client_id
                    .as_ref()
                    .map(|c| format!(" [{}]", c))
                    .unwrap_or_default();
                println!(
                    "  {}. {}{} ({})",
                    i + 1,
                    session.username,
                    client_info,
                    format_timestamp(session.created_at)
                );
            }
            println!("  N. New connection\n");

            let choice = Text::new("Select session (number) or 'N' for new:")
                .prompt()
                .map_err(|e| color_eyre::eyre::eyre!("Input error: {}", e))?;

            if choice.to_lowercase() == "n" || choice.is_empty() {
                prompt_for_pairing_code()?
            } else if let Ok(idx) = choice.parse::<usize>() {
                if idx > 0 && idx <= sessions.len() {
                    // Use cached session - we still need a pairing code for username extraction
                    // but the PSK will be loaded from cache
                    let session = &sessions[idx - 1];
                    println!("Using cached session for: {}", session.username);
                    // For cached sessions, we create a dummy pairing code that will be ignored
                    // since the PSK is already cached
                    "cached:e30=".to_string() // "cached" + base64("{}") - will be overridden
                } else {
                    bail!("Invalid selection");
                }
            } else {
                bail!("Invalid selection");
            }
        } else {
            prompt_for_pairing_code()?
        }
    };

    // Decode pairing code to get username
    let username = match bitwarden_noise::psk::decode_pairing_code(&pairing_code) {
        Ok(decoded) => decoded.username,
        Err(_) => {
            // If decoding fails, prompt for username
            Text::new("Username:")
                .prompt()
                .map_err(|e| color_eyre::eyre::eyre!("Input error: {}", e))?
        }
    };

    // Get client ID
    let client_id = if let Some(id) = args.client_id {
        Some(id)
    } else {
        let input = Text::new("Client ID (optional):")
            .prompt()
            .map_err(|e| color_eyre::eyre::eyre!("Input error: {}", e))?;
        if input.is_empty() { None } else { Some(input) }
    };

    let config = RemoteClientConfig {
        proxy_url: args.proxy_url,
        username,
        pairing_code,
        client_id,
        use_cached_auth: !args.no_cache,
    };

    println!("\nConnecting to proxy...");
    if args.no_cache {
        println!("Session caching disabled");
    } else {
        println!("Session caching enabled (use --no-cache to disable)");
    }
    println!("Waiting for user approval from trusted device...\n");

    // Create event channel
    let (event_tx, mut event_rx) = mpsc::channel(32);

    // Create client and connect
    let mut client = RemoteClient::new(Some(cache));

    // Spawn event handler
    let event_handle = tokio::spawn(async move {
        while let Some(event) = event_rx.recv().await {
            handle_event(&event);
        }
    });

    // Connect
    if let Err(e) = client.connect(config, event_tx).await {
        bail!("Connection failed: {}", e);
    }

    println!("\nConnection established! You can now request credentials.");
    println!("Enter a domain to request credentials, or 'exit' to quit.\n");

    // Credential request loop
    loop {
        let domain = Text::new("Domain (or 'exit'):")
            .prompt()
            .map_err(|e| color_eyre::eyre::eyre!("Input error: {}", e))?;

        let domain_lower = domain.to_lowercase();
        if domain_lower == "exit" || domain_lower == "quit" {
            break;
        }

        if domain.is_empty() {
            println!("Domain is required\n");
            continue;
        }

        match client.request_credential(&domain).await {
            Ok(credential) => {
                println!("\nCREDENTIAL RECEIVED");
                println!("  Domain: {}", domain);
                if let Some(username) = &credential.username {
                    println!("  Username: {}", username);
                }
                if let Some(password) = &credential.password {
                    println!("  Password: {}", password);
                }
                if let Some(totp) = &credential.totp {
                    println!("  TOTP: {}", totp);
                }
                if let Some(uri) = &credential.uri {
                    println!("  URI: {}", uri);
                }
                println!();
            }
            Err(e) => {
                println!("Failed to get credential: {}\n", e);
            }
        }
    }

    println!("\nClosing connection...");
    client.close().await;
    event_handle.abort();

    Ok("Connection closed. Goodbye!".into())
}

fn prompt_for_pairing_code() -> Result<String> {
    let code = Text::new("Pairing code (format: password:metadata):")
        .prompt()
        .map_err(|e| color_eyre::eyre::eyre!("Input error: {}", e))?;

    if code.is_empty() {
        bail!("Pairing code is required");
    }

    if !code.contains(':') {
        bail!("Invalid format. Expected: password:metadata");
    }

    // Validate the pairing code
    bitwarden_noise::psk::decode_pairing_code(&code)
        .map_err(|e| color_eyre::eyre::eyre!("Invalid pairing code: {}", e))?;

    Ok(code)
}

fn handle_event(event: &RemoteClientEvent) {
    match event {
        RemoteClientEvent::Connecting { proxy_url } => {
            info!("Connecting to proxy: {}", proxy_url);
        }
        RemoteClientEvent::Connected { client_id } => {
            println!("Connected as: {}", client_id);
        }
        RemoteClientEvent::CacheCheck {
            has_cached_auth,
            username,
            ..
        } => {
            if *has_cached_auth {
                println!("Using cached authentication for {}", username);
            } else {
                println!("Performing full authentication");
            }
        }
        RemoteClientEvent::AuthStart { phase } => {
            println!("Starting authentication ({})", phase);
        }
        RemoteClientEvent::AuthComplete { session_cached, .. } => {
            if *session_cached {
                println!("Authentication complete (session cached)");
            } else {
                println!("Authentication complete");
            }
        }
        RemoteClientEvent::HandshakeStart => {
            println!("Starting secure channel handshake...");
        }
        RemoteClientEvent::HandshakeProgress { message } => {
            info!("Handshake: {}", message);
        }
        RemoteClientEvent::HandshakeComplete => {
            println!("Secure channel established");
        }
        RemoteClientEvent::Ready { .. } => {
            // Handled in main loop
        }
        RemoteClientEvent::CredentialRequestSent { domain } => {
            println!("Requesting credential for: {}...", domain);
        }
        RemoteClientEvent::CredentialReceived { domain, .. } => {
            info!("Credential received for: {}", domain);
        }
        RemoteClientEvent::Error { message, context } => {
            let ctx = context.as_deref().unwrap_or("unknown");
            println!("Error ({}): {}", ctx, message);
        }
        RemoteClientEvent::Disconnected { reason } => {
            let reason_str = reason.as_deref().unwrap_or("unknown");
            println!("Disconnected: {}", reason_str);
        }
    }
}

fn format_timestamp(ts: u64) -> String {
    // Simple timestamp formatting
    use std::time::{Duration, UNIX_EPOCH};

    let datetime = UNIX_EPOCH + Duration::from_secs(ts);
    if let Ok(elapsed) = datetime.elapsed() {
        let secs = elapsed.as_secs();
        if secs < 60 {
            "just now".to_string()
        } else if secs < 3600 {
            format!("{} min ago", secs / 60)
        } else if secs < 86400 {
            format!("{} hours ago", secs / 3600)
        } else {
            format!("{} days ago", secs / 86400)
        }
    } else {
        "unknown".to_string()
    }
}
