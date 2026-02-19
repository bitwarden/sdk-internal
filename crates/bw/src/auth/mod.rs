use bitwarden_core::ClientSettings;
use clap::{Args, Subcommand};

use crate::render::CommandResult;

mod login;

pub(crate) mod logout;
pub(crate) mod state;
pub(crate) mod unlock;

// TODO(CLI): This is incompatible with the current node CLI
#[derive(Args, Clone)]
pub struct LoginArgs {
    #[command(subcommand)]
    pub command: LoginCommands,

    #[arg(short = 's', long, global = true, help = "Server URL")]
    pub server: Option<String>,
}

#[derive(Subcommand, Clone)]
pub enum LoginCommands {
    Password {
        #[arg(short = 'e', long, help = "Email address")]
        email: Option<String>,
    },
    ApiKey {
        client_id: Option<String>,
        client_secret: Option<String>,
    },
    Device {
        #[arg(short = 'e', long, help = "Email address")]
        email: Option<String>,
        device_identifier: Option<String>,
    },
}

impl LoginArgs {
    pub async fn run(self) -> CommandResult {
        let settings = self.server.map(|server| ClientSettings {
            api_url: format!("{server}/api"),
            identity_url: format!("{server}/identity"),
            ..Default::default()
        });
        let client = bitwarden_core::Client::new(settings);

        match self.command {
            // FIXME: Rust CLI will not support password login!
            LoginCommands::Password { email } => {
                login::login_password(client, email).await?;
            }
            LoginCommands::ApiKey {
                client_id,
                client_secret,
            } => login::login_api_key(client, client_id, client_secret).await?,
            LoginCommands::Device {
                email,
                device_identifier,
            } => {
                login::login_device(client, email, device_identifier).await?;
            }
        }
        Ok("Successfully logged in!".into())
    }
}
