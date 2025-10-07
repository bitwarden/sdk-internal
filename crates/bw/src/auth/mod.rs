use bitwarden_cli::text_prompt_when_none;
use bitwarden_core::ClientSettings;
use clap::{Args, Subcommand};

mod login;
use inquire::Password;

use crate::render::CommandResult;

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

#[derive(Args, Clone)]
pub struct RegisterArgs {
    #[arg(short = 'e', long, help = "Email address")]
    email: Option<String>,

    name: Option<String>,

    password_hint: Option<String>,

    #[arg(short = 's', long, global = true, help = "Server URL")]
    server: Option<String>,
}

impl RegisterArgs {
    #[allow(unused_variables, clippy::unused_async)]
    pub async fn run(self) -> CommandResult {
        let settings = self.server.map(|server| ClientSettings {
            api_url: format!("{server}/api"),
            identity_url: format!("{server}/identity"),
            ..Default::default()
        });
        let client = bitwarden_core::Client::new(settings);

        let email = text_prompt_when_none("Email", self.email)?;
        let password = Password::new("Password").prompt()?;

        unimplemented!("Registration is not yet implemented");
    }
}
