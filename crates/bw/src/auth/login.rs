use bitwarden_cli::text_prompt_when_none;
use bitwarden_core::{
    Client,
    auth::login::{
        ApiKeyLoginRequest, PasswordLoginRequest, TwoFactorEmailRequest, TwoFactorProvider,
        TwoFactorRequest,
    },
};
use color_eyre::eyre::{Result, bail};
use inquire::{Password, Text};
use tracing::{debug, error, info};

use crate::vault::{SyncRequest, sync};

/// Save authentication state to disk after successful login.
///
/// This helper function initializes the database if needed and persists the current
/// authentication state (tokens, user_id, login method) to allow session restoration
/// across CLI restarts.
async fn save_session_after_login(client: &Client) -> Result<()> {
    if client.internal.get_user_id().is_some() {
        // Initialize database if not already initialized
        crate::platform::state::initialize_database(client).await?;

        // Save auth state (extracts tokens internally)
        super::state::save(client).await?;

        crate::vault::sync(
            client,
            &crate::vault::SyncRequest {
                exclude_subdomains: None,
            },
        )
        .await?;

        info!("Session saved to disk");
    }
    Ok(())
}

pub(crate) async fn login_password(client: Client, email: Option<String>) -> Result<()> {
    let email = text_prompt_when_none("Email", email)?;

    let password = Password::new("Password").without_confirmation().prompt()?;

    let result = client
        .auth()
        .login_password(&PasswordLoginRequest {
            email: email.clone(),
            password: password.clone(),
            two_factor: None,
        })
        .await?;

    if let Some(two_factor) = result.two_factor {
        error!(?two_factor);

        let two_factor = if let Some(tf) = two_factor.authenticator {
            debug!(?tf);

            let token = Text::new("Authenticator code").prompt()?;

            Some(TwoFactorRequest {
                token,
                provider: TwoFactorProvider::Authenticator,
                remember: false,
            })
        } else if let Some(tf) = two_factor.email {
            // Send token
            client
                .auth()
                .send_two_factor_email(&TwoFactorEmailRequest {
                    email: email.clone(),
                    password: password.clone(),
                })
                .await?;

            info!(?tf, "Two factor code sent to");
            let token = Text::new("Two factor code").prompt()?;

            Some(TwoFactorRequest {
                token,
                provider: TwoFactorProvider::Email,
                remember: false,
            })
        } else {
            bail!("Not supported: {:?}", two_factor);
        };

        let result = client
            .auth()
            .login_password(&PasswordLoginRequest {
                email,
                password,
                two_factor,
            })
            .await?;

        debug!(?result);
    } else {
        debug!(?result);
    }

    let res = sync(
        &client,
        &SyncRequest {
            exclude_subdomains: Some(true),
        },
    )
    .await?;
    info!(?res);

    Ok(())
}

pub(crate) async fn login_api_key(
    client: Client,
    client_id: Option<String>,
    client_secret: Option<String>,
) -> Result<()> {
    let client_id = text_prompt_when_none("Client ID", client_id)?;
    let client_secret = text_prompt_when_none("Client Secret", client_secret)?;

    let password = Password::new("Password").without_confirmation().prompt()?;

    let result = client
        .auth()
        .login_api_key(&ApiKeyLoginRequest {
            client_id,
            client_secret,
            password,
        })
        .await?;

    debug!(?result);

    save_session_after_login(&client).await?;

    Ok(())
}

pub(crate) async fn login_device(
    client: Client,
    email: Option<String>,
    device_identifier: Option<String>,
) -> Result<()> {
    let email = text_prompt_when_none("Email", email)?;
    let device_identifier = text_prompt_when_none("Device Identifier", device_identifier)?;

    let auth = client.auth().login_device(email, device_identifier).await?;

    println!("Fingerprint: {}", auth.fingerprint);

    Text::new("Press enter once approved").prompt()?;

    client.auth().login_device_complete(auth).await?;

    Ok(())
}
