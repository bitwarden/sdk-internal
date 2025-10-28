use bitwarden_cli::{resolve_user_input_value, text_prompt_when_none};
use bitwarden_core::{
    Client,
    auth::login::{
        ApiKeyLoginRequest, PasswordLoginRequest, TwoFactorEmailRequest, TwoFactorProvider,
        TwoFactorRequest,
    },
};
use bitwarden_vault::{SyncRequest, VaultClientExt};
use color_eyre::eyre::{Result, bail};
use inquire::{Password, Text};
use log::{debug, error, info};

use crate::auth::tmp_session::export_session;

pub(crate) async fn login_password(client: Client, email: Option<String>) -> Result<()> {
    let email = text_prompt_when_none("Email", email)?;

    let password = Password::new("Password").without_confirmation().prompt()?;

    let kdf = client.auth().prelogin(email.clone()).await?;

    let result = client
        .auth()
        .login_password(&PasswordLoginRequest {
            email: email.clone(),
            password: password.clone(),
            two_factor: None,
            kdf: kdf.clone(),
        })
        .await?;

    if let Some(two_factor) = result.two_factor {
        error!("{two_factor:?}");

        let two_factor = if let Some(tf) = two_factor.authenticator {
            debug!("{tf:?}");

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

            info!("Two factor code sent to {tf:?}");
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
                kdf,
            })
            .await?;

        debug!("{result:?}");
    } else {
        debug!("{result:?}");
    }

    let res = client
        .vault()
        .sync(&SyncRequest {
            exclude_subdomains: Some(true),
        })
        .await?;
    info!("{res:#?}");

    Ok(())
}

pub(crate) async fn login_api_key(
    client: Client,
    client_id: Option<String>,
    client_secret: Option<String>,
) -> Result<String> {
    let client_id =
        resolve_user_input_value("Client ID", client_id, &["BW_CLIENTID", "BW_CLIENT_ID"])?;
    let client_secret = resolve_user_input_value(
        "Client Secret",
        client_secret,
        &["BW_CLIENTSECRET", "BW_CLIENT_SECRET"],
    )?;

    // Check for password in environment variable first
    let password = if let Ok(pwd) = std::env::var("BW_PASSWORD") {
        if !pwd.is_empty() {
            pwd
        } else {
            Password::new("Password").without_confirmation().prompt()?
        }
    } else {
        Password::new("Password").without_confirmation().prompt()?
    };

    let result = client
        .auth()
        .login_api_key(&ApiKeyLoginRequest {
            client_id,
            client_secret,
            password,
        })
        .await?;

    debug!("{result:?}");

    // Sync vault data after successful login
    let sync_result = client
        .vault()
        .sync(&SyncRequest {
            exclude_subdomains: Some(true),
        })
        .await?;
    info!("Synced {} ciphers", sync_result.ciphers.len());

    // Export the full session (user key + tokens)
    let session = export_session(&client).await?;

    Ok(session)
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
