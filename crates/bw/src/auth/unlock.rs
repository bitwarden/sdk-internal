use bitwarden_core::{Client, client::UserLoginMethod};
use bitwarden_crypto::{SymmetricCryptoKey, SymmetricKeyAlgorithm};
use color_eyre::eyre::bail;
use inquire::Password;

use crate::{
    key_management::{UnlockArgs, crypto::CryptoStateStore},
    render::CommandResult,
};

pub(crate) async fn unlock(client: &Client, args: UnlockArgs) -> CommandResult {
    // Check if user is logged in
    if client.internal.get_user_id().is_none() {
        bail!("You are not logged in. Please run `bw login` first.");
    }

    // Load auth state
    let auth_state = super::state::load(client)
        .await?
        .ok_or_else(|| color_eyre::eyre::eyre!("Not logged in. Please run 'bw login'"))?;

    // Load crypto state components
    let crypto_store = CryptoStateStore::new(client)?;

    let master_key_encrypted = crypto_store.master_key.get().await?.ok_or_else(|| {
        color_eyre::eyre::eyre!(
            "Master key encrypted user key not available. Please run 'bw login' again"
        )
    })?;

    let wrapped_crypto_state = crypto_store.wrapped_state.get().await?.ok_or_else(|| {
        color_eyre::eyre::eyre!(
            "Account cryptographic state not available. Please run 'bw login' again"
        )
    })?;

    // Prompt for password
    let password = Password::new("Master password")
        .without_confirmation()
        .prompt()?;

    // Get KDF and email from login method
    let (email, kdf) = match &auth_state.login_method {
        UserLoginMethod::Username { email, kdf, .. } => (email.clone(), kdf.clone()),
        UserLoginMethod::ApiKey { email, kdf, .. } => (email.clone(), kdf.clone()),
    };

    // Derive master key and initialize crypto
    let master_key = bitwarden_crypto::MasterKey::derive(&password, &email, &kdf)?;

    client.internal.initialize_user_crypto_key_connector_key(
        master_key,
        master_key_encrypted,
        wrapped_crypto_state,
    )?;

    // Generate session key (64 random bytes using AES256-CBC-HMAC)
    let session_key = SymmetricCryptoKey::make(SymmetricKeyAlgorithm::Aes256CbcHmac);

    // Try to encrypt and store user key if crypto is initialized
    // This happens after login when the vault is already unlocked
    match crate::key_management::session::encrypt_and_store(client, &session_key).await {
        Ok(_) => {
            tracing::info!("Encrypted and stored user key");
        }
        Err(e) => {
            tracing::warn!(
                "Could not encrypt user key (crypto may not be initialized): {}",
                e
            );
            tracing::info!(
                "Run 'bw sync' after login to fully unlock your vault, then run 'bw unlock' again"
            );
        }
    }

    // Format output
    let session_key_str = session_key.to_base64().to_string();
    if args.raw {
        Ok(session_key_str.into())
    } else {
        Ok(format!(
            "Your vault is now unlocked!\n\n\
            To unlock your vault, set the BW_SESSION environment variable:\n\
            $ export BW_SESSION=\"{}\"\n\n\
            or pass it as an argument:\n\
            $ bw list items --session {}",
            session_key_str, session_key_str
        )
        .into())
    }
}
