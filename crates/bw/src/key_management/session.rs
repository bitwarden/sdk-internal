//! Session key management for encrypting/decrypting user keys.
//!
//! The session key is a 64-byte random value that encrypts the user's encryption key,
//! allowing vault access without re-entering the master password.

use bitwarden_core::{Client, UserId};
use bitwarden_crypto::{
    EncString, SymmetricCryptoKey,
    safe::{DataEnvelope, DataEnvelopeNamespace, SealableData, SealableVersionedData},
};
use bitwarden_encoding::B64;
use bitwarden_state::register_setting_key;
use serde::{Deserialize, Serialize};

use crate::platform::StateError;

register_setting_key!(const ENCRYPTED_USER_KEY: EncryptedUserKeyData = "encrypted_user_key");

/// Encrypted user key storage
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EncryptedUserKeyData {
    /// DataEnvelope containing encrypted user key (base64-encoded)
    pub envelope: DataEnvelope,
    /// Wrapped content encryption key
    pub wrapped_cek: EncString,
    /// User ID this key belongs to
    pub user_id: UserId,
}

/// User key payload for encryption
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct UserKeyPayload {
    /// The user's encryption key in base64
    pub user_key: B64,
}

impl SealableData for UserKeyPayload {}

impl SealableVersionedData for UserKeyPayload {
    const NAMESPACE: DataEnvelopeNamespace = DataEnvelopeNamespace::CliSession;
}

/// Encrypt the user's encryption key with a session key and store it.
pub async fn encrypt_and_store(
    client: &Client,
    session_key: &SymmetricCryptoKey,
) -> Result<(), StateError> {
    // Get the user's encryption key
    let user_key = client.crypto().get_user_encryption_key().await?;

    // Get key store and add session key
    let key_store = client.internal.get_key_store();
    let mut ctx = key_store.context_mut();
    let wrapping_key_id = ctx.add_local_symmetric_key(session_key.clone());

    // Seal user key with DataEnvelope
    let payload = UserKeyPayload { user_key };
    let (envelope, wrapped_cek) =
        DataEnvelope::seal_with_wrapping_key(payload, &wrapping_key_id, &mut ctx)?;

    // Store encrypted data
    let user_id = client.internal.get_user_id().ok_or(StateError::NoUserId)?;

    let encrypted_data = EncryptedUserKeyData {
        envelope,
        wrapped_cek,
        user_id,
    };

    client
        .platform()
        .state()
        .setting(ENCRYPTED_USER_KEY)?
        .update(encrypted_data)
        .await?;

    Ok(())
}

/// Decrypt the user's encryption key using a session key.
pub async fn decrypt_user_key(client: &Client, session_key_b64: B64) -> Result<B64, StateError> {
    let session_sym_key = SymmetricCryptoKey::try_from(session_key_b64)?;

    // Load encrypted user key from database
    let encrypted_data = client
        .platform()
        .state()
        .setting(ENCRYPTED_USER_KEY)?
        .get()
        .await?
        .ok_or(StateError::NotFound(
            "No encrypted user key found. Please run 'bw unlock' first.",
        ))?;

    // Verify user ID matches
    let current_user_id = client.internal.get_user_id().ok_or(StateError::NoUserId)?;
    if encrypted_data.user_id != current_user_id {
        return Err(StateError::UserMismatch);
    }

    // Get key store and add session key
    let key_store = client.internal.get_key_store();
    let mut ctx = key_store.context_mut();
    let wrapping_key_id = ctx.add_local_symmetric_key(session_sym_key);

    // Unseal with DataEnvelope
    let payload: UserKeyPayload = encrypted_data.envelope.unseal_with_wrapping_key(
        &wrapping_key_id,
        &encrypted_data.wrapped_cek,
        &mut ctx,
    )?;

    Ok(payload.user_key)
}

/// Clear encrypted user key (on logout).
pub async fn clear(client: &Client) -> Result<(), StateError> {
    client
        .platform()
        .state()
        .setting(ENCRYPTED_USER_KEY)?
        .delete()
        .await?;
    Ok(())
}

/// Restore vault access using a session key.
///
/// This function:
/// 1. Decrypts the stored user key using the session key
/// 2. Initializes crypto with the decrypted user key
pub async fn restore_with_session_key(
    client: &Client,
    session_key_b64: B64,
) -> Result<(), StateError> {
    tracing::info!("Attempting to unlock with session key");

    // Decrypt user key with session key
    let user_key_b64 = decrypt_user_key(client, session_key_b64)
        .await
        .map_err(|e| {
            tracing::error!("Failed to decrypt user key: {}", e);
            StateError::NotFound(
                "Invalid session key. Please run 'bw unlock' to generate a new session key.",
            )
        })?;

    tracing::info!("Successfully decrypted user key with session");

    // Initialize crypto with the decrypted user key
    initialize_crypto_with_user_key(client, user_key_b64)
        .await
        .map_err(|e| {
            tracing::error!("Failed to initialize crypto: {}", e);
            StateError::NotFound(
                "Failed to unlock vault with session key. Please run 'bw unlock' again.",
            )
        })?;

    tracing::info!("Vault unlocked with session key");
    Ok(())
}

/// Initialize crypto with a decrypted user key.
async fn initialize_crypto_with_user_key(
    client: &Client,
    user_key_b64: B64,
) -> Result<(), StateError> {
    use bitwarden_core::key_management::crypto::{InitUserCryptoMethod, InitUserCryptoRequest};

    // Load auth state to get email and KDF
    let auth_state = crate::auth::state::load(client)
        .await?
        .ok_or(StateError::NotFound(
            "Not logged in. Auth state not available.",
        ))?;

    // Get user ID
    let user_id = client.internal.get_user_id().ok_or(StateError::NoUserId)?;

    // Load wrapped account crypto state
    let wrapped_crypto_state = super::crypto::CryptoStateStore::new(client)?
        .wrapped_state
        .get()
        .await?
        .ok_or(StateError::NotFound(
            "Account cryptographic state not available. Please run 'bw unlock' again.",
        ))?;

    // Extract email and KDF from login method
    let (email, kdf) = match &auth_state.login_method {
        bitwarden_core::client::UserLoginMethod::Username { email, kdf, .. } => {
            (email.clone(), kdf.clone())
        }
        bitwarden_core::client::UserLoginMethod::ApiKey { email, kdf, .. } => {
            (email.clone(), kdf.clone())
        }
    };

    // Initialize crypto with the decrypted user key
    client
        .crypto()
        .initialize_user_crypto(InitUserCryptoRequest {
            user_id: Some(user_id),
            kdf_params: kdf,
            email,
            account_cryptographic_state: wrapped_crypto_state,
            method: InitUserCryptoMethod::DecryptedKey {
                decrypted_user_key: user_key_b64.to_string(),
            },
        })
        .await?;

    tracing::info!("Vault crypto fully initialized with session key");

    Ok(())
}
