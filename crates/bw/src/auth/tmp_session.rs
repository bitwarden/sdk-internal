//! Contains temporary glue code to recover a session.
//!
//! None of this code should be considered final but rather as a temporary hack until auth
//! persistence is properly implemented.

use bitwarden_core::Client;
use bitwarden_crypto::{AsymmetricCryptoKey, Pkcs8PrivateKeyBytes};
use bitwarden_crypto::{CryptoError, SymmetricCryptoKey};
use bitwarden_encoding::B64;
use serde::{Deserialize, Serialize};

use bitwarden_core::key_management::{AsymmetricKeyId, SymmetricKeyId};

#[derive(Serialize, Deserialize)]
struct SessionData {
    user_key: String,
    private_key: Option<String>,
    access_token: Option<String>,
    refresh_token: Option<String>,
    expires_on: Option<i64>,
}

pub(crate) async fn export_session(client: &Client) -> Result<String, CryptoError> {
    // Get the user encryption key and private key
    #[allow(deprecated)]
    let (user_key, private_key) = {
        let ctx = client.internal.get_key_store().context();
        let user_key = ctx.dangerous_get_symmetric_key(SymmetricKeyId::User)?;
        let private_key = if ctx.has_asymmetric_key(AsymmetricKeyId::UserPrivateKey) {
            let key = ctx.dangerous_get_asymmetric_key(AsymmetricKeyId::UserPrivateKey)?;
            Some(B64::from(key.to_der()?.as_ref()).to_string())
        } else {
            None
        };
        (user_key.to_base64().to_string(), private_key)
    };

    // Get the tokens
    let (access_token, refresh_token, expires_on) = client.internal.cli_get_tokens();

    let session_data = SessionData {
        user_key,
        private_key,
        access_token,
        refresh_token,
        expires_on,
    };

    // Serialize to JSON and then base64 encode
    let json = serde_json::to_string(&session_data).map_err(|_| CryptoError::InvalidKey)?;
    let encoded = bitwarden_encoding::B64::from(json.as_bytes());

    Ok(encoded.to_string())
}

/// Import a session and restore the client state
/// This includes restoring the user key, private key, and setting tokens
pub(crate) async fn import_session(client: &Client, session: &str) -> Result<(), CryptoError> {
    // Decode from base64 and parse JSON
    let decoded = B64::try_from(session.to_string()).map_err(|_| CryptoError::InvalidKey)?;
    let json_str =
        String::from_utf8(decoded.as_bytes().to_vec()).map_err(|_| CryptoError::InvalidKey)?;
    let session_data: SessionData =
        serde_json::from_str(&json_str).map_err(|_| CryptoError::InvalidKey)?;

    // Restore the user key and private key
    let user_key = SymmetricCryptoKey::try_from(session_data.user_key)?;

    #[allow(deprecated)]
    {
        let mut ctx = client.internal.get_key_store().context_mut();
        ctx.set_symmetric_key(SymmetricKeyId::User, user_key)?;

        // Restore private key if present
        if let Some(private_key_b64) = session_data.private_key {
            let private_key_b64_parsed =
                B64::try_from(private_key_b64).map_err(|_| CryptoError::InvalidKey)?;
            let private_key_der = Pkcs8PrivateKeyBytes::from(private_key_b64_parsed.as_bytes());
            let private_key = AsymmetricCryptoKey::from_der(&private_key_der)?;
            ctx.set_asymmetric_key(AsymmetricKeyId::UserPrivateKey, private_key)?;
        }
    }

    // Restore the tokens
    client
        .internal
        .cli_set_tokens(session_data.access_token.unwrap_or_default(), None, 0);

    Ok(())
}
