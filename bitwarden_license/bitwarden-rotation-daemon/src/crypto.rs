//! Cryptographic helpers used by the rotation daemon.
//!
//! This module owns the daemon's [`crate::crypto::DaemonKeyStore`] slot definitions and two
//! operations built on top of it:
//!
//! * [`crate::crypto::unwrap_org_key`] — install the org key delivered in the identity-server auth
//!   payload.
//! * [`crate::crypto::encrypt_cipher_password`] — encrypt a new plaintext password into the
//!   cipher's opaque `data` JSON blob, optionally via a per-item cipher key.

use bitwarden_crypto::{
    BitwardenLegacyKeyBytes, EncString, KeyDecryptable, KeyStore, PrimitiveEncryptable,
    SymmetricCryptoKey, key_slot_ids,
};
use bitwarden_encoding::B64;
use serde::Deserialize;
use thiserror::Error;

// ---------------------------------------------------------------------------
// Key-slot definitions
// ---------------------------------------------------------------------------

// Symmetric slots: Organization (global) and Local (ephemeral per-operation).
// Private and signing slots are stubs — the daemon carries no RSA or signing
// keys, but the macro requires all three slot enum types.
key_slot_ids! {
    #[symmetric]
    pub enum DaemonSymmSlotId {
        Organization,
        #[local]
        Local(LocalId),
    }

    #[private]
    pub enum DaemonPrivateSlotId {
        #[local]
        Local(LocalId),
    }

    #[signing]
    pub enum DaemonSigningSlotId {
        #[local]
        Local(LocalId),
    }

    pub DaemonKeySlotIds => DaemonSymmSlotId, DaemonPrivateSlotId, DaemonSigningSlotId;
}

/// The key store used throughout the daemon.
pub type DaemonKeyStore = KeyStore<DaemonKeySlotIds>;

// ---------------------------------------------------------------------------
// Error type
// ---------------------------------------------------------------------------

/// Errors produced by the cryptographic helpers in this module.
#[derive(Debug, Error)]
pub enum CryptoModuleError {
    /// The encrypted payload could not be decoded or decrypted.
    #[error("org-key payload is invalid")]
    InvalidPayload,

    /// The decrypted payload does not contain a valid org key.
    #[error("org-key payload does not contain a valid encryption key")]
    InvalidOrgKey,

    /// The cipher's `data` JSON blob does not have the expected parent at the
    /// password pointer path (CONTRACT ITEM C2).
    ///
    /// The error carries **no** blob content to avoid echoing cipher data.
    #[error("cipher data JSON does not contain the expected password field parent")]
    CipherDataShape,

    /// A generic cryptographic operation failed.
    #[error("cryptographic operation failed")]
    Crypto(#[from] bitwarden_crypto::CryptoError),

    /// JSON serialisation/deserialisation error.
    #[error("JSON error")]
    Json(#[from] serde_json::Error),
}

// ---------------------------------------------------------------------------
// unwrap_org_key
// ---------------------------------------------------------------------------

/// Install the organisation encryption key into `store`.
///
/// `token_key` is the 16-byte derived key from the daemon access token.
/// `encrypted_payload` is the `encryptedPayload` EncString returned by the
/// identity server on authentication.
///
/// The plaintext org-key bytes exist only transiently inside this synchronous
/// function and are never returned to callers.
///
/// Errors carry no payload content.
pub fn unwrap_org_key(
    store: &DaemonKeyStore,
    token_key: &SymmetricCryptoKey,
    encrypted_payload: &str,
) -> Result<(), CryptoModuleError> {
    // Decode the EncString
    let payload_enc: EncString = encrypted_payload
        .parse()
        .map_err(|_| CryptoModuleError::InvalidPayload)?;

    // Decrypt with the token's local encryption key
    let decrypted: Vec<u8> = payload_enc
        .decrypt_with_key(token_key)
        .map_err(|_| CryptoModuleError::InvalidPayload)?;

    // JSON decode to extract the org encryption key
    #[derive(Deserialize)]
    struct Payload {
        #[serde(rename = "encryptionKey")]
        encryption_key: B64,
    }

    let payload: Payload =
        serde_json::from_slice(&decrypted).map_err(|_| CryptoModuleError::InvalidPayload)?;

    // Convert the raw bytes to a SymmetricCryptoKey
    let encryption_key = BitwardenLegacyKeyBytes::from(&payload.encryption_key);
    let org_key = SymmetricCryptoKey::try_from(&encryption_key)
        .map_err(|_| CryptoModuleError::InvalidOrgKey)?;

    // Install into the global Organization slot.
    // FIXME: [PM-18098] When key installation is part of bitwarden-crypto we
    // won't need to call the deprecated set_symmetric_key here.
    #[allow(deprecated)]
    store
        .context_mut()
        .set_symmetric_key(DaemonSymmSlotId::Organization, org_key)
        .map_err(CryptoModuleError::Crypto)?;

    Ok(())
}

// ---------------------------------------------------------------------------
// encrypt_cipher_password
// ---------------------------------------------------------------------------

/// JSON pointer for the login-password field inside the server's cipher `data`
/// blob.
///
/// CONTRACT ITEM C2 (provisional): the server's `CipherLoginData` is a
/// flat PascalCase JSON object; the password lives at the top-level key
/// `Password`.  This is the PascalCase top-level field of the server cipher
/// data blob — NOT the SDK's nested camelCase client models. The pointer must
/// be verified end-to-end before production use.
const CIPHER_PASSWORD_JSON_POINTER: &str = "/Password";

/// Encrypt `new_password` and replace the password field in `data`.
///
/// * If `cipher_key` is `Some`, it is an EncString (per-item cipher key) wrapped under the org key;
///   it is unwrapped into a local slot and used to encrypt the password.
/// * If `cipher_key` is `None`, the org key (Organisation slot) is used directly.
///
/// `data` is modified in place: only the value at
/// `CIPHER_PASSWORD_JSON_POINTER` is replaced; all sibling fields are
/// preserved byte-for-byte.
///
/// Returns `Err(CipherDataShape)` when the pointer's parent object is missing
/// in `data`, without echoing any content.
///
/// The `KeyStoreContext` is never held across an await point — this function
/// is synchronous.
pub fn encrypt_cipher_password(
    store: &DaemonKeyStore,
    cipher_key: Option<&str>,
    data: &mut serde_json::Value,
    new_password: &str,
) -> Result<(), CryptoModuleError> {
    // Obtain a mutable context (kept entirely within this sync fn).
    let mut ctx = store.context_mut();

    // Choose the key slot to encrypt with.
    let encrypt_slot = if let Some(wrapped_key_str) = cipher_key {
        let wrapped_enc: EncString = wrapped_key_str
            .parse()
            .map_err(|_| CryptoModuleError::InvalidPayload)?;

        // Unwrap the per-item cipher key using the org key; returns a fresh local slot.
        ctx.unwrap_symmetric_key(DaemonSymmSlotId::Organization, &wrapped_enc)
            .map_err(CryptoModuleError::Crypto)?
    } else {
        DaemonSymmSlotId::Organization
    };

    // Encrypt the new password.
    let encrypted: EncString = new_password
        .encrypt(&mut ctx, encrypt_slot)
        .map_err(CryptoModuleError::Crypto)?;

    let encrypted_str = encrypted.to_string();

    // Replace only the password field; verify the parent exists first.
    //
    // `pointer_mut` returns None when the parent object is absent, which we
    // surface as CipherDataShape — no content is echoed in the error.
    match data.pointer_mut(CIPHER_PASSWORD_JSON_POINTER) {
        Some(target) => {
            *target = serde_json::Value::String(encrypted_str);
            Ok(())
        }
        None => Err(CryptoModuleError::CipherDataShape),
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use bitwarden_crypto::{
        KeyDecryptable, SymmetricCryptoKey, SymmetricKeyAlgorithm, derive_shareable_key,
    };
    use serde_json::json;
    use zeroize::Zeroizing;

    use super::*;

    // -----------------------------------------------------------------------
    // Helpers shared by tests
    // -----------------------------------------------------------------------

    /// Build a fresh Aes256CbcHmac org key and return it alongside the store
    /// with the key installed at the Organization slot.
    fn make_store_with_org_key() -> (DaemonKeyStore, SymmetricCryptoKey) {
        let store: DaemonKeyStore = KeyStore::default();
        let org_key = SymmetricCryptoKey::make(SymmetricKeyAlgorithm::Aes256CbcHmac);

        // Install directly for setup purposes.
        #[allow(deprecated)]
        store
            .context_mut()
            .set_symmetric_key(DaemonSymmSlotId::Organization, org_key.clone())
            .expect("set_symmetric_key");

        (store, org_key)
    }

    /// Derive a token key from a 16-byte secret (mirrors the C1 derivation in
    /// `token.rs`; constants kept local so tests don't depend on that module).
    fn derive_token_key(secret: Zeroizing<[u8; 16]>) -> SymmetricCryptoKey {
        SymmetricCryptoKey::Aes256CbcHmacKey(derive_shareable_key(
            secret,
            "accesstoken",
            Some("sm-access-token"),
        ))
    }

    /// Encrypt `{"encryptionKey": <b64(org_key_bytes)>}` under `token_key` to
    /// produce the `encryptedPayload` that the identity server would return.
    fn make_encrypted_payload(
        token_key: &SymmetricCryptoKey,
        org_key: &SymmetricCryptoKey,
    ) -> String {
        // Encode the org key bytes to base64 for the JSON payload.
        let org_key_bytes = org_key.to_encoded();
        let org_key_b64 = bitwarden_encoding::B64::from(org_key_bytes.as_ref());
        let org_key_b64_str: String = org_key_b64.into();

        let payload_json = format!(r#"{{"encryptionKey":"{org_key_b64_str}"}}"#);

        // Encrypt the JSON under the token key.
        // `&str` implements `KeyEncryptable<SymmetricCryptoKey, EncString>`.
        use bitwarden_crypto::KeyEncryptable;
        let enc: EncString = payload_json
            .as_str()
            .encrypt_with_key(token_key)
            .expect("encrypt payload");
        enc.to_string()
    }

    // -----------------------------------------------------------------------
    // unwrap_org_key tests
    // -----------------------------------------------------------------------

    #[test]
    fn unwrap_org_key_round_trip() {
        // Build a token key from a known 16-byte secret.
        let secret = Zeroizing::new([0x42u8; 16]);
        let token_key = derive_token_key(secret);

        // Build an org key and produce the encrypted payload.
        let org_key = SymmetricCryptoKey::make(SymmetricKeyAlgorithm::Aes256CbcHmac);
        let encrypted_payload = make_encrypted_payload(&token_key, &org_key);

        // Start with an empty store.
        let store: DaemonKeyStore = KeyStore::default();
        assert!(
            !store
                .context()
                .has_symmetric_key(DaemonSymmSlotId::Organization)
        );

        unwrap_org_key(&store, &token_key, &encrypted_payload).expect("unwrap_org_key");

        // Verify the org key is now installed by encrypting and decrypting a
        // probe string.
        let probe = "probe value";
        let encrypted_probe = {
            let mut ctx = store.context();
            use bitwarden_crypto::PrimitiveEncryptable;
            probe
                .encrypt(&mut ctx, DaemonSymmSlotId::Organization)
                .expect("encrypt probe")
        };

        // Decrypt using the original org_key directly to confirm they match.
        let decrypted: String = encrypted_probe
            .decrypt_with_key(&org_key)
            .expect("decrypt probe");
        assert_eq!(decrypted, probe);
    }

    #[test]
    fn unwrap_org_key_bad_payload_returns_error() {
        let secret = Zeroizing::new([0x01u8; 16]);
        let token_key = derive_token_key(secret);
        let store: DaemonKeyStore = KeyStore::default();

        let result = unwrap_org_key(&store, &token_key, "not-an-enc-string");
        assert!(
            matches!(result, Err(CryptoModuleError::InvalidPayload)),
            "expected InvalidPayload, got {result:?}",
        );
    }

    // -----------------------------------------------------------------------
    // encrypt_cipher_password tests — org-key path (no cipher_key)
    // -----------------------------------------------------------------------

    #[test]
    fn encrypt_cipher_password_org_key_path() {
        let (store, org_key) = make_store_with_org_key();

        let mut data = json!({ "Password": "old", "Username": "alice" });
        encrypt_cipher_password(&store, None, &mut data, "new-secret").expect("encrypt");

        // The Password field must have been replaced with an EncString.
        let password_field = data["Password"].as_str().expect("Password is a string");
        assert!(
            password_field.contains('.'),
            "expected EncString format, got: {password_field}",
        );

        // Decrypt with the org key and confirm the plaintext.
        let enc: EncString = password_field.parse().expect("parse EncString");
        let plaintext: String = enc.decrypt_with_key(&org_key).expect("decrypt");
        assert_eq!(plaintext, "new-secret");

        // Sibling field must be untouched.
        assert_eq!(data["Username"].as_str(), Some("alice"));
    }

    // -----------------------------------------------------------------------
    // encrypt_cipher_password tests — per-item cipher-key path
    // -----------------------------------------------------------------------

    #[test]
    fn encrypt_cipher_password_per_item_key_path() {
        let (store, _org_key) = make_store_with_org_key();

        // Generate a fresh per-item key and wrap it under the org key.
        let item_key = SymmetricCryptoKey::make(SymmetricKeyAlgorithm::Aes256CbcHmac);
        let wrapped_cipher_key_str = {
            let mut ctx = store.context_mut();
            // Store item_key as a local slot so we can wrap it.
            let item_key_slot = ctx.add_local_symmetric_key(item_key.clone());
            let wrapped = ctx
                .wrap_symmetric_key(DaemonSymmSlotId::Organization, item_key_slot)
                .expect("wrap item key");
            wrapped.to_string()
        };

        let mut data = json!({ "Password": "old" });
        encrypt_cipher_password(
            &store,
            Some(&wrapped_cipher_key_str),
            &mut data,
            "per-item-secret",
        )
        .expect("encrypt");

        let password_field = data["Password"].as_str().expect("Password is a string");
        let enc: EncString = password_field.parse().expect("parse EncString");

        // Must decrypt under the item key, not the org key.
        let plaintext: String = enc
            .decrypt_with_key(&item_key)
            .expect("decrypt with item key");
        assert_eq!(plaintext, "per-item-secret");
    }

    // -----------------------------------------------------------------------
    // JSON pointer replacement preserves siblings
    // -----------------------------------------------------------------------

    #[test]
    fn encrypt_cipher_password_preserves_sibling_fields() {
        let (store, _) = make_store_with_org_key();

        let original = json!({
            "Password": "old",
            "Username": "bob",
            "Uri": "https://example.com",
            "Totp": null,
        });
        let mut data = original.clone();

        encrypt_cipher_password(&store, None, &mut data, "new").expect("encrypt");

        // All siblings must be byte-for-byte identical.
        assert_eq!(data["Username"], original["Username"]);
        assert_eq!(data["Uri"], original["Uri"]);
        assert_eq!(data["Totp"], original["Totp"]);

        // Only the Password key changed.
        assert_ne!(data["Password"], original["Password"]);
    }

    // -----------------------------------------------------------------------
    // Missing pointer parent → CipherDataShape
    // -----------------------------------------------------------------------

    #[test]
    fn encrypt_cipher_password_missing_parent_returns_cipher_data_shape() {
        let (store, _) = make_store_with_org_key();

        // Data has no "Password" key at all.
        let mut data = json!({ "Username": "carol" });

        let result = encrypt_cipher_password(&store, None, &mut data, "new");
        assert!(
            matches!(result, Err(CryptoModuleError::CipherDataShape)),
            "expected CipherDataShape, got {result:?}",
        );
    }
}
