//! Cryptographic helpers used by the rotation daemon.
//!
//! Owns [`DaemonKeyStore`]'s slot definitions, [`unwrap_org_key`] (installs the auth-payload
//! org key), and [`encrypt_cipher_password`] (writes a new password into the cipher's data blob).

use bitwarden_crypto::{
    BitwardenLegacyKeyBytes, EncString, KeyDecryptable, KeyStore, PrimitiveEncryptable,
    SymmetricCryptoKey, key_slot_ids,
};
use bitwarden_encoding::B64;
use serde::Deserialize;
use thiserror::Error;

// Symmetric slots: Organization (global) and Local (ephemeral per-operation). Private and
// signing slots are stubs; the macro requires all three slot enum types.
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

/// Errors produced by the cryptographic helpers in this module.
#[derive(Debug, Error)]
pub enum CryptoModuleError {
    /// The encrypted payload could not be decoded or decrypted.
    #[error("org-key payload is invalid")]
    InvalidPayload,

    /// The decrypted payload does not contain a valid org key.
    #[error("org-key payload does not contain a valid encryption key")]
    InvalidOrgKey,

    /// The cipher's `data` JSON blob is not a JSON object (CONTRACT ITEM C2).
    ///
    /// The error carries **no** blob content to avoid echoing cipher data.
    #[error("cipher data JSON is not a JSON object")]
    CipherDataShape,

    /// A generic cryptographic operation failed.
    #[error("cryptographic operation failed")]
    Crypto(#[from] bitwarden_crypto::CryptoError),

    /// JSON serialisation/deserialisation error.
    #[error("JSON error")]
    Json(#[from] serde_json::Error),
}

/// Install the organisation encryption key into `store`.
///
/// `token_key` is the daemon access token's derived key; `encrypted_payload` is the
/// identity server's `encrypted_payload` EncString. The plaintext org-key bytes are
/// transient and never returned; errors carry no payload content.
pub fn unwrap_org_key(
    store: &DaemonKeyStore,
    token_key: &SymmetricCryptoKey,
    encrypted_payload: &str,
) -> Result<(), CryptoModuleError> {
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

    #[allow(deprecated)]
    store
        .context_mut()
        .set_symmetric_key(DaemonSymmSlotId::Organization, org_key)
        .map_err(CryptoModuleError::Crypto)?;

    Ok(())
}

/// Top-level key name for the login-password field inside the server's cipher `data` blob.
///
/// The server's `CipherLoginData` serializes as a flat PascalCase object; `"Password"` is
/// absent (not null) until the first rotation, then inserted or replaced.
const CIPHER_PASSWORD_KEY: &str = "Password";

/// Encrypt `new_password` and insert-or-replace the password field in `data`.
///
/// A `Some(cipher_key)` is unwrapped from the org key into a local slot; `None` uses the org
/// key directly. Other fields are preserved byte-for-byte; a non-object `data` errors with
/// `CipherDataShape` rather than echoing content.
pub fn encrypt_cipher_password(
    store: &DaemonKeyStore,
    cipher_key: Option<&str>,
    data: &mut serde_json::Value,
    new_password: &str,
) -> Result<(), CryptoModuleError> {
    // Obtain a mutable context (kept entirely within this sync fn).
    let mut ctx = store.context_mut();

    let encrypt_slot = if let Some(wrapped_key_str) = cipher_key {
        let wrapped_enc: EncString = wrapped_key_str
            .parse()
            .map_err(|_| CryptoModuleError::InvalidPayload)?;

        // Unwrap the per-item cipher key under the org key into a fresh local slot.
        ctx.unwrap_symmetric_key(DaemonSymmSlotId::Organization, &wrapped_enc)
            .map_err(CryptoModuleError::Crypto)?
    } else {
        DaemonSymmSlotId::Organization
    };

    let encrypted: EncString = new_password
        .encrypt(&mut ctx, encrypt_slot)
        .map_err(CryptoModuleError::Crypto)?;

    let encrypted_str = encrypted.to_string();

    // A `None` match here means a real shape violation, not a normal case.
    match data.as_object_mut() {
        Some(obj) => {
            obj.insert(
                CIPHER_PASSWORD_KEY.to_owned(),
                serde_json::Value::String(encrypted_str),
            );
            Ok(())
        }
        None => Err(CryptoModuleError::CipherDataShape),
    }
}

#[cfg(test)]
mod tests {
    use bitwarden_crypto::{
        KeyDecryptable, SymmetricCryptoKey, SymmetricKeyAlgorithm, derive_shareable_key,
    };
    use serde_json::json;
    use zeroize::Zeroizing;

    use super::*;

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

    /// A cipher data blob that has never had a password (server omits null fields)
    /// must have the key inserted rather than erroring.  Sibling fields must be
    /// byte-identical after the call.
    #[test]
    fn encrypt_cipher_password_inserts_missing_password_key() {
        let (store, org_key) = make_store_with_org_key();

        // Real-world shape: flat PascalCase object, no Password key.
        let mut data = json!({
            "Uris": [],
            "Username": "2.abc==|def==|ghi==",
            "Name": "2.jkl==|mno==|pqr==",
            "Fields": []
        });
        let original_username = data["Username"].clone();
        let original_name = data["Name"].clone();
        let original_uris = data["Uris"].clone();
        let original_fields = data["Fields"].clone();

        encrypt_cipher_password(&store, None, &mut data, "first-rotation-secret")
            .expect("insert must succeed even when Password key is absent");

        // The Password key must now be present and parseable as an EncString.
        let password_field = data["Password"].as_str().expect("Password is a string");
        assert!(
            password_field.contains('.'),
            "expected EncString format, got: {password_field}",
        );

        // Must decrypt to the plaintext we passed in.
        let enc: EncString = password_field.parse().expect("parse EncString");
        let plaintext: String = enc.decrypt_with_key(&org_key).expect("decrypt");
        assert_eq!(plaintext, "first-rotation-secret");

        // All siblings must be byte-for-byte identical.
        assert_eq!(
            data["Username"], original_username,
            "Username must be untouched"
        );
        assert_eq!(data["Name"], original_name, "Name must be untouched");
        assert_eq!(data["Uris"], original_uris, "Uris must be untouched");
        assert_eq!(data["Fields"], original_fields, "Fields must be untouched");
    }

    /// A `data` value that is not a JSON object (string, array, null, …) is a
    /// genuine shape violation and must return `CipherDataShape`.
    #[test]
    fn encrypt_cipher_password_non_object_root_returns_cipher_data_shape() {
        let (store, _) = make_store_with_org_key();

        for mut bad_root in [
            serde_json::Value::String("not-an-object".to_owned()),
            serde_json::json!([1, 2, 3]),
            serde_json::Value::Null,
            serde_json::json!(42),
        ] {
            let result = encrypt_cipher_password(&store, None, &mut bad_root, "pw");
            assert!(
                matches!(result, Err(CryptoModuleError::CipherDataShape)),
                "expected CipherDataShape for non-object root, got {result:?}",
            );
        }
    }
}
