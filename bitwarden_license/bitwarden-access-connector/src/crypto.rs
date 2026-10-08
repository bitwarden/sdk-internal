//! Cryptographic helpers used by the access connector.

use bitwarden_access_token::{AccessToken, AccessTokenError};
use bitwarden_crypto::{EncString, KeyStore, PrimitiveEncryptable, key_slot_ids};
use thiserror::Error;

// Private and signing slots are stubs; the macro requires all three slot enum types.
key_slot_ids! {
    #[symmetric]
    pub enum AccessConnectorSymmSlotId {
        Organization,
        #[local]
        Local(LocalId),
    }

    #[private]
    pub enum AccessConnectorPrivateSlotId {
        #[local]
        Local(LocalId),
    }

    #[signing]
    pub enum AccessConnectorSigningSlotId {
        #[local]
        Local(LocalId),
    }

    pub AccessConnectorKeySlotIds =>
        AccessConnectorSymmSlotId, AccessConnectorPrivateSlotId, AccessConnectorSigningSlotId;
}

/// The key store used throughout the connector.
pub type AccessConnectorKeyStore = KeyStore<AccessConnectorKeySlotIds>;

/// Errors produced by the cryptographic helpers in this module.
#[derive(Debug, Error)]
pub enum CryptoModuleError {
    /// An encrypted payload or wrapped cipher key could not be decoded or decrypted.
    #[error("org-key payload is invalid")]
    InvalidPayload,

    /// The decrypted payload does not contain a valid org key.
    #[error("org-key payload does not contain a valid encryption key")]
    InvalidOrgKey,

    /// The cipher's `data` JSON is not an object. Carries no content, to avoid echoing cipher data.
    #[error("cipher data JSON is not a JSON object")]
    CipherDataShape,

    /// A generic cryptographic operation failed.
    #[error("cryptographic operation failed")]
    Crypto(#[from] bitwarden_crypto::CryptoError),

    /// JSON serialisation/deserialisation error.
    #[error("JSON error")]
    Json(#[from] serde_json::Error),
}

/// Decrypt the identity server's `encrypted_payload` with `token`'s derived key and install the org
/// key into `store`. The key bytes are never returned, and errors carry no payload content.
pub fn unwrap_org_key(
    store: &AccessConnectorKeyStore,
    token: &AccessToken,
    encrypted_payload: &str,
) -> Result<(), CryptoModuleError> {
    let mut ctx = store.context_mut();

    token
        .open_payload(
            &mut ctx,
            encrypted_payload,
            AccessConnectorSymmSlotId::Organization,
        )
        .map_err(|e| match e {
            AccessTokenError::InvalidPayload => CryptoModuleError::InvalidPayload,
            AccessTokenError::InvalidOrgKey => CryptoModuleError::InvalidOrgKey,
            AccessTokenError::Crypto(c) => CryptoModuleError::Crypto(c),
        })
}

/// The server's `CipherLoginData` serializes as a flat PascalCase object that omits `Password`
/// while it is null.
const CIPHER_PASSWORD_KEY: &str = "Password";

/// Encrypt `new_password` with the per-item `cipher_key` when present (unwrapped by the org key),
/// else the org key, and insert or replace the password field in `data`. Other fields are
/// untouched.
pub fn encrypt_cipher_password(
    store: &AccessConnectorKeyStore,
    cipher_key: Option<&str>,
    data: &mut serde_json::Value,
    new_password: &str,
) -> Result<(), CryptoModuleError> {
    let mut ctx = store.context_mut();

    let encrypt_slot = if let Some(wrapped_key_str) = cipher_key {
        let wrapped_enc: EncString = wrapped_key_str
            .parse()
            .map_err(|_| CryptoModuleError::InvalidPayload)?;

        ctx.unwrap_symmetric_key(AccessConnectorSymmSlotId::Organization, &wrapped_enc)
            .map_err(CryptoModuleError::Crypto)?
    } else {
        AccessConnectorSymmSlotId::Organization
    };

    let encrypted: EncString = new_password
        .encrypt(&mut ctx, encrypt_slot)
        .map_err(CryptoModuleError::Crypto)?;

    let encrypted_str = encrypted.to_string();

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
    use bitwarden_access_token::{AccessTokenKind, make_access_token_secrets};
    use bitwarden_crypto::{KeyDecryptable, SymmetricCryptoKey, SymmetricKeyAlgorithm};
    use serde_json::json;
    use uuid::uuid;

    use super::*;

    fn make_store_with_org_key() -> (AccessConnectorKeyStore, SymmetricCryptoKey) {
        let store: AccessConnectorKeyStore = KeyStore::default();
        let org_key = SymmetricCryptoKey::make(SymmetricKeyAlgorithm::Aes256CbcHmac);

        #[allow(deprecated)]
        store
            .context_mut()
            .set_symmetric_key(AccessConnectorSymmSlotId::Organization, org_key.clone())
            .expect("set_symmetric_key");

        (store, org_key)
    }

    /// Mints a token the way `bitwarden-pam` does, keyed to the organization key in
    /// `issuer_store`, plus the `encrypted_payload` that goes with it.
    fn mint_token_and_payload(issuer_store: &AccessConnectorKeyStore) -> (AccessToken, String) {
        let secrets = {
            let mut ctx = issuer_store.context_mut();
            make_access_token_secrets(
                &mut ctx,
                AccessConnectorSymmSlotId::Organization,
                AccessTokenKind::AccessConnector,
            )
            .expect("mint secrets")
        };
        let encrypted_payload = secrets.encrypted_payload.to_string();
        let token_str = secrets.into_token(uuid!("22222222-2222-2222-2222-222222222222"), "secret");
        let token = AccessToken::parse(&token_str, AccessTokenKind::AccessConnector)
            .expect("the token parses");
        (token, encrypted_payload)
    }

    #[test]
    fn unwrap_org_key_round_trip() {
        let (issuer_store, org_key) = make_store_with_org_key();
        let (token, encrypted_payload) = mint_token_and_payload(&issuer_store);

        let store: AccessConnectorKeyStore = KeyStore::default();
        assert!(
            !store
                .context()
                .has_symmetric_key(AccessConnectorSymmSlotId::Organization)
        );

        unwrap_org_key(&store, &token, &encrypted_payload).expect("unwrap_org_key");

        // Probe that the org key is installed.
        let probe = "probe value";
        let encrypted_probe = {
            let mut ctx = store.context();
            probe
                .encrypt(&mut ctx, AccessConnectorSymmSlotId::Organization)
                .expect("encrypt probe")
        };

        let decrypted: String = encrypted_probe
            .decrypt_with_key(&org_key)
            .expect("decrypt probe");
        assert_eq!(decrypted, probe);
    }

    #[test]
    fn unwrap_org_key_bad_payload_returns_error() {
        let (issuer_store, _org_key) = make_store_with_org_key();
        let (token, _payload) = mint_token_and_payload(&issuer_store);
        let store: AccessConnectorKeyStore = KeyStore::default();

        let result = unwrap_org_key(&store, &token, "not-an-enc-string");
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

        let password_field = data["Password"].as_str().expect("Password is a string");
        assert!(
            password_field.contains('.'),
            "expected EncString format, got: {password_field}",
        );

        let enc: EncString = password_field.parse().expect("parse EncString");
        let plaintext: String = enc.decrypt_with_key(&org_key).expect("decrypt");
        assert_eq!(plaintext, "new-secret");

        assert_eq!(data["Username"].as_str(), Some("alice"));
    }

    #[test]
    fn encrypt_cipher_password_per_item_key_path() {
        let (store, _org_key) = make_store_with_org_key();

        let item_key = SymmetricCryptoKey::make(SymmetricKeyAlgorithm::Aes256CbcHmac);
        let wrapped_cipher_key_str = {
            let mut ctx = store.context_mut();
            let item_key_slot = ctx.add_local_symmetric_key(item_key.clone());
            let wrapped = ctx
                .wrap_symmetric_key(AccessConnectorSymmSlotId::Organization, item_key_slot)
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

        assert_eq!(data["Username"], original["Username"]);
        assert_eq!(data["Uri"], original["Uri"]);
        assert_eq!(data["Totp"], original["Totp"]);

        assert_ne!(data["Password"], original["Password"]);
    }

    /// The server omits a null `Password`, so a missing key is inserted rather than an error.
    #[test]
    fn encrypt_cipher_password_inserts_missing_password_key() {
        let (store, org_key) = make_store_with_org_key();

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

        let password_field = data["Password"].as_str().expect("Password is a string");
        assert!(
            password_field.contains('.'),
            "expected EncString format, got: {password_field}",
        );

        let enc: EncString = password_field.parse().expect("parse EncString");
        let plaintext: String = enc.decrypt_with_key(&org_key).expect("decrypt");
        assert_eq!(plaintext, "first-rotation-secret");

        assert_eq!(
            data["Username"], original_username,
            "Username must be untouched"
        );
        assert_eq!(data["Name"], original_name, "Name must be untouched");
        assert_eq!(data["Uris"], original_uris, "Uris must be untouched");
        assert_eq!(data["Fields"], original_fields, "Fields must be untouched");
    }

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
