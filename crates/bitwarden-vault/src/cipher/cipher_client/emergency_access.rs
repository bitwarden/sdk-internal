use bitwarden_core::key_management::{KeySlotIds, PrivateKeySlotId, SymmetricKeySlotId};
use bitwarden_crypto::{Decryptable, KeyStore, KeyStoreContext, UnsignedSharedKey};
#[cfg(feature = "wasm")]
use wasm_bindgen::prelude::wasm_bindgen;

use crate::{
    Cipher, CipherView, CiphersClient, DecryptCipherResult, DecryptError,
    cipher::cipher::StrictDecrypt,
};

/// Decrypts a grantor's ciphers shared with the current user through emergency access.
///
/// The grantor's user key arrives encapsulated to the grantee's public key. It is decapsulated
/// into a local key slot and used in place of each cipher's natural `User`/`Organization` slot,
/// so it never leaves the key store.
pub(super) fn decrypt_emergency_access_list(
    grantor_key: UnsignedSharedKey,
    ciphers: Vec<Cipher>,
    key_store: &KeyStore<KeySlotIds>,
    use_strict_decryption: bool,
) -> Result<DecryptCipherResult, DecryptError> {
    let mut ctx = key_store.context();
    let grantor_key_id = grantor_key.decapsulate(PrivateKeySlotId::UserPrivateKey, &mut ctx)?;

    // Keep one context for the whole list; clearing local keys would drop the grantor key.
    let mut successes = Vec::with_capacity(ciphers.len());
    let mut failures = Vec::new();
    for cipher in ciphers {
        match decrypt_one(&cipher, &mut ctx, grantor_key_id, use_strict_decryption) {
            Ok(view) => successes.push(view),
            Err(_) => failures.push(cipher),
        }
    }

    Ok(DecryptCipherResult {
        successes,
        failures,
    })
}

fn decrypt_one(
    cipher: &Cipher,
    ctx: &mut KeyStoreContext<KeySlotIds>,
    key: SymmetricKeySlotId,
    use_strict_decryption: bool,
) -> Result<CipherView, bitwarden_crypto::CryptoError> {
    if use_strict_decryption {
        return StrictDecrypt(cipher.clone()).decrypt(ctx, key);
    }

    cipher.decrypt(ctx, key)
}

#[cfg_attr(feature = "wasm", wasm_bindgen)]
impl CiphersClient {
    /// Decrypts a grantor's ciphers returned by the emergency access view endpoint.
    ///
    /// `grantor_key` is the grantor's user key encapsulated to the current user's public key
    /// (`keyEncrypted` in the view response). Ciphers that fail to decrypt are returned in
    /// `failures`.
    pub async fn decrypt_emergency_access_list(
        &self,
        grantor_key: UnsignedSharedKey,
        ciphers: Vec<Cipher>,
    ) -> Result<DecryptCipherResult, DecryptError> {
        decrypt_emergency_access_list(
            grantor_key,
            ciphers,
            &self.key_store,
            self.is_strict_decrypt().await,
        )
    }
}

#[cfg(test)]
mod tests {
    use bitwarden_core::{
        Client,
        client::test_accounts::{test_bitwarden_com_account, test_bitwarden_com_account_v2},
        key_management::BLOB_SECURITY_VERSION,
    };
    use bitwarden_crypto::{CompositeEncryptable, SymmetricCryptoKey, SymmetricKeyAlgorithm};

    use super::*;
    use crate::{
        CipherRepromptType, CipherType, LoginView, VaultClientExt,
        cipher::{blob::try_parse_blob, cipher::EncryptMode},
    };

    fn test_cipher_view(name: &str) -> CipherView {
        CipherView {
            r#type: CipherType::Login,
            login: Some(LoginView {
                username: Some("user".to_string()),
                password: Some("pass".to_string()),
                password_revision_date: None,
                uris: None,
                totp: None,
                autofill_on_page_load: None,
                fido2_credentials: None,
            }),
            id: None,
            organization_id: None,
            folder_id: None,
            collection_ids: vec![],
            key: None,
            name: name.to_string(),
            notes: None,
            identity: None,
            card: None,
            secure_note: None,
            ssh_key: None,
            bank_account: None,
            drivers_license: None,
            passport: None,
            favorite: false,
            reprompt: CipherRepromptType::None,
            organization_use_totp: false,
            edit: true,
            permissions: None,
            view_password: true,
            local_data: None,
            attachments: None,
            attachment_decryption_failures: None,
            fields: None,
            password_history: None,
            creation_date: "2024-01-01T00:00:00Z".parse().unwrap(),
            deleted_date: None,
            revision_date: "2024-01-01T00:00:00Z".parse().unwrap(),
            archived_date: None,
            partial: false,
        }
    }

    /// Grantor encrypts a cipher under their user key, in legacy or blob format.
    fn encrypt_as_grantor(grantor: &Client, view: CipherView, blob: bool) -> Cipher {
        let key_store = grantor.internal.get_key_store();
        let mut ctx = key_store.context();
        let mode = if blob {
            EncryptMode::Blob(view)
        } else {
            EncryptMode::Legacy(view)
        };

        mode.encrypt_composite(&mut ctx, SymmetricKeySlotId::User)
            .unwrap()
    }

    /// Grantor user key encapsulated to the grantee's public key, as the server returns it.
    fn grantor_key_for(grantor: &Client, grantee: &Client) -> UnsignedSharedKey {
        let grantee_public_key = grantee
            .internal
            .get_key_store()
            .context()
            .get_public_key(PrivateKeySlotId::UserPrivateKey)
            .unwrap();

        UnsignedSharedKey::encapsulate(
            SymmetricKeySlotId::User,
            &grantee_public_key,
            &grantor.internal.get_key_store().context(),
        )
        .unwrap()
    }

    #[tokio::test]
    async fn decrypts_legacy_and_blob_ciphers_with_grantor_key() {
        let grantor = Client::init_test_account(test_bitwarden_com_account()).await;
        let grantee = Client::init_test_account(test_bitwarden_com_account_v2()).await;

        let legacy = encrypt_as_grantor(&grantor, test_cipher_view("legacy"), false);
        let blob = encrypt_as_grantor(&grantor, test_cipher_view("blob"), true);
        assert!(try_parse_blob(&blob).is_some());

        // The grantee cannot decrypt with their own user key.
        assert!(
            grantee
                .vault()
                .ciphers()
                .decrypt(blob.clone())
                .await
                .is_err()
        );

        let result = grantee
            .vault()
            .ciphers()
            .decrypt_emergency_access_list(grantor_key_for(&grantor, &grantee), vec![legacy, blob])
            .await
            .unwrap();

        let names: Vec<_> = result.successes.iter().map(|c| c.name.as_str()).collect();
        assert_eq!(names, ["legacy", "blob"]);
        assert!(result.failures.is_empty());
        assert_eq!(
            result.successes[1]
                .login
                .as_ref()
                .unwrap()
                .password
                .as_deref(),
            Some("pass")
        );
    }

    #[tokio::test]
    async fn decrypts_blob_cipher_at_blob_security_version() {
        let grantor = Client::init_test_account(test_bitwarden_com_account()).await;
        grantor
            .internal
            .get_key_store()
            .set_security_state_version(BLOB_SECURITY_VERSION);
        let grantee = Client::init_test_account(test_bitwarden_com_account_v2()).await;

        let cipher = grantor
            .vault()
            .ciphers()
            .encrypt(test_cipher_view("item"))
            .await
            .unwrap()
            .cipher;
        assert!(try_parse_blob(&cipher).is_some());

        let result = grantee
            .vault()
            .ciphers()
            .decrypt_emergency_access_list(grantor_key_for(&grantor, &grantee), vec![cipher])
            .await
            .unwrap();

        assert_eq!(result.successes.len(), 1);
        assert_eq!(result.successes[0].name, "item");
    }

    #[tokio::test]
    async fn reports_ciphers_under_other_keys_as_failures() {
        let grantor = Client::init_test_account(test_bitwarden_com_account()).await;
        let grantee = Client::init_test_account(test_bitwarden_com_account_v2()).await;

        // Blob-encrypted under an unrelated key. Blob decryption fails hard, unlike lenient
        // legacy decryption which nulls out undecryptable fields.
        let other = {
            let key_store = grantor.internal.get_key_store();
            let mut ctx = key_store.context();
            let other_key = ctx.add_local_symmetric_key(SymmetricCryptoKey::make(
                SymmetricKeyAlgorithm::Aes256CbcHmac,
            ));
            EncryptMode::Blob(test_cipher_view("other"))
                .encrypt_composite(&mut ctx, other_key)
                .unwrap()
        };
        let owned = encrypt_as_grantor(&grantor, test_cipher_view("owned"), false);

        let result = grantee
            .vault()
            .ciphers()
            .decrypt_emergency_access_list(grantor_key_for(&grantor, &grantee), vec![other, owned])
            .await
            .unwrap();

        assert_eq!(result.successes.len(), 1);
        assert_eq!(result.successes[0].name, "owned");
        assert_eq!(result.failures.len(), 1);
    }

    #[tokio::test]
    async fn fails_when_grantor_key_is_not_for_current_user() {
        let grantor = Client::init_test_account(test_bitwarden_com_account()).await;
        let grantee = Client::init_test_account(test_bitwarden_com_account_v2()).await;

        // Encapsulated to the grantor itself, not the grantee.
        let wrong_key = grantor_key_for(&grantor, &grantor);
        let cipher = encrypt_as_grantor(&grantor, test_cipher_view("item"), false);

        let result = grantee
            .vault()
            .ciphers()
            .decrypt_emergency_access_list(wrong_key, vec![cipher])
            .await;

        assert!(result.is_err());
    }
}
