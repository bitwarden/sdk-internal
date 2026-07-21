use std::sync::Arc;

use bitwarden_core::{
    Client, FromClient, OrganizationId,
    client::{ApiConfigurations, FromClientPart},
    key_management::{BLOB_SECURITY_VERSION, KeySlotIds},
};
#[cfg(feature = "wasm")]
use bitwarden_crypto::{CompositeEncryptable, SymmetricCryptoKey};
use bitwarden_crypto::{IdentifyKey, KeyStore, KeyStoreContext};
#[cfg(feature = "wasm")]
use bitwarden_encoding::B64;
use bitwarden_state::repository::{Repository, RepositoryError};
#[cfg(feature = "wasm")]
use wasm_bindgen::prelude::*;

use super::EncryptionContext;
use crate::{
    Cipher, CipherError, CipherListView, CipherView, DecryptError, EncryptError,
    cipher::cipher::{DecryptCipherListResult, EncryptMode, StrictDecrypt},
    cipher_client::admin::CipherAdminClient,
};
#[cfg(feature = "wasm")]
use crate::{Fido2CredentialFullView, cipher::cipher::DecryptCipherResult};

mod admin;
mod bulk_update_collections;

pub use admin::GetAssignedOrgCiphersAdminError;
mod create;
mod delete;
mod edit;
mod get;
mod move_many;
mod restore;
mod share_cipher;

/// Returns `true` when cipher data for the given scope should be written in the blob-encrypted
/// format, based on the current security state version. Individual-vault ciphers qualify once the
/// security state has reached [`BLOB_SECURITY_VERSION`]. Organization-vault support is tracked in
/// PM-32430.
pub fn should_use_blob_encryption(
    ctx: &KeyStoreContext<KeySlotIds>,
    organization_id: Option<OrganizationId>,
) -> bool {
    organization_id.is_none() && ctx.get_security_state_version() >= BLOB_SECURITY_VERSION
}

#[allow(missing_docs)]
#[cfg_attr(feature = "wasm", wasm_bindgen)]
pub struct CiphersClient {
    #[allow(dead_code)]
    pub(crate) key_store: KeyStore<KeySlotIds>,
    pub(crate) api_configurations: Arc<ApiConfigurations>,
    pub(crate) repository: Option<Arc<dyn Repository<Cipher>>>,
    #[deprecated(
        note = "Use the component fields (key_store, api_configurations, repository) for new operations"
    )]
    pub(crate) client: Client,
}

impl FromClient for CiphersClient {
    fn from_client(client: &Client) -> Self {
        #[allow(deprecated)]
        Self {
            key_store: client.get_part(),
            api_configurations: client.get_part(),
            repository: client.get_part(),
            client: client.clone(),
        }
    }
}

#[allow(deprecated)]
#[cfg_attr(feature = "wasm", wasm_bindgen)]
impl CiphersClient {
    pub(crate) fn should_use_blob_encryption(
        &self,
        organization_id: Option<OrganizationId>,
    ) -> bool {
        let key_store = self.client.internal.get_key_store();
        should_use_blob_encryption(&key_store.context(), organization_id)
    }

    #[allow(missing_docs)]
    pub fn encrypt(&self, mut cipher_view: CipherView) -> Result<EncryptionContext, EncryptError> {
        let user_id = self
            .client
            .internal
            .get_user_id()
            .ok_or(EncryptError::MissingUserId)?;
        let key_store = self.client.internal.get_key_store();

        // TODO: The key generation logic should be moved directly into the
        // KeyEncryptable implementation
        if cipher_view.key.is_none() {
            let key = cipher_view.key_identifier();
            cipher_view.generate_cipher_key(&mut key_store.context(), key)?;
        }

        let mode = if self.should_use_blob_encryption(cipher_view.organization_id) {
            EncryptMode::Blob(cipher_view)
        } else {
            EncryptMode::Legacy(cipher_view)
        };
        let cipher = key_store.encrypt(mode)?;
        Ok(EncryptionContext {
            cipher,
            encrypted_for: user_id,
        })
    }

    /// Encrypt a cipher with the provided key. This should only be used when rotating encryption
    /// keys in the Web client.
    ///
    /// Until key rotation is fully implemented in the SDK, this method must be provided the new
    /// symmetric key in base64 format. See PM-23084
    ///
    /// If the cipher has a CipherKey, it will be re-encrypted with the new key.
    /// If the cipher does not have a CipherKey, one will be generated using the new key.
    #[cfg(feature = "wasm")]
    pub fn encrypt_cipher_for_rotation(
        &self,
        mut cipher_view: CipherView,
        new_key: B64,
    ) -> Result<EncryptionContext, CipherError> {
        let new_key = SymmetricCryptoKey::try_from(new_key)?;

        let user_id = self
            .client
            .internal
            .get_user_id()
            .ok_or(EncryptError::MissingUserId)?;

        let key_store = self.client.internal.get_key_store();
        let mut ctx = key_store.context();

        // Set the new key in the key store context
        let new_key_id = ctx.add_local_symmetric_key(new_key);

        if cipher_view.key.is_none() {
            cipher_view.generate_cipher_key(&mut ctx, new_key_id)?;
        } else {
            cipher_view.reencrypt_cipher_keys(&mut ctx, new_key_id)?;
        }

        // Rotation installs the new key under a `Local` slot id (`new_key_id`), not the view's
        // natural `User`/`Organization` slot — so pass it explicitly to `encrypt_composite` rather
        // than going through `key_store.encrypt`, which uses the view's natural key identifier.
        let mode = if self.should_use_blob_encryption(cipher_view.organization_id) {
            EncryptMode::Blob(cipher_view)
        } else {
            EncryptMode::Legacy(cipher_view)
        };
        let cipher = mode.encrypt_composite(&mut ctx, new_key_id)?;

        Ok(EncryptionContext {
            cipher,
            encrypted_for: user_id,
        })
    }

    /// Encrypt a list of cipher views.
    ///
    /// This method attempts to encrypt all ciphers in the list. If any cipher
    /// fails to encrypt, the entire operation fails and an error is returned.
    #[cfg(feature = "wasm")]
    pub fn encrypt_list(
        &self,
        cipher_views: Vec<CipherView>,
    ) -> Result<Vec<EncryptionContext>, EncryptError> {
        let user_id = self
            .client
            .internal
            .get_user_id()
            .ok_or(EncryptError::MissingUserId)?;
        let key_store = self.client.internal.get_key_store();

        let mut ctx = key_store.context();

        let prepared_modes: Vec<EncryptMode<CipherView>> = cipher_views
            .into_iter()
            .map(|mut cv| {
                if cv.key.is_none() {
                    let key = cv.key_identifier();
                    cv.generate_cipher_key(&mut ctx, key)?;
                }
                let mode = if self.should_use_blob_encryption(cv.organization_id) {
                    EncryptMode::Blob(cv)
                } else {
                    EncryptMode::Legacy(cv)
                };
                Ok(mode)
            })
            .collect::<Result<Vec<_>, bitwarden_crypto::CryptoError>>()?;

        let ciphers: Vec<Cipher> = key_store.encrypt_list(&prepared_modes)?;

        Ok(ciphers
            .into_iter()
            .map(|cipher| EncryptionContext {
                cipher,
                encrypted_for: user_id,
            })
            .collect())
    }

    #[allow(missing_docs)]
    pub async fn decrypt(&self, cipher: Cipher) -> Result<CipherView, DecryptError> {
        let key_store = self.client.internal.get_key_store();
        Ok(if self.is_strict_decrypt().await {
            key_store.decrypt(&StrictDecrypt(cipher))?
        } else {
            key_store.decrypt(&cipher)?
        })
    }

    #[allow(missing_docs)]
    pub async fn decrypt_list(
        &self,
        ciphers: Vec<Cipher>,
    ) -> Result<Vec<CipherListView>, DecryptError> {
        let key_store = self.client.internal.get_key_store();
        Ok(if self.is_strict_decrypt().await {
            let wrapped: Vec<StrictDecrypt<Cipher>> =
                ciphers.into_iter().map(StrictDecrypt).collect();
            key_store.decrypt_list(&wrapped)?
        } else {
            key_store.decrypt_list(&ciphers)?
        })
    }

    /// Decrypt cipher list with failures
    /// Returns both successfully decrypted ciphers and any that failed to decrypt
    pub async fn decrypt_list_with_failures(
        &self,
        ciphers: Vec<Cipher>,
    ) -> DecryptCipherListResult {
        let key_store = self.client.internal.get_key_store();
        if self.is_strict_decrypt().await {
            let wrapped: Vec<StrictDecrypt<Cipher>> =
                ciphers.into_iter().map(StrictDecrypt).collect();
            let (successes, failures) = key_store.decrypt_list_with_failures(&wrapped);
            DecryptCipherListResult {
                successes,
                failures: failures.into_iter().map(|f| f.0.clone()).collect(),
            }
        } else {
            let (successes, failures) = key_store.decrypt_list_with_failures(&ciphers);
            DecryptCipherListResult {
                successes,
                failures: failures.into_iter().cloned().collect(),
            }
        }
    }

    /// Decrypt full cipher list
    /// Returns both successfully fully decrypted ciphers and any that failed to decrypt
    #[cfg(feature = "wasm")]
    pub async fn decrypt_list_full_with_failures(
        &self,
        ciphers: Vec<Cipher>,
    ) -> DecryptCipherResult {
        let key_store = self.client.internal.get_key_store();
        if self.is_strict_decrypt().await {
            let wrapped: Vec<StrictDecrypt<Cipher>> =
                ciphers.into_iter().map(StrictDecrypt).collect();
            let (successes, failures) = key_store.decrypt_list_with_failures(&wrapped);
            DecryptCipherResult {
                successes,
                failures: failures.into_iter().map(|f| f.0.clone()).collect(),
            }
        } else {
            let (successes, failures) = key_store.decrypt_list_with_failures(&ciphers);
            DecryptCipherResult {
                successes,
                failures: failures.into_iter().cloned().collect(),
            }
        }
    }

    #[allow(missing_docs)]
    pub fn decrypt_fido2_credentials(
        &self,
        cipher_view: CipherView,
    ) -> Result<Vec<crate::Fido2CredentialView>, DecryptError> {
        let key_store = self.client.internal.get_key_store();
        let credentials = cipher_view.decrypt_fido2_credentials(&mut key_store.context())?;
        Ok(credentials)
    }

    /// Temporary method used to re-encrypt FIDO2 credentials for a cipher view.
    /// Necessary until the TS clients utilize the SDK entirely for FIDO2 credentials management.
    /// TS clients create decrypted FIDO2 credentials that need to be encrypted manually when
    /// encrypting the rest of the CipherView.
    /// TODO: Remove once TS passkey provider implementation uses SDK - PM-8313
    #[cfg(feature = "wasm")]
    pub fn set_fido2_credentials(
        &self,
        mut cipher_view: CipherView,
        fido2_credentials: Vec<Fido2CredentialFullView>,
    ) -> Result<CipherView, CipherError> {
        let key_store = self.client.internal.get_key_store();

        cipher_view.set_new_fido2_credentials(&mut key_store.context(), fido2_credentials)?;

        Ok(cipher_view)
    }

    #[allow(missing_docs)]
    pub fn move_to_organization(
        &self,
        mut cipher_view: CipherView,
        organization_id: OrganizationId,
    ) -> Result<CipherView, CipherError> {
        let key_store = self.client.internal.get_key_store();
        cipher_view.move_to_organization(&mut key_store.context(), organization_id)?;
        Ok(cipher_view)
    }

    #[cfg(feature = "wasm")]
    #[allow(missing_docs)]
    pub fn decrypt_fido2_private_key(
        &self,
        cipher_view: CipherView,
    ) -> Result<String, CipherError> {
        let key_store = self.client.internal.get_key_store();
        let decrypted_key = cipher_view.decrypt_fido2_private_key(&mut key_store.context())?;
        Ok(decrypted_key)
    }

    /// Returns a new client for performing admin operations.
    /// Uses the admin server API endpoints and does not modify local state.
    pub fn admin(&self) -> CipherAdminClient {
        CipherAdminClient::from_client(&self.client)
    }
}

#[allow(deprecated)]
impl CiphersClient {
    fn get_repository(&self) -> Result<Arc<dyn Repository<Cipher>>, RepositoryError> {
        Ok(self.client.platform().state().get::<Cipher>()?)
    }

    async fn is_strict_decrypt(&self) -> bool {
        self.client.flags().get().await.strict_cipher_decryption
    }
}

#[cfg(test)]
mod tests {

    use bitwarden_core::client::test_accounts::test_bitwarden_com_account;
    #[cfg(feature = "wasm")]
    use bitwarden_crypto::{CryptoError, SymmetricKeyAlgorithm};

    use super::*;
    use crate::{
        Attachment, CipherRepromptType, CipherType, Login, VaultClientExt,
        cipher::blob::try_parse_blob,
    };

    fn test_cipher() -> Cipher {
        Cipher {
            id: Some("358f2b2b-9326-4e5e-94a8-b18100bb0908".parse().unwrap()),
            organization_id: None,
            folder_id: None,
            collection_ids: vec![],
            key: None,
            name: Some("2.+oPT8B4xJhyhQRe1VkIx0A==|PBtC/bZkggXR+fSnL/pG7g==|UkjRD0VpnUYkjRC/05ZLdEBAmRbr3qWRyJey2bUvR9w=".parse().unwrap()),
            notes: None,
            r#type: CipherType::Login,
            login: Some(Login{
                username: None,
                password: None,
                password_revision_date: None,
                uris:None,
                totp: None,
                autofill_on_page_load: None,
                fido2_credentials: None,
            }),
            identity: None,
            card: None,
            secure_note: None,
            ssh_key: None,
            bank_account: None,
            drivers_license: None,
            passport: None,
            favorite: false,
            reprompt: CipherRepromptType::None,
            organization_use_totp: true,
            edit: true,
            permissions: None,
            view_password: true,
            local_data: None,
            attachments: None,
            fields:  None,
            password_history: None,
            creation_date: "2024-05-31T11:20:58.4566667Z".parse().unwrap(),
            deleted_date: None,
            revision_date: "2024-05-31T11:20:58.4566667Z".parse().unwrap(),
            archived_date: None,
            data: None,
        }
    }

    #[cfg(feature = "wasm")]
    fn test_cipher_view() -> CipherView {
        let test_id = "fd411a1a-fec8-4070-985d-0e6560860e69".parse().unwrap();
        CipherView {
            r#type: CipherType::Login,
            login: Some(crate::LoginView {
                username: Some("test_username".to_string()),
                password: Some("test_password".to_string()),
                password_revision_date: None,
                uris: None,
                totp: None,
                autofill_on_page_load: None,
                fido2_credentials: None,
            }),
            id: Some(test_id),
            organization_id: None,
            folder_id: None,
            collection_ids: vec![],
            key: None,
            name: "My test login".to_string(),
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
            organization_use_totp: true,
            edit: true,
            permissions: None,
            view_password: true,
            local_data: None,
            attachments: None,
            attachment_decryption_failures: None,
            fields: None,
            password_history: None,
            creation_date: "2024-01-30T17:55:36.150Z".parse().unwrap(),
            deleted_date: None,
            revision_date: "2024-01-30T17:55:36.150Z".parse().unwrap(),
            archived_date: None,
        }
    }

    fn test_attachment_legacy() -> Attachment {
        Attachment {
            id: Some("uf7bkexzag04d3cw04jsbqqkbpbwhxs0".to_string()),
            url: Some("http://localhost:4000/attachments//358f2b2b-9326-4e5e-94a8-b18100bb0908/uf7bkexzag04d3cw04jsbqqkbpbwhxs0".to_string()),
            file_name: Some("2.mV50WiLq6duhwGbhM1TO0A==|dTufWNH8YTPP0EMlNLIpFA==|QHp+7OM8xHtEmCfc9QPXJ0Ro2BeakzvLgxJZ7NdLuDc=".parse().unwrap()),
            key: None,
            size: Some("65".to_string()),
            size_name: Some("65 Bytes".to_string()),
        }
    }

    fn test_attachment_v2() -> Attachment {
        Attachment {
            id: Some("a77m56oerrz5b92jm05lq5qoyj1xh2t9".to_string()),
            url: Some("http://localhost:4000/attachments//358f2b2b-9326-4e5e-94a8-b18100bb0908/uf7bkexzag04d3cw04jsbqqkbpbwhxs0".to_string()),
            file_name: Some("2.GhazFdCYQcM5v+AtVwceQA==|98bMUToqC61VdVsSuXWRwA==|bsLByMht9Hy5QO9pPMRz0K4d0aqBiYnnROGM5YGbNu4=".parse().unwrap()),
            key: Some("2.6TPEiYULFg/4+3CpDRwCqw==|6swweBHCJcd5CHdwBBWuRN33XRV22VoroDFDUmiM4OzjPEAhgZK57IZS1KkBlCcFvT+t+YbsmDcdv+Lqr+iJ3MmzfJ40MCB5TfYy+22HVRA=|rkgFDh2IWTfPC1Y66h68Diiab/deyi1p/X0Fwkva0NQ=".parse().unwrap()),
            size: Some("65".to_string()),
            size_name: Some("65 Bytes".to_string()),
        }
    }

    #[tokio::test]
    async fn test_decrypt_list() {
        let client = Client::init_test_account(test_bitwarden_com_account()).await;

        let dec = client
            .vault()
            .ciphers()
            .decrypt_list(vec![Cipher {
                id: Some("a1569f46-0797-4d3f-b859-b181009e2e49".parse().unwrap()),
                organization_id: Some("1bc9ac1e-f5aa-45f2-94bf-b181009709b8".parse().unwrap()),
                folder_id: None,
                collection_ids: vec!["66c5ca57-0868-4c7e-902f-b181009709c0".parse().unwrap()],
                key: None,
                name: Some("2.RTdUGVWYl/OZHUMoy68CMg==|sCaT5qHx8i0rIvzVrtJKww==|jB8DsRws6bXBtXNfNXUmFJ0JLDlB6GON6Y87q0jgJ+0=".parse().unwrap()),
                notes: None,
                r#type: CipherType::Login,
                login: Some(Login{
                    username: Some("2.ouEYEk+SViUtqncesfe9Ag==|iXzEJq1zBeNdDbumFO1dUA==|RqMoo9soSwz/yB99g6YPqk8+ASWRcSdXsKjbwWzyy9U=".parse().unwrap()),
                    password: Some("2.6yXnOz31o20Z2kiYDnXueA==|rBxTb6NK9lkbfdhrArmacw==|ogZir8Z8nLgiqlaLjHH+8qweAtItS4P2iPv1TELo5a0=".parse().unwrap()),
                    password_revision_date: None, uris:None, totp: None, autofill_on_page_load: None, fido2_credentials: None }),
                identity: None,
                card: None,
                secure_note: None,
                ssh_key: None,
                bank_account: None,
                drivers_license: None,
                passport: None,
                favorite: false,
                reprompt: CipherRepromptType::None,
                organization_use_totp: true,
                edit: true,
                permissions: None,
                view_password: true,
                local_data: None,
                attachments: None,
                fields:  None,
                password_history: None,
                creation_date: "2024-05-31T09:35:55.12Z".parse().unwrap(),
                deleted_date: None,
                revision_date: "2024-05-31T09:35:55.12Z".parse().unwrap(),
                archived_date: None,
                data: None,
            }])
            .await
            .unwrap();

        assert_eq!(dec[0].name, "Test item");
    }

    #[tokio::test]
    async fn test_decrypt_list_with_failures_all_success() {
        let client = Client::init_test_account(test_bitwarden_com_account()).await;

        let valid_cipher = test_cipher();

        let result = client
            .vault()
            .ciphers()
            .decrypt_list_with_failures(vec![valid_cipher])
            .await;

        assert_eq!(result.successes.len(), 1);
        assert!(result.failures.is_empty());
        assert_eq!(result.successes[0].name, "234234");
    }

    #[tokio::test]
    async fn test_decrypt_list_with_failures_mixed_results() {
        let client = Client::init_test_account(test_bitwarden_com_account()).await;
        let valid_cipher = test_cipher();
        let mut invalid_cipher = test_cipher();
        // Set an invalid encryptedkey to cause decryption failure
        invalid_cipher.key = Some("2.Gg8yCM4IIgykCZyq0O4+cA==|GJLBtfvSJTDJh/F7X4cJPkzI6ccnzJm5DYl3yxOW2iUn7DgkkmzoOe61sUhC5dgVdV0kFqsZPcQ0yehlN1DDsFIFtrb4x7LwzJNIkMgxNyg=|1rGkGJ8zcM5o5D0aIIwAyLsjMLrPsP3EWm3CctBO3Fw=".parse().unwrap());

        let ciphers = vec![valid_cipher, invalid_cipher.clone()];

        let result = client
            .vault()
            .ciphers()
            .decrypt_list_with_failures(ciphers)
            .await;

        assert_eq!(result.successes.len(), 1);
        assert_eq!(result.failures.len(), 1);

        assert_eq!(result.successes[0].name, "234234");
    }

    #[tokio::test]
    async fn test_move_user_cipher_with_attachment_without_key_to_org_fails() {
        let client = Client::init_test_account(test_bitwarden_com_account()).await;

        let mut cipher = test_cipher();
        cipher.attachments = Some(vec![test_attachment_legacy()]);

        let view = client
            .vault()
            .ciphers()
            .decrypt(cipher.clone())
            .await
            .unwrap();

        //  Move cipher to organization
        let res = client.vault().ciphers().move_to_organization(
            view,
            "1bc9ac1e-f5aa-45f2-94bf-b181009709b8".parse().unwrap(),
        );

        assert!(res.is_err());
    }

    #[tokio::test]
    async fn test_encrypt_cipher_with_legacy_attachment_without_key() {
        let client = Client::init_test_account(test_bitwarden_com_account()).await;

        let mut cipher = test_cipher();
        let attachment = test_attachment_legacy();
        cipher.attachments = Some(vec![attachment.clone()]);

        let view = client
            .vault()
            .ciphers()
            .decrypt(cipher.clone())
            .await
            .unwrap();

        assert!(cipher.key.is_none());

        // Assert the cipher has a key, and the attachment is still readable
        let EncryptionContext {
            cipher: new_cipher,
            encrypted_for: _,
        } = client.vault().ciphers().encrypt(view).unwrap();
        assert!(new_cipher.key.is_some());

        let view = client.vault().ciphers().decrypt(new_cipher).await.unwrap();
        let attachments = view.clone().attachments.unwrap();
        let attachment_view = attachments.first().unwrap().clone();
        assert!(attachment_view.key.is_none());

        assert_eq!(attachment_view.file_name.as_deref(), Some("h.txt"));

        let buf = vec![
            2, 100, 205, 148, 152, 77, 184, 77, 53, 80, 38, 240, 83, 217, 251, 118, 254, 27, 117,
            41, 148, 244, 216, 110, 216, 255, 104, 215, 23, 15, 176, 239, 208, 114, 95, 159, 23,
            211, 98, 24, 145, 166, 60, 197, 42, 204, 131, 144, 253, 204, 195, 154, 27, 201, 215,
            43, 10, 244, 107, 226, 152, 85, 167, 66, 185,
        ];

        let content = client
            .vault()
            .attachments()
            .decrypt_buffer(cipher, attachment_view.clone(), buf.as_slice())
            .unwrap();

        assert_eq!(content, b"Hello");
    }

    #[tokio::test]
    async fn test_encrypt_cipher_with_v1_attachment_without_key() {
        let client = Client::init_test_account(test_bitwarden_com_account()).await;

        let mut cipher = test_cipher();
        let attachment = test_attachment_v2();
        cipher.attachments = Some(vec![attachment.clone()]);

        let view = client
            .vault()
            .ciphers()
            .decrypt(cipher.clone())
            .await
            .unwrap();

        assert!(cipher.key.is_none());

        // Assert the cipher has a key, and the attachment is still readable
        let EncryptionContext {
            cipher: new_cipher,
            encrypted_for: _,
        } = client.vault().ciphers().encrypt(view).unwrap();
        assert!(new_cipher.key.is_some());

        // The stored (wrapped) attachment key changed: it is now protected by the cipher key
        // rather than the user key.
        let enrolled_wrapped_key = new_cipher.attachments.as_ref().unwrap()[0]
            .key
            .as_ref()
            .unwrap()
            .to_string();
        assert_ne!(
            attachment.key.as_ref().unwrap().to_string(),
            enrolled_wrapped_key
        );

        let view = client
            .vault()
            .ciphers()
            .decrypt(new_cipher.clone())
            .await
            .unwrap();
        let attachments = view.clone().attachments.unwrap();
        let attachment_view = attachments.first().unwrap().clone();
        assert!(attachment_view.key.is_some());

        assert_eq!(attachment_view.file_name.as_deref(), Some("h.txt"));

        let buf = vec![
            2, 114, 53, 72, 20, 82, 18, 46, 48, 137, 97, 1, 100, 142, 120, 187, 28, 36, 180, 46,
            189, 254, 133, 23, 169, 58, 73, 212, 172, 116, 185, 127, 111, 92, 112, 145, 99, 28,
            158, 198, 48, 241, 121, 218, 66, 37, 152, 197, 122, 241, 110, 82, 245, 72, 47, 230, 95,
            188, 196, 170, 127, 67, 44, 129, 90,
        ];

        let content = client
            .vault()
            .attachments()
            .decrypt_buffer(new_cipher.clone(), attachment_view.clone(), buf.as_slice())
            .unwrap();

        assert_eq!(content, b"Hello");

        // Move cipher to organization
        let new_view = client
            .vault()
            .ciphers()
            .move_to_organization(
                view,
                "1bc9ac1e-f5aa-45f2-94bf-b181009709b8".parse().unwrap(),
            )
            .unwrap();
        let EncryptionContext {
            cipher: new_cipher,
            encrypted_for: _,
        } = client.vault().ciphers().encrypt(new_view).unwrap();

        // The stored key remains present after the move. Its wrapped bytes are not compared: the
        // attachment key is re-wrapped (with a fresh IV) on every encryption, so the ciphertext
        // differs even though the underlying content key is unchanged - which the readable content
        // below confirms.
        assert!(new_cipher.attachments.as_ref().unwrap()[0].key.is_some());

        let content = client
            .vault()
            .attachments()
            .decrypt_buffer(new_cipher, attachment_view, buf.as_slice())
            .unwrap();

        assert_eq!(content, b"Hello");
    }

    #[tokio::test]
    #[cfg(feature = "wasm")]
    async fn test_decrypt_list_full_with_failures_all_success() {
        let client = Client::init_test_account(test_bitwarden_com_account()).await;

        let valid_cipher = test_cipher();

        let result = client
            .vault()
            .ciphers()
            .decrypt_list_full_with_failures(vec![valid_cipher])
            .await;

        assert_eq!(result.successes.len(), 1);
        assert!(result.failures.is_empty());
        assert_eq!(result.successes[0].name, "234234");
    }

    #[tokio::test]
    #[cfg(feature = "wasm")]
    async fn test_decrypt_list_full_with_failures_mixed_results() {
        let client = Client::init_test_account(test_bitwarden_com_account()).await;
        let valid_cipher = test_cipher();
        let mut invalid_cipher = test_cipher();
        // Set an invalid encrypted key to cause decryption failure
        invalid_cipher.key = Some("2.Gg8yCM4IIgykCZyq0O4+cA==|GJLBtfvSJTDJh/F7X4cJPkzI6ccnzJm5DYl3yxOW2iUn7DgkkmzoOe61sUhC5dgVdV0kFqsZPcQ0yehlN1DDsFIFtrb4x7LwzJNIkMgxNyg=|1rGkGJ8zcM5o5D0aIIwAyLsjMLrPsP3EWm3CctBO3Fw=".parse().unwrap());

        let ciphers = vec![valid_cipher, invalid_cipher.clone()];

        let result = client
            .vault()
            .ciphers()
            .decrypt_list_full_with_failures(ciphers)
            .await;

        assert_eq!(result.successes.len(), 1);
        assert_eq!(result.failures.len(), 1);

        assert_eq!(result.successes[0].name, "234234");
    }

    #[tokio::test]
    #[cfg(feature = "wasm")]
    async fn test_decrypt_list_full_with_failures_all_failures() {
        let client = Client::init_test_account(test_bitwarden_com_account()).await;
        let mut invalid_cipher1 = test_cipher();
        let mut invalid_cipher2 = test_cipher();
        // Set invalid encrypted keys to cause decryption failures
        invalid_cipher1.key = Some("2.Gg8yCM4IIgykCZyq0O4+cA==|GJLBtfvSJTDJh/F7X4cJPkzI6ccnzJm5DYl3yxOW2iUn7DgkkmzoOe61sUhC5dgVdV0kFqsZPcQ0yehlN1DDsFIFtrb4x7LwzJNIkMgxNyg=|1rGkGJ8zcM5o5D0aIIwAyLsjMLrPsP3EWm3CctBO3Fw=".parse().unwrap());
        invalid_cipher2.key = Some("2.Gg8yCM4IIgykCZyq0O4+cA==|GJLBtfvSJTDJh/F7X4cJPkzI6ccnzJm5DYl3yxOW2iUn7DgkkmzoOe61sUhC5dgVdV0kFqsZPcQ0yehlN1DDsFIFtrb4x7LwzJNIkMgxNyg=|1rGkGJ8zcM5o5D0aIIwAyLsjMLrPsP3EWm3CctBO3Fw=".parse().unwrap());

        let ciphers = vec![invalid_cipher1, invalid_cipher2];

        let result = client
            .vault()
            .ciphers()
            .decrypt_list_full_with_failures(ciphers)
            .await;

        assert!(result.successes.is_empty());
        assert_eq!(result.failures.len(), 2);
    }

    #[tokio::test]
    #[cfg(feature = "wasm")]
    async fn test_decrypt_list_full_with_failures_empty_list() {
        let client = Client::init_test_account(test_bitwarden_com_account()).await;

        let result = client
            .vault()
            .ciphers()
            .decrypt_list_full_with_failures(vec![])
            .await;

        assert!(result.successes.is_empty());
        assert!(result.failures.is_empty());
    }

    #[tokio::test]
    #[cfg(feature = "wasm")]
    async fn test_encrypt_cipher_for_rotation() {
        let client = Client::init_test_account(test_bitwarden_com_account()).await;

        let new_key = SymmetricCryptoKey::make(SymmetricKeyAlgorithm::Aes256CbcHmac);

        let cipher_view = test_cipher_view();
        let new_key_b64 = new_key.to_base64();

        let ctx = client
            .vault()
            .ciphers()
            .encrypt_cipher_for_rotation(cipher_view, new_key_b64)
            .unwrap();

        assert!(ctx.cipher.key.is_some());

        // Decrypting the cipher "normally" will fail because it was encrypted with a new key
        assert!(matches!(
            client.vault().ciphers().decrypt(ctx.cipher).await.err(),
            Some(DecryptError::Crypto(CryptoError::Decrypt))
        ));
    }

    #[cfg(feature = "wasm")]
    #[tokio::test]
    async fn test_encrypt_list() {
        let client = Client::init_test_account(test_bitwarden_com_account()).await;

        let cipher_views = vec![test_cipher_view(), test_cipher_view()];

        let result = client.vault().ciphers().encrypt_list(cipher_views);

        assert!(result.is_ok());
        let contexts = result.unwrap();
        assert_eq!(contexts.len(), 2);

        // Verify each encrypted cipher has a key (cipher key encryption is enabled)
        for ctx in &contexts {
            assert!(ctx.cipher.key.is_some());
        }
    }

    #[cfg(feature = "wasm")]
    #[tokio::test]
    async fn test_encrypt_list_empty() {
        let client = Client::init_test_account(test_bitwarden_com_account()).await;

        let result = client.vault().ciphers().encrypt_list(vec![]);

        assert!(result.is_ok());
        assert!(result.unwrap().is_empty());
    }

    #[cfg(feature = "wasm")]
    #[tokio::test]
    async fn test_encrypt_list_roundtrip() {
        let client = Client::init_test_account(test_bitwarden_com_account()).await;

        let original_views = vec![test_cipher_view(), test_cipher_view()];
        let original_names: Vec<_> = original_views.iter().map(|v| v.name.clone()).collect();

        let contexts = client
            .vault()
            .ciphers()
            .encrypt_list(original_views)
            .unwrap();

        // Decrypt each cipher and verify the name matches
        for (ctx, original_name) in contexts.iter().zip(original_names.iter()) {
            let decrypted = client
                .vault()
                .ciphers()
                .decrypt(ctx.cipher.clone())
                .await
                .unwrap();
            assert_eq!(&decrypted.name, original_name);
        }
    }

    #[cfg(feature = "wasm")]
    #[tokio::test]
    async fn test_encrypt_list_preserves_user_id() {
        let client = Client::init_test_account(test_bitwarden_com_account()).await;

        let expected_user_id = client.internal.get_user_id().unwrap();

        let cipher_views = vec![test_cipher_view(), test_cipher_view(), test_cipher_view()];
        let contexts = client.vault().ciphers().encrypt_list(cipher_views).unwrap();

        for ctx in contexts {
            assert_eq!(ctx.encrypted_for, expected_user_id);
        }
    }

    #[tokio::test]
    async fn should_use_blob_encryption_individual_above_threshold_returns_true() {
        let client = Client::init_test_account(test_bitwarden_com_account()).await;
        client
            .internal
            .get_key_store()
            .set_security_state_version(BLOB_SECURITY_VERSION);

        assert!(client.vault().ciphers().should_use_blob_encryption(None));
    }

    #[tokio::test]
    async fn should_use_blob_encryption_individual_below_threshold_returns_false() {
        let client = Client::init_test_account(test_bitwarden_com_account()).await;
        // Default KeyStore security_state_version is 1, below BLOB_SECURITY_VERSION (2).

        assert!(!client.vault().ciphers().should_use_blob_encryption(None));
    }

    #[tokio::test]
    async fn should_use_blob_encryption_organization_returns_false() {
        let client = Client::init_test_account(test_bitwarden_com_account()).await;
        client
            .internal
            .get_key_store()
            .set_security_state_version(BLOB_SECURITY_VERSION);
        let org_id: OrganizationId = "1bc9ac1e-f5aa-45f2-94bf-b181009709b8".parse().unwrap();

        assert!(
            !client
                .vault()
                .ciphers()
                .should_use_blob_encryption(Some(org_id))
        );
    }

    /// At `BLOB_SECURITY_VERSION`, personal ciphers encrypt through the blob
    /// path, producing a blob-shaped `Cipher`.
    #[cfg(feature = "wasm")]
    #[tokio::test]
    async fn encrypt_produces_blob_shape_at_blob_version() {
        let client = Client::init_test_account(test_bitwarden_com_account()).await;
        client
            .internal
            .get_key_store()
            .set_security_state_version(BLOB_SECURITY_VERSION);

        let ctx = client
            .vault()
            .ciphers()
            .encrypt(test_cipher_view())
            .unwrap();

        assert!(try_parse_blob(&ctx.cipher).is_some());
        assert!(ctx.cipher.login.is_none());
    }

    /// `encrypt_list` at blob version, mixing a personal (blob-eligible) view
    /// with an organization-owned (legacy-only) view
    #[cfg(feature = "wasm")]
    #[tokio::test]
    async fn encrypt_list_mixed_personal_and_organization() {
        let client = Client::init_test_account(test_bitwarden_com_account()).await;
        client
            .internal
            .get_key_store()
            .set_security_state_version(BLOB_SECURITY_VERSION);

        let personal_view = test_cipher_view();
        let mut org_view = test_cipher_view();
        org_view.organization_id = Some("1bc9ac1e-f5aa-45f2-94bf-b181009709b8".parse().unwrap());

        let contexts = client
            .vault()
            .ciphers()
            .encrypt_list(vec![personal_view, org_view])
            .unwrap();

        assert_eq!(contexts.len(), 2);
        assert!(
            try_parse_blob(&contexts[0].cipher).is_some(),
            "personal cipher at blob version should be blob-shaped",
        );
        assert!(
            try_parse_blob(&contexts[1].cipher).is_none(),
            "organization cipher should stay legacy-shaped",
        );
    }

    /// Rotation at blob version must produce a blob-shaped cipher wrapped
    /// under the new key, not under the view's original scope slot.
    #[cfg(feature = "wasm")]
    #[tokio::test]
    async fn encrypt_cipher_for_rotation_blob_path() {
        let client = Client::init_test_account(test_bitwarden_com_account()).await;
        client
            .internal
            .get_key_store()
            .set_security_state_version(BLOB_SECURITY_VERSION);

        let new_key = SymmetricCryptoKey::make(SymmetricKeyAlgorithm::Aes256CbcHmac);
        let new_key_b64 = new_key.to_base64();

        let ctx = client
            .vault()
            .ciphers()
            .encrypt_cipher_for_rotation(test_cipher_view(), new_key_b64)
            .unwrap();

        assert!(try_parse_blob(&ctx.cipher).is_some());
        assert!(ctx.cipher.key.is_some());
        // Decrypting with the current key store (which has the old user key)
        // fails because the cipher is now wrapped under the new key.
        assert!(client.vault().ciphers().decrypt(ctx.cipher).await.is_err());
    }
}
