use bitwarden_core::{Client, OrganizationId, key_management::SymmetricKeyId};
use bitwarden_crypto::{CompositeEncryptable, IdentifyKey, SymmetricCryptoKey};
#[cfg(feature = "wasm")]
use bitwarden_encoding::B64;
#[cfg(feature = "wasm")]
use wasm_bindgen::prelude::*;

use super::EncryptionContext;
use crate::{
    Cipher, CipherError, CipherListView, CipherView, DecryptError, EncryptError,
    Fido2CredentialFullView, cipher::cipher::DecryptCipherListResult,
};

#[allow(missing_docs)]
#[cfg_attr(feature = "wasm", wasm_bindgen)]
pub struct CiphersClient {
    pub(crate) client: Client,
}

#[cfg_attr(feature = "wasm", wasm_bindgen)]
impl CiphersClient {
    #[allow(missing_docs)]
    pub fn encrypt(&self, mut cipher_view: CipherView) -> Result<EncryptionContext, EncryptError> {
        let user_id = self
            .client
            .internal
            .get_user_id()
            .ok_or(EncryptError::MissingUserId)?;
        let key_store = self.client.internal.get_key_store();

        // TODO: Once this flag is removed, the key generation logic should
        // be moved directly into the KeyEncryptable implementation
        if cipher_view.key.is_none()
            && self
                .client
                .internal
                .get_flags()
                .enable_cipher_key_encryption
        {
            let key = cipher_view.key_identifier();
            cipher_view.generate_cipher_key(&mut key_store.context(), key)?;
        }

        let cipher = key_store.encrypt(cipher_view)?;
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
    /// If the cipher does not have a CipherKey and CipherKeyEncryption is enabled, one will be
    /// generated using the new key. Otherwise, the cipher's data will be encrypted with the new
    /// key directly.
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
        const NEW_KEY_ID: SymmetricKeyId = SymmetricKeyId::Local("new_cipher_key");
        #[allow(deprecated)]
        ctx.set_symmetric_key(NEW_KEY_ID, new_key)?;

        if cipher_view.key.is_none()
            && self
                .client
                .internal
                .get_flags()
                .enable_cipher_key_encryption
        {
            cipher_view.generate_cipher_key(&mut ctx, NEW_KEY_ID)?;
        } else {
            cipher_view.reencrypt_cipher_keys(&mut ctx, NEW_KEY_ID)?;
        }

        let cipher = cipher_view.encrypt_composite(&mut ctx, NEW_KEY_ID)?;

        Ok(EncryptionContext {
            cipher,
            encrypted_for: user_id,
        })
    }

    #[allow(missing_docs)]
    pub fn decrypt(&self, cipher: Cipher) -> Result<CipherView, DecryptError> {
        let key_store = self.client.internal.get_key_store();
        let cipher_view = key_store.decrypt(&cipher)?;
        Ok(cipher_view)
    }

    #[allow(missing_docs)]
    pub fn decrypt_list(&self, ciphers: Vec<Cipher>) -> Result<Vec<CipherListView>, DecryptError> {
        let key_store = self.client.internal.get_key_store();
        let cipher_views = key_store.decrypt_list(&ciphers)?;
        Ok(cipher_views)
    }

    /// Decrypt cipher list with failures
    /// Returns both successfully decrypted ciphers and any that failed to decrypt
    pub fn decrypt_list_with_failures(&self, ciphers: Vec<Cipher>) -> DecryptCipherListResult {
        let key_store = self.client.internal.get_key_store();
        let (successes, failures) = key_store.decrypt_list_with_failures(&ciphers);

        DecryptCipherListResult {
            successes,
            failures: failures.into_iter().cloned().collect(),
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
}

#[cfg(test)]
mod tests {

    use bitwarden_core::client::test_accounts::test_bitwarden_com_account;
    use bitwarden_crypto::CryptoError;

    use super::*;
    use crate::{Attachment, CipherRepromptType, CipherType, Login, LoginView, VaultClientExt};

    fn test_cipher() -> Cipher {
        Cipher {
            id: Some("358f2b2b-9326-4e5e-94a8-b18100bb0908".parse().unwrap()),
            organization_id: None,
            folder_id: None,
            collection_ids: vec![],
            key: None,
            name: "2.+oPT8B4xJhyhQRe1VkIx0A==|PBtC/bZkggXR+fSnL/pG7g==|UkjRD0VpnUYkjRC/05ZLdEBAmRbr3qWRyJey2bUvR9w=".parse().unwrap(),
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
        }
    }

    fn test_cipher_view() -> CipherView {
        let test_id = "fd411a1a-fec8-4070-985d-0e6560860e69".parse().unwrap();
        CipherView {
            r#type: CipherType::Login,
            login: Some(LoginView {
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
            favorite: false,
            reprompt: CipherRepromptType::None,
            organization_use_totp: true,
            edit: true,
            permissions: None,
            view_password: true,
            local_data: None,
            attachments: None,
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
                name: "2.RTdUGVWYl/OZHUMoy68CMg==|sCaT5qHx8i0rIvzVrtJKww==|jB8DsRws6bXBtXNfNXUmFJ0JLDlB6GON6Y87q0jgJ+0=".parse().unwrap(),
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
            }])

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
            .decrypt_list_with_failures(vec![valid_cipher]);

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

        let result = client.vault().ciphers().decrypt_list_with_failures(ciphers);

        assert_eq!(result.successes.len(), 1);
        assert_eq!(result.failures.len(), 1);

        assert_eq!(result.successes[0].name, "234234");
    }

    #[tokio::test]
    async fn test_move_user_cipher_with_attachment_without_key_to_org_fails() {
        let client = Client::init_test_account(test_bitwarden_com_account()).await;

        let mut cipher = test_cipher();
        cipher.attachments = Some(vec![test_attachment_legacy()]);

        let view = client.vault().ciphers().decrypt(cipher.clone()).unwrap();

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

        let view = client.vault().ciphers().decrypt(cipher.clone()).unwrap();

        assert!(cipher.key.is_none());

        // Assert the cipher has a key, and the attachment is still readable
        let EncryptionContext {
            cipher: new_cipher,
            encrypted_for: _,
        } = client.vault().ciphers().encrypt(view).unwrap();
        assert!(new_cipher.key.is_some());

        let view = client.vault().ciphers().decrypt(new_cipher).unwrap();
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

        let view = client.vault().ciphers().decrypt(cipher.clone()).unwrap();

        assert!(cipher.key.is_none());

        // Assert the cipher has a key, and the attachment is still readable
        let EncryptionContext {
            cipher: new_cipher,
            encrypted_for: _,
        } = client.vault().ciphers().encrypt(view).unwrap();
        assert!(new_cipher.key.is_some());

        let view = client
            .vault()
            .ciphers()
            .decrypt(new_cipher.clone())
            .unwrap();
        let attachments = view.clone().attachments.unwrap();
        let attachment_view = attachments.first().unwrap().clone();
        assert!(attachment_view.key.is_some());

        // Ensure attachment key is updated since it's now protected by the cipher key
        assert_ne!(
            attachment.clone().key.unwrap().to_string(),
            attachment_view.clone().key.unwrap().to_string()
        );

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

        let attachment = new_cipher
            .clone()
            .attachments
            .unwrap()
            .first()
            .unwrap()
            .clone();

        // Ensure attachment key is still the same since it's protected by the cipher key
        assert_eq!(
            attachment.clone().key.as_ref().unwrap().to_string(),
            attachment_view.key.as_ref().unwrap().to_string()
        );

        let content = client
            .vault()
            .attachments()
            .decrypt_buffer(new_cipher, attachment_view, buf.as_slice())
            .unwrap();

        assert_eq!(content, b"Hello");
    }

    #[tokio::test]
    async fn test_encrypt_cipher_for_rotation() {
        let client = Client::init_test_account(test_bitwarden_com_account()).await;

        let new_key = SymmetricCryptoKey::make_aes256_cbc_hmac_key();

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
            client.vault().ciphers().decrypt(ctx.cipher).err(),
            Some(DecryptError::Crypto(CryptoError::InvalidMac))
        ));
    }
}
