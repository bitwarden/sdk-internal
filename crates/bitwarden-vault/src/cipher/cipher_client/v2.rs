//! Encryption and decryption of the fully decrypted [`CipherViewV2`] model.

#[cfg(feature = "wasm")]
use wasm_bindgen::prelude::*;

use super::CiphersClient;
use crate::{
    Cipher, CipherListViewV2, CipherViewV2, DecryptCipherListResultV2, DecryptError, EncryptError,
    EncryptionContext,
    cipher::cipher_view_v2::{DecryptedCipher, view_to_v1},
};

#[cfg_attr(feature = "wasm", wasm_bindgen)]
impl CiphersClient {
    /// Encrypt a [`CipherViewV2`]. Behaves like [`CiphersClient::encrypt`].
    pub async fn encrypt_v2(
        &self,
        cipher_view: CipherViewV2,
    ) -> Result<EncryptionContext, EncryptError> {
        let cipher_view = view_to_v1(&self.key_store, &cipher_view)?;
        self.encrypt(cipher_view).await
    }

    /// Decrypt a cipher into a [`CipherViewV2`].
    pub async fn decrypt_v2(&self, cipher: Cipher) -> Result<CipherViewV2, DecryptError> {
        Ok(CipherViewV2::decrypt_cipher(
            &self.key_store,
            &cipher,
            self.is_strict_decrypt().await,
        )?)
    }

    /// Decrypt a list of ciphers into [`CipherListViewV2`]. Fails if any cipher fails to decrypt.
    pub async fn decrypt_list_v2(
        &self,
        ciphers: Vec<Cipher>,
    ) -> Result<Vec<CipherListViewV2>, DecryptError> {
        Ok(CipherListViewV2::decrypt_ciphers(
            &self.key_store,
            &ciphers,
            self.is_strict_decrypt().await,
        )?)
    }

    /// Decrypt a list of ciphers into [`CipherListViewV2`].
    /// Returns both successfully decrypted ciphers and any that failed to decrypt.
    pub async fn decrypt_list_with_failures_v2(
        &self,
        ciphers: Vec<Cipher>,
    ) -> DecryptCipherListResultV2 {
        let (successes, failures) = CipherListViewV2::decrypt_ciphers_with_failures(
            &self.key_store,
            &ciphers,
            self.is_strict_decrypt().await,
        );
        DecryptCipherListResultV2 {
            successes,
            failures,
        }
    }
}

#[cfg(test)]
mod tests {
    use bitwarden_core::{Client, client::test_accounts::test_bitwarden_com_account};
    use bitwarden_crypto::{SymmetricCryptoKey, SymmetricKeyAlgorithm};

    use crate::{
        AttachmentViewV2, CipherViewV2, VaultClientExt,
        cipher::cipher_view_v2::tests::cipher_view_v2, generate_totp_cipher_view_v2,
    };

    const TEST_ORG_ID: &str = "1bc9ac1e-f5aa-45f2-94bf-b181009709b8";

    fn view() -> CipherViewV2 {
        cipher_view_v2(Some(SymmetricCryptoKey::make(
            SymmetricKeyAlgorithm::Aes256CbcHmac,
        )))
    }

    #[tokio::test]
    async fn encrypt_v2_then_decrypt_v2_round_trips() {
        let client = Client::init_test_account(test_bitwarden_com_account()).await;
        let ciphers = client.vault().ciphers();
        let view = view();

        let encrypted = ciphers.encrypt_v2(view.clone()).await.unwrap();
        let decrypted = ciphers.decrypt_v2(encrypted.cipher.clone()).await.unwrap();
        assert_eq!(decrypted, view);

        // The original model decrypts the same cipher, with the nested values still encrypted.
        let v1 = ciphers.decrypt(encrypted.cipher).await.unwrap();
        assert_eq!(v1.key.is_some(), view.key.is_some());
        assert_eq!(v1.login.unwrap().fido2_credentials.unwrap().len(), 1);
    }

    #[tokio::test]
    async fn decrypt_list_v2_has_decrypted_totp() {
        let client = Client::init_test_account(test_bitwarden_com_account()).await;
        let ciphers = client.vault().ciphers();
        let cipher = ciphers.encrypt_v2(view()).await.unwrap().cipher;

        let list = ciphers.decrypt_list_v2(vec![cipher.clone()]).await.unwrap();
        assert_eq!(list.len(), 1);
        let totp = generate_totp_cipher_view_v2(list.into_iter().next().unwrap(), None).unwrap();
        assert_eq!(totp.code.len(), 6);

        let mut broken = cipher.clone();
        // A cipher key wrapped under a different key makes the whole cipher fail to decrypt.
        broken.key = Some("2.Gg8yCM4IIgykCZyq0O4+cA==|GJLBtfvSJTDJh/F7X4cJPkzI6ccnzJm5DYl3yxOW2iUn7DgkkmzoOe61sUhC5dgVdV0kFqsZPcQ0yehlN1DDsFIFtrb4x7LwzJNIkMgxNyg=|1rGkGJ8zcM5o5D0aIIwAyLsjMLrPsP3EWm3CctBO3Fw=".parse().unwrap());
        let result = ciphers
            .decrypt_list_with_failures_v2(vec![cipher, broken])
            .await;
        assert_eq!(result.successes.len(), 1);
        assert_eq!(result.failures.len(), 1);
    }

    #[tokio::test]
    async fn move_to_organization_v2_keeps_decrypted_values() {
        let client = Client::init_test_account(test_bitwarden_com_account()).await;
        let ciphers = client.vault().ciphers();
        let view = view();
        let org_id = TEST_ORG_ID.parse().unwrap();

        let moved = ciphers
            .move_to_organization_v2(view.clone(), org_id)
            .unwrap();
        assert_eq!(moved.organization_id, Some(org_id));
        assert_eq!(moved.key, view.key);
        assert_eq!(moved.attachments, view.attachments);
        assert_eq!(moved.login, view.login);

        // After the move it encrypts under the organization key.
        let encrypted = ciphers.encrypt_v2(moved.clone()).await.unwrap();
        assert_eq!(ciphers.decrypt_v2(encrypted.cipher).await.unwrap(), moved);
    }

    #[tokio::test]
    async fn attachment_buffer_v2_round_trips() {
        let client = Client::init_test_account(test_bitwarden_com_account()).await;
        let mut view = view();
        view.attachments = None;
        let cipher = client
            .vault()
            .ciphers()
            .encrypt_v2(view)
            .await
            .unwrap()
            .cipher;

        let attachments = client.vault().attachments();
        let attachment = AttachmentViewV2 {
            id: None,
            url: None,
            size: Some("5".to_string()),
            size_name: Some("5 Bytes".to_string()),
            file_name: Some("file.txt".to_string()),
            key: None,
        };
        let encrypted = attachments
            .encrypt_buffer_v2(cipher.clone(), attachment, b"hello")
            .unwrap();

        // Decrypt the stored attachment metadata the same way a cipher decrypt does.
        let mut with_attachment = cipher.clone();
        with_attachment.attachments = Some(vec![encrypted.attachment]);
        let view = client
            .vault()
            .ciphers()
            .decrypt_v2(with_attachment)
            .await
            .unwrap();
        let attachment = view.attachments.unwrap().remove(0);
        assert!(attachment.key.is_some());

        let decrypted = attachments
            .decrypt_buffer_v2(cipher, attachment, &encrypted.contents)
            .unwrap();
        assert_eq!(decrypted, b"hello");
    }
}
