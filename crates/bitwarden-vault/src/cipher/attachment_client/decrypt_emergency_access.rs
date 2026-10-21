use bitwarden_crypto::{CryptoError, EncString};
use bitwarden_error::bitwarden_error;
use thiserror::Error;

use super::AttachmentsClient;
use crate::{AttachmentView, cipher::attachment::decrypt_with_attachment_key};

/// Errors returned when decrypting an attachment of a grantor's vault item.
#[bitwarden_error(flat)]
#[derive(Debug, Error)]
pub enum DecryptEmergencyAccessAttachmentError {
    /// The buffer is malformed, or the attachment key doesn't decrypt it.
    #[error(transparent)]
    Crypto(#[from] CryptoError),
    /// The attachment uses legacy v1 encryption, which has no attachment key.
    #[error("Legacy attachments without an attachment key are not supported")]
    LegacyAttachmentUnsupported,
}

#[bitwarden_ffi::wasm_export]
impl AttachmentsClient {
    /// Decrypts an attachment of a grantor's vault item returned by emergency access
    /// `view_vault_items`.
    ///
    /// Only attachments with an attachment key (v2/v3) are supported. Legacy v1 attachments
    /// return [`DecryptEmergencyAccessAttachmentError::LegacyAttachmentUnsupported`]. Use
    /// [`AttachmentsClient::decrypt_buffer`] for attachments of the user's own vault.
    pub fn decrypt_emergency_access_buffer(
        &self,
        attachment: AttachmentView,
        encrypted_buffer: &[u8],
    ) -> Result<Vec<u8>, DecryptEmergencyAccessAttachmentError> {
        let key = attachment
            .key
            .ok_or(DecryptEmergencyAccessAttachmentError::LegacyAttachmentUnsupported)?;
        let contents = EncString::from_buffer(encrypted_buffer)?;
        let mut ctx = self.key_store.context();
        decrypt_with_attachment_key(&mut ctx, key, &contents).map_err(|e| {
            tracing::warn!(
                attachment_id = ?attachment.id,
                error = %e,
                "Failed to decrypt emergency access attachment contents with attachment key"
            );
            e.into()
        })
    }
}

#[cfg(test)]
mod tests {
    use std::sync::Arc;

    use bitwarden_api_api::apis::ApiClient;
    use bitwarden_core::{
        client::ApiConfigurations,
        key_management::{KeySlotIds, SymmetricKeySlotId, create_test_crypto_with_user_key},
    };
    use bitwarden_crypto::{EncString, KeyStore, SymmetricCryptoKey, SymmetricKeyAlgorithm};
    use bitwarden_encoding::B64;

    use super::*;
    use crate::Cipher;

    const USER_KEY: &str =
        "w2LO+nwV4oxwswVYCxlOfRUseXfvU03VzvKQHrqeklPgiMZrspUe6sOBToCnDn9Ay0tuCBn8ykVVRb7PWhub2Q==";
    const CIPHER_KEY: &str = "2.Gg8yCM4IIgykCZyq0O4+cA==|GJLBtfvSJTDJh/F7X4cJPkzI6ccnzJm5DYl3yxOW2iUn7DgkkmzoOe61sUhC5dgVdV0kFqsZPcQ0yehlN1DDsFIFtrb4x7LwzJNIkMgxNyg=|1rGkGJ8zcM5o5D0aIIwAyLsjMLrPsP3EWm3CctBO3Fw=";
    const ATTACHMENT_KEY: &str = "2.r288/AOSPiaLFkW07EBGBw==|SAmnnCbOLFjX5lnURvoualOetQwuyPc54PAmHDTRrhT0gwO9ailna9U09q9bmBfI5XrjNNEsuXssgzNygRkezoVQvZQggZddOwHB6KQW5EQ=|erIMUJp8j+aTcmhdE50zEX+ipv/eR1sZ7EwULJm/6DY=";
    const ENCRYPTED_FILE: &str = "Ao00qr1xLsV+ZNQpYZ/UwEwOWo3hheKwCYcOGIbsorZ6JIG2vLWfWEXCVqP0hDuzRvmx8otApNZr8pJYLNwCe1aQ+ySHQYGkdubFjoMojulMbQ959Y4SJ6Its/EnVvpbDnxpXTDpbutDxyhxfq1P3lstL2G9rObJRrxiwdGlRGu1h94UA1fCCkIUQux5LcqUee6W4MyQmRnsUziH8gGzmtI=";
    const PLAINTEXT: &str = "rMweTemxOL9D0iWWfRxiY3enxiZ5IrwWD6ef2apGO6MvgdGhy2fpwmATmn7BpSj9lRumddLLXm7u8zSp6hnXt1hS71YDNh78LjGKGhGL4sbg8uNnpa/I6GK/83jzqGYN7+ESbg==";

    /// An `AttachmentsClient` with an empty key store and a mocked API that has no expectations,
    /// so any key-store lookup or network call would fail the test.
    fn client() -> AttachmentsClient {
        AttachmentsClient {
            key_store: KeyStore::<KeySlotIds>::default(),
            api_configurations: Arc::new(ApiConfigurations::from_api_client(
                ApiClient::new_mocked(|_| {}),
            )),
            repository: None,
            http_client: reqwest::Client::new(),
        }
    }

    /// The raw attachment key, as `view_vault_items` exports it on `AttachmentView.key`.
    fn raw_attachment_key() -> SymmetricCryptoKey {
        let key_store = create_test_crypto_with_user_key(USER_KEY.to_string().try_into().unwrap());
        let mut ctx = key_store.context();
        let cipher_key = Cipher::decrypt_cipher_key(
            &mut ctx,
            SymmetricKeySlotId::User,
            &Some(CIPHER_KEY.parse::<EncString>().unwrap()),
        )
        .unwrap();
        let slot = ctx
            .unwrap_symmetric_key(cipher_key, &ATTACHMENT_KEY.parse().unwrap())
            .unwrap();
        #[allow(deprecated)]
        ctx.dangerous_get_symmetric_key(slot).unwrap().clone()
    }

    fn attachment(key: Option<SymmetricCryptoKey>) -> AttachmentView {
        AttachmentView {
            id: Some("attachment-id".into()),
            url: None,
            size: Some("161".into()),
            size_name: Some("161 Bytes".into()),
            file_name: Some("Test.txt".into()),
            key,
        }
    }

    fn encrypted_file() -> Vec<u8> {
        B64::try_from(ENCRYPTED_FILE).unwrap().as_bytes().to_vec()
    }

    #[test]
    fn decrypts_v2_attachment_without_cipher_or_user_key() {
        let decrypted = client()
            .decrypt_emergency_access_buffer(
                attachment(Some(raw_attachment_key())),
                &encrypted_file(),
            )
            .unwrap();

        assert_eq!(decrypted, B64::try_from(PLAINTEXT).unwrap().as_bytes());
    }

    #[test]
    fn legacy_attachment_without_key_is_unsupported() {
        let result = client().decrypt_emergency_access_buffer(attachment(None), &encrypted_file());

        assert!(matches!(
            result,
            Err(DecryptEmergencyAccessAttachmentError::LegacyAttachmentUnsupported)
        ));
    }

    #[test]
    fn corrupt_buffer_returns_crypto_error() {
        let mut buffer = encrypted_file();
        let last = buffer.len() - 1;
        buffer[last] ^= 0xFF;

        let result = client()
            .decrypt_emergency_access_buffer(attachment(Some(raw_attachment_key())), &buffer);

        assert!(matches!(
            result,
            Err(DecryptEmergencyAccessAttachmentError::Crypto(_))
        ));
    }

    #[test]
    fn empty_buffer_returns_crypto_error() {
        let result =
            client().decrypt_emergency_access_buffer(attachment(Some(raw_attachment_key())), &[]);

        assert!(matches!(
            result,
            Err(DecryptEmergencyAccessAttachmentError::Crypto(_))
        ));
    }

    #[test]
    fn wrong_key_returns_crypto_error() {
        let result = client().decrypt_emergency_access_buffer(
            attachment(Some(SymmetricCryptoKey::make(
                SymmetricKeyAlgorithm::Aes256CbcHmac,
            ))),
            &encrypted_file(),
        );

        assert!(matches!(
            result,
            Err(DecryptEmergencyAccessAttachmentError::Crypto(_))
        ));
    }
}
