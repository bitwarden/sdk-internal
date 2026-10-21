use bitwarden_crypto::{CryptoError, EncString};
use bitwarden_error::bitwarden_error;
use bitwarden_vault::{AttachmentFile, AttachmentView, LegacyAttachmentError};
use thiserror::Error;

use crate::EmergencyAccessClient;

/// Errors returned when decrypting an attachment of a grantor's vault item.
#[bitwarden_error(flat)]
#[derive(Debug, Error)]
pub enum EmergencyAccessDecryptAttachmentError {
    /// The encrypted buffer is malformed or could not be decrypted with the attachment key.
    #[error(transparent)]
    Crypto(#[from] CryptoError),
    /// The attachment has no attachment key (legacy v1), so it can't be decrypted without the
    /// grantor's account key.
    #[error(transparent)]
    LegacyAttachmentUnsupported(#[from] LegacyAttachmentError),
}

#[bitwarden_ffi::wasm_export]
impl EmergencyAccessClient {
    /// Decrypts an attachment of a grantor's vault item returned by
    /// [`view_vault_items`](EmergencyAccessClient::view_vault_items).
    ///
    /// `attachment` must carry its attachment key, which `view_vault_items` provides for v2 and v3
    /// attachments. Legacy v1 attachments have none and are rejected.
    ///
    /// Called by the grantee. Makes no request to the server: `encrypted_buffer` is the file as
    /// downloaded from the attachment's download URL.
    pub fn decrypt_attachment(
        &self,
        attachment: AttachmentView,
        encrypted_buffer: &[u8],
    ) -> Result<Vec<u8>, EmergencyAccessDecryptAttachmentError> {
        let file = AttachmentFile::for_emergency_access(
            attachment,
            EncString::from_buffer(encrypted_buffer)?,
        )?;
        Ok(self.key_store.decrypt(&file)?)
    }
}

#[cfg(test)]
mod tests {
    use bitwarden_core::client::test_accounts::test_bitwarden_com_account_v2;
    use bitwarden_crypto::SymmetricCryptoKey;
    use bitwarden_encoding::B64;

    use super::*;
    use crate::{EmergencyAccessClientExt, test_support::test_client};

    // Recorded from a v3 attachment: `TEST_VECTOR_ATTACHMENT_KEY` is the raw attachment key as
    // `view_vault_items` returns it, and the buffer is the encrypted file. Never regenerate these
    // to make a test pass: a vector that stops decrypting is a backward-compatibility break.
    const TEST_VECTOR_ATTACHMENT_KEY: &str =
        "62xEeYgG+asG+mPAvVGWRJawgX6VSdPRBqUMO/b24LbGiXuBX36g8EOj0RzybXG2SYBzvZtYXS19D+FDxn6S2w==";
    const TEST_VECTOR_ENCRYPTED_FILE: &str = "Ao00qr1xLsV+ZNQpYZ/UwEwOWo3hheKwCYcOGIbsorZ6JIG2vLWfWEXCVqP0hDuzRvmx8otApNZr8pJYLNwCe1aQ+ySHQYGkdubFjoMojulMbQ959Y4SJ6Its/EnVvpbDnxpXTDpbutDxyhxfq1P3lstL2G9rObJRrxiwdGlRGu1h94UA1fCCkIUQux5LcqUee6W4MyQmRnsUziH8gGzmtI=";
    const TEST_VECTOR_DECRYPTED_FILE: &str = "rMweTemxOL9D0iWWfRxiY3enxiZ5IrwWD6ef2apGO6MvgdGhy2fpwmATmn7BpSj9lRumddLLXm7u8zSp6hnXt1hS71YDNh78LjGKGhGL4sbg8uNnpa/I6GK/83jzqGYN7+ESbg==";

    fn attachment(key: Option<&str>) -> AttachmentView {
        AttachmentView {
            id: Some("attachment-id".to_string()),
            url: None,
            size: None,
            size_name: None,
            file_name: Some("Test.txt".to_string()),
            key: key.map(|key| SymmetricCryptoKey::try_from(key.to_string()).unwrap()),
        }
    }

    fn b64(value: &str) -> Vec<u8> {
        B64::try_from(value).unwrap().as_bytes().to_vec()
    }

    /// Decrypts as the grantee. No API expectations are set, so any request would fail the test.
    async fn decrypt(
        attachment: AttachmentView,
        encrypted_buffer: &[u8],
    ) -> Result<Vec<u8>, EmergencyAccessDecryptAttachmentError> {
        test_client(test_bitwarden_com_account_v2(), |_| {})
            .await
            .emergency_access()
            .decrypt_attachment(attachment, encrypted_buffer)
    }

    #[tokio::test]
    async fn decrypts_with_attachment_key() {
        let decrypted = decrypt(
            attachment(Some(TEST_VECTOR_ATTACHMENT_KEY)),
            &b64(TEST_VECTOR_ENCRYPTED_FILE),
        )
        .await
        .unwrap();

        assert_eq!(decrypted, b64(TEST_VECTOR_DECRYPTED_FILE));
    }

    #[tokio::test]
    async fn fails_for_legacy_attachment_without_key() {
        let result = decrypt(attachment(None), &b64(TEST_VECTOR_ENCRYPTED_FILE)).await;

        assert!(matches!(
            result,
            Err(EmergencyAccessDecryptAttachmentError::LegacyAttachmentUnsupported(_))
        ));
    }

    #[tokio::test]
    async fn fails_when_buffer_is_malformed() {
        let result = decrypt(attachment(Some(TEST_VECTOR_ATTACHMENT_KEY)), &[]).await;

        assert!(matches!(
            result,
            Err(EmergencyAccessDecryptAttachmentError::Crypto(_))
        ));
    }

    #[tokio::test]
    async fn fails_with_wrong_attachment_key() {
        let wrong_key = "w2LO+nwV4oxwswVYCxlOfRUseXfvU03VzvKQHrqeklPgiMZrspUe6sOBToCnDn9Ay0tuCBn8ykVVRb7PWhub2Q==";

        let result = decrypt(
            attachment(Some(wrong_key)),
            &b64(TEST_VECTOR_ENCRYPTED_FILE),
        )
        .await;

        assert!(matches!(
            result,
            Err(EmergencyAccessDecryptAttachmentError::Crypto(_))
        ));
    }
}
