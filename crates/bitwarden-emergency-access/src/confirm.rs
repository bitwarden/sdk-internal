use bitwarden_api_api::models::OrganizationUserConfirmRequestModel;
use bitwarden_core::{ApiError, key_management::SymmetricKeySlotId};
use bitwarden_crypto::{CryptoError, PublicKey, SpkiPublicKeyBytes, UnsignedSharedKey};
use bitwarden_encoding::B64;
use bitwarden_error::bitwarden_error;
use thiserror::Error;

use crate::{EmergencyAccessClient, EmergencyAccessId};

/// Errors returned when confirming an emergency contact.
#[bitwarden_error(flat)]
#[derive(Debug, Error)]
pub enum EmergencyAccessConfirmError {
    /// The request to the server failed.
    #[error(transparent)]
    Api(#[from] ApiError),
    /// The grantee public key is malformed, or the user key could not be encapsulated to it.
    #[error(transparent)]
    Crypto(#[from] CryptoError),
}

#[bitwarden_ffi::wasm_export]
impl EmergencyAccessClient {
    /// Shares the current user's user key with the grantee. Step 3 of the setup.
    ///
    /// `grantee_public_key` is the base64 SPKI DER public key the user verified through the
    /// grantee's fingerprint. It is never fetched here, so an unverified key can't slip in.
    ///
    /// Called by the grantor.
    pub async fn confirm(
        &self,
        emergency_access_id: EmergencyAccessId,
        grantee_public_key: B64,
    ) -> Result<(), EmergencyAccessConfirmError> {
        // TODO: Use the trust log / KM APIs instead of a caller-supplied key.
        let grantee_public_key =
            PublicKey::from_der(&SpkiPublicKeyBytes::from(&grantee_public_key))?;

        // Encapsulate inside the key store so the user key never leaves it.
        let key = UnsignedSharedKey::encapsulate(
            SymmetricKeySlotId::User,
            &grantee_public_key,
            &self.key_store.context(),
        )?;

        // The server reuses the organization confirm request model; only the key applies.
        let request = OrganizationUserConfirmRequestModel {
            key: key.to_string(),
            default_user_collection_name: None,
        };

        self.api_configurations
            .api_client
            .emergency_access_api()
            .confirm(emergency_access_id.into(), Some(request))
            .await?;

        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use std::sync::{Arc, Mutex};

    use bitwarden_core::{
        Client,
        client::test_accounts::{test_bitwarden_com_account, test_bitwarden_com_account_v2},
        key_management::PrivateKeySlotId,
    };

    use super::*;
    use crate::{
        EmergencyAccessClientExt,
        test_support::{TEST_VECTOR_GRANTOR_KEY, api_error, is_test_id, test_client, test_id},
    };

    /// Base64 SPKI DER public key of the given client, as the clients pass it.
    fn public_key_of(client: &Client) -> B64 {
        let public_key = client
            .internal
            .get_key_store()
            .context()
            .get_public_key(PrivateKeySlotId::UserPrivateKey)
            .unwrap();

        public_key.to_der().unwrap().into()
    }

    #[tokio::test]
    async fn shares_user_key_with_grantee() {
        let grantee = Client::init_test_account(test_bitwarden_com_account_v2()).await;

        let sent_key = Arc::new(Mutex::new(None));
        let captured = sent_key.clone();
        let grantor = test_client(test_bitwarden_com_account(), move |mock| {
            mock.emergency_access_api
                .expect_confirm()
                .withf(|id, _| is_test_id(id))
                .returning(move |_, request| {
                    *captured.lock().unwrap() = request.map(|r| r.key);
                    Ok(())
                })
                .once();
        })
        .await;

        grantor
            .emergency_access()
            .confirm(test_id(), public_key_of(&grantee))
            .await
            .unwrap();

        // The grantee decapsulates the same key as the recorded grantor key vector: the
        // grantor's user key.
        let sent_key: UnsignedSharedKey = sent_key.lock().unwrap().take().unwrap().parse().unwrap();
        let recorded_key: UnsignedSharedKey = TEST_VECTOR_GRANTOR_KEY.parse().unwrap();

        let key_store = grantee.internal.get_key_store();
        let mut ctx = key_store.context();
        let sent = sent_key
            .decapsulate(PrivateKeySlotId::UserPrivateKey, &mut ctx)
            .unwrap();
        let recorded = recorded_key
            .decapsulate(PrivateKeySlotId::UserPrivateKey, &mut ctx)
            .unwrap();

        #[allow(deprecated)]
        let (sent, recorded) = (
            ctx.dangerous_get_symmetric_key(sent).unwrap(),
            ctx.dangerous_get_symmetric_key(recorded).unwrap(),
        );
        assert_eq!(sent, recorded);
    }

    #[tokio::test]
    async fn fails_when_public_key_is_malformed() {
        let grantor = test_client(test_bitwarden_com_account(), |mock| {
            mock.emergency_access_api.expect_confirm().never();
        })
        .await;

        let result = grantor
            .emergency_access()
            .confirm(test_id(), B64::from(b"not a key".as_slice()))
            .await;

        assert!(matches!(
            result,
            Err(EmergencyAccessConfirmError::Crypto(_))
        ));
    }

    #[tokio::test]
    async fn fails_when_request_fails() {
        let grantee = Client::init_test_account(test_bitwarden_com_account_v2()).await;
        let grantor = test_client(test_bitwarden_com_account(), |mock| {
            mock.emergency_access_api
                .expect_confirm()
                .returning(|_, _| api_error())
                .once();
        })
        .await;

        let result = grantor
            .emergency_access()
            .confirm(test_id(), public_key_of(&grantee))
            .await;

        assert!(matches!(result, Err(EmergencyAccessConfirmError::Api(_))));
    }
}
