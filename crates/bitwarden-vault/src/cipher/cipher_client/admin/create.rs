use bitwarden_api_api::models::CipherCreateRequestModel;
use bitwarden_core::{
    ApiError, MissingFieldError, NotAuthenticatedError, UserId, key_management::KeyIds,
};
use bitwarden_crypto::{CryptoError, IdentifyKey, KeyStore};
use bitwarden_error::bitwarden_error;
use thiserror::Error;
#[cfg(feature = "wasm")]
use wasm_bindgen::prelude::*;

use crate::{
    Cipher, CipherView, VaultParseError,
    cipher::cipher::PartialCipher,
    cipher_client::{
        admin::CipherAdminClient,
        create::{CipherCreateRequest, CipherCreateRequestInternal},
    },
};

#[allow(missing_docs)]
#[bitwarden_error(flat)]
#[derive(Debug, Error)]
pub enum CreateCipherAdminError {
    #[error(transparent)]
    Crypto(#[from] CryptoError),
    #[error(transparent)]
    Api(#[from] ApiError),
    #[error(transparent)]
    VaultParse(#[from] VaultParseError),
    #[error(transparent)]
    MissingField(#[from] MissingFieldError),
    #[error(transparent)]
    NotAuthenticated(#[from] NotAuthenticatedError),
}

impl<T> From<bitwarden_api_api::apis::Error<T>> for CreateCipherAdminError {
    fn from(val: bitwarden_api_api::apis::Error<T>) -> Self {
        Self::Api(val.into())
    }
}

/// Wraps the API call to create a cipher using the admin endpoint, for easier testing.
async fn create_cipher(
    request: CipherCreateRequestInternal,
    encrypted_for: UserId,
    api_client: &bitwarden_api_api::apis::ApiClient,
    key_store: &KeyStore<KeyIds>,
) -> Result<CipherView, CreateCipherAdminError> {
    let collection_ids = request.create_request.collection_ids.clone();
    let mut cipher_request = key_store.encrypt(request)?;
    cipher_request.encrypted_for = Some(encrypted_for.into());

    let cipher: Cipher = api_client
        .ciphers_api()
        .post_admin(Some(CipherCreateRequestModel {
            collection_ids: Some(collection_ids.into_iter().map(Into::into).collect()),
            cipher: Box::new(cipher_request),
        }))
        .await?
        .merge_with_cipher(None)?;

    Ok(key_store.decrypt(&cipher)?)
}

#[cfg_attr(feature = "wasm", wasm_bindgen)]
impl CipherAdminClient {
    /// Creates a new [Cipher] for an organization, using the admin server endpoints.
    /// Creates the Cipher on the server only, does not store it to local state.
    pub async fn create(
        &self,
        request: CipherCreateRequest,
    ) -> Result<CipherView, CreateCipherAdminError> {
        let key_store = self.client.internal.get_key_store();
        let config = self.client.internal.get_api_configurations().await;
        let mut internal_request: CipherCreateRequestInternal = request.into();

        let user_id = self
            .client
            .internal
            .get_user_id()
            .ok_or(NotAuthenticatedError)?;

        // TODO: Once this flag is removed, the key generation logic should
        // be moved closer to the actual encryption logic.
        if self
            .client
            .internal
            .get_flags()
            .enable_cipher_key_encryption
        {
            let key = internal_request.key_identifier();
            internal_request.generate_cipher_key(&mut key_store.context(), key)?;
        }

        create_cipher(internal_request, user_id, &config.api_client, key_store).await
    }
}

#[cfg(test)]
mod tests {
    use bitwarden_api_api::models::CipherMiniResponseModel;
    use bitwarden_core::{OrganizationId, key_management::SymmetricKeyId};
    use bitwarden_crypto::SymmetricCryptoKey;
    use chrono::Utc;

    use super::*;
    use crate::{CipherRepromptType, CipherViewType, LoginView};

    const TEST_CIPHER_ID: &str = "5faa9684-c793-4a2d-8a12-b33900187097";
    const TEST_COLLECTION_ID: &str = "73546b86-8802-4449-ad2a-69ea981b4ffd";
    const TEST_USER_ID: &str = "550e8400-e29b-41d4-a716-446655440000";
    const TEST_ORG_ID: &str = "1bc9ac1e-f5aa-45f2-94bf-b181009709b8";

    #[tokio::test]
    async fn test_create_org_cipher() {
        let api_client = bitwarden_api_api::apis::ApiClient::new_mocked(|mock| {
            mock.ciphers_api
                .expect_post_admin()
                .returning(move |request| {
                    let request = request.unwrap();

                    Ok(CipherMiniResponseModel {
                        id: Some(TEST_CIPHER_ID.try_into().unwrap()),
                        organization_id: request
                            .cipher
                            .organization_id
                            .and_then(|id| id.parse().ok()),
                        name: Some(request.cipher.name.clone()),
                        r#type: request.cipher.r#type,
                        creation_date: Some(
                            Utc::now().to_rfc3339_opts(chrono::SecondsFormat::Secs, true),
                        ),
                        revision_date: Some(
                            Utc::now().to_rfc3339_opts(chrono::SecondsFormat::Secs, true),
                        ),
                        ..Default::default()
                    })
                });
        });

        let store: KeyStore<KeyIds> = KeyStore::default();
        #[allow(deprecated)]
        let _ = store.context_mut().set_symmetric_key(
            SymmetricKeyId::User,
            SymmetricCryptoKey::make_aes256_cbc_hmac_key(),
        );
        #[allow(deprecated)]
        let _ = store.context_mut().set_symmetric_key(
            SymmetricKeyId::Organization(TEST_ORG_ID.parse::<OrganizationId>().unwrap()),
            SymmetricCryptoKey::make_aes256_cbc_hmac_key(),
        );

        let cipher_request: CipherCreateRequestInternal = CipherCreateRequest {
            organization_id: Some(TEST_ORG_ID.parse().unwrap()),
            collection_ids: vec![TEST_COLLECTION_ID.parse().unwrap()],
            folder_id: None,
            name: "Test Cipher".into(),
            notes: None,
            favorite: false,
            reprompt: CipherRepromptType::None,
            r#type: CipherViewType::Login(LoginView {
                username: None,
                password: None,
                password_revision_date: None,
                uris: None,
                totp: None,
                autofill_on_page_load: None,
                fido2_credentials: None,
            }),
            fields: vec![],
        }
        .into();

        let response = create_cipher(
            cipher_request.clone(),
            TEST_USER_ID.parse().unwrap(),
            &api_client,
            &store,
        )
        .await
        .unwrap();

        assert_eq!(response.id, Some(TEST_CIPHER_ID.parse().unwrap()));
        assert_eq!(
            response.organization_id,
            cipher_request.create_request.organization_id
        );
    }
}
