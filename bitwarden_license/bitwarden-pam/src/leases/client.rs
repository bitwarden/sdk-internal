use std::sync::Arc;

use bitwarden_core::{FromClient, client::ApiConfigurations, key_management::KeySlotIds};
use bitwarden_crypto::KeyStore;
use bitwarden_vault::{Cipher, CipherId, CipherView};
#[cfg(feature = "wasm")]
use wasm_bindgen::prelude::wasm_bindgen;

use super::{
    error::AccessLeaseError,
    models::{AccessLeaseExtensionRequest, AccessLeaseRevokeRequest, AccessLeaseView},
};
use crate::{AccessLeaseId, access_requests::AccessRequestView};

/// Client for reading and managing a requester's PAM access leases.
///
/// A lease is minted by [`AccessRequestsClient::activate`](crate::AccessRequestsClient::activate);
/// this client covers the rest of a lease's life: listing the caller's leases, extending an active
/// one, and ending one early.
#[cfg_attr(feature = "wasm", wasm_bindgen)]
#[derive(FromClient)]
pub struct LeasesClient {
    pub(crate) key_store: KeyStore<KeySlotIds>,
    pub(crate) api_configurations: Arc<ApiConfigurations>,
}

#[cfg_attr(feature = "wasm", wasm_bindgen)]
impl LeasesClient {
    /// Lists the caller's currently active leases.
    pub async fn list_active(&self) -> Result<Vec<AccessLeaseView>, AccessLeaseError> {
        let response = self
            .api_configurations
            .api_client
            .leases_api()
            .get_active()
            .await?;

        response
            .data
            .unwrap_or_default()
            .into_iter()
            .map(AccessLeaseView::try_from)
            .collect::<Result<Vec<_>, _>>()
            .map_err(Into::into)
    }

    /// Lists all of the caller's leases, active or not.
    pub async fn list_mine(&self) -> Result<Vec<AccessLeaseView>, AccessLeaseError> {
        let response = self
            .api_configurations
            .api_client
            .leases_api()
            .get_mine()
            .await?;

        response
            .data
            .unwrap_or_default()
            .into_iter()
            .map(AccessLeaseView::try_from)
            .collect::<Result<Vec<_>, _>>()
            .map_err(Into::into)
    }

    /// Extends an active lease, returning the updated originating request.
    pub async fn extend(
        &self,
        lease_id: AccessLeaseId,
        request: AccessLeaseExtensionRequest,
    ) -> Result<AccessRequestView, AccessLeaseError> {
        let response = self
            .api_configurations
            .api_client
            .leases_api()
            .extend(lease_id.into(), request.into())
            .await?;

        Ok(AccessRequestView::try_from(response)?)
    }

    /// Ends a lease before it expires, re-locking the cipher.
    pub async fn end(
        &self,
        lease_id: AccessLeaseId,
        request: AccessLeaseRevokeRequest,
    ) -> Result<(), AccessLeaseError> {
        self.api_configurations
            .api_client
            .leases_api()
            .revoke(lease_id.into(), request.into())
            .await?;

        Ok(())
    }

    /// Reads the full cipher a lease unlocks, straight from the server.
    ///
    /// Returns `None` when the server still answers with a restricted (partial) payload, which
    /// means the caller's lease is not in effect - it lapsed between the access-state read that
    /// sent them here and this call. Handing the partial back as if it were unlocked would show
    /// an empty credential as though it were the real one.
    ///
    /// Three properties make this a lease operation rather than a plain vault read:
    ///
    /// - It goes through the STANDARD single-cipher endpoint. The server already decides per caller
    ///   what a cipher's payload contains - restricted without a lease, complete with one - so
    ///   there is no PAM-specific route to call, and the partial-cipher pivot deliberately left the
    ///   old `GET /leases/ciphers/{id}/cipher` without a successor.
    /// - The result is NEVER written to the cipher repository. Local state stays partial for the
    ///   lease's whole life, so closing and reopening the item re-reads it, and a lapsed lease
    ///   cannot leave decryptable secrets behind in state.
    /// - It is the read that a lease authorizes, so it fails with the same [`AccessLeaseError`] as
    ///   the rest of this client.
    pub async fn leased_cipher(
        &self,
        cipher_id: CipherId,
    ) -> Result<Option<CipherView>, AccessLeaseError> {
        let response = self
            .api_configurations
            .api_client
            .ciphers_api()
            .get_details(cipher_id.into())
            .await?;

        let cipher = Cipher::try_from(response)?;

        if cipher.partial_data.is_some() {
            return Ok(None);
        }

        Ok(Some(self.key_store.decrypt(&cipher)?))
    }
}

#[cfg(test)]
mod tests {
    use std::num::NonZeroU32;

    use bitwarden_api_api::{
        apis::ApiClient,
        models::{
            AccessLeaseResponseModel, AccessLeaseResponseModelListResponseModel,
            AccessLeaseStatus as ApiAccessLeaseStatus, AccessRequestDetailsResponseModel,
            CipherDetailsResponseModel,
        },
    };
    use bitwarden_core::key_management::create_test_crypto_with_user_key;
    use bitwarden_crypto::{SymmetricCryptoKey, SymmetricKeyAlgorithm};
    use chrono::{DateTime, Utc};
    use uuid::uuid;

    use super::*;
    use crate::leases::models::AccessLeaseStatus;

    fn lease_id() -> AccessLeaseId {
        AccessLeaseId::new(uuid!("33333333-3333-3333-3333-333333333333"))
    }

    fn client(api_client: ApiClient) -> LeasesClient {
        LeasesClient {
            key_store: create_test_crypto_with_user_key(SymmetricCryptoKey::make(
                SymmetricKeyAlgorithm::Aes256CbcHmac,
            )),
            api_configurations: Arc::new(ApiConfigurations::from_api_client(api_client)),
        }
    }

    fn cipher_id() -> CipherId {
        CipherId::new(uuid!("55555555-5555-5555-5555-555555555555"))
    }

    /// A full (unrestricted) cipher payload, as the server answers a caller holding a lease. Its
    /// `name` is encrypted under a key the test store does not have, which is all the decrypt path
    /// needs to be exercised - see `leased_cipher_surfaces_a_decrypt_failure`.
    fn full_cipher_response() -> CipherDetailsResponseModel {
        CipherDetailsResponseModel {
            id: Some(cipher_id().into()),
            name: Some("2.pMS6/icTQABtulw52pq2lg==|XXbxKxDTh+mWiN1HjH2N1w==|Q6PkuT+KX/axrgN9ubD5Ajk2YNwxQkgs3WJM0S0wtG8=".to_string()),
            r#type: Some(bitwarden_api_api::models::CipherType::Login),
            login: Some(Box::new(bitwarden_api_api::models::CipherLoginModel::default())),
            creation_date: Some("2025-01-01T00:00:00Z".to_string()),
            revision_date: Some("2025-01-01T00:00:00Z".to_string()),
            ..Default::default()
        }
    }

    fn sample_lease() -> AccessLeaseResponseModel {
        AccessLeaseResponseModel {
            id: Some(lease_id().into()),
            request_id: Some(uuid!("44444444-4444-4444-4444-444444444444")),
            cipher_id: Some(uuid!("55555555-5555-5555-5555-555555555555")),
            collection_id: Some(uuid!("66666666-6666-6666-6666-666666666666")),
            organization_id: Some(uuid!("77777777-7777-7777-7777-777777777777")),
            requester_id: Some(uuid!("88888888-8888-8888-8888-888888888888")),
            status: Some(ApiAccessLeaseStatus::Active),
            not_before: Some("2025-01-01T00:00:00Z".to_string()),
            not_after: Some("2025-01-01T01:00:00Z".to_string()),
            ..Default::default()
        }
    }

    #[tokio::test]
    async fn list_active_returns_views() {
        let api_client = ApiClient::new_mocked(move |mock| {
            mock.leases_api
                .expect_get_active()
                .returning(move || {
                    let mut list = AccessLeaseResponseModelListResponseModel::new();
                    list.data = Some(vec![sample_lease()]);
                    Ok(list)
                })
                .once();
        });

        let result = client(api_client).list_active().await.unwrap();

        assert_eq!(result.len(), 1);
        assert_eq!(result[0].id, lease_id());
        assert_eq!(result[0].status, AccessLeaseStatus::Active);
    }

    #[tokio::test]
    async fn list_mine_surfaces_api_error() {
        let api_client = ApiClient::new_mocked(move |mock| {
            mock.leases_api
                .expect_get_mine()
                .returning(move || {
                    Err(bitwarden_api_api::apis::Error::Response(
                        bitwarden_api_api::apis::ResponseContent {
                            status: reqwest::StatusCode::INTERNAL_SERVER_ERROR,
                            message: String::new(),
                        },
                    ))
                })
                .once();
        });

        let result = client(api_client).list_mine().await;

        assert!(matches!(result, Err(AccessLeaseError::Api(_))));
    }

    #[tokio::test]
    async fn extend_returns_updated_request() {
        let api_client = ApiClient::new_mocked(move |mock| {
            mock.leases_api
                .expect_extend()
                .returning(move |_id, _request| {
                    Ok(AccessRequestDetailsResponseModel {
                        id: Some(uuid!("44444444-4444-4444-4444-444444444444")),
                        cipher_id: Some(uuid!("55555555-5555-5555-5555-555555555555")),
                        collection_id: Some(uuid!("66666666-6666-6666-6666-666666666666")),
                        requester_id: Some(uuid!("88888888-8888-8888-8888-888888888888")),
                        status: Some(bitwarden_api_api::models::AccessRequestStatus::Approved),
                        lease_not_before: Some("2025-01-01T00:00:00Z".to_string()),
                        lease_not_after: Some("2025-01-01T02:00:00Z".to_string()),
                        submitted_at: Some("2025-01-01T00:00:00Z".to_string()),
                        ..Default::default()
                    })
                })
                .once();
        });

        let request = AccessLeaseExtensionRequest {
            duration_seconds: NonZeroU32::new(3600),
            reason: "Need more time".to_string(),
        };
        let result = client(api_client)
            .extend(lease_id(), request)
            .await
            .unwrap();

        assert_eq!(
            result.lease_not_after,
            "2025-01-01T02:00:00Z".parse::<DateTime<Utc>>().unwrap()
        );
    }

    #[tokio::test]
    async fn end_succeeds() {
        let api_client = ApiClient::new_mocked(move |mock| {
            mock.leases_api
                .expect_revoke()
                .returning(move |_id, _request| Ok(()))
                .once();
        });

        let result = client(api_client)
            .end(lease_id(), AccessLeaseRevokeRequest::default())
            .await;

        assert!(result.is_ok());
    }

    #[tokio::test]
    async fn leased_cipher_reports_no_access_when_the_server_still_restricts_the_cipher() {
        let api_client = ApiClient::new_mocked(move |mock| {
            mock.ciphers_api
                .expect_get_details()
                .returning(move |_id| {
                    Ok(CipherDetailsResponseModel {
                        partial_data: Some(r#"{"name":"Prod DB root"}"#.to_string()),
                        ..full_cipher_response()
                    })
                })
                .once();
        });

        let result = client(api_client).leased_cipher(cipher_id()).await.unwrap();

        // The lease lapsed between the access-state read and this one. Returning the partial would
        // reveal an empty credential dressed as the real one.
        assert!(result.is_none());
    }

    /// A full payload is decrypted and handed back. Producing the *right* plaintext is
    /// bitwarden-vault's contract, covered by its own tests - and note that its decrypt degrades
    /// gracefully, so a field this store holds no key for arrives as an empty string rather than an
    /// error. What matters here is that a non-restricted payload takes the decrypt branch and comes
    /// back as a view the caller can render, marked `partial: false`.
    #[tokio::test]
    async fn leased_cipher_returns_a_view_for_a_full_payload() {
        let api_client = ApiClient::new_mocked(move |mock| {
            mock.ciphers_api
                .expect_get_details()
                .returning(move |_id| Ok(full_cipher_response()))
                .once();
        });

        let view = client(api_client)
            .leased_cipher(cipher_id())
            .await
            .unwrap()
            .expect("a full payload should resolve to a view");

        assert_eq!(view.id, Some(cipher_id()));
        assert!(!view.partial);
    }

    #[tokio::test]
    async fn leased_cipher_surfaces_api_errors() {
        let api_client = ApiClient::new_mocked(move |mock| {
            mock.ciphers_api
                .expect_get_details()
                .returning(move |_id| {
                    Err(bitwarden_api_api::ApiError::Response(
                        bitwarden_api_api::ResponseContent {
                            status: reqwest::StatusCode::NOT_FOUND,
                            message: String::new(),
                        },
                    ))
                })
                .once();
        });

        let result = client(api_client).leased_cipher(cipher_id()).await;

        assert!(matches!(result, Err(AccessLeaseError::Api(_))));
    }
}
