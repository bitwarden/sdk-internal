use std::sync::Arc;

use bitwarden_core::{FromClient, client::ApiConfigurations};
#[cfg(feature = "wasm")]
use wasm_bindgen::prelude::wasm_bindgen;

use super::models::AccessRequestView;
use crate::{AccessRequestId, error::LeasingError, leases::AccessLeaseView};

/// Client for a requester's PAM access requests.
///
/// Covers the requester side of the request lifecycle: listing and reading the caller's own
/// requests, [`activate`](AccessRequestsClient::activate)ing an approved request to mint a lease,
/// and [`cancel`](AccessRequestsClient::cancel)ling a request that is still pending.
///
/// Creating a request (`POST /leases/ciphers/{id}`) is not yet exposed here - its binding lives on
/// the not-yet-generated `cipher_lease_api` surface and lands with a later change.
#[cfg_attr(feature = "wasm", wasm_bindgen)]
#[derive(FromClient)]
pub struct AccessRequestsClient {
    pub(crate) api_configurations: Arc<ApiConfigurations>,
}

#[cfg_attr(feature = "wasm", wasm_bindgen)]
impl AccessRequestsClient {
    /// Lists the caller's own access requests.
    pub async fn list_mine(&self) -> Result<Vec<AccessRequestView>, LeasingError> {
        let response = self
            .api_configurations
            .api_client
            .access_requests_api()
            .get_mine()
            .await?;

        response
            .data
            .unwrap_or_default()
            .into_iter()
            .map(AccessRequestView::try_from)
            .collect()
    }

    /// Retrieves a single access request by ID.
    pub async fn get(&self, id: AccessRequestId) -> Result<AccessRequestView, LeasingError> {
        let response = self
            .api_configurations
            .api_client
            .access_requests_api()
            .get_details(id.into())
            .await?;

        AccessRequestView::try_from(response)
    }

    /// Activates an approved request, minting and returning the resulting lease.
    ///
    /// This is the second half of the automatic flow: once a request reaches
    /// [`Approved`](super::AccessRequestStatus::Approved), the requester activates it to obtain a
    /// short-lived [`AccessLease`](AccessLeaseView) over the cipher.
    pub async fn activate(&self, id: AccessRequestId) -> Result<AccessLeaseView, LeasingError> {
        let response = self
            .api_configurations
            .api_client
            .access_requests_api()
            .activate(id.into())
            .await?;

        AccessLeaseView::try_from(response)
    }

    /// Cancels the caller's own request while it is still pending.
    pub async fn cancel(&self, id: AccessRequestId) -> Result<(), LeasingError> {
        self.api_configurations
            .api_client
            .access_requests_api()
            .revoke(id.into())
            .await?;

        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use bitwarden_api_api::{
        apis::ApiClient,
        models::{
            AccessLeaseResponseModel, AccessLeaseStatus as ApiAccessLeaseStatus,
            AccessRequestDetailsResponseModel, AccessRequestDetailsResponseModelListResponseModel,
            AccessRequestStatus as ApiAccessRequestStatus,
        },
    };
    use uuid::uuid;

    use super::*;
    use crate::{AccessLeaseStatus, AccessRequestStatus};

    fn request_id() -> AccessRequestId {
        AccessRequestId::new(uuid!("44444444-4444-4444-4444-444444444444"))
    }

    fn client(api_client: ApiClient) -> AccessRequestsClient {
        AccessRequestsClient {
            api_configurations: Arc::new(ApiConfigurations::from_api_client(api_client)),
        }
    }

    fn sample_request() -> AccessRequestDetailsResponseModel {
        AccessRequestDetailsResponseModel {
            id: Some(request_id().into()),
            cipher_id: Some(uuid!("55555555-5555-5555-5555-555555555555")),
            collection_id: Some(uuid!("66666666-6666-6666-6666-666666666666")),
            requester_id: Some(uuid!("88888888-8888-8888-8888-888888888888")),
            status: Some(ApiAccessRequestStatus::Approved),
            lease_not_before: Some("2025-01-01T00:00:00Z".to_string()),
            lease_not_after: Some("2025-01-01T01:00:00Z".to_string()),
            submitted_at: Some("2025-01-01T00:00:00Z".to_string()),
            ..Default::default()
        }
    }

    fn sample_lease() -> AccessLeaseResponseModel {
        AccessLeaseResponseModel {
            id: Some(uuid!("33333333-3333-3333-3333-333333333333")),
            request_id: Some(request_id().into()),
            cipher_id: Some(uuid!("55555555-5555-5555-5555-555555555555")),
            collection_id: Some(uuid!("66666666-6666-6666-6666-666666666666")),
            requester_id: Some(uuid!("88888888-8888-8888-8888-888888888888")),
            status: Some(ApiAccessLeaseStatus::Active),
            not_before: Some("2025-01-01T00:00:00Z".to_string()),
            not_after: Some("2025-01-01T01:00:00Z".to_string()),
            ..Default::default()
        }
    }

    #[tokio::test]
    async fn list_mine_returns_views() {
        let api_client = ApiClient::new_mocked(move |mock| {
            mock.access_requests_api
                .expect_get_mine()
                .returning(move || {
                    let mut list = AccessRequestDetailsResponseModelListResponseModel::new();
                    list.data = Some(vec![sample_request()]);
                    Ok(list)
                })
                .once();
        });

        let result = client(api_client).list_mine().await.unwrap();

        assert_eq!(result.len(), 1);
        assert_eq!(result[0].id, request_id());
        assert_eq!(result[0].status, AccessRequestStatus::Approved);
    }

    #[tokio::test]
    async fn get_returns_view() {
        let api_client = ApiClient::new_mocked(move |mock| {
            mock.access_requests_api
                .expect_get_details()
                .returning(move |_id| Ok(sample_request()))
                .once();
        });

        let result = client(api_client).get(request_id()).await.unwrap();

        assert_eq!(result.id, request_id());
    }

    #[tokio::test]
    async fn activate_mints_a_lease() {
        let api_client = ApiClient::new_mocked(move |mock| {
            mock.access_requests_api
                .expect_activate()
                .returning(move |_id| Ok(sample_lease()))
                .once();
        });

        let lease = client(api_client).activate(request_id()).await.unwrap();

        assert_eq!(lease.request_id, request_id());
        assert_eq!(lease.status, AccessLeaseStatus::Active);
    }

    #[tokio::test]
    async fn activate_surfaces_api_error() {
        let api_client = ApiClient::new_mocked(move |mock| {
            mock.access_requests_api
                .expect_activate()
                .returning(move |_id| {
                    Err(bitwarden_api_api::apis::Error::Response(
                        bitwarden_api_api::apis::ResponseContent {
                            status: reqwest::StatusCode::CONFLICT,
                            message: "Not approved".to_string(),
                        },
                    ))
                })
                .once();
        });

        let result = client(api_client).activate(request_id()).await;

        assert!(matches!(result, Err(LeasingError::Api(_))));
    }

    #[tokio::test]
    async fn cancel_succeeds() {
        let api_client = ApiClient::new_mocked(move |mock| {
            mock.access_requests_api
                .expect_revoke()
                .returning(move |_id| Ok(()))
                .once();
        });

        let result = client(api_client).cancel(request_id()).await;

        assert!(result.is_ok());
    }
}
