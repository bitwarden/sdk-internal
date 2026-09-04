use std::sync::Arc;

use bitwarden_core::{FromClient, client::ApiConfigurations};
#[cfg(feature = "wasm")]
use wasm_bindgen::prelude::wasm_bindgen;

use super::models::{AccessLeaseExtensionRequest, AccessLeaseRevokeRequest, AccessLeaseView};
use crate::{AccessLeaseId, access_requests::AccessRequestView, error::LeasingError};

/// Client for reading and managing a requester's PAM access leases.
///
/// A lease is minted by [`AccessRequestsClient::activate`](crate::AccessRequestsClient::activate);
/// this client covers the rest of a lease's life: listing the caller's leases, extending an active
/// one, and ending one early.
#[bitwarden_ffi::wasm_object]
#[derive(FromClient)]
pub struct LeasesClient {
    pub(crate) api_configurations: Arc<ApiConfigurations>,
}

#[bitwarden_ffi::wasm_export]
impl LeasesClient {
    /// Lists the caller's currently active leases.
    pub async fn list_active(&self) -> Result<Vec<AccessLeaseView>, LeasingError> {
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
            .collect()
    }

    /// Lists all of the caller's leases, active or not.
    pub async fn list_mine(&self) -> Result<Vec<AccessLeaseView>, LeasingError> {
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
            .collect()
    }

    /// Extends an active lease, returning the updated originating request.
    pub async fn extend(
        &self,
        lease_id: AccessLeaseId,
        request: AccessLeaseExtensionRequest,
    ) -> Result<AccessRequestView, LeasingError> {
        let response = self
            .api_configurations
            .api_client
            .leases_api()
            .extend(lease_id.into(), request.into())
            .await?;

        AccessRequestView::try_from(response)
    }

    /// Ends a lease before it expires, re-locking the cipher.
    pub async fn end(
        &self,
        lease_id: AccessLeaseId,
        request: AccessLeaseRevokeRequest,
    ) -> Result<(), LeasingError> {
        self.api_configurations
            .api_client
            .leases_api()
            .revoke(lease_id.into(), request.into())
            .await?;

        Ok(())
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
        },
    };
    use chrono::{DateTime, Utc};
    use uuid::uuid;

    use super::*;
    use crate::leases::models::AccessLeaseStatus;

    fn lease_id() -> AccessLeaseId {
        AccessLeaseId::new(uuid!("33333333-3333-3333-3333-333333333333"))
    }

    fn client(api_client: ApiClient) -> LeasesClient {
        LeasesClient {
            api_configurations: Arc::new(ApiConfigurations::from_api_client(api_client)),
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

        assert!(matches!(result, Err(LeasingError::Api(_))));
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
}
